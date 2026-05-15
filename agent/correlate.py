"""Correlation engine — link Frida runtime events to MITM HTTP flows.

Scoring algorithm:
    score = 0.20 * gauss(|Δt|, σ=0.5s)
          + 0.35 * url_substring_match
          + 0.30 * body_match
          + 0.10 * thread_proximity
          + 0.15 * stack_url_match
          + 0.10 * arg_type_hint

Accept when score >= 0.45. Multiple Frida events can attach to one flow.
"""

from __future__ import annotations

import bisect
import hashlib
import math
import re
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Iterable

from .schema import Correlation, CorrelationSignal, FridaEvent, MitmFlow
from .store import EventStore


@dataclass
class CorrelationConfig:
    temporal_window_s: float = 2.0
    temporal_sigma_s: float = 0.5
    accept_threshold: float = 0.45
    max_per_flow: int = 5
    weights: dict[str, float] = field(
        default_factory=lambda: {
            "temporal": 0.20,
            "url_substring": 0.35,
            "body_match": 0.30,
            "thread_proximity": 0.10,
            "stack_url": 0.15,
            "arg_type_hint": 0.10,
        }
    )


_URL_TYPES = re.compile(r"NS(?:Mutable)?URL(?:Request|Response)?|URLSession|URLRequest")


class Correlator:
    """Stream Frida events and MITM flows; emit correlations.

    Indexes are kept in-memory for the hot path. The store is the authoritative
    record on disk — we only re-build the in-memory indexes on `Correlator(...)`.
    """

    def __init__(self, store: EventStore, cfg: CorrelationConfig | None = None) -> None:
        self.store = store
        self.cfg = cfg or CorrelationConfig()
        self._frida_by_ts: list[tuple[float, FridaEvent]] = []
        self._frida_ts_keys: list[float] = []
        self._frida_by_thread: dict[int, deque[FridaEvent]] = defaultdict(
            lambda: deque(maxlen=256)
        )
        self._last_correlated_thread_per_flow: dict[str, int] = {}

    # ------------------------------------------------------------------ ingest

    def ingest_frida(self, e: FridaEvent) -> None:
        idx = bisect.bisect_left(self._frida_ts_keys, e.ts)
        self._frida_ts_keys.insert(idx, e.ts)
        self._frida_by_ts.insert(idx, (e.ts, e))
        self._frida_by_thread[e.thread_id].append(e)

    def ingest_flow(self, f: MitmFlow) -> list[Correlation]:
        candidates = self._candidates_for_flow(f)
        ranked: list[tuple[float, FridaEvent, list[CorrelationSignal]]] = []
        for c in candidates:
            score, signals = self._score(f, c)
            if score > 0:
                ranked.append((score, c, signals))
        ranked.sort(key=lambda x: x[0], reverse=True)

        accepted = [
            (score, c, signals)
            for (score, c, signals) in ranked[: self.cfg.max_per_flow]
            if score >= self.cfg.accept_threshold
        ]
        if not accepted:
            return []

        corr = Correlation(
            flow_event_id=f.event_id,
            frida_event_ids=[c.event_id for (_, c, _) in accepted],
            score=accepted[0][0],
            signals=[s for (_, _, sigs) in accepted for s in sigs],
        )
        self.store.append("correlations", corr)
        self._last_correlated_thread_per_flow[f.flow_id] = accepted[0][1].thread_id
        return [corr]

    # ------------------------------------------------------------ ingest helpers

    def _candidates_for_flow(self, f: MitmFlow) -> list[FridaEvent]:
        lo = bisect.bisect_left(self._frida_ts_keys, f.ts_request - self.cfg.temporal_window_s)
        hi = bisect.bisect_right(self._frida_ts_keys, f.ts_request + self.cfg.temporal_window_s)
        return [e for (_, e) in self._frida_by_ts[lo:hi]]

    def _score(
        self, flow: MitmFlow, ev: FridaEvent
    ) -> tuple[float, list[CorrelationSignal]]:
        signals: list[CorrelationSignal] = []
        w = self.cfg.weights

        dt = abs(ev.ts - flow.ts_request)
        temporal = math.exp(-(dt**2) / (2 * self.cfg.temporal_sigma_s**2))
        signals.append(
            CorrelationSignal(kind="temporal", weight=w["temporal"] * temporal, detail=f"Δt={dt:.3f}s")
        )

        host = self._host(flow.request.url)
        path = self._path(flow.request.url)
        previews = " ".join(
            [a.preview or "" for a in ev.args] + [(ev.ret.preview if ev.ret else "")]
        )
        url_hit = 0.0
        if host and host in previews:
            url_hit = 1.0
        elif path and any(seg and seg in previews for seg in path.split("/") if len(seg) >= 3):
            url_hit = 0.6
        if url_hit:
            signals.append(
                CorrelationSignal(kind="url_substring", weight=w["url_substring"] * url_hit, detail=host or path)
            )

        body_hit = 0.0
        if flow.request.body_sha256:
            for a in ev.args:
                if a.hash and a.hash == flow.request.body_sha256:
                    body_hit = 1.0
                    break
            if not body_hit:
                preview_lc = previews.lower()
                if flow.request.body_b64 and len(flow.request.body_b64) > 32:
                    sample = flow.request.body_b64[:32].lower()
                    if sample in preview_lc:
                        body_hit = 0.5
        if body_hit:
            signals.append(
                CorrelationSignal(kind="body_match", weight=w["body_match"] * body_hit, detail=f"hit={body_hit:.2f}")
            )

        prev_thread = self._last_correlated_thread_per_flow.get(flow.flow_id)
        if prev_thread is not None and ev.thread_id == prev_thread:
            signals.append(
                CorrelationSignal(kind="thread_proximity", weight=w["thread_proximity"], detail=str(ev.thread_id))
            )

        if host and any(host in frame for frame in ev.stack):
            signals.append(
                CorrelationSignal(kind="stack_url", weight=w["stack_url"], detail=host)
            )

        if any(_URL_TYPES.search(a.type or "") for a in ev.args):
            signals.append(
                CorrelationSignal(kind="arg_type_hint", weight=w["arg_type_hint"], detail="URL-like arg")
            )

        score = min(1.0, sum(s.weight for s in signals))
        return score, signals

    # ----------------------------------------------------------------- helpers

    @staticmethod
    def _host(url: str) -> str:
        try:
            from urllib.parse import urlparse

            return urlparse(url).hostname or ""
        except Exception:
            return ""

    @staticmethod
    def _path(url: str) -> str:
        try:
            from urllib.parse import urlparse

            return urlparse(url).path or ""
        except Exception:
            return ""

    # ------------------------------------------------------------ batch helper

    def replay_from_store(self) -> list[Correlation]:
        """Recompute all correlations from JSONL. Used by `openrecon correlate`."""
        self._frida_by_ts.clear()
        self._frida_ts_keys.clear()
        self._frida_by_thread.clear()
        self._last_correlated_thread_per_flow.clear()
        for ev in self.store.read_typed("frida_events", FridaEvent):
            self.ingest_frida(ev)

        results: list[Correlation] = []
        flows = sorted(
            self.store.read_typed("mitm_flows", MitmFlow), key=lambda f: f.ts_request
        )
        for flow in flows:
            results.extend(self.ingest_flow(flow))
        return results

    @staticmethod
    def body_sha256(body: bytes) -> str:
        return hashlib.sha256(body).hexdigest()


def correlate_run(store: EventStore, cfg: CorrelationConfig | None = None) -> list[Correlation]:
    """Convenience: rebuild correlations for a finished run directory."""
    return Correlator(store, cfg).replay_from_store()


__all__ = ["Correlator", "CorrelationConfig", "correlate_run"]
