"""Frida HTTP event → MitmFlow normalizer.

Some iOS apps pin SSL aggressively enough that mitmproxy can't read response
bodies even with our standard bypass hooks loaded. In those cases the
NSURLSession / NSURLConnection body tracers (under ``frida_layer/hooks/``)
capture the *plaintext* request and response at the Obj-C delegate /
completion-handler layer — well above the TLS stack, so no pinning bypass
is needed.

This module turns those Frida-captured HTTP events into ``MitmFlow`` records
that look identical to mitmproxy-sourced flows. Once normalized, every
downstream consumer (correlator, endpoint_map, finders, idor/auth/mass_assignment
modules, replay) works unchanged.

Two event shapes are accepted:

1. **One-shot ``flow.complete``** — emitted by the rewritten body tracers.
   Carries full request + response in a single Frida event. The normalizer
   emits a ``MitmFlow`` immediately on receipt.

2. **Legacy granular events** — ``flow.request`` + ``flow.response.chunk`` *
   ``flow.response``, emitted by the older tracer versions. The normalizer
   stitches them per ``task_ptr`` and emits when ``flow.response`` arrives.

Synthetic flow_ids are prefixed ``frida-`` so they never collide with
mitmproxy's UUIDs. Downstream replay uses the prefix to dispatch to the
synthetic-replay path in ``mitm/client.py``.
"""

from __future__ import annotations

import base64
import hashlib
import time
from collections.abc import Iterable
from typing import Any

from ulid import ULID

from .schema import FridaEvent, HttpRequest, HttpResponse, MitmFlow

_HTTP_HOOK_SOURCES = frozenset(
    {
        "url_session_body_tracer.js",
        "ns_url_connection_tracer.js",
    }
)


def _decode_or_hash_body(body_b64: str | None) -> tuple[str | None, str | None]:
    if not body_b64:
        return None, None
    try:
        raw = base64.b64decode(body_b64)
    except Exception:
        return body_b64, None
    return body_b64, hashlib.sha256(raw).hexdigest()


def _coerce_headers(value: Any) -> dict[str, str]:
    if not isinstance(value, dict):
        return {}
    return {str(k): str(v) for k, v in value.items()}


def _build_request(req: dict[str, Any], default_url: str, default_method: str) -> HttpRequest:
    body_b64 = req.get("body_b64")
    body_sha = req.get("body_sha256")
    if body_b64 and not body_sha:
        body_b64, body_sha = _decode_or_hash_body(body_b64)
    return HttpRequest(
        url=str(req.get("url") or default_url),
        method=str(req.get("method") or default_method).upper(),
        headers=_coerce_headers(req.get("headers")),
        body_b64=body_b64,
        body_sha256=body_sha,
    )


def _build_response(resp: dict[str, Any]) -> HttpResponse:
    body_b64 = resp.get("body_b64")
    body_sha = resp.get("body_sha256")
    if body_b64 and not body_sha:
        body_b64, body_sha = _decode_or_hash_body(body_b64)
    return HttpResponse(
        status=int(resp.get("status") or 0),
        headers=_coerce_headers(resp.get("headers")),
        body_b64=body_b64,
        body_sha256=body_sha,
    )


class FridaFlowNormalizer:
    """Stateful per-task stitcher that emits MitmFlow records.

    The normalizer is stream-safe: feed events in arrival order via
    :meth:`ingest`. It returns a list of zero or more :class:`MitmFlow`
    objects that the caller should append to the event store.
    """

    def __init__(self, *, source_tag: str = "frida-sourced") -> None:
        self.source_tag = source_tag
        self._pending: dict[str, dict[str, Any]] = {}

    # ------------------------------------------------------------------ public

    def ingest(self, event: FridaEvent | dict[str, Any]) -> list[MitmFlow]:
        ev = event if isinstance(event, FridaEvent) else FridaEvent.model_validate(event)
        if ev.hook_source not in _HTTP_HOOK_SOURCES:
            return []
        extra = ev.extra or {}
        kind = str(extra.get("kind") or ev.method or "")
        if kind == "flow.complete":
            flow = self._from_complete(ev, extra)
            return [flow] if flow else []
        if kind == "flow.request":
            self._on_request(ev, extra)
            return []
        if kind in ("flow.response.chunk", "flow.response"):
            flow = self._on_response(ev, extra, finalize=kind == "flow.response")
            return [flow] if flow else []
        return []

    def ingest_many(self, events: Iterable[FridaEvent | dict[str, Any]]) -> list[MitmFlow]:
        out: list[MitmFlow] = []
        for ev in events:
            out.extend(self.ingest(ev))
        return out

    # --------------------------------------------------------- one-shot path

    def _from_complete(self, ev: FridaEvent, extra: dict[str, Any]) -> MitmFlow | None:
        flow_id = str(extra.get("flow_id_synthetic") or f"frida-{ULID()}")
        ts_request = float(extra.get("ts_request") or ev.ts)
        ts_response = float(extra.get("ts_response") or ev.ts)
        req = extra.get("request") or {}
        resp = extra.get("response") or {}
        default_url = str(extra.get("url") or req.get("url") or "?")
        default_method = str(extra.get("method") or req.get("method") or "GET")
        try:
            return MitmFlow(
                flow_id=flow_id,
                ts_request=ts_request,
                ts_response=ts_response,
                request=_build_request(req, default_url, default_method),
                response=_build_response(resp),
                duration_ms=max(0.0, (ts_response - ts_request) * 1000.0),
                tags=[self.source_tag, str(extra.get("source") or "frida")],
            )
        except Exception:
            return None

    # --------------------------------------------------- legacy granular path

    def _on_request(self, ev: FridaEvent, extra: dict[str, Any]) -> None:
        task_ptr = str(extra.get("task_ptr") or "")
        if not task_ptr:
            return
        self._pending[task_ptr] = {
            "url": extra.get("url"),
            "method": extra.get("method"),
            "request_headers": extra.get("headers") or extra.get("request_headers") or {},
            "request_body_b64": extra.get("body_b64"),
            "ts_request": float(extra.get("ts") or ev.ts),
            "response_chunks": [],
            "response_status": 0,
            "response_headers": {},
        }

    def _on_response(
        self,
        ev: FridaEvent,
        extra: dict[str, Any],
        *,
        finalize: bool,
    ) -> MitmFlow | None:
        task_ptr = str(extra.get("task_ptr") or "")
        if not task_ptr:
            return None
        info = self._pending.setdefault(
            task_ptr,
            {
                "url": extra.get("url"),
                "method": extra.get("method"),
                "request_headers": extra.get("request_headers") or {},
                "request_body_b64": None,
                "ts_request": float(extra.get("ts") or ev.ts),
                "response_chunks": [],
                "response_status": 0,
                "response_headers": {},
            },
        )
        chunk = extra.get("body_b64") or extra.get("body_preview")
        if isinstance(chunk, str) and extra.get("body_b64"):
            info["response_chunks"].append(chunk)
        if finalize:
            info["response_status"] = int(extra.get("response_status") or info["response_status"])
            info["response_headers"] = (
                extra.get("response_headers") or info["response_headers"]
            )
            ts_response = float(extra.get("ts") or ev.ts)
            chunks_b64 = info["response_chunks"]
            body_b64 = None
            if chunks_b64:
                try:
                    raw = b"".join(base64.b64decode(c) for c in chunks_b64)
                    body_b64 = base64.b64encode(raw).decode("ascii")
                except Exception:
                    body_b64 = None
            req_body_b64, req_sha = _decode_or_hash_body(info.get("request_body_b64"))
            resp_body_b64, resp_sha = _decode_or_hash_body(body_b64)
            try:
                flow = MitmFlow(
                    flow_id=f"frida-{ULID()}",
                    ts_request=info["ts_request"],
                    ts_response=ts_response,
                    request=HttpRequest(
                        url=str(info.get("url") or "?"),
                        method=str(info.get("method") or "GET").upper(),
                        headers=_coerce_headers(info.get("request_headers")),
                        body_b64=req_body_b64,
                        body_sha256=req_sha,
                    ),
                    response=HttpResponse(
                        status=int(info.get("response_status") or 0),
                        headers=_coerce_headers(info.get("response_headers")),
                        body_b64=resp_body_b64,
                        body_sha256=resp_sha,
                    ),
                    duration_ms=max(0.0, (ts_response - info["ts_request"]) * 1000.0),
                    tags=[self.source_tag, "frida_nsurlsession"],
                )
            except Exception:
                self._pending.pop(task_ptr, None)
                return None
            self._pending.pop(task_ptr, None)
            return flow
        return None

    # --------------------------------------------------------------- helpers

    def pending_task_count(self) -> int:
        return len(self._pending)

    def reap_stale(self, *, older_than_seconds: float = 60.0) -> int:
        """Drop in-flight stitching state for tasks abandoned mid-flight."""
        now = time.time()
        stale: list[str] = []
        for ptr, info in self._pending.items():
            ts = info.get("ts_request")
            if ts is None:
                ts = now
            if now - float(ts) >= older_than_seconds:
                stale.append(ptr)
        for ptr in stale:
            self._pending.pop(ptr, None)
        return len(stale)


__all__ = ["FridaFlowNormalizer"]
