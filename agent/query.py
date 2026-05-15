"""Read-only query API over a run directory.

The planner, finder rules, and bug-bounty modules all read run state through
this layer. It returns plain dicts (already JSON-ready) so callers can pass
results straight into prompts or logs.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from .schema import Finding, FridaEvent, MitmFlow


class RunQuery:
    def __init__(self, run_dir: Path) -> None:
        self.run_dir = Path(run_dir)
        self._db: sqlite3.Connection | None = None

    @property
    def db(self) -> sqlite3.Connection:
        if self._db is None:
            self._db = sqlite3.connect(self.run_dir / "index" / "events.sqlite")
            self._db.row_factory = sqlite3.Row
        return self._db

    # --------------------------------------------------------------- flows

    def flow(self, flow_id: str) -> dict[str, Any] | None:
        for record in self._read_jsonl("mitm_flows.jsonl"):
            if record["flow_id"] == flow_id:
                return record
        return None

    def flows(self, *, since: float | None = None) -> Iterator[dict[str, Any]]:
        for record in self._read_jsonl("mitm_flows.jsonl"):
            if since is None or record["ts_request"] >= since:
                yield record

    def flows_by_endpoint(self, host: str, path_glob: str) -> list[dict[str, Any]]:
        import fnmatch

        out: list[dict[str, Any]] = []
        for record in self._read_jsonl("mitm_flows.jsonl"):
            from urllib.parse import urlparse

            url = urlparse(record["request"]["url"])
            if (url.hostname or "") != host:
                continue
            if not fnmatch.fnmatch(url.path or "", path_glob):
                continue
            out.append(record)
        return out

    def flows_matching(self, fts_query: str) -> list[dict[str, Any]]:
        cur = self.db.cursor()
        rows = cur.execute(
            "SELECT event_id FROM fts WHERE stream='mitm_flows' AND fts MATCH ?",
            (fts_query,),
        ).fetchall()
        ids = {r["event_id"] for r in rows}
        return [r for r in self._read_jsonl("mitm_flows.jsonl") if r["event_id"] in ids]

    # --------------------------------------------------------- frida events

    def frida_event(self, event_id: str) -> dict[str, Any] | None:
        for record in self._read_jsonl("frida_events.jsonl"):
            if record["event_id"] == event_id:
                return record
        return None

    def frida_events_by_method(self, cls: str, method: str) -> list[dict[str, Any]]:
        cur = self.db.cursor()
        rows = cur.execute(
            "SELECT event_id FROM by_method WHERE cls=? AND method=?",
            (cls, method),
        ).fetchall()
        ids = {r["event_id"] for r in rows}
        return [r for r in self._read_jsonl("frida_events.jsonl") if r["event_id"] in ids]

    # ----------------------------------------------------------- correlations

    def correlations_for_flow(self, flow_id: str) -> list[dict[str, Any]]:
        flow = self.flow(flow_id)
        if not flow:
            return []
        out: list[dict[str, Any]] = []
        for record in self._read_jsonl("correlations.jsonl"):
            if record["flow_event_id"] == flow["event_id"]:
                out.append(record)
        return out

    def method_for_flow(self, flow_id: str) -> dict[str, Any] | None:
        corrs = self.correlations_for_flow(flow_id)
        if not corrs:
            return None
        top = max(corrs, key=lambda c: c["score"])
        if not top["frida_event_ids"]:
            return None
        return self.frida_event(top["frida_event_ids"][0])

    def flows_by_method(self, cls: str, method: str) -> list[dict[str, Any]]:
        events = self.frida_events_by_method(cls, method)
        event_ids = {e["event_id"] for e in events}
        flow_ids: set[str] = set()
        for record in self._read_jsonl("correlations.jsonl"):
            if any(eid in event_ids for eid in record["frida_event_ids"]):
                flow_ids.add(record["flow_event_id"])
        return [r for r in self._read_jsonl("mitm_flows.jsonl") if r["event_id"] in flow_ids]

    def call_stack_for_flow(self, flow_id: str) -> list[str]:
        ev = self.method_for_flow(flow_id)
        return list(ev.get("stack", [])) if ev else []

    # --------------------------------------------------------------- findings

    def findings(self, *, category: str | None = None, severity: str | None = None) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for record in self._read_jsonl("findings.jsonl"):
            if category and record.get("category") != category:
                continue
            if severity and record.get("severity") != severity:
                continue
            out.append(record)
        return out

    # ----------------------------------------------------------------- typed views

    def typed_flow(self, flow_id: str) -> MitmFlow | None:
        d = self.flow(flow_id)
        return MitmFlow.model_validate(d) if d else None

    def typed_findings(self) -> list[Finding]:
        return [Finding.model_validate(r) for r in self.findings()]

    def typed_frida_events_by_method(self, cls: str, method: str) -> list[FridaEvent]:
        return [FridaEvent.model_validate(r) for r in self.frida_events_by_method(cls, method)]

    # ---------------------------------------------------------------- helpers

    def _read_jsonl(self, name: str) -> Iterator[dict[str, Any]]:
        path = self.run_dir / name
        if not path.exists():
            return iter(())
        with path.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    yield json.loads(line)

    def close(self) -> None:
        if self._db is not None:
            self._db.close()
            self._db = None


__all__ = ["RunQuery"]
