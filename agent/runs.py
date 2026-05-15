"""Run-directory listing + summary helpers.

Backs `openrecon runs` — enumerates everything under `runs/`, reads each run's
`state.json` if present, and reports a compact summary for each.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path


@dataclass
class RunSummary:
    run_id: str
    path: Path
    bundle_id: str | None
    phase: str | None
    started_at: float | None
    duration_seconds: float | None
    flows: int
    frida_events: int
    findings_by_severity: dict[str, int]

    @property
    def findings_total(self) -> int:
        return sum(self.findings_by_severity.values())

    def as_dict(self) -> dict:
        return {
            "run_id": self.run_id,
            "path": str(self.path),
            "bundle_id": self.bundle_id,
            "phase": self.phase,
            "started_at": (
                datetime.fromtimestamp(self.started_at, tz=timezone.utc).isoformat()
                if self.started_at
                else None
            ),
            "duration_seconds": self.duration_seconds,
            "flows": self.flows,
            "frida_events": self.frida_events,
            "findings": self.findings_by_severity,
            "findings_total": self.findings_total,
        }


def summarize_run(run_dir: Path) -> RunSummary:
    state_path = run_dir / "state.json"
    bundle_id = phase = None
    started_at = None
    duration_seconds = None
    if state_path.exists():
        try:
            state = json.loads(state_path.read_text(encoding="utf-8"))
            bundle_id = state.get("target", {}).get("bundle_id")
            phase = state.get("phase")
            started_at = state.get("started_at")
            completed = state.get("completed_steps") or []
            if started_at and completed:
                last = completed[-1]
                duration_seconds = max(0.0, last.get("finished_at", started_at) - started_at)
        except Exception:
            pass

    return RunSummary(
        run_id=run_dir.name,
        path=run_dir,
        bundle_id=bundle_id,
        phase=phase,
        started_at=started_at,
        duration_seconds=duration_seconds,
        flows=_count_lines(run_dir / "mitm_flows.jsonl"),
        frida_events=_count_lines(run_dir / "frida_events.jsonl"),
        findings_by_severity=_findings_by_severity(run_dir / "findings.jsonl"),
    )


def list_runs(runs_root: Path) -> list[RunSummary]:
    if not runs_root.exists():
        return []
    summaries = []
    for child in sorted(runs_root.iterdir()):
        if not child.is_dir() or child.name.startswith("_"):
            continue
        summaries.append(summarize_run(child))
    # Newest first if started_at is present.
    summaries.sort(key=lambda s: s.started_at or 0, reverse=True)
    return summaries


def _count_lines(path: Path) -> int:
    if not path.exists():
        return 0
    with path.open("r", encoding="utf-8") as fh:
        return sum(1 for line in fh if line.strip())


def _findings_by_severity(path: Path) -> dict[str, int]:
    out = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    if not path.exists():
        return out
    with path.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except Exception:
                continue
            sev = record.get("severity")
            if sev in out:
                out[sev] += 1
    return out


__all__ = ["RunSummary", "summarize_run", "list_runs"]
