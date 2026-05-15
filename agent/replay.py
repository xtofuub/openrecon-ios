"""Replay a finding's reproduction steps.

Each `Finding` carries a list of `ReproStep` entries. This module locates a
finding by id under a run directory, walks its steps, dispatches each to the
right primitive (today: `replay_flow`), and reports whether the issue still
reproduces.

Used by `openrecon replay <finding_id>`.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .schema import Finding, ReproStep


@dataclass
class StepOutcome:
    step: ReproStep
    status: str  # "ok", "skipped", "reproduced", "no-repro", "error"
    detail: str = ""
    artifact: dict[str, Any] | None = None


@dataclass
class ReplayReport:
    finding_id: str
    run_id: str
    overall: str  # "reproduced", "no-repro", "partial", "error"
    step_outcomes: list[StepOutcome] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "run_id": self.run_id,
            "overall": self.overall,
            "steps": [
                {
                    "description": o.step.description,
                    "primitive": o.step.primitive,
                    "status": o.status,
                    "detail": o.detail,
                }
                for o in self.step_outcomes
            ],
        }


class FindingNotFoundError(LookupError):
    pass


def iter_findings(run_dir: Path) -> Iterator[Finding]:
    path = run_dir / "findings.jsonl"
    if not path.exists():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        yield Finding.model_validate_json(line)


def find_finding(run_dir: Path, finding_id: str) -> Finding:
    for f in iter_findings(run_dir):
        if f.finding_id == finding_id:
            return f
    raise FindingNotFoundError(f"finding {finding_id!r} not under {run_dir}")


def locate_finding(runs_root: Path, finding_id: str) -> tuple[Path, Finding]:
    """Search every run dir under runs_root for a matching finding."""
    for child in runs_root.iterdir():
        if not child.is_dir():
            continue
        try:
            return child, find_finding(child, finding_id)
        except FindingNotFoundError:
            continue
    raise FindingNotFoundError(f"finding {finding_id!r} not found in any run under {runs_root}")


async def replay_finding(
    finding: Finding,
    *,
    mitm_client: Any,
    run_dir: Path,
) -> ReplayReport:
    """Execute every ReproStep, classifying each as reproduced / no-repro / skipped."""
    outcomes: list[StepOutcome] = []
    for step in finding.reproduction:
        outcomes.append(await _execute_step(step, mitm_client=mitm_client, run_dir=run_dir))
    overall = _summarize(outcomes)
    return ReplayReport(
        finding_id=finding.finding_id,
        run_id=finding.run_id,
        overall=overall,
        step_outcomes=outcomes,
    )


async def _execute_step(step: ReproStep, *, mitm_client: Any, run_dir: Path) -> StepOutcome:
    primitive = step.primitive
    try:
        if primitive == "replay_flow":
            flow_id = step.args.get("flow_id")
            overrides = step.args.get("overrides")
            if not flow_id:
                return StepOutcome(step=step, status="skipped", detail="missing flow_id")
            result = await mitm_client.replay_flow(flow_id, overrides=overrides)
            status = (result.get("response") or {}).get("status")
            detail = f"replay status {status}"
            if _matches_expected(step.expected, status, result):
                return StepOutcome(step=step, status="reproduced", detail=detail, artifact=result)
            return StepOutcome(step=step, status="no-repro", detail=detail, artifact=result)
        if primitive == "extract":
            flow_id = step.args.get("flow_id")
            jsonpath = step.args.get("jsonpath")
            css = step.args.get("css")
            value = await mitm_client.extract(flow_id, jsonpath=jsonpath, css=css)
            return StepOutcome(step=step, status="ok", detail=f"extracted: {value!r}")
        if primitive == "detect_auth":
            value = await mitm_client.detect_auth()
            return StepOutcome(step=step, status="ok", detail=f"auth: {value}")
        return StepOutcome(step=step, status="skipped", detail=f"unknown primitive {primitive!r}")
    except Exception as exc:
        return StepOutcome(step=step, status="error", detail=f"{type(exc).__name__}: {exc}")


def _matches_expected(expected: str | None, status: int | None, result: dict[str, Any]) -> bool:
    """Heuristic: did the replay match the finding's `expected` text?

    Tolerant by design — `expected` is human prose, not a strict assertion.
    """
    if not expected:
        # If no expected text, treat any 2xx as 'reproduced'.
        return status is not None and 200 <= status < 300
    txt = expected.lower()
    body = ""
    try:
        import base64

        body_b64 = (result.get("response") or {}).get("body_b64") or ""
        body = base64.b64decode(body_b64).decode("utf-8", "ignore").lower()
    except Exception:
        pass
    # Look for any status mention or substring match against the body.
    if "2xx" in txt or "200" in txt or "201" in txt or "ok" in txt:
        if status is not None and 200 <= status < 300:
            return True
    if any(token in body for token in txt.split() if len(token) >= 4):
        return True
    return False


def _summarize(outcomes: list[StepOutcome]) -> str:
    if not outcomes:
        return "no-repro"
    statuses = {o.status for o in outcomes}
    if "error" in statuses and len(statuses) == 1:
        return "error"
    if statuses == {"reproduced"} or (statuses == {"reproduced", "ok"}):
        return "reproduced"
    if "reproduced" in statuses:
        return "partial"
    return "no-repro"


def render_report(report: ReplayReport) -> str:
    """Human-readable Markdown for the report."""
    lines = [
        f"# Replay report — {report.finding_id}",
        "",
        f"**Run:** `{report.run_id}`",
        f"**Overall:** `{report.overall}`",
        "",
        "## Steps",
        "",
    ]
    for i, o in enumerate(report.step_outcomes, 1):
        lines.append(f"{i}. **{o.step.description}** → `{o.status}` — {o.detail}")
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# CLI helper — async entrypoint for `openrecon replay`.
# ---------------------------------------------------------------------------


async def run_replay_cli(finding_id: str, runs_root: Path) -> ReplayReport:
    """Look up a finding by id, instantiate MitmClient, execute repro."""
    from mitm.client import MitmClient

    run_dir, finding = locate_finding(runs_root, finding_id)
    async with MitmClient.connect(run_dir=run_dir) as client:
        return await replay_finding(finding, mitm_client=client, run_dir=run_dir)


def run_replay_sync(finding_id: str, runs_root: Path) -> ReplayReport:
    return asyncio.run(run_replay_cli(finding_id, runs_root))


__all__ = [
    "FindingNotFoundError",
    "ReplayReport",
    "StepOutcome",
    "find_finding",
    "iter_findings",
    "locate_finding",
    "render_report",
    "replay_finding",
    "run_replay_cli",
    "run_replay_sync",
]
