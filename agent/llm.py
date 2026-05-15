"""Optional Anthropic-SDK fallback for the planner.

Today the planner is rule-driven and deterministic. When a rule chain has
nothing useful left to do, we can ask Claude for a next step instead of
defaulting straight to report. This module wraps that decision behind a clean
interface so the planner has no SDK import at the top level.

Usage:

    proposer = LlmStepProposer.from_env()    # respects ANTHROPIC_API_KEY
    if proposer.enabled:
        step = proposer.propose(state, query)
        if step is not None:
            return step

If `ANTHROPIC_API_KEY` is unset or the SDK is not installed, `enabled` is False
and `propose()` is a no-op. No exceptions propagate to the planner.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

import structlog

from .steps import (
    CorrelateRange,
    DetectAuthPattern,
    MapEndpoints,
    ObservePassive,
    RunModule,
    Step,
)

if TYPE_CHECKING:
    from .query import RunQuery
    from .schema import EngagementState

log = structlog.get_logger(__name__)


DEFAULT_MODEL = "claude-opus-4-7"

_SYSTEM_PROMPT = """
You are the autonomous planner for openrecon, an iOS bug-bounty platform.

Given the current engagement state (phase, counters, hypotheses, recent
findings) you choose ONE next action. Your reply MUST be a single JSON object:

  {"action": "<name>", "args": {...}}

Where action is one of:
  - "observe_passive"   (args: {"duration": seconds})
  - "map_endpoints"     (no args)
  - "detect_auth"       (no args)
  - "correlate_range"   (no args)
  - "run_module"        (args: {"module": "idor"|"auth"|"mass_assignment"|"tamper"|"graphql"|"token_analysis"})
  - "noop"              (only if literally nothing left to do)

No prose. No explanation. JSON only.
""".strip()


@dataclass
class _Proposal:
    action: str
    args: dict[str, Any]


class LlmStepProposer:
    """Wraps the Anthropic SDK in a way the planner can call safely.

    If the SDK isn't installed or the API key is missing, the instance is
    effectively a no-op (`enabled` is False, `propose()` returns None).
    """

    def __init__(self, *, api_key: str | None = None, model: str = DEFAULT_MODEL) -> None:
        self.api_key = api_key or os.environ.get("ANTHROPIC_API_KEY")
        self.model = model
        self._client = self._make_client()

    @classmethod
    def from_env(cls, *, model: str = DEFAULT_MODEL) -> "LlmStepProposer":
        return cls(api_key=os.environ.get("ANTHROPIC_API_KEY"), model=model)

    @property
    def enabled(self) -> bool:
        return self._client is not None

    def _make_client(self) -> Any:
        if not self.api_key:
            return None
        try:
            import anthropic
        except ImportError:
            log.warning("llm.anthropic_sdk_missing")
            return None
        return anthropic.Anthropic(api_key=self.api_key)

    def propose(self, state: "EngagementState", query: "RunQuery") -> Step | None:
        if not self.enabled:
            return None
        try:
            ctx = self._build_context(state, query)
            response = self._client.messages.create(  # type: ignore[union-attr]
                model=self.model,
                max_tokens=256,
                system=_SYSTEM_PROMPT,
                messages=[{"role": "user", "content": ctx}],
            )
            text = self._extract_text(response)
            proposal = self._parse(text)
            return self._materialize(proposal)
        except Exception as exc:
            log.warning("llm.propose_failed", error=str(exc))
            return None

    def _build_context(self, state: "EngagementState", query: "RunQuery") -> str:
        flows = list(query.flows())
        findings = query.findings()
        ctx = {
            "phase": state.phase.value,
            "counters": dict(state.counters),
            "budget_remaining_s": int(state.budget.remaining_seconds()),
            "flows_observed": len(flows),
            "endpoints_seen": len(_dedupe_endpoints(flows)),
            "findings_by_severity": _by_severity(findings),
            "hypotheses": [
                {"id": h.hypothesis_id, "claim": h.claim, "status": h.status}
                for h in state.hypotheses[:5]
            ],
            "completed_steps_recent": [
                {"name": s.name, "success": s.success, "summary": s.summary}
                for s in state.completed_steps[-5:]
            ],
        }
        return "Current engagement state:\n\n" + json.dumps(ctx, indent=2, default=str)

    @staticmethod
    def _extract_text(response: Any) -> str:
        # Anthropic SDK returns Message with content blocks (TextBlock for text).
        for block in getattr(response, "content", []) or []:
            if getattr(block, "type", None) == "text":
                return block.text  # type: ignore[no-any-return]
        return str(response)

    @staticmethod
    def _parse(text: str) -> _Proposal:
        text = text.strip()
        if text.startswith("```"):
            # Strip possible markdown fence
            lines = [ln for ln in text.splitlines() if not ln.startswith("```")]
            text = "\n".join(lines)
        data = json.loads(text)
        return _Proposal(action=data.get("action", "noop"), args=data.get("args") or {})

    @staticmethod
    def _materialize(p: _Proposal) -> Step | None:
        action = p.action
        if action == "observe_passive":
            duration = int(p.args.get("duration", 30))
            return ObservePassive(duration=duration)
        if action == "map_endpoints":
            return MapEndpoints()
        if action == "detect_auth":
            return DetectAuthPattern()
        if action == "correlate_range":
            return CorrelateRange()
        if action == "run_module":
            module = p.args.get("module")
            if module in (
                "idor",
                "auth",
                "mass_assignment",
                "tamper",
                "graphql",
                "token_analysis",
            ):
                return RunModule(module=module)
        return None  # noop or unknown


def _dedupe_endpoints(flows: list[dict[str, Any]]) -> set[tuple[str, str, str]]:
    from urllib.parse import urlparse

    out: set[tuple[str, str, str]] = set()
    for f in flows:
        u = urlparse(f["request"]["url"])
        out.add((u.hostname or "", f["request"]["method"], u.path or ""))
    return out


def _by_severity(findings: list[dict[str, Any]]) -> dict[str, int]:
    out: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev = f.get("severity") or "info"
        if sev in out:
            out[sev] += 1
    return out


__all__ = ["LlmStepProposer", "DEFAULT_MODEL"]
