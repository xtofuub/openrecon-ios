"""Autonomous planner — decides what step to run next.

Pure rule-based. The rules below are deterministic so the planner can be tested
without an LLM. An LLM fallback hook is provided for novel decisions (Phase 6
target). Today the fallback returns a no-op; wire in Anthropic SDK there when
ready.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from .schema import Phase
from .steps import (
    CorrelateRange,
    DetectAuthPattern,
    EnvironmentCheck,
    GenerateReport,
    InstallHook,
    LaunchTarget,
    MapEndpoints,
    ObjectionRecon,
    ObservePassive,
    RenderFindings,
    RunModule,
    Step,
)

if TYPE_CHECKING:
    from .query import RunQuery
    from .schema import EngagementState


_DEFAULT_MODULE_ORDER = (
    "auth",
    "idor",
    "mass_assignment",
    "tamper",
    "graphql",
    "token_analysis",
)

_DEFAULT_HOOKS = (
    "ssl_pinning_bypass.js",
    "jailbreak_bypass.js",
    "url_session_tracer.js",
    "commoncrypto_tracer.js",
)


class Planner:
    """Rule-driven next-step picker."""

    def __init__(
        self,
        state: "EngagementState",
        query: "RunQuery",
        *,
        modules: tuple[str, ...] = _DEFAULT_MODULE_ORDER,
    ) -> None:
        self.state = state
        self.query = query
        self.modules = modules
        self._bootstrap_index = 0  # how many bootstrap sub-steps we've emitted
        self._modules_run: set[str] = set()

    def next_step(self) -> Step:
        if self.state.budget.exceeded() and self.state.phase != Phase.REPORT:
            self.state.phase = Phase.REPORT

        if self.state.phase == Phase.BOOTSTRAP:
            step = self._bootstrap_next()
            if step is None:
                self.state.phase = Phase.PASSIVE
                return ObservePassive(duration=60)
            return step

        if self.state.phase == Phase.PASSIVE:
            if self._passive_complete():
                self.state.phase = Phase.MAPPING
                return MapEndpoints()
            return ObservePassive(duration=30)

        if self.state.phase == Phase.MAPPING:
            if not self._auth_pattern_recorded():
                return DetectAuthPattern()
            if not self._correlations_run_recently():
                return CorrelateRange()
            self.state.phase = Phase.ACTIVE
            return self._next_module_step()

        if self.state.phase == Phase.ACTIVE:
            step = self._next_module_step()
            if step is not None:
                return step
            findings = self.query.findings()
            self.state.phase = (
                Phase.EXPLOIT if self._has_high_severity(findings) else Phase.REPORT
            )
            return RenderFindings() if self.state.phase == Phase.REPORT else self._next_module_step() or RenderFindings()

        if self.state.phase == Phase.EXPLOIT:
            # Phase 6 will add real confirmation logic. Today: jump to report.
            self.state.phase = Phase.REPORT
            return RenderFindings()

        return RenderFindings()

    # --------------------------------------------------------- bootstrap helpers

    def _bootstrap_next(self) -> Step | None:
        sequence: list[Step] = [
            EnvironmentCheck(),
            LaunchTarget(),
            *[InstallHook(hook=h) for h in _DEFAULT_HOOKS],
            ObjectionRecon(),
        ]
        if self._bootstrap_index >= len(sequence):
            return None
        step = sequence[self._bootstrap_index]
        self._bootstrap_index += 1
        return step

    # ----------------------------------------------------------- phase triggers

    def _passive_complete(self) -> bool:
        flows = list(self.query.flows())
        return len(flows) >= 50

    def _auth_pattern_recorded(self) -> bool:
        return (self.query.run_dir / "artifacts" / "auth_pattern.json").exists()

    def _correlations_run_recently(self) -> bool:
        return (self.query.run_dir / "correlations.jsonl").exists()

    def _next_module_step(self) -> Step | None:
        for name in self.modules:
            if name not in self._modules_run:
                self._modules_run.add(name)
                return RunModule(module=name)
        return None

    @staticmethod
    def _has_high_severity(findings: list[dict]) -> bool:
        return any(f.get("severity") in ("high", "critical") for f in findings)


__all__ = ["Planner"]
