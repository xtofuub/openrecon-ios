"""Autonomous planner — decides what step to run next.

Pure rule-based. The rules below are deterministic so the planner can be tested
without an LLM. An LLM fallback hook is provided for novel decisions (Phase 6
target). Today the fallback returns a no-op; wire in Anthropic SDK there when
ready.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from .schema import Phase
from .steps import (  # noqa: I001  (keep import order stable)
    CorrelateRange,
    DetectAuthPattern,
    EnvironmentCheck,
    InstallHook,
    LaunchTarget,
    MapEndpoints,
    ObjectionRecon,
    ObservePassive,
    RenderFindings,
    RunModule,
    Step,
    TestHypothesis,
)

if TYPE_CHECKING:
    from .llm import LlmStepProposer
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
    """Rule-driven next-step picker.

    The decision loop is deterministic by default. If an `LlmStepProposer` is
    passed (or `enable_llm=True` and `ANTHROPIC_API_KEY` is set), the planner
    falls back to it when the rules would otherwise emit `RenderFindings` too
    early — letting Claude propose a novel investigation step.
    """

    def __init__(
        self,
        state: EngagementState,
        query: RunQuery,
        *,
        modules: tuple[str, ...] = _DEFAULT_MODULE_ORDER,
        llm: LlmStepProposer | None = None,
        enable_llm: bool = False,
    ) -> None:
        self.state = state
        self.query = query
        self.modules = modules
        self._bootstrap_index = 0
        self._modules_run: set[str] = set()
        self.llm = llm
        if llm is None and enable_llm:
            from .llm import LlmStepProposer

            self.llm = LlmStepProposer.from_env()

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
            hypothesis_step = self._open_hypothesis_step()
            if hypothesis_step is not None:
                return hypothesis_step
            proposed = self._llm_propose()
            if proposed is not None:
                return proposed
            self.state.phase = Phase.REPORT
            return RenderFindings()

        hypothesis_step = self._open_hypothesis_step()
        if hypothesis_step is not None:
            return hypothesis_step
        proposed = self._llm_propose()
        if proposed is not None:
            return proposed
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

    def _llm_propose(self) -> Step | None:
        if self.llm is None or not getattr(self.llm, "enabled", False):
            return None
        return self.llm.propose(self.state, self.query)

    def _open_hypothesis_step(self) -> Step | None:
        from . import hypotheses as h_store

        opens = h_store.open_hypotheses(self.query.run_dir)
        if not opens:
            return None
        return TestHypothesis(hypothesis_id=opens[0].hypothesis_id)


__all__ = ["Planner"]
