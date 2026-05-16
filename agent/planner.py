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
    AcquireBinary,
    CorrelateRange,
    DetectAuthPattern,
    EnvironmentCheck,
    InstallHook,
    LaunchTarget,
    MapEndpoints,
    ObjectionRecon,
    ObservePassive,
    RenderFindings,
    ResumeTarget,
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
    "url_session_body_tracer.js",
    "ns_url_connection_tracer.js",
    "commoncrypto_tracer.js",
    "keychain_full_dump.js",
    "nshttpcookiestorage_tracer.js",
    "nsuserdefaults_tracer.js",
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
        hooks: tuple[str, ...] | None = None,
        llm: LlmStepProposer | None = None,
        enable_llm: bool = False,
    ) -> None:
        self.state = state
        self.query = query
        self.modules = modules
        # ``hooks`` overrides _DEFAULT_HOOKS for the bootstrap sequence. An
        # empty tuple disables auto-install entirely (MCP-driven mode).
        self.hooks: tuple[str, ...] = _DEFAULT_HOOKS if hooks is None else hooks
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
            *[InstallHook(hook=h) for h in self.hooks],
            # Resume immediately after bypass hooks are installed. Doing this
            # *before* AcquireBinary keeps the iOS launchd from killing the
            # suspended process while we read the binary off disk (Wobo and
            # other timer-sensitive apps die after ~20 s suspended).
            ResumeTarget(),
            AcquireBinary(),
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
                baselines = self._pick_baselines(limit=50)
                return RunModule(module=name, baseline_flow_ids=baselines)
        return None

    # ------------------------------------------------------------ flow scoring

    _AUTH_HEADERS = ("authorization", "cookie", "x-api-key", "x-auth-token", "x-session-token")

    def _pick_baselines(self, *, limit: int = 50) -> list[str]:
        """Rank recorded flows by 'value' for active testing and return top N.

        Heuristics, in priority order:
          1. Authenticated (carries one of the known auth-bearing headers).
          2. Successful (2xx).
          3. Bears an ID-like position in path/query/body — modules want IDs.
          4. Non-GET methods (more likely to mutate state).
          5. JSON content-type (cheap to mutate cleanly).
          6. Non-trivial response size (real data, not 204s / health pings).
        """
        try:
            from api.base import identify_id_positions
        except Exception:
            identify_id_positions = None  # type: ignore[assignment]

        scored: list[tuple[float, str]] = []
        for flow in self.query.flows():
            request = flow.get("request") or {}
            response = flow.get("response") or {}
            status = int(response.get("status") or 0)
            if status == 0 or status >= 400:
                continue
            headers_lower = {str(k).lower() for k in (request.get("headers") or {})}
            if not any(h in headers_lower for h in self._AUTH_HEADERS):
                continue
            score = 1.0
            if 200 <= status < 300:
                score += 1.0
            method = str(request.get("method") or "GET").upper()
            if method in ("POST", "PUT", "PATCH", "DELETE"):
                score += 1.0
            content_type = ""
            for k, v in (response.get("headers") or {}).items():
                if str(k).lower() == "content-type":
                    content_type = str(v).lower()
                    break
            if "json" in content_type:
                score += 0.5
            body_b64 = (response.get("body_b64") or "")
            if len(body_b64) > 200:
                score += 0.5
            if identify_id_positions is not None:
                try:
                    if identify_id_positions(flow):
                        score += 1.5
                except Exception:
                    pass
            scored.append((score, str(flow.get("flow_id") or "")))

        scored.sort(key=lambda x: x[0], reverse=True)
        return [fid for _, fid in scored[:limit] if fid]

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
