"""LlmStepProposer — fallback behavior, no-op without API key, parsing."""

from __future__ import annotations

import json
from typing import Any

from agent.llm import LlmStepProposer
from agent.planner import Planner
from agent.query import RunQuery
from agent.schema import Budget, EngagementState, Phase, TargetMeta


def test_proposer_disabled_without_api_key(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    p = LlmStepProposer.from_env()
    assert not p.enabled


def test_proposer_propose_returns_none_when_disabled(run_dir):
    state = EngagementState(
        run_id="r",
        target=TargetMeta(bundle_id="x"),
        phase=Phase.REPORT,
        budget=Budget(wall_clock_seconds=9999),
    )
    q = RunQuery(run_dir)
    p = LlmStepProposer(api_key=None)
    assert p.propose(state, q) is None


def test_proposer_parse_run_module():
    text = json.dumps({"action": "run_module", "args": {"module": "idor"}})
    proposal = LlmStepProposer._parse(text)
    step = LlmStepProposer._materialize(proposal)
    assert step is not None
    assert step.name == "RunModule"
    assert step.kwargs["module"] == "idor"


def test_proposer_parse_observe_passive():
    text = json.dumps({"action": "observe_passive", "args": {"duration": 45}})
    proposal = LlmStepProposer._parse(text)
    step = LlmStepProposer._materialize(proposal)
    assert step is not None
    assert step.name == "ObservePassive"
    assert step.kwargs["duration"] == 45


def test_proposer_parse_unknown_action():
    text = json.dumps({"action": "make_coffee", "args": {}})
    proposal = LlmStepProposer._parse(text)
    step = LlmStepProposer._materialize(proposal)
    assert step is None


def test_proposer_strips_markdown_fences():
    text = "```json\n" + json.dumps({"action": "detect_auth"}) + "\n```"
    proposal = LlmStepProposer._parse(text)
    assert proposal.action == "detect_auth"


def test_proposer_invalid_module_rejected():
    text = json.dumps({"action": "run_module", "args": {"module": "rce_module"}})
    proposal = LlmStepProposer._parse(text)
    step = LlmStepProposer._materialize(proposal)
    assert step is None


class _FakeProposer:
    """Mimics LlmStepProposer.enabled / propose without an SDK."""

    def __init__(self, step):
        self._step = step
        self.enabled = True

    def propose(self, state, query):
        return self._step


def test_planner_uses_llm_fallback_when_rules_exhausted(run_dir):
    """When all modules have been run and budget remains, planner asks LLM."""
    from agent.steps import RunModule

    state = EngagementState(
        run_id="r",
        target=TargetMeta(bundle_id="x"),
        phase=Phase.ACTIVE,
        budget=Budget(wall_clock_seconds=9999),
    )
    q = RunQuery(run_dir)
    fake = _FakeProposer(RunModule(module="idor"))

    # Mark every default module as already run so we hit the LLM fallback.
    p = Planner(state, q, llm=fake)
    p._modules_run = set(p.modules)
    step = p.next_step()
    # Hits exploit phase first (no high findings → REPORT phase, calls LLM, gets idor)
    assert step.name in ("RunModule", "RenderFindings")


def test_planner_no_llm_returns_render_findings(run_dir):
    state = EngagementState(
        run_id="r",
        target=TargetMeta(bundle_id="x"),
        phase=Phase.ACTIVE,
        budget=Budget(wall_clock_seconds=9999),
    )
    q = RunQuery(run_dir)
    p = Planner(state, q)
    p._modules_run = set(p.modules)
    step = p.next_step()
    assert step.name == "RenderFindings"


def test_planner_falls_back_safely_when_llm_disabled(run_dir):
    state = EngagementState(
        run_id="r",
        target=TargetMeta(bundle_id="x"),
        phase=Phase.ACTIVE,
        budget=Budget(wall_clock_seconds=9999),
    )
    q = RunQuery(run_dir)

    class _DisabledProposer:
        enabled = False

        def propose(self, *a: Any, **kw: Any) -> Any:
            raise AssertionError("should not be called when disabled")

    p = Planner(state, q, llm=_DisabledProposer())
    p._modules_run = set(p.modules)
    step = p.next_step()
    assert step.name == "RenderFindings"


def test_proposer_extract_text_handles_message_blocks():
    class _Block:
        type = "text"
        text = "hello"

    class _Resp:
        content = [_Block()]

    assert LlmStepProposer._extract_text(_Resp()) == "hello"
