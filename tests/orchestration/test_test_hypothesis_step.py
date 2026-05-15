"""TestHypothesis step — confirm / refute via body-mutation replay."""

from __future__ import annotations

import pytest

from agent import hypotheses as h_store
from agent.query import RunQuery
from agent.schema import Budget, EngagementState, Hypothesis, Phase, TargetMeta
from agent.steps import ExecContext, TestHypothesis


@pytest.mark.asyncio
async def test_test_hypothesis_confirms_when_replay_rejected(event_store, mitm_flow_factory, fake_mitm_client):
    flow = mitm_flow_factory(flow_id="signed-1", response_status=200)
    event_store.append("mitm_flows", flow)
    h = Hypothesis(claim="body signed", tests=[f"replay_with_body_mutation:{flow.flow_id}"])
    h_store.append(event_store.run_dir, h)

    state = EngagementState(
        run_id="r", target=TargetMeta(bundle_id="x"), phase=Phase.EXPLOIT,
        budget=Budget(wall_clock_seconds=9999),
    )
    client = fake_mitm_client(
        scripts={"replay_flow": lambda flow_id, overrides, fake: {"flow_id": "r", "response": {"status": 400}}}
    )
    q = RunQuery(event_store.run_dir)
    ctx = ExecContext(state=state, store=event_store, query=q, extras={"mitm_client": client})

    step = TestHypothesis(hypothesis_id=h.hypothesis_id)
    result = await step.execute(ctx)
    assert result.success
    again = h_store.read_all(event_store.run_dir)
    assert again[0].status == "confirmed"


@pytest.mark.asyncio
async def test_test_hypothesis_refutes_when_replay_accepted(event_store, mitm_flow_factory, fake_mitm_client):
    flow = mitm_flow_factory(flow_id="signed-2", response_status=200)
    event_store.append("mitm_flows", flow)
    h = Hypothesis(claim="body signed too", tests=[f"replay_with_body_mutation:{flow.flow_id}"])
    h_store.append(event_store.run_dir, h)

    state = EngagementState(
        run_id="r", target=TargetMeta(bundle_id="x"), phase=Phase.EXPLOIT,
        budget=Budget(wall_clock_seconds=9999),
    )
    client = fake_mitm_client(
        scripts={"replay_flow": lambda flow_id, overrides, fake: {"flow_id": "r", "response": {"status": 200}}}
    )
    q = RunQuery(event_store.run_dir)
    ctx = ExecContext(state=state, store=event_store, query=q, extras={"mitm_client": client})

    step = TestHypothesis(hypothesis_id=h.hypothesis_id)
    await step.execute(ctx)
    again = h_store.read_all(event_store.run_dir)
    assert again[0].status == "refuted"


@pytest.mark.asyncio
async def test_test_hypothesis_marks_stale_on_unknown_test(event_store, fake_mitm_client):
    h = Hypothesis(claim="unparseable", tests=["unsupported_test:foo"])
    h_store.append(event_store.run_dir, h)

    state = EngagementState(
        run_id="r", target=TargetMeta(bundle_id="x"), phase=Phase.EXPLOIT,
        budget=Budget(wall_clock_seconds=9999),
    )
    q = RunQuery(event_store.run_dir)
    ctx = ExecContext(state=state, store=event_store, query=q, extras={"mitm_client": fake_mitm_client()})

    step = TestHypothesis(hypothesis_id=h.hypothesis_id)
    await step.execute(ctx)
    again = h_store.read_all(event_store.run_dir)
    assert again[0].status == "stale"


@pytest.mark.asyncio
async def test_test_hypothesis_no_open_returns_failure(event_store, fake_mitm_client):
    state = EngagementState(
        run_id="r", target=TargetMeta(bundle_id="x"), phase=Phase.EXPLOIT,
        budget=Budget(wall_clock_seconds=9999),
    )
    q = RunQuery(event_store.run_dir)
    ctx = ExecContext(state=state, store=event_store, query=q, extras={"mitm_client": fake_mitm_client()})

    step = TestHypothesis()
    result = await step.execute(ctx)
    assert not result.success
    assert "no open hypothesis" in result.summary


def test_planner_emits_test_hypothesis_when_open(event_store):
    from agent.planner import Planner

    h = Hypothesis(claim="dispatch me", tests=["replay_with_body_mutation:abc"])
    h_store.append(event_store.run_dir, h)
    state = EngagementState(
        run_id="r", target=TargetMeta(bundle_id="x"), phase=Phase.EXPLOIT,
        budget=Budget(wall_clock_seconds=9999),
    )
    q = RunQuery(event_store.run_dir)
    planner = Planner(state, q)
    step = planner.next_step()
    assert step.name == "TestHypothesis"
    assert step.kwargs["hypothesis_id"] == h.hypothesis_id
