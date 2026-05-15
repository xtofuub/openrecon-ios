"""Hypothesis-emitting finder rules + planner dispatch."""

from __future__ import annotations

from agent import finder
from agent import hypotheses as h_store
from agent.finder import SignedRequestSuspicionRule
from agent.query import RunQuery
from agent.schema import Budget, EngagementState, Phase, TargetMeta


def _state() -> EngagementState:
    return EngagementState(
        run_id="r1",
        target=TargetMeta(bundle_id="com.example.foo"),
        phase=Phase.ACTIVE,
        budget=Budget(wall_clock_seconds=99999),
    )


def test_signed_request_suspicion_writes_hypothesis(event_store, mitm_flow_factory):
    flow = mitm_flow_factory(
        flow_id="signed-1",
        request_headers={"Authorization": "Bearer x", "X-Signature": "abc123"},
    )
    event_store.append("mitm_flows", flow)
    q = RunQuery(event_store.run_dir)

    hypotheses = SignedRequestSuspicionRule().match_hypotheses(q, _state())
    assert len(hypotheses) == 1
    assert "X-Signature".lower() in hypotheses[0].claim.lower() or "x-signature" in hypotheses[0].claim
    assert hypotheses[0].status == "open"
    assert hypotheses[0].tests
    assert hypotheses[0].tests[0].startswith("replay_with_body_mutation:")


def test_signed_request_suspicion_skips_unauthenticated(event_store, mitm_flow_factory):
    flow = mitm_flow_factory(flow_id="anon", request_headers={"X-Signature": "abc"})
    event_store.append("mitm_flows", flow)
    q = RunQuery(event_store.run_dir)
    hypotheses = SignedRequestSuspicionRule().match_hypotheses(q, _state())
    assert hypotheses == []


def test_run_all_writes_hypotheses_when_run_dir_provided(event_store, mitm_flow_factory):
    flow = mitm_flow_factory(
        flow_id="signed-2",
        request_headers={"Authorization": "Bearer x", "X-Sig": "hmac"},
    )
    event_store.append("mitm_flows", flow)
    q = RunQuery(event_store.run_dir)
    finder.run_all(q, _state(), run_dir=event_store.run_dir)
    stored = h_store.read_all(event_store.run_dir)
    assert stored, "expected hypothesis to land in hypotheses.jsonl"


def test_run_all_skips_hypothesis_write_without_run_dir(event_store, mitm_flow_factory):
    flow = mitm_flow_factory(
        flow_id="signed-3",
        request_headers={"Authorization": "Bearer x", "X-Sig": "hmac"},
    )
    event_store.append("mitm_flows", flow)
    q = RunQuery(event_store.run_dir)
    finder.run_all(q, _state(), run_dir=None)
    assert h_store.read_all(event_store.run_dir) == []
