"""Finder rules — AuthHeaderInference + CrossTenantLeak."""

from __future__ import annotations

from agent import finder
from agent.query import RunQuery
from agent.schema import Budget, EngagementState, Phase, SessionCreds, Severity, TargetMeta


def _state() -> EngagementState:
    return EngagementState(
        run_id="r1",
        target=TargetMeta(bundle_id="x"),
        phase=Phase.ACTIVE,
        budget=Budget(wall_clock_seconds=99999),
        sessions={"user_b": SessionCreds(label="user_b", identity_id="victim-99")},
    )


def test_auth_header_inference_flags_authorization(event_store, mitm_flow_factory):
    # 5 flows with Authorization → 200; 2 flows without → 401
    for i in range(5):
        event_store.append(
            "mitm_flows",
            mitm_flow_factory(
                flow_id=f"auth-{i}",
                request_headers={"Authorization": "Bearer x"},
                response_status=200,
            ),
        )
    for i in range(2):
        event_store.append(
            "mitm_flows",
            mitm_flow_factory(flow_id=f"unauth-{i}", request_headers={}, response_status=401),
        )
    q = RunQuery(event_store.run_dir)
    out = finder.AuthHeaderInferenceRule().match(q, _state())
    assert out
    assert any("authorization" in f.title.lower() for f in out)


def test_finder_dedupes_by_category_and_flows(event_store):
    class AlwaysSame:
        name = "AlwaysSame"

        def match(self, q, state):
            from agent.schema import Finding

            return [
                Finding(run_id="r", severity=Severity.LOW, category="x", title="t", summary="s", correlated_flows=["a", "b"]),
                Finding(run_id="r", severity=Severity.LOW, category="x", title="t2", summary="s", correlated_flows=["b", "a"]),
            ]

    q = RunQuery(event_store.run_dir)
    out = finder.run_all(q, _state(), rules=[AlwaysSame()])
    # Same (category, sorted(flows)) → only one survives.
    assert len(out) == 1
