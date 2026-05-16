"""Planner — ranks high-value flows and passes them as baseline_flow_ids."""

from __future__ import annotations

import base64

from agent.planner import Planner
from agent.query import RunQuery
from agent.schema import Budget, EngagementState, Phase, TargetMeta


def _state(phase: Phase = Phase.ACTIVE) -> EngagementState:
    return EngagementState(
        run_id="r1",
        target=TargetMeta(bundle_id="com.example"),
        phase=phase,
        budget=Budget(wall_clock_seconds=1800),
    )


def test_baselines_prefer_authed_2xx_with_id_position(event_store, mitm_flow_factory, run_dir):
    # 1. High-value flow: auth + POST + JSON + ID in path + non-trivial body
    high = mitm_flow_factory(
        flow_id="hv",
        url="https://api.example.com/v1/users/42/profile",
        method="POST",
        request_headers={"Authorization": "Bearer x"},
        response_status=200,
        response_headers={"Content-Type": "application/json"},
        response_body=base64.b64decode("eyJlbWFpbCI6ICJhbGljZUBleGFtcGxlLmNvbSIsICJ1c2VyX2lkIjogNDJ9" + "A" * 200),
    )
    # 2. Auth GET no ID
    low = mitm_flow_factory(
        flow_id="lo",
        url="https://api.example.com/v1/me",
        method="GET",
        request_headers={"Authorization": "Bearer x"},
    )
    # 3. Unauth flow — should be ignored
    unauth = mitm_flow_factory(flow_id="ua", request_headers={})
    # 4. Error — should be ignored
    err = mitm_flow_factory(flow_id="er", request_headers={"Authorization": "Bearer x"}, response_status=500)
    for f in (high, low, unauth, err):
        event_store.append("mitm_flows", f)

    planner = Planner(_state(), RunQuery(run_dir))
    step = planner._next_module_step()
    assert step is not None
    ids = step.kwargs["baseline_flow_ids"]
    assert ids
    assert ids[0] == "hv"
    assert "ua" not in ids
    assert "er" not in ids


def test_baselines_empty_when_no_authed_flows(event_store, mitm_flow_factory, run_dir):
    for i in range(3):
        event_store.append("mitm_flows", mitm_flow_factory(flow_id=f"f{i}", request_headers={}))
    planner = Planner(_state(), RunQuery(run_dir))
    step = planner._next_module_step()
    assert step is not None
    assert step.kwargs["baseline_flow_ids"] == []
