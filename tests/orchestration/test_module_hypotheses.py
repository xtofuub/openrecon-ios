"""Modules emit hypotheses on ambiguous results so the planner can re-test."""

from __future__ import annotations

import pytest

from agent.schema import SessionCreds, Severity
from api.auth import AuthModule
from api.auth import ModuleInput as AuthInput
from api.idor import IdorModule
from api.idor import ModuleInput as IdorInput


@pytest.mark.asyncio
async def test_idor_low_signal_emits_hypothesis_not_finding(
    run_dir, write_flow_to_run, mitm_flow_factory, fake_mitm_client
):
    """A 2xx replay with no recognized leak keys must produce a hypothesis."""
    baseline = mitm_flow_factory(
        flow_id="baseline",
        url="https://api.example.com/v1/users/42/profile",
    ).model_dump()
    write_flow_to_run(run_dir, baseline)
    # Empty body → _classify returns Severity.LOW (no leak keys, no body change to flag).
    client = fake_mitm_client(
        flows={"baseline": baseline},
        scripts={
            "replay_flow": lambda flow_id, overrides, fake: {
                "flow_id": f"replay-{fake._replay_counter}",
                "response": {"status": 200, "body_b64": "", "body_sha256": "y"},
            }
        },
    )
    inp = IdorInput(
        run_dir=run_dir,
        baseline_flow_ids=["baseline"],
        session_pool={},
        mitm_mcp=client,
        config={},
    )
    result = await IdorModule().run(inp)
    assert all(f.severity != Severity.LOW for f in result.findings), "LOW should become hypothesis"
    assert result.hypotheses, "expected at least one open hypothesis"
    assert "may leak" in result.hypotheses[0].claim


@pytest.mark.asyncio
async def test_auth_swap_noop_emits_hypothesis(
    run_dir, write_flow_to_run, mitm_flow_factory, fake_mitm_client
):
    flow = mitm_flow_factory(
        flow_id="f1",
        request_headers={"Authorization": "Bearer a"},
    ).model_dump()
    write_flow_to_run(run_dir, flow)

    # Swap user_b → 200 with same body hash (swap-noop).
    def replay(flow_id, overrides, fake):
        return {
            "flow_id": "r",
            "response": {
                "status": 200,
                "body_b64": flow["response"]["body_b64"],
                "body_sha256": flow["response"]["body_sha256"],
            },
        }

    client = fake_mitm_client(flows={"f1": flow}, scripts={"replay_flow": replay})
    inp = AuthInput(
        run_dir=run_dir,
        baseline_flow_ids=["f1"],
        session_pool={"user_b": SessionCreds(label="user_b", auth_header="Bearer b")},
        mitm_mcp=client,
        config={},
    )
    result = await AuthModule().run(inp)
    assert result.hypotheses, "swap-noop should open a hypothesis"
    assert any("ownership" in h.claim.lower() for h in result.hypotheses)
