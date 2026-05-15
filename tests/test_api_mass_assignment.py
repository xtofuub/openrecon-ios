"""Mass assignment module — hidden field injection."""

from __future__ import annotations

import base64
import json

import pytest

from api.mass_assignment import MassAssignmentModule, ModuleInput
from agent.schema import Severity


def _post_flow(flow_id: str, url: str, body: dict) -> dict:
    payload = json.dumps(body).encode()
    return {
        "event_id": flow_id + ".req",
        "flow_id": flow_id,
        "ts_request": 1.0,
        "request": {
            "url": url,
            "method": "POST",
            "headers": {"Content-Type": "application/json"},
            "body_b64": base64.b64encode(payload).decode(),
            "body_sha256": None,
        },
        "response": {"status": 200, "headers": {}, "body_b64": None, "body_sha256": None},
        "tags": [],
    }


def _get_flow(flow_id: str, url: str, body: dict) -> dict:
    payload = json.dumps(body).encode()
    return {
        "event_id": flow_id + ".req",
        "flow_id": flow_id,
        "ts_request": 1.0,
        "request": {"url": url, "method": "GET", "headers": {}, "body_b64": None, "body_sha256": None},
        "response": {
            "status": 200,
            "headers": {"Content-Type": "application/json"},
            "body_b64": base64.b64encode(payload).decode(),
            "body_sha256": None,
        },
        "tags": [],
    }


@pytest.mark.asyncio
async def test_mass_assignment_emits_finding_when_hidden_field_accepted(
    run_dir, write_flow_to_run, fake_mitm_client
):
    # GET reveals an "is_admin" field; POST never sets it; injection should trigger.
    write_flow_to_run(run_dir, _get_flow("g1", "https://api/x/me", {"id": 1, "is_admin": False}))
    write_flow_to_run(run_dir, _post_flow("p1", "https://api/x/me", {"name": "alice"}))

    client = fake_mitm_client(
        flows={"p1": _post_flow("p1", "https://api/x/me", {"name": "alice"})},
        scripts={"replay_flow": lambda flow_id, overrides, fake: {"flow_id": "r", "response": {"status": 200}}},
    )
    inp = ModuleInput(
        run_dir=run_dir,
        baseline_flow_ids=["p1"],
        session_pool={},
        mitm_mcp=client,
        config={},
    )
    result = await MassAssignmentModule().run(inp)
    crit = [f for f in result.findings if f.severity == Severity.CRITICAL]
    assert crit
    titles = " ".join(f.title for f in crit)
    assert "is_admin" in titles or "role" in titles


@pytest.mark.asyncio
async def test_mass_assignment_skips_non_json_body(run_dir, write_flow_to_run, fake_mitm_client):
    flow = {
        "event_id": "f.req",
        "flow_id": "f",
        "ts_request": 1.0,
        "request": {"url": "https://api/x", "method": "POST", "headers": {"Content-Type": "text/plain"}, "body_b64": "aGVsbG8="},
        "response": {"status": 200, "headers": {}, "body_b64": None, "body_sha256": None},
        "tags": [],
    }
    write_flow_to_run(run_dir, flow)
    client = fake_mitm_client(flows={"f": flow})
    inp = ModuleInput(
        run_dir=run_dir,
        baseline_flow_ids=["f"],
        session_pool={},
        mitm_mcp=client,
        config={},
    )
    result = await MassAssignmentModule().run(inp)
    assert any("non-JSON body" in reason for _, reason in result.coverage.skipped)


@pytest.mark.asyncio
async def test_mass_assignment_skips_get_method(run_dir, write_flow_to_run, fake_mitm_client):
    flow = _get_flow("g1", "https://api/x", {"id": 1})
    write_flow_to_run(run_dir, flow)
    client = fake_mitm_client(flows={"g1": flow})
    inp = ModuleInput(
        run_dir=run_dir,
        baseline_flow_ids=["g1"],
        session_pool={},
        mitm_mcp=client,
        config={},
    )
    result = await MassAssignmentModule().run(inp)
    assert any("not a write flow" in reason for _, reason in result.coverage.skipped)
