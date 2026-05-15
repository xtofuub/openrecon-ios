"""IDOR module — mutation coverage, classification, evidence."""

from __future__ import annotations

import base64
import json

import pytest

from agent.schema import SessionCreds, Severity
from api.base import identify_id_positions
from api.idor import IdorModule, ModuleInput


@pytest.mark.asyncio
async def test_idor_runs_against_seeded_flow(run_dir, write_flow_to_run, mitm_flow_factory, fake_mitm_client):
    """End-to-end: baseline path-id flow → mutations → at least one finding emitted."""
    baseline = mitm_flow_factory(
        flow_id="baseline",
        url="https://api.example.com/v1/users/42/profile",
    ).model_dump()
    write_flow_to_run(run_dir, baseline)

    # Scripted replay: pretend mutated id returns another user's data.
    leak_body = base64.b64encode(b'{"email": "victim@example.com", "user_id": 99}').decode()
    client = fake_mitm_client(
        flows={"baseline": baseline},
        scripts={
            "replay_flow": lambda flow_id, overrides, fake: {
                "flow_id": f"replay-{fake._replay_counter}",
                "response": {"status": 200, "body_b64": leak_body, "body_sha256": "x"},
            }
        },
    )
    inp = ModuleInput(
        run_dir=run_dir,
        baseline_flow_ids=["baseline"],
        session_pool={"user_b": SessionCreds(label="user_b", identity_id="99")},
        mitm_mcp=client,
        config={},
    )
    result = await IdorModule().run(inp)
    assert result.module == "idor"
    assert result.findings, "expected at least one IDOR finding"
    high = [f for f in result.findings if f.severity == Severity.HIGH]
    assert high, "expected a HIGH severity finding when other user's data appears in response"


@pytest.mark.asyncio
async def test_idor_negative_control_no_finding(run_dir, write_flow_to_run, mitm_flow_factory, fake_mitm_client):
    """When mutations return 403/404, no finding should be emitted."""
    baseline = mitm_flow_factory(flow_id="baseline", url="https://api.example.com/v1/users/42").model_dump()
    write_flow_to_run(run_dir, baseline)
    client = fake_mitm_client(
        flows={"baseline": baseline},
        scripts={"replay_flow": lambda flow_id, overrides, fake: {"flow_id": "r", "response": {"status": 403}}},
    )
    inp = ModuleInput(
        run_dir=run_dir,
        baseline_flow_ids=["baseline"],
        session_pool={},
        mitm_mcp=client,
        config={},
    )
    result = await IdorModule().run(inp)
    assert all(f.severity != Severity.HIGH for f in result.findings)


@pytest.mark.asyncio
async def test_idor_missing_flow_skipped(run_dir, fake_mitm_client):
    inp = ModuleInput(
        run_dir=run_dir,
        baseline_flow_ids=["never-existed"],
        session_pool={},
        mitm_mcp=fake_mitm_client(),
        config={},
    )
    result = await IdorModule().run(inp)
    assert result.findings == []
    assert result.coverage.skipped


def test_identify_id_positions_finds_numeric_path():
    flow = {"request": {"url": "https://x/v1/users/42", "method": "GET", "headers": {}}}
    positions = identify_id_positions(flow)
    types = {p["type"] for p in positions}
    kinds = {p["kind"] for p in positions}
    assert "numeric" in types
    assert "path" in kinds


def test_identify_id_positions_finds_uuid_path():
    flow = {
        "request": {
            "url": "https://x/v1/orgs/550e8400-e29b-41d4-a716-446655440000",
            "method": "GET",
            "headers": {},
        }
    }
    positions = identify_id_positions(flow)
    assert any(p["type"] == "uuid" for p in positions)


def test_identify_id_positions_finds_body_keys():
    body = json.dumps({"user_id": 42, "name": "alice", "nested": {"owner_id": 5}}).encode()
    flow = {
        "request": {
            "url": "https://x/v1/things",
            "method": "POST",
            "headers": {},
            "body_b64": base64.b64encode(body).decode(),
        }
    }
    positions = identify_id_positions(flow)
    body_keys = [p["key"] for p in positions if p["kind"] == "body"]
    assert any("user_id" in k for k in body_keys)
    assert any("owner_id" in k for k in body_keys)
