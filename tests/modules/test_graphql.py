"""GraphQL module — introspection, depth abuse, alias bypass, batch smuggling."""

from __future__ import annotations

import base64
import json
import time

import pytest

from agent.schema import Severity
from api.graphql import GraphqlModule, ModuleInput


@pytest.mark.asyncio
async def test_graphql_introspection_finding(run_dir, write_flow_to_run, fake_mitm_client):
    body = json.dumps({"query": "{ me { id } }"}).encode()
    flow = {
        "event_id": "g.req",
        "flow_id": "g",
        "ts_request": time.time(),
        "request": {
            "url": "https://api.example.com/graphql",
            "method": "POST",
            "headers": {"Content-Type": "application/json"},
            "body_b64": base64.b64encode(body).decode(),
            "body_sha256": None,
        },
        "response": {"status": 200, "headers": {}, "body_b64": None, "body_sha256": None},
        "tags": [],
    }
    write_flow_to_run(run_dir, flow)
    introspection_body = json.dumps({"data": {"__schema": {"types": []}}}).encode()
    client = fake_mitm_client(
        flows={"g": flow},
        scripts={
            "replay_flow": lambda flow_id, overrides, fake: {
                "flow_id": "r",
                "response": {
                    "status": 200,
                    "body_b64": base64.b64encode(introspection_body).decode(),
                },
            }
        },
    )
    inp = ModuleInput(
        run_dir=run_dir,
        baseline_flow_ids=["g"],
        session_pool={},
        mitm_mcp=client,
        config={},
    )
    result = await GraphqlModule().run(inp)
    intro = [f for f in result.findings if "introspection" in f.title.lower()]
    assert intro
    assert intro[0].severity == Severity.MEDIUM
