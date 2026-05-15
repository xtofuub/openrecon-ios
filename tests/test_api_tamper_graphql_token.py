"""Smoke tests for tamper, graphql, token_analysis modules."""

from __future__ import annotations

import base64
import json
import time

import pytest

from api.graphql import GraphqlModule, ModuleInput as GqlInput
from api.tamper import TamperModule, ModuleInput as TamperInput
from api.token_analysis import TokenAnalysisModule, ModuleInput as TokInput, jwt_alg_none
from agent.schema import Severity


def _basic_flow(flow_id: str, url: str, headers: dict | None = None) -> dict:
    return {
        "event_id": flow_id + ".req",
        "flow_id": flow_id,
        "ts_request": time.time(),
        "request": {
            "url": url,
            "method": "GET",
            "headers": headers or {},
            "body_b64": None,
            "body_sha256": None,
        },
        "response": {"status": 200, "headers": {}, "body_b64": None, "body_sha256": None},
        "tags": [],
    }


@pytest.mark.asyncio
async def test_tamper_emits_finding_on_status_divergence(run_dir, write_flow_to_run, fake_mitm_client):
    flow = _basic_flow("f1", "https://api/x/y?id=1")
    write_flow_to_run(run_dir, flow)

    def replay(flow_id, overrides, fake):
        # Pretend trailing /. flips 200 to 500 (parser bug).
        if overrides and "append_to_url" in overrides:
            return {"flow_id": "r", "response": {"status": 500}}
        return {"flow_id": "r", "response": {"status": 200}}

    client = fake_mitm_client(flows={"f1": flow}, scripts={"replay_flow": replay})
    inp = TamperInput(
        run_dir=run_dir,
        baseline_flow_ids=["f1"],
        session_pool={},
        mitm_mcp=client,
        config={},
    )
    result = await TamperModule().run(inp)
    assert any(f.category == "api-tampering" for f in result.findings)


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
    inp = GqlInput(
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


@pytest.mark.asyncio
async def test_token_analysis_alg_none_critical(run_dir, write_flow_to_run, fake_mitm_client):
    header = base64.urlsafe_b64encode(json.dumps({"alg": "HS256"}).encode()).rstrip(b"=").decode()
    payload = base64.urlsafe_b64encode(json.dumps({"sub": "u", "exp": time.time() + 3600}).encode()).rstrip(b"=").decode()
    token = f"{header}.{payload}.sig"
    flow = _basic_flow("t1", "https://api/x", {"Authorization": f"Bearer {token}"})
    write_flow_to_run(run_dir, flow)

    def replay(flow_id, overrides, fake):
        headers = (overrides or {}).get("set_headers") or {}
        auth = headers.get("Authorization", "")
        # Accept only alg=none variants (signature is empty -> ends with ".")
        if auth.endswith("."):
            return {"flow_id": "r", "response": {"status": 200}}
        return {"flow_id": "r", "response": {"status": 401}}

    client = fake_mitm_client(flows={"t1": flow}, scripts={"replay_flow": replay})
    inp = TokInput(
        run_dir=run_dir,
        baseline_flow_ids=["t1"],
        session_pool={},
        mitm_mcp=client,
        config={},
    )
    result = await TokenAnalysisModule().run(inp)
    crit = [f for f in result.findings if f.severity == Severity.CRITICAL]
    assert crit


def test_jwt_alg_none_helper_round_trip():
    header = base64.urlsafe_b64encode(json.dumps({"alg": "HS256"}).encode()).rstrip(b"=").decode()
    payload = base64.urlsafe_b64encode(json.dumps({"sub": "u"}).encode()).rstrip(b"=").decode()
    token = f"{header}.{payload}.sig"
    forged = jwt_alg_none(token)
    assert forged is not None
    parts = forged.split(".")
    assert len(parts) == 3
    assert parts[2] == ""
    new_header = json.loads(base64.urlsafe_b64decode(parts[0] + "=" * (-len(parts[0]) % 4)))
    assert new_header["alg"] == "none"


def test_jwt_alg_none_helper_returns_none_for_malformed():
    assert jwt_alg_none("not.a.jwt.too.many.dots") is None
    assert jwt_alg_none("only-one") is None
