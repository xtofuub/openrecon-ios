"""Auth module — strip / swap / JWT alg=none probes."""

from __future__ import annotations

import pytest

from api.auth import AuthModule, ModuleInput
from agent.schema import SessionCreds, Severity


def _unsigned_jwt() -> str:
    import base64
    import json

    header = base64.urlsafe_b64encode(json.dumps({"alg": "HS256"}).encode()).rstrip(b"=").decode()
    payload = base64.urlsafe_b64encode(json.dumps({"sub": "user", "role": "user"}).encode()).rstrip(b"=").decode()
    sig = "abc123"
    return f"{header}.{payload}.{sig}"


@pytest.mark.asyncio
async def test_auth_strip_returning_2xx_emits_finding(run_dir, write_flow_to_run, mitm_flow_factory, fake_mitm_client):
    flow = mitm_flow_factory(
        flow_id="f1",
        url="https://api.example.com/v1/profile",
        request_headers={"Authorization": "Bearer abc"},
    ).model_dump()
    write_flow_to_run(run_dir, flow)
    client = fake_mitm_client(
        flows={"f1": flow},
        scripts={"replay_flow": lambda flow_id, overrides, fake: {"flow_id": "r", "response": {"status": 200}}},
    )
    inp = ModuleInput(
        run_dir=run_dir,
        baseline_flow_ids=["f1"],
        session_pool={},
        mitm_mcp=client,
        config={},
    )
    result = await AuthModule().run(inp)
    auth_findings = [f for f in result.findings if "strip" in (f.tags or [])]
    assert auth_findings, "expected auth bypass finding when stripping Authorization returns 2xx"


@pytest.mark.asyncio
async def test_auth_skip_when_no_auth_header(run_dir, write_flow_to_run, mitm_flow_factory, fake_mitm_client):
    flow = mitm_flow_factory(flow_id="f1", request_headers={}).model_dump()
    write_flow_to_run(run_dir, flow)
    client = fake_mitm_client(flows={"f1": flow})
    inp = ModuleInput(
        run_dir=run_dir,
        baseline_flow_ids=["f1"],
        session_pool={},
        mitm_mcp=client,
        config={},
    )
    result = await AuthModule().run(inp)
    assert result.findings == []
    assert any("no auth header" in reason for _, reason in result.coverage.skipped)


@pytest.mark.asyncio
async def test_auth_jwt_alg_none_critical(run_dir, write_flow_to_run, mitm_flow_factory, fake_mitm_client):
    token = _unsigned_jwt()
    flow = mitm_flow_factory(
        flow_id="f1",
        request_headers={"Authorization": f"Bearer {token}"},
    ).model_dump()
    write_flow_to_run(run_dir, flow)

    # Only return 2xx for alg=none replay; 401 for others to avoid noise.
    def replay(flow_id, overrides, fake):
        headers = (overrides or {}).get("set_headers") or {}
        auth = headers.get("Authorization", "")
        if auth.endswith("."):  # signature stripped == alg-none variant ends with `.`
            return {"flow_id": "r", "response": {"status": 200}}
        return {"flow_id": "r", "response": {"status": 401}}

    client = fake_mitm_client(flows={"f1": flow}, scripts={"replay_flow": replay})
    inp = ModuleInput(
        run_dir=run_dir,
        baseline_flow_ids=["f1"],
        session_pool={},
        mitm_mcp=client,
        config={},
    )
    result = await AuthModule().run(inp)
    crit = [f for f in result.findings if f.severity == Severity.CRITICAL]
    assert crit, "alg=none acceptance should be critical"
    assert any("jwt-alg-none" in (f.tags or []) for f in crit)


@pytest.mark.asyncio
async def test_auth_swap_with_user_b_session(run_dir, write_flow_to_run, mitm_flow_factory, fake_mitm_client):
    flow = mitm_flow_factory(
        flow_id="f1",
        request_headers={"Authorization": "Bearer user_a"},
        response_body=b'{"user":"alice"}',
    ).model_dump()
    write_flow_to_run(run_dir, flow)

    def replay(flow_id, overrides, fake):
        set_headers = (overrides or {}).get("set_headers") or {}
        if set_headers.get("Authorization") == "Bearer user_b":
            return {
                "flow_id": "r",
                "response": {
                    "status": 200,
                    "body_sha256": "different-hash",
                    "body_b64": "Y2hhbmdlZA==",
                },
            }
        return {"flow_id": "r", "response": {"status": 401}}

    client = fake_mitm_client(flows={"f1": flow}, scripts={"replay_flow": replay})
    inp = ModuleInput(
        run_dir=run_dir,
        baseline_flow_ids=["f1"],
        session_pool={"user_b": SessionCreds(label="user_b", auth_header="Bearer user_b")},
        mitm_mcp=client,
        config={},
    )
    result = await AuthModule().run(inp)
    swap_findings = [f for f in result.findings if "swap" in (f.tags or [])]
    assert swap_findings
