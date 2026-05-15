"""Tamper module — generic mutators surface response divergence."""

from __future__ import annotations

import time

import pytest

from api.tamper import ModuleInput, TamperModule


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
    inp = ModuleInput(
        run_dir=run_dir,
        baseline_flow_ids=["f1"],
        session_pool={},
        mitm_mcp=client,
        config={},
    )
    result = await TamperModule().run(inp)
    assert any(f.category == "api-tampering" for f in result.findings)
