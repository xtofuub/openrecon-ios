from __future__ import annotations

import asyncio
import base64
import json
import shutil
import sys
from pathlib import Path

import pytest

from mitm.client import MitmClient

ROOT = Path(__file__).resolve().parents[1]
FIXTURE_HAR = ROOT / "tests" / "fixtures" / "recorded_ios.har"
FIXTURE_SERVER = ROOT / "tests" / "fixtures" / "mitm_mcp_fixture_server.py"


@pytest.mark.asyncio
async def test_mitm_client_uses_stdio_transport_with_recorded_har(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    artifacts_dir = run_dir / "artifacts"
    artifacts_dir.mkdir(parents=True)
    har_path = artifacts_dir / FIXTURE_HAR.name
    shutil.copyfile(FIXTURE_HAR, har_path)

    async with MitmClient.connect(
        port=18080,
        run_dir=run_dir,
        server_command=sys.executable,
        server_args=[str(FIXTURE_SERVER)],
        cwd=tmp_path,
        tool_timeout_seconds=5,
    ) as client:
        await asyncio.wait_for(client.start_proxy(scope=["api.example.test"]), timeout=3)

        stats = await client.load_traffic_file(har_path)
        assert stats == {"status": "ok", "imported": 2, "skipped": 0, "errors": 0}

        flow_ids = await client.list_flows()
        assert "flow-user-123" in flow_ids

        flow = await client.inspect_flow("flow-user-123")
        assert flow["flow_id"] == "flow-user-123"
        assert flow["request"]["method"] == "GET"
        assert flow["request"]["headers"]["Authorization"].startswith("Bearer ")
        assert flow["response"]["status"] == 200

        extracted = await client.extract("flow-user-123", jsonpath="$.user.id")
        assert extracted == [123]

        auth = await client.detect_auth()
        assert auth.scheme == "jwt"
        assert auth.headers == ["authorization"]

        replay = await client.replay_flow(
            "flow-user-123",
            overrides={"headers": {"X-Test": "1"}, "body_patch": {"$.probe": True}},
        )
        assert replay["flow_id"].startswith("replay-")
        assert replay["request"]["headers"]["X-Test"] == "1"
        assert replay["response"]["status"] == 200
        replay_body = json.loads(base64.b64decode(replay["request"]["body_b64"]))
        assert replay_body == {"probe": True}

        spec = await client.export_openapi_spec("api.example.test")
        assert spec["openapi"] == "3.0.0"


@pytest.mark.asyncio
async def test_load_traffic_file_rejects_paths_outside_run_dir(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    outside = tmp_path / "outside.har"
    shutil.copyfile(FIXTURE_HAR, outside)

    client = MitmClient(
        run_dir=run_dir,
        server_command=sys.executable,
        server_args=[str(FIXTURE_SERVER)],
    )

    with pytest.raises(ValueError, match="outside allowed root"):
        await client.load_traffic_file(outside)
