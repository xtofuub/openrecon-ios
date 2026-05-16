"""Synthetic replay — frida-* flows replay through httpx, append back to JSONL."""

from __future__ import annotations

import base64
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from agent.schema import HttpRequest, HttpResponse, MitmFlow
from mitm.client import MitmClient


class _Echo(BaseHTTPRequestHandler):
    def _send(self, status: int, body: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):  # noqa: N802
        self._send(200, json.dumps({"ok": True, "path": self.path}).encode())

    def do_POST(self):  # noqa: N802
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        echo = {"received": body.decode("utf-8", "replace"), "headers": dict(self.headers)}
        self._send(200, json.dumps(echo).encode())

    def log_message(self, *args, **kwargs):  # silence
        pass


@pytest.fixture
def local_server():
    server = HTTPServer(("127.0.0.1", 0), _Echo)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()


@pytest.mark.asyncio
async def test_replay_synthetic_returns_response_and_appends_flow(run_dir, local_server):
    flow = MitmFlow(
        flow_id="frida-test-1",
        ts_request=0.0,
        ts_response=0.1,
        request=HttpRequest(
            url=f"{local_server}/v1/users/42",
            method="GET",
            headers={"X-Test": "1"},
        ),
        response=HttpResponse(status=200, headers={}, body_b64=None),
        duration_ms=100.0,
    )
    (run_dir / "mitm_flows.jsonl").write_text(flow.model_dump_json() + "\n", encoding="utf-8")

    client = MitmClient(run_dir=run_dir)
    result = await client.replay_synthetic("frida-test-1")
    assert result["response"]["status"] == 200
    assert "synthetic-replay" in result["tags"]

    lines = (run_dir / "mitm_flows.jsonl").read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 2  # original + replay
    replay_record = json.loads(lines[1])
    assert replay_record["flow_id"].startswith("frida-replay-")
    assert "synthetic-replay" in replay_record["tags"]


@pytest.mark.asyncio
async def test_replay_synthetic_applies_body_patch(run_dir, local_server):
    body = base64.b64encode(json.dumps({"x": 1, "y": 2}).encode()).decode()
    flow = MitmFlow(
        flow_id="frida-test-2",
        ts_request=0.0,
        request=HttpRequest(
            url=f"{local_server}/api/post",
            method="POST",
            headers={"Content-Type": "application/json"},
            body_b64=body,
        ),
        response=None,
    )
    (run_dir / "mitm_flows.jsonl").write_text(flow.model_dump_json() + "\n", encoding="utf-8")

    client = MitmClient(run_dir=run_dir)
    result = await client.replay_synthetic(
        "frida-test-2",
        overrides={"body_patch": {"y": 999, "z": "added"}},
    )
    assert result["response"]["status"] == 200
    echo_body = base64.b64decode(result["response"]["body_b64"])
    decoded = json.loads(echo_body)
    assert json.loads(decoded["received"]) == {"x": 1, "y": 999, "z": "added"}


@pytest.mark.asyncio
async def test_replay_flow_dispatches_synthetic_for_frida_prefix(run_dir, local_server):
    flow = MitmFlow(
        flow_id="frida-foo-1",
        ts_request=0.0,
        request=HttpRequest(url=f"{local_server}/dispatch", method="GET", headers={}),
        response=None,
    )
    (run_dir / "mitm_flows.jsonl").write_text(flow.model_dump_json() + "\n", encoding="utf-8")
    client = MitmClient(run_dir=run_dir)
    # `replay_flow` should route to synthetic path without needing the mitm subprocess.
    result = await client.replay_flow("frida-foo-1")
    assert result["response"]["status"] == 200
