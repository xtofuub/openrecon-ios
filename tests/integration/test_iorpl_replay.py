"""ReplayEngine end-to-end against a local httpx test server."""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from iorpl.format import IorplSession, SessionMeta
from iorpl.mutations import MutationContext
from iorpl.replay import ReplayEngine
from iorpl.suite import FlowFilter, Suite


class _Echo(BaseHTTPRequestHandler):
    """Tiny server: GET /protected with valid Authorization → 200 leaking email;
    same path without auth → 401. POST /things echoes the body."""

    def _send(self, status: int, body: bytes, ct: str = "application/json") -> None:
        self.send_response(status)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):  # noqa: N802
        auth = self.headers.get("Authorization") or ""
        if self.path.startswith("/protected"):
            if not auth.startswith("Bearer "):
                self._send(401, b'{"error":"missing auth"}')
                return
            self._send(200, json.dumps({"email": "victim@example.com", "user_id": 42}).encode())
            return
        self._send(200, b'{"ok":true}')

    def do_POST(self):  # noqa: N802
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        self._send(200, body)

    def log_message(self, *args, **kwargs):
        pass


@pytest.fixture
def server():
    srv = HTTPServer(("127.0.0.1", 0), _Echo)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


@pytest.mark.asyncio
async def test_strip_auth_detected_when_baseline_2xx(tmp_path, server):
    session = IorplSession()
    session.meta = SessionMeta(target_bundle="com.example")
    session.flows = [
        {
            "flow_id": "f1",
            "request": {
                "url": f"{server}/protected",
                "method": "GET",
                "headers": {"Authorization": "Bearer secret"},
            },
            "response": {"status": 200, "headers": {}, "body_b64": None},
        }
    ]
    # Baseline 401 (without auth) → strip_auth should NOT yield AUTH_BYPASSED because
    # baseline was 2xx (200) and mutated is 401 — but our test server returns 401
    # without auth, so strip_auth result will be status_change, NOT auth_bypassed.

    suite = Suite(
        name="strip-test",
        target=FlowFilter(methods=["GET"], require_auth=True),
        mutation_names=["strip_auth"],
        context=MutationContext(),
    )
    engine = ReplayEngine(session, suite, output_path=tmp_path / "results.jsonl")
    results = await engine.run()
    assert results
    r = results[0]
    assert r.mutation_name == "strip_auth"
    assert r.mutated_response["status"] == 401
    assert r.verdict in ("status_change", "no_diff")


@pytest.mark.asyncio
async def test_method_swap_runs_against_local_server(tmp_path, server):
    session = IorplSession()
    session.meta = SessionMeta(target_bundle="com.example")
    session.flows = [
        {
            "flow_id": "f1",
            "request": {
                "url": f"{server}/protected",
                "method": "GET",
                "headers": {"Authorization": "Bearer secret"},
            },
            "response": {"status": 200, "headers": {}, "body_b64": None},
        }
    ]
    suite = Suite(
        name="method-swap",
        target=FlowFilter(methods=["GET"], require_auth=True),
        mutation_names=["method_swap"],
        context=MutationContext(),
    )
    engine = ReplayEngine(session, suite, output_path=tmp_path / "results.jsonl")
    results = await engine.run()
    assert len(results) == 4  # DELETE, PUT, PATCH, POST
    # Result file should be written
    assert (tmp_path / "results.jsonl").exists()
    lines = (tmp_path / "results.jsonl").read_text(encoding="utf-8").splitlines()
    assert len(lines) == 4
