"""mitmproxy addon — emit one MitmFlow JSONL line per captured flow.

Drop in via `mitmdump -s mitm/addons/correlation_emitter.py`. The addon writes
to `$LOLMCP_RUN_DIR/mitm_flows.jsonl` so the correlator can ingest live.

This file is loaded by mitmproxy's interpreter, not by our Python entrypoint.
Keep imports minimal so the addon stays fast and dependency-light.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import time
from pathlib import Path

import structlog
from mitmproxy import http  # type: ignore[import-not-found]

log = structlog.get_logger(__name__)


class CorrelationEmitter:
    def __init__(self) -> None:
        run_dir = Path(os.environ.get("LOLMCP_RUN_DIR", "runs/_default"))
        run_dir.mkdir(parents=True, exist_ok=True)
        self.path = run_dir / "mitm_flows.jsonl"

    def response(self, flow: http.HTTPFlow) -> None:
        record = _flow_to_record(flow)
        with self.path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(record) + "\n")


def _flow_to_record(flow: http.HTTPFlow) -> dict:
    req = flow.request
    resp = flow.response
    req_body = req.raw_content or b""
    resp_body = (resp.raw_content if resp else None) or b""
    return {
        "event_id": flow.id + ".req",
        "flow_id": flow.id,
        "ts_request": flow.request.timestamp_start,
        "ts_response": (resp.timestamp_end if resp else None),
        "duration_ms": (
            (resp.timestamp_end - flow.request.timestamp_start) * 1000.0
            if resp and resp.timestamp_end
            else None
        ),
        "request": {
            "url": req.pretty_url,
            "method": req.method,
            "headers": {k: v for k, v in req.headers.items()},
            "body_b64": base64.b64encode(req_body).decode("ascii") if req_body else None,
            "body_sha256": hashlib.sha256(req_body).hexdigest() if req_body else None,
        },
        "response": (
            {
                "status": resp.status_code,
                "headers": {k: v for k, v in resp.headers.items()},
                "body_b64": base64.b64encode(resp_body).decode("ascii") if resp_body else None,
                "body_sha256": hashlib.sha256(resp_body).hexdigest() if resp_body else None,
            }
            if resp
            else None
        ),
        "tags": [],
    }


addons = [CorrelationEmitter()]
