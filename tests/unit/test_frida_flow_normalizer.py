"""Frida flow normalizer — turn HTTP tracer events into MitmFlow records."""

from __future__ import annotations

import base64

import pytest

from agent.frida_flow_normalizer import FridaFlowNormalizer
from agent.schema import FridaEvent


def _ev(*, hook: str, kind: str, extra: dict, ts: float = 1.0) -> FridaEvent:
    return FridaEvent(
        ts=ts,
        pid=1,
        cls="NSURLSession",
        method=kind,
        hook_source=hook,
        extra={**extra, "kind": kind},
    )


def test_flow_complete_event_emits_mitmflow() -> None:
    body = b'{"id": 1}'
    body_b64 = base64.b64encode(body).decode()
    norm = FridaFlowNormalizer()
    out = norm.ingest(
        _ev(
            hook="url_session_body_tracer.js",
            kind="flow.complete",
            extra={
                "flow_id_synthetic": "frida-NSURLSession-ABC123",
                "url": "https://api.example.com/v1/users/42",
                "method": "POST",
                "ts_request": 100.0,
                "ts_response": 100.5,
                "request": {
                    "url": "https://api.example.com/v1/users/42",
                    "method": "POST",
                    "headers": {"Authorization": "Bearer x"},
                    "body_b64": None,
                },
                "response": {
                    "status": 200,
                    "headers": {"Content-Type": "application/json"},
                    "body_b64": body_b64,
                    "body_sha256": None,
                },
                "source": "frida_nsurlsession",
            },
        )
    )
    assert len(out) == 1
    flow = out[0]
    assert flow.flow_id == "frida-NSURLSession-ABC123"
    assert flow.request.method == "POST"
    assert flow.response.status == 200
    assert flow.response.body_b64 == body_b64
    assert flow.response.body_sha256, "sha256 must be filled in if missing on input"
    assert "frida-sourced" in flow.tags
    assert "frida_nsurlsession" in flow.tags


def test_unrelated_hook_source_is_ignored() -> None:
    norm = FridaFlowNormalizer()
    out = norm.ingest(_ev(hook="commoncrypto_tracer.js", kind="flow.complete", extra={}))
    assert out == []


def test_granular_legacy_events_are_stitched_per_task() -> None:
    norm = FridaFlowNormalizer()
    # flow.request alone returns nothing yet — pending.
    out1 = norm.ingest(
        _ev(
            hook="url_session_body_tracer.js",
            kind="flow.request",
            extra={
                "task_ptr": "0x7f01",
                "url": "https://api.example.com/v1/items",
                "method": "GET",
                "headers": {"Authorization": "Bearer x"},
                "ts": 100.0,
            },
            ts=100.0,
        )
    )
    assert out1 == []
    assert norm.pending_task_count() == 1

    # A chunk event with a body_b64 is appended to chunks but does not finalize.
    chunk = base64.b64encode(b'{"items":').decode()
    out2 = norm.ingest(
        _ev(
            hook="url_session_body_tracer.js",
            kind="flow.response.chunk",
            extra={"task_ptr": "0x7f01", "body_b64": chunk},
            ts=100.2,
        )
    )
    assert out2 == []

    final_chunk = base64.b64encode(b'[]}').decode()
    # The final flow.response carries response_status / response_headers / final chunk.
    out3 = norm.ingest(
        _ev(
            hook="url_session_body_tracer.js",
            kind="flow.response",
            extra={
                "task_ptr": "0x7f01",
                "response_status": 200,
                "response_headers": {"Content-Type": "application/json"},
                "body_b64": final_chunk,
                "ts": 100.4,
            },
            ts=100.4,
        )
    )
    assert len(out3) == 1
    flow = out3[0]
    assert flow.flow_id.startswith("frida-")
    assert flow.response.status == 200
    assert flow.response.body_b64
    assert base64.b64decode(flow.response.body_b64) == b'{"items":[]}'


def test_reap_stale_drops_in_flight_state() -> None:
    norm = FridaFlowNormalizer()
    norm.ingest(
        _ev(
            hook="url_session_body_tracer.js",
            kind="flow.request",
            extra={"task_ptr": "0xabc", "url": "https://x", "method": "GET", "headers": {}, "ts": 0.0},
            ts=0.0,
        )
    )
    assert norm.pending_task_count() == 1
    reaped = norm.reap_stale(older_than_seconds=0.0)
    assert reaped == 1
    assert norm.pending_task_count() == 0


def test_malformed_flow_complete_returns_empty() -> None:
    norm = FridaFlowNormalizer()
    out = norm.ingest(
        _ev(
            hook="url_session_body_tracer.js",
            kind="flow.complete",
            extra={"response": "not a dict"},
        )
    )
    # MitmFlow construction fails → normalizer swallows + returns []
    assert out == []
