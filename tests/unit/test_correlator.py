"""Correlation engine — scoring math + acceptance behavior."""

from __future__ import annotations

import hashlib
import time

from agent.correlate import CorrelationConfig, Correlator
from agent.schema import ArgValue, FridaEvent
from agent.store import EventStore


def test_temporal_only_below_threshold(event_store: EventStore, frida_event_factory, mitm_flow_factory):
    """Pure temporal match shouldn't be enough to accept a correlation."""
    correlator = Correlator(event_store)
    t = time.time()
    ev = frida_event_factory(ts=t, cls="X", method="y", args_preview=["unrelated"])
    flow = mitm_flow_factory(ts=t, url="https://unrelated-host.invalid/p")
    correlator.ingest_frida(ev)
    out = correlator.ingest_flow(flow)
    assert out == []  # temporal=0.2 max < 0.45 threshold


def test_url_substring_in_args_lifts_above_threshold(event_store: EventStore, frida_event_factory, mitm_flow_factory):
    correlator = Correlator(event_store)
    t = time.time()
    ev = frida_event_factory(
        ts=t,
        cls="NSURLSession",
        method="dataTaskWithRequest:",
        args_preview=["https://api.example.com/v1/users/42"],
        arg_types=["NSURLRequest"],
    )
    flow = mitm_flow_factory(ts=t, url="https://api.example.com/v1/users/42")
    correlator.ingest_frida(ev)
    out = correlator.ingest_flow(flow)
    assert out
    assert out[0].score >= 0.45
    assert ev.event_id in out[0].frida_event_ids
    kinds = {s.kind for s in out[0].signals}
    assert "url_substring" in kinds
    assert "arg_type_hint" in kinds


def test_body_sha256_match_strong_signal(event_store: EventStore, frida_event_factory, mitm_flow_factory):
    body = b'{"hello":"world"}'
    sha = hashlib.sha256(body).hexdigest()
    correlator = Correlator(event_store)
    t = time.time()
    ev = FridaEvent(
        ts=t,
        pid=1,
        cls="C",
        method="m",
        args=[ArgValue(type="NSData", repr="<NSData>", preview="…", hash=sha)],
        thread_id=1,
    )
    flow = mitm_flow_factory(ts=t, url="https://x/y", request_body=body)
    correlator.ingest_frida(ev)
    out = correlator.ingest_flow(flow)
    assert out
    assert any(s.kind == "body_match" for s in out[0].signals)


def test_temporal_window_filters_distant_events(event_store: EventStore, frida_event_factory, mitm_flow_factory):
    correlator = Correlator(event_store, CorrelationConfig(temporal_window_s=1.0))
    t = time.time()
    ev_distant = frida_event_factory(ts=t - 10.0, args_preview=["https://api.example.com/v1/users/42"])
    correlator.ingest_frida(ev_distant)
    flow = mitm_flow_factory(ts=t, url="https://api.example.com/v1/users/42")
    out = correlator.ingest_flow(flow)
    assert out == []  # event outside temporal window not considered


def test_max_per_flow_cap(event_store: EventStore, frida_event_factory, mitm_flow_factory):
    correlator = Correlator(event_store, CorrelationConfig(max_per_flow=2, accept_threshold=0.0))
    t = time.time()
    for _ in range(5):
        correlator.ingest_frida(frida_event_factory(ts=t, args_preview=["api.example.com"]))
    flow = mitm_flow_factory(ts=t, url="https://api.example.com/x")
    out = correlator.ingest_flow(flow)
    assert out
    assert len(out[0].frida_event_ids) <= 2


def test_replay_from_store_reads_all_events(event_store: EventStore, frida_event_factory, mitm_flow_factory):
    t = time.time()
    event_store.append("frida_events", frida_event_factory(ts=t, args_preview=["api.example.com"]))
    event_store.append("mitm_flows", mitm_flow_factory(ts=t, url="https://api.example.com/x"))
    correlator = Correlator(event_store)
    results = correlator.replay_from_store()
    assert results
    assert results[0].score >= 0.45


def test_thread_proximity_only_adds_after_first_correlation(event_store: EventStore, frida_event_factory, mitm_flow_factory):
    correlator = Correlator(event_store)
    t = time.time()
    ev1 = frida_event_factory(ts=t, thread_id=7, args_preview=["api.example.com"])
    ev2 = frida_event_factory(ts=t + 0.05, thread_id=7, args_preview=["api.example.com"])
    correlator.ingest_frida(ev1)
    correlator.ingest_frida(ev2)
    flow1 = mitm_flow_factory(flow_id="f1", ts=t, url="https://api.example.com/x")
    correlator.ingest_flow(flow1)
    flow2 = mitm_flow_factory(flow_id="f1", ts=t + 0.05, url="https://api.example.com/x")
    out = correlator.ingest_flow(flow2)
    assert out
    assert any(s.kind == "thread_proximity" for s in out[0].signals)


def test_stack_url_signal_present_when_host_in_stack(event_store: EventStore, frida_event_factory, mitm_flow_factory):
    correlator = Correlator(event_store)
    t = time.time()
    ev = frida_event_factory(
        ts=t,
        args_preview=["unrelated"],
        stack=["0x1 frame_in_api.example.com_module"],
    )
    correlator.ingest_frida(ev)
    flow = mitm_flow_factory(ts=t, url="https://api.example.com/x")
    out = correlator.ingest_flow(flow)
    if out:
        assert any(s.kind == "stack_url" for s in out[0].signals)


def test_body_sha256_helper():
    assert Correlator.body_sha256(b"a") == hashlib.sha256(b"a").hexdigest()
