"""EventStore — append, read, SQLite indexes, rebuild."""

from __future__ import annotations

import json
from pathlib import Path

from agent.schema import Correlation, CorrelationSignal, FridaEvent, MitmFlow
from agent.store import EventStore


def test_append_and_read_round_trip(event_store: EventStore, frida_event_factory, mitm_flow_factory):
    ev = frida_event_factory(cls="NSURLSession", method="dataTaskWithRequest:")
    flow = mitm_flow_factory(flow_id="flow-1")
    event_store.append("frida_events", ev)
    event_store.append("mitm_flows", flow)
    fridas = list(event_store.read("frida_events"))
    flows = list(event_store.read("mitm_flows"))
    assert len(fridas) == 1
    assert len(flows) == 1
    assert fridas[0]["cls"] == "NSURLSession"
    assert flows[0]["flow_id"] == "flow-1"


def test_unknown_stream_raises(event_store: EventStore):
    import pytest

    with pytest.raises(KeyError):
        event_store.append("nope", {})


def test_jsonl_files_are_append_only(event_store: EventStore, frida_event_factory):
    event_store.append("frida_events", frida_event_factory())
    event_store.append("frida_events", frida_event_factory(cls="WKWebView"))
    text = (event_store.run_dir / "frida_events.jsonl").read_text(encoding="utf-8")
    assert text.count("\n") == 2
    for line in text.splitlines():
        json.loads(line)  # each line parses


def test_index_by_flow_populates(event_store: EventStore, mitm_flow_factory):
    flow = mitm_flow_factory(flow_id="flow-abc")
    event_store.append("mitm_flows", flow)
    conn = event_store._index_db_conn()
    row = conn.execute("SELECT flow_id, event_id FROM by_flow WHERE flow_id=?", ("flow-abc",)).fetchone()
    assert row is not None
    assert row[0] == "flow-abc"


def test_index_by_method_populates(event_store: EventStore, frida_event_factory):
    event_store.append("frida_events", frida_event_factory(cls="C1", method="m1"))
    event_store.append("frida_events", frida_event_factory(cls="C1", method="m1"))
    conn = event_store._index_db_conn()
    rows = conn.execute("SELECT cls, method FROM by_method WHERE cls=? AND method=?", ("C1", "m1")).fetchall()
    assert len(rows) == 2


def test_fts_indexes_request_url(event_store: EventStore, mitm_flow_factory):
    event_store.append("mitm_flows", mitm_flow_factory(url="https://api.example.com/v1/admin/keys"))
    conn = event_store._index_db_conn()
    rows = conn.execute(
        "SELECT event_id FROM fts WHERE fts MATCH ?", ("admin",)
    ).fetchall()
    assert len(rows) == 1


def test_correlations_index_populates(event_store: EventStore):
    corr = Correlation(
        flow_event_id="fe-1",
        frida_event_ids=["a", "b"],
        score=0.6,
        signals=[CorrelationSignal(kind="temporal", weight=0.2)],
    )
    event_store.append("correlations", corr)
    conn = event_store._index_db_conn()
    rows = conn.execute("SELECT correlation_id, score FROM correlations").fetchall()
    assert len(rows) == 1
    assert rows[0][1] == 0.6


def test_write_artifact_creates_subpaths(event_store: EventStore):
    rel = event_store.write_artifact("openapi/draft.yaml", "openapi: 3.0.0\n")
    assert (event_store.run_dir / rel).exists()
    assert rel == Path("artifacts/openapi/draft.yaml") or str(rel).endswith("draft.yaml")


def test_rebuild_indexes_recreates_db(event_store: EventStore, mitm_flow_factory, frida_event_factory):
    event_store.append("mitm_flows", mitm_flow_factory(flow_id="f1"))
    event_store.append("frida_events", frida_event_factory(cls="X", method="y"))
    db_path = event_store.run_dir / "index" / "events.sqlite"
    assert db_path.exists()
    size_before = db_path.stat().st_size
    event_store.rebuild_indexes()
    assert db_path.exists()
    assert db_path.stat().st_size >= 1
    # Indexes still queryable.
    conn = event_store._index_db_conn()
    assert conn.execute("SELECT COUNT(*) FROM by_flow").fetchone()[0] == 1
    assert conn.execute("SELECT COUNT(*) FROM by_method").fetchone()[0] == 1
    _ = size_before


def test_read_typed_returns_pydantic_models(event_store: EventStore, mitm_flow_factory):
    event_store.append("mitm_flows", mitm_flow_factory(flow_id="typed"))
    items = list(event_store.read_typed("mitm_flows", MitmFlow))
    assert len(items) == 1
    assert isinstance(items[0], MitmFlow)
    assert items[0].flow_id == "typed"


def test_append_dict_form_supported(event_store: EventStore):
    raw = {
        "event_id": "manual",
        "ts": 1.0,
        "pid": 1,
        "cls": "C",
        "method": "m",
        "args": [],
        "ret": None,
        "thread_id": 0,
        "stack": [],
        "hook_source": None,
        "extra": {},
    }
    event_store.append("frida_events", raw)
    items = list(event_store.read_typed("frida_events", FridaEvent))
    assert items[0].event_id == "manual"
