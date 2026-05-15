"""RunQuery — flow lookups, FTS search, correlation queries."""

from __future__ import annotations

from agent.query import RunQuery
from agent.schema import Correlation, CorrelationSignal


def test_flow_lookup_round_trip(event_store, mitm_flow_factory):
    event_store.append("mitm_flows", mitm_flow_factory(flow_id="abc"))
    q = RunQuery(event_store.run_dir)
    flow = q.flow("abc")
    assert flow is not None
    assert flow["flow_id"] == "abc"


def test_flow_lookup_missing_returns_none(event_store):
    q = RunQuery(event_store.run_dir)
    assert q.flow("does-not-exist") is None


def test_flows_by_endpoint_globs_path(event_store, mitm_flow_factory):
    event_store.append("mitm_flows", mitm_flow_factory(flow_id="a", url="https://api.example.com/v1/users/1"))
    event_store.append("mitm_flows", mitm_flow_factory(flow_id="b", url="https://api.example.com/v1/users/2"))
    event_store.append("mitm_flows", mitm_flow_factory(flow_id="c", url="https://other.example.com/v1/users/3"))
    q = RunQuery(event_store.run_dir)
    out = q.flows_by_endpoint("api.example.com", "/v1/users/*")
    ids = {f["flow_id"] for f in out}
    assert ids == {"a", "b"}


def test_flows_matching_fts_search(event_store, mitm_flow_factory):
    event_store.append("mitm_flows", mitm_flow_factory(flow_id="admin", url="https://api.example.com/admin/keys"))
    event_store.append("mitm_flows", mitm_flow_factory(flow_id="normal", url="https://api.example.com/users/1"))
    q = RunQuery(event_store.run_dir)
    out = q.flows_matching("admin")
    assert {f["flow_id"] for f in out} == {"admin"}


def test_findings_filter_by_category(event_store, run_dir):
    (run_dir / "findings.jsonl").write_text(
        '{"finding_id":"f1","run_id":"r","severity":"high","category":"idor","title":"t","summary":"s"}\n'
        '{"finding_id":"f2","run_id":"r","severity":"low","category":"auth-bypass","title":"t","summary":"s"}\n',
        encoding="utf-8",
    )
    q = RunQuery(run_dir)
    assert {f["finding_id"] for f in q.findings(category="idor")} == {"f1"}
    assert {f["finding_id"] for f in q.findings(severity="low")} == {"f2"}


def test_correlations_for_flow(event_store, mitm_flow_factory):
    flow = mitm_flow_factory(flow_id="f-x")
    event_store.append("mitm_flows", flow)
    corr = Correlation(
        flow_event_id=flow.event_id,
        frida_event_ids=["ev-1"],
        score=0.8,
        signals=[CorrelationSignal(kind="temporal", weight=0.2)],
    )
    event_store.append("correlations", corr)
    q = RunQuery(event_store.run_dir)
    out = q.correlations_for_flow("f-x")
    assert len(out) == 1
    assert out[0]["frida_event_ids"] == ["ev-1"]
