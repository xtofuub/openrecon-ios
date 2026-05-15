"""Cross-run diff — endpoint deltas, finding new/resolved/persistent, counters."""

from __future__ import annotations

import json
from pathlib import Path

from agent.diff import diff_runs, render_diff


def _seed_flows(run_dir: Path, urls: list[str]) -> None:
    import base64
    import hashlib

    with (run_dir / "mitm_flows.jsonl").open("w", encoding="utf-8") as fh:
        for i, url in enumerate(urls):
            body = b'{"id": 1}'
            record = {
                "event_id": f"e{i}",
                "flow_id": f"f{i}",
                "ts_request": float(1700000000 + i),
                "request": {
                    "url": url,
                    "method": "GET",
                    "headers": {"Authorization": "Bearer x"},
                    "body_b64": None,
                    "body_sha256": None,
                },
                "response": {
                    "status": 200,
                    "headers": {},
                    "body_b64": base64.b64encode(body).decode(),
                    "body_sha256": hashlib.sha256(body).hexdigest(),
                },
                "tags": [],
            }
            fh.write(json.dumps(record) + "\n")


def _seed_findings(run_dir: Path, findings: list[dict]) -> None:
    with (run_dir / "findings.jsonl").open("w", encoding="utf-8") as fh:
        for f in findings:
            fh.write(json.dumps(f) + "\n")


def _finding(category: str, title: str, severity: str = "high") -> dict:
    return {
        "finding_id": f"fid-{category}-{title}",
        "run_id": "r",
        "severity": severity,
        "category": category,
        "title": title,
        "summary": "s",
    }


def test_diff_runs_detects_new_endpoint(tmp_path):
    a = tmp_path / "a"
    b = tmp_path / "b"
    a.mkdir()
    b.mkdir()
    _seed_flows(a, ["https://api.example.com/v1/users/1"])
    _seed_flows(b, [
        "https://api.example.com/v1/users/2",
        "https://api.example.com/v1/orders/9",
    ])
    diff = diff_runs(a, b)
    assert diff.endpoints.new == ["GET api.example.com/v1/orders/{id}"]
    assert diff.endpoints.persistent == ["GET api.example.com/v1/users/{id}"]
    assert diff.endpoints.removed == []


def test_diff_runs_detects_removed_endpoint(tmp_path):
    a = tmp_path / "a"
    b = tmp_path / "b"
    a.mkdir()
    b.mkdir()
    _seed_flows(a, ["https://api.example.com/v1/users/1", "https://api.example.com/v1/orders/9"])
    _seed_flows(b, ["https://api.example.com/v1/users/2"])
    diff = diff_runs(a, b)
    assert diff.endpoints.removed == ["GET api.example.com/v1/orders/{id}"]


def test_diff_findings_new_resolved_persistent(tmp_path):
    a = tmp_path / "a"
    b = tmp_path / "b"
    a.mkdir()
    b.mkdir()
    _seed_findings(a, [
        _finding("idor", "old-idor"),
        _finding("auth-bypass", "persistent-auth"),
    ])
    _seed_findings(b, [
        _finding("auth-bypass", "persistent-auth"),
        _finding("graphql", "new-introspection"),
    ])
    diff = diff_runs(a, b)
    assert len(diff.findings.new) == 1
    assert diff.findings.new[0]["category"] == "graphql"
    assert len(diff.findings.resolved) == 1
    assert diff.findings.resolved[0]["category"] == "idor"
    assert len(diff.findings.persistent) == 1


def test_diff_counters_track_delta(tmp_path):
    a = tmp_path / "a"
    b = tmp_path / "b"
    a.mkdir()
    b.mkdir()
    _seed_flows(a, ["https://api/x"])
    _seed_flows(b, ["https://api/x", "https://api/y"])
    _seed_findings(a, [_finding("idor", "x", "high")])
    _seed_findings(b, [_finding("idor", "x", "high"), _finding("auth-bypass", "y", "critical")])
    diff = diff_runs(a, b)
    assert diff.counters.flows == (1, 2)
    assert diff.counters.findings_total == (1, 2)
    assert diff.counters.findings_by_severity["critical"] == (0, 1)
    assert diff.counters.findings_by_severity["high"] == (1, 1)


def test_diff_runs_empty_dirs(tmp_path):
    a = tmp_path / "a"
    b = tmp_path / "b"
    a.mkdir()
    b.mkdir()
    diff = diff_runs(a, b)
    assert diff.endpoints.new == []
    assert diff.findings.new == []
    assert diff.counters.flows == (0, 0)


def test_render_diff_markdown_includes_sections(tmp_path):
    a = tmp_path / "a"
    b = tmp_path / "b"
    a.mkdir()
    b.mkdir()
    _seed_findings(b, [_finding("idor", "new", "critical")])
    diff = diff_runs(a, b)
    md = render_diff(diff)
    assert "Counters" in md
    assert "New findings" in md
    assert "critical" in md


def test_diff_as_dict_serializable(tmp_path):
    a = tmp_path / "a"
    b = tmp_path / "b"
    a.mkdir()
    b.mkdir()
    diff = diff_runs(a, b)
    d = diff.as_dict()
    # Round-trip through json to confirm pure-JSON shape.
    blob = json.dumps(d)
    again = json.loads(blob)
    assert again["run_a"] == "a"
    assert again["run_b"] == "b"
