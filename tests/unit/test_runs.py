"""Run-directory listing + summary."""

from __future__ import annotations

import json

from agent.runs import list_runs, summarize_run


def test_summarize_empty_run_dir(run_dir):
    summary = summarize_run(run_dir)
    assert summary.run_id == run_dir.name
    assert summary.flows == 0
    assert summary.frida_events == 0
    assert summary.findings_total == 0
    assert summary.bundle_id is None


def test_summarize_with_state_and_events(event_store, mitm_flow_factory, frida_event_factory):
    # Seed events.
    for i in range(3):
        event_store.append("mitm_flows", mitm_flow_factory(flow_id=f"f{i}"))
    for _ in range(5):
        event_store.append("frida_events", frida_event_factory())
    # Seed state.
    state = {
        "run_id": event_store.run_dir.name,
        "target": {"bundle_id": "com.example.foo"},
        "phase": "active",
        "started_at": 1000.0,
        "completed_steps": [
            {"step_uid": "a", "name": "X", "started_at": 1000.0, "finished_at": 1010.0, "success": True, "summary": ""}
        ],
    }
    (event_store.run_dir / "state.json").write_text(json.dumps(state), encoding="utf-8")
    # Seed findings.
    (event_store.run_dir / "findings.jsonl").write_text(
        '{"finding_id":"x","run_id":"r","severity":"high","category":"idor","title":"t","summary":"s"}\n'
        '{"finding_id":"y","run_id":"r","severity":"low","category":"auth-bypass","title":"t","summary":"s"}\n',
        encoding="utf-8",
    )

    summary = summarize_run(event_store.run_dir)
    assert summary.flows == 3
    assert summary.frida_events == 5
    assert summary.bundle_id == "com.example.foo"
    assert summary.phase == "active"
    assert summary.findings_by_severity["high"] == 1
    assert summary.findings_by_severity["low"] == 1
    assert summary.findings_total == 2
    assert summary.duration_seconds == 10.0


def test_list_runs_empty_root_returns_empty(tmp_path):
    assert list_runs(tmp_path / "nope") == []


def test_list_runs_skips_hidden_and_underscore(tmp_path):
    runs_root = tmp_path / "runs"
    runs_root.mkdir()
    (runs_root / "_default").mkdir()  # underscore = skipped
    (runs_root / "real").mkdir()
    (runs_root / "file.txt").write_text("not a dir", encoding="utf-8")
    out = list_runs(runs_root)
    assert {s.run_id for s in out} == {"real"}


def test_list_runs_sorted_newest_first(tmp_path):
    runs_root = tmp_path / "runs"
    runs_root.mkdir()
    for run_id, started in (("a", 1000), ("b", 3000), ("c", 2000)):
        d = runs_root / run_id
        d.mkdir()
        (d / "state.json").write_text(
            json.dumps({
                "run_id": run_id,
                "target": {"bundle_id": "x"},
                "phase": "report",
                "started_at": started,
            }),
            encoding="utf-8",
        )
    out = list_runs(runs_root)
    assert [s.run_id for s in out] == ["b", "c", "a"]


def test_summary_as_dict_iso_format():
    from pathlib import Path

    from agent.runs import RunSummary

    s = RunSummary(
        run_id="x",
        path=Path("/tmp/x"),
        bundle_id="b",
        phase="active",
        started_at=1700000000.0,
        duration_seconds=42.0,
        flows=1,
        frida_events=2,
        findings_by_severity={"high": 1, "critical": 0, "medium": 0, "low": 0, "info": 0},
    )
    d = s.as_dict()
    assert "T" in d["started_at"]
    assert d["findings_total"] == 1
