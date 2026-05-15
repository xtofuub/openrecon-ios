"""Reporter — render Markdown + JSON, validate against schema."""

from __future__ import annotations

import json
from pathlib import Path

import jsonschema
import pytest

from agent.reporter import render_finding, render_run
from agent.schema import Evidence, Finding, ReproStep, Severity

SCHEMA_PATH = Path(__file__).resolve().parents[2] / "templates" / "finding.schema.json"


def _finding(**kwargs) -> Finding:
    defaults = dict(
        run_id="run-1",
        severity=Severity.HIGH,
        category="idor",
        title="Possible IDOR on /v1/users/{id}",
        summary="Mutated path id from 42 to 43 returned victim's profile.",
        evidence=[Evidence(kind="flow", ref="baseline-flow", note="auth'd")],
        correlated_flows=["baseline-flow", "replay-flow"],
        reproduction=[ReproStep(description="Replay with mutation", primitive="replay_flow", args={"flow_id": "baseline-flow"})],
        confidence=0.8,
        tags=["idor", "numeric"],
    )
    defaults.update(kwargs)
    return Finding(**defaults)


def test_render_finding_outputs_markdown_with_title():
    md = render_finding(_finding())
    assert "Possible IDOR" in md
    assert "## Summary" in md
    assert "## Reproduction" in md
    assert "replay_flow" in md


def test_render_run_writes_files_and_index(run_dir):
    findings = [_finding(), _finding(category="auth-bypass", severity=Severity.CRITICAL, title="Auth bypass strip")]
    with (run_dir / "findings.jsonl").open("w", encoding="utf-8") as fh:
        for f in findings:
            fh.write(f.model_dump_json() + "\n")
    n = render_run(run_dir)
    assert n == 2
    out_dir = run_dir / "findings"
    md_files = list(out_dir.glob("*.md"))
    json_files = list(out_dir.glob("*.json"))
    assert len(md_files) == 2
    assert len(json_files) == 2
    report_md = (run_dir / "report.md").read_text(encoding="utf-8")
    assert "Critical" in report_md
    assert "High" in report_md


def test_render_run_zero_findings_when_no_jsonl(run_dir):
    n = render_run(run_dir)
    assert n == 0


def test_finding_json_validates_against_schema():
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    payload = _finding().model_dump(mode="json")
    jsonschema.validate(instance=payload, schema=schema)


def test_finding_missing_required_field_fails_schema():
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    bad = {"finding_id": "x", "severity": "high"}  # missing run_id, category, title, summary
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(instance=bad, schema=schema)
