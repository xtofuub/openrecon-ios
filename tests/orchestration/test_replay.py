"""Replay — finding lookup, step dispatch, overall classification."""

from __future__ import annotations

import base64
from pathlib import Path

import pytest

from agent.replay import (
    FindingNotFoundError,
    ReplayReport,
    find_finding,
    iter_findings,
    locate_finding,
    render_report,
    replay_finding,
)
from agent.schema import Finding, ReproStep, Severity


def _seed(run_dir: Path, findings: list[Finding]) -> None:
    path = run_dir / "findings.jsonl"
    with path.open("w", encoding="utf-8") as fh:
        for f in findings:
            fh.write(f.model_dump_json() + "\n")


def _finding(finding_id: str | None = None, **kwargs) -> Finding:
    defaults = dict(
        run_id="run-1",
        severity=Severity.HIGH,
        category="idor",
        title="t",
        summary="s",
        reproduction=[
            ReproStep(
                description="Replay baseline",
                primitive="replay_flow",
                args={"flow_id": "baseline"},
                expected="2xx with victim data",
            )
        ],
    )
    defaults.update(kwargs)
    if finding_id:
        defaults["finding_id"] = finding_id
    return Finding(**defaults)


def test_find_finding_returns_match(run_dir):
    f = _finding(finding_id="abc")
    _seed(run_dir, [f])
    out = find_finding(run_dir, "abc")
    assert out.finding_id == "abc"


def test_find_finding_raises_when_missing(run_dir):
    _seed(run_dir, [])
    with pytest.raises(FindingNotFoundError):
        find_finding(run_dir, "nope")


def test_iter_findings_empty_when_no_jsonl(run_dir):
    assert list(iter_findings(run_dir)) == []


def test_locate_finding_searches_all_runs(tmp_path):
    runs_root = tmp_path / "runs"
    runs_root.mkdir()
    run_a = runs_root / "a"
    run_a.mkdir()
    run_b = runs_root / "b"
    run_b.mkdir()
    _seed(run_a, [_finding(finding_id="other")])
    _seed(run_b, [_finding(finding_id="target")])
    run_dir, f = locate_finding(runs_root, "target")
    assert run_dir == run_b
    assert f.finding_id == "target"


def test_locate_finding_raises_when_no_match(tmp_path):
    runs_root = tmp_path / "runs"
    runs_root.mkdir()
    (runs_root / "empty").mkdir()
    with pytest.raises(FindingNotFoundError):
        locate_finding(runs_root, "missing")


@pytest.mark.asyncio
async def test_replay_finding_classifies_reproduced(run_dir, fake_mitm_client):
    f = _finding(finding_id="r1")
    leak = base64.b64encode(b'{"email":"victim@example.com"}').decode()
    client = fake_mitm_client(
        scripts={
            "replay_flow": lambda flow_id, overrides, fake: {
                "flow_id": "rr",
                "response": {"status": 200, "body_b64": leak, "body_sha256": "x"},
            }
        }
    )
    report = await replay_finding(f, mitm_client=client, run_dir=run_dir)
    assert isinstance(report, ReplayReport)
    assert report.overall == "reproduced"
    assert report.step_outcomes[0].status == "reproduced"


@pytest.mark.asyncio
async def test_replay_finding_classifies_no_repro_on_403(run_dir, fake_mitm_client):
    f = _finding(finding_id="r2")
    client = fake_mitm_client(
        scripts={"replay_flow": lambda flow_id, overrides, fake: {"flow_id": "rr", "response": {"status": 403}}}
    )
    report = await replay_finding(f, mitm_client=client, run_dir=run_dir)
    assert report.overall == "no-repro"


@pytest.mark.asyncio
async def test_replay_finding_error_on_client_exception(run_dir, fake_mitm_client):
    async def raiser(*a, **kw):
        raise RuntimeError("boom")

    client = fake_mitm_client()
    client.replay_flow = raiser  # type: ignore[assignment]
    f = _finding(finding_id="r3")
    report = await replay_finding(f, mitm_client=client, run_dir=run_dir)
    assert report.overall == "error"
    assert report.step_outcomes[0].status == "error"
    assert "boom" in report.step_outcomes[0].detail


@pytest.mark.asyncio
async def test_replay_finding_skips_unknown_primitive(run_dir, fake_mitm_client):
    f = _finding(
        finding_id="r4",
        reproduction=[ReproStep(description="weird", primitive="not_a_primitive", args={})],
    )
    client = fake_mitm_client()
    report = await replay_finding(f, mitm_client=client, run_dir=run_dir)
    assert report.step_outcomes[0].status == "skipped"


def test_render_report_markdown_includes_steps():
    rep = ReplayReport(
        finding_id="f1",
        run_id="r1",
        overall="reproduced",
        step_outcomes=[],
    )
    out = render_report(rep)
    assert "f1" in out
    assert "Overall" in out
    assert "Steps" in out
