"""Pydantic round-trip + invariant tests for every schema model."""

from __future__ import annotations

import json
import time

import pytest

from agent.schema import (
    Budget,
    Correlation,
    CorrelationSignal,
    EngagementState,
    Evidence,
    Finding,
    FridaEvent,
    HttpRequest,
    HttpResponse,
    Hypothesis,
    MitmFlow,
    ModuleCoverage,
    ModuleResult,
    Phase,
    ReproStep,
    Severity,
    SessionCreds,
    StepRecord,
    TargetMeta,
)


def test_severity_phase_string_enum():
    assert Severity.CRITICAL.value == "critical"
    assert Phase.BOOTSTRAP.value == "bootstrap"


def test_frida_event_defaults_assign_ulid_and_now():
    ev = FridaEvent(pid=1, cls="C", method="m")
    assert ev.event_id and len(ev.event_id) >= 24  # ULIDs are 26 chars
    assert abs(ev.ts - time.time()) < 2.0


def test_mitm_flow_round_trip():
    flow = MitmFlow(
        flow_id="f1",
        ts_request=time.time(),
        request=HttpRequest(url="https://a/b", method="GET"),
        response=HttpResponse(status=200),
    )
    again = MitmFlow.model_validate_json(flow.model_dump_json())
    assert again.flow_id == "f1"
    assert again.request.url == "https://a/b"


def test_correlation_signals_weights_sum():
    corr = Correlation(
        flow_event_id="fe",
        frida_event_ids=["a", "b"],
        score=0.62,
        signals=[
            CorrelationSignal(kind="temporal", weight=0.2),
            CorrelationSignal(kind="url_substring", weight=0.42),
        ],
    )
    assert pytest.approx(sum(s.weight for s in corr.signals), abs=1e-6) == 0.62


def test_finding_round_trip_preserves_evidence_and_repro():
    f = Finding(
        run_id="r1",
        severity=Severity.HIGH,
        category="idor",
        title="t",
        summary="s",
        evidence=[Evidence(kind="flow", ref="x"), Evidence(kind="frida_event", ref="y")],
        reproduction=[ReproStep(description="d", primitive="replay_flow", args={"flow_id": "x"})],
    )
    blob = f.model_dump_json()
    again = Finding.model_validate_json(blob)
    assert again.severity == Severity.HIGH
    assert again.evidence[0].ref == "x"
    assert again.reproduction[0].primitive == "replay_flow"


def test_engagement_state_save_round_trip(tmp_path):
    state = EngagementState(
        run_id="r1",
        target=TargetMeta(bundle_id="com.example.foo"),
        phase=Phase.MAPPING,
        sessions={"user_a": SessionCreds(label="user_a", identity_id="42")},
        hypotheses=[Hypothesis(claim="X is auth")],
    )
    state.save(tmp_path)
    raw = (tmp_path / "state.json").read_text(encoding="utf-8")
    again = EngagementState.model_validate_json(raw)
    assert again.run_id == "r1"
    assert again.phase == Phase.MAPPING
    assert again.sessions["user_a"].identity_id == "42"


def test_budget_remaining_seconds_negative_when_past():
    b = Budget(wall_clock_seconds=1)
    time.sleep(0.01)
    assert b.remaining_seconds() < 1
    b2 = Budget(wall_clock_seconds=0)
    assert b2.exceeded()


def test_engagement_state_is_terminal_only_when_report_complete():
    state = EngagementState(
        run_id="r1",
        target=TargetMeta(bundle_id="b"),
        phase=Phase.REPORT,
        budget=Budget(wall_clock_seconds=99999),
    )
    assert not state.is_terminal()
    state.completed_steps.append(
        StepRecord(
            step_uid="u1", name="RenderFindings", started_at=1.0, finished_at=2.0, success=True
        )
    )
    assert state.is_terminal()


def test_module_result_default_coverage():
    r = ModuleResult(module="idor")
    assert r.findings == []
    assert isinstance(r.coverage, ModuleCoverage)


def test_evidence_kind_validated():
    with pytest.raises(ValueError):
        Evidence(kind="invalid", ref="x")  # type: ignore[arg-type]
