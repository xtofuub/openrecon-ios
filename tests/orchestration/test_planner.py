"""Planner — phase transitions are deterministic, terminal on report."""

from __future__ import annotations

from agent.planner import Planner
from agent.query import RunQuery
from agent.schema import (
    Budget,
    EngagementState,
    Phase,
    TargetMeta,
)


def _make_state(*, phase: Phase = Phase.BOOTSTRAP, budget: int = 1800) -> EngagementState:
    return EngagementState(
        run_id="r1",
        target=TargetMeta(bundle_id="com.example.foo"),
        phase=phase,
        budget=Budget(wall_clock_seconds=budget),
    )


def test_bootstrap_emits_env_check_first(run_dir):
    state = _make_state()
    p = Planner(state, RunQuery(run_dir))
    step = p.next_step()
    assert step.name == "EnvironmentCheck"


def test_bootstrap_walks_through_hooks_in_order(run_dir):
    from agent.planner import _DEFAULT_HOOKS

    state = _make_state()
    p = Planner(state, RunQuery(run_dir))
    expected_len = 2 + len(_DEFAULT_HOOKS) + 3  # EnvCheck + LaunchTarget + N hooks + ResumeTarget + AcquireBinary + ObjectionRecon
    names = [p.next_step().name for _ in range(expected_len)]
    assert names[0] == "EnvironmentCheck"
    assert names[1] == "LaunchTarget"
    assert "InstallHook" in names
    assert "ObjectionRecon" in names
    assert names[-1] == "ObjectionRecon"


def test_passive_observes_when_few_flows(event_store, mitm_flow_factory):
    state = _make_state(phase=Phase.PASSIVE)
    for i in range(3):
        event_store.append("mitm_flows", mitm_flow_factory(flow_id=f"f{i}"))
    p = Planner(state, RunQuery(event_store.run_dir))
    step = p.next_step()
    assert step.name == "ObservePassive"


def test_passive_transitions_to_mapping_at_50_flows(event_store, mitm_flow_factory):
    state = _make_state(phase=Phase.PASSIVE)
    for i in range(50):
        event_store.append("mitm_flows", mitm_flow_factory(flow_id=f"f{i}"))
    p = Planner(state, RunQuery(event_store.run_dir))
    step = p.next_step()
    assert step.name == "MapEndpoints"
    assert state.phase == Phase.MAPPING


def test_budget_exceeded_forces_report_phase(run_dir):
    state = _make_state(phase=Phase.ACTIVE, budget=0)
    p = Planner(state, RunQuery(run_dir))
    step = p.next_step()
    assert state.phase == Phase.REPORT
    assert step.name == "RenderFindings"


def test_mapping_runs_auth_detect_before_modules(event_store, mitm_flow_factory):
    state = _make_state(phase=Phase.MAPPING)
    event_store.append("mitm_flows", mitm_flow_factory(flow_id="f1"))
    p = Planner(state, RunQuery(event_store.run_dir))
    step = p.next_step()
    # auth_pattern.json not present → DetectAuthPattern emitted
    assert step.name == "DetectAuthPattern"
