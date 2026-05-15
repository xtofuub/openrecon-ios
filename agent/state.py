"""Engagement state loading, bootstrap, and persistence helpers.

Wraps the `EngagementState` model from `agent.schema` with file I/O. The state
is snapshot to `state.json` after every planner step so crashes are recoverable.
"""

from __future__ import annotations

from pathlib import Path

from ulid import ULID

from .schema import Budget, EngagementState, Phase, SessionCreds, TargetMeta


def new_run_id() -> str:
    return str(ULID())


def bootstrap_state(
    bundle_id: str,
    *,
    device_id: str | None = None,
    budget_seconds: int = 1800,
    sessions: dict[str, SessionCreds] | None = None,
) -> EngagementState:
    return EngagementState(
        run_id=new_run_id(),
        target=TargetMeta(bundle_id=bundle_id, device_id=device_id),
        phase=Phase.BOOTSTRAP,
        budget=Budget(wall_clock_seconds=budget_seconds),
        sessions=sessions or {},
    )


def load_state(run_dir: Path) -> EngagementState:
    path = run_dir / "state.json"
    if not path.exists():
        raise FileNotFoundError(f"no state.json at {path}")
    return EngagementState.model_validate_json(path.read_text(encoding="utf-8"))


def save_state(state: EngagementState, run_dir: Path) -> None:
    state.save(run_dir)


__all__ = [
    "bootstrap_state",
    "load_state",
    "save_state",
    "new_run_id",
]
