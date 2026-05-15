"""Pydantic models for every event, artifact, and finding the platform produces.

Every other module in the repo depends on these types. They define the wire
format for JSONL on disk and the in-memory shape the planner reasons over.
"""

from __future__ import annotations

import time
from enum import Enum
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field
from ulid import ULID


def _ulid() -> str:
    return str(ULID())


def _now() -> float:
    return time.time()


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Phase(str, Enum):
    BOOTSTRAP = "bootstrap"
    PASSIVE = "passive"
    MAPPING = "mapping"
    ACTIVE = "active"
    EXPLOIT = "exploit"
    REPORT = "report"


class ArgValue(BaseModel):
    """Serialized representation of a runtime argument or return value."""

    model_config = ConfigDict(extra="ignore")

    type: str
    repr: str
    hash: str | None = None
    preview: str | None = Field(None, max_length=512)


class FridaEvent(BaseModel):
    """One runtime event captured by a Frida hook."""

    model_config = ConfigDict(extra="ignore")

    event_id: str = Field(default_factory=_ulid)
    ts: float = Field(default_factory=_now)
    pid: int
    cls: str
    method: str
    args: list[ArgValue] = []
    ret: ArgValue | None = None
    thread_id: int = 0
    stack: list[str] = []
    hook_source: str | None = None  # which .js file emitted this
    extra: dict[str, Any] = {}


class HttpRequest(BaseModel):
    model_config = ConfigDict(extra="ignore")

    url: str
    method: str
    headers: dict[str, str] = {}
    body_b64: str | None = None
    body_sha256: str | None = None


class HttpResponse(BaseModel):
    model_config = ConfigDict(extra="ignore")

    status: int
    headers: dict[str, str] = {}
    body_b64: str | None = None
    body_sha256: str | None = None


class MitmFlow(BaseModel):
    """One HTTP flow captured by mitmproxy."""

    model_config = ConfigDict(extra="ignore")

    event_id: str = Field(default_factory=_ulid)
    flow_id: str  # mitmproxy's own UUID
    ts_request: float
    ts_response: float | None = None
    request: HttpRequest
    response: HttpResponse | None = None
    duration_ms: float | None = None
    tags: list[str] = []


class CorrelationSignal(BaseModel):
    kind: Literal[
        "temporal",
        "url_substring",
        "body_match",
        "thread_proximity",
        "stack_url",
        "arg_type_hint",
    ]
    weight: float
    detail: str | None = None


class Correlation(BaseModel):
    correlation_id: str = Field(default_factory=_ulid)
    flow_event_id: str
    frida_event_ids: list[str]
    score: float
    signals: list[CorrelationSignal] = []
    ts: float = Field(default_factory=_now)


class Endpoint(BaseModel):
    host: str
    method: str
    path_template: str
    sample_flow_ids: list[str] = []
    id_positions: list[str] = []  # e.g. "path.users.id", "query.org", "body.owner_id"
    auth_pattern: str | None = None
    response_keys: set[str] = set()


class SessionCreds(BaseModel):
    model_config = ConfigDict(extra="ignore")

    label: str
    auth_header: str | None = None
    cookie: str | None = None
    jwt: str | None = None
    identity_id: str | None = None


class ReproStep(BaseModel):
    """One reproducible step a reader (or `openrecon replay`) can re-execute."""

    description: str
    primitive: str  # e.g. "replay_flow"
    args: dict[str, Any] = {}
    expected: str | None = None


class Evidence(BaseModel):
    kind: Literal["flow", "frida_event", "correlation", "artifact"]
    ref: str  # flow_id, event_id, correlation_id, or relative artifact path
    note: str | None = None


class Finding(BaseModel):
    model_config = ConfigDict(extra="ignore")

    finding_id: str = Field(default_factory=_ulid)
    run_id: str
    severity: Severity
    category: str
    title: str
    summary: str
    evidence: list[Evidence] = []
    correlated_flows: list[str] = []
    correlated_frida: list[str] = []
    reproduction: list[ReproStep] = []
    confidence: float = 0.5
    tags: list[str] = []
    ts: float = Field(default_factory=_now)


class Hypothesis(BaseModel):
    hypothesis_id: str = Field(default_factory=_ulid)
    claim: str
    status: Literal["open", "confirmed", "refuted", "stale"] = "open"
    tests: list[str] = []  # step_uids that test this
    evidence: list[Evidence] = []


class Budget(BaseModel):
    wall_clock_seconds: int = 1800
    max_replays: int = 2000
    max_active_mutations: int = 500
    started_at: float = Field(default_factory=_now)

    def remaining_seconds(self) -> float:
        return self.wall_clock_seconds - (time.time() - self.started_at)

    def exceeded(self) -> bool:
        return self.remaining_seconds() <= 0


class TargetMeta(BaseModel):
    bundle_id: str
    app_version: str | None = None
    ios_version: str | None = None
    device_id: str | None = None
    discovered_hosts: list[str] = []
    discovered_endpoints: list[Endpoint] = []


class StepRecord(BaseModel):
    step_uid: str
    name: str
    started_at: float
    finished_at: float
    success: bool
    summary: str = ""


class Artifact(BaseModel):
    artifact_id: str = Field(default_factory=_ulid)
    kind: str
    path: str  # relative to run_dir
    note: str | None = None


class EngagementState(BaseModel):
    model_config = ConfigDict(extra="ignore")

    run_id: str
    target: TargetMeta
    phase: Phase = Phase.BOOTSTRAP
    counters: dict[str, int] = {}
    sessions: dict[str, SessionCreds] = {}
    hypotheses: list[Hypothesis] = []
    completed_steps: list[StepRecord] = []
    pending_steps: list[dict[str, Any]] = []  # serialized Step instances
    budget: Budget = Field(default_factory=Budget)
    started_at: float = Field(default_factory=_now)

    def is_terminal(self) -> bool:
        if self.phase == Phase.REPORT and self.completed_steps:
            last = self.completed_steps[-1]
            if last.name == "RenderFindings" and last.success:
                return True
        return self.budget.exceeded()

    def save(self, run_dir: Path) -> None:
        (run_dir / "state.json").write_text(
            self.model_dump_json(indent=2),
            encoding="utf-8",
        )


# ---------------------------------------------------------------------------
# Module I/O contracts (used by api/base.py and the planner's RunModule step)
# ---------------------------------------------------------------------------


class ModuleCoverage(BaseModel):
    tested: list[str] = []
    skipped: list[tuple[str, str]] = []  # (item, reason)
    totals: dict[str, int] = {}


class ModuleResult(BaseModel):
    module: str
    findings: list[Finding] = []
    artifacts: list[Artifact] = []
    coverage: ModuleCoverage = Field(default_factory=ModuleCoverage)
    duration_ms: float | None = None
    error: str | None = None
