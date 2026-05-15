"""Workflow primitives the planner chains together.

Every Step is async, idempotent on its `step_uid`, and returns a `StepResult`
that ends up in `state.completed_steps`. Concrete steps live alongside their
adapter modules (frida_layer, objection_layer, mitm, api). The base classes
here keep the protocol identical across all of them.
"""

from __future__ import annotations

import time
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from pydantic import BaseModel

from .schema import StepRecord

if TYPE_CHECKING:
    from .query import RunQuery
    from .schema import EngagementState
    from .store import EventStore


@dataclass
class ExecContext:
    state: EngagementState
    store: EventStore
    query: RunQuery
    extras: dict[str, Any] = field(default_factory=dict)


class StepResult(BaseModel):
    success: bool = True
    summary: str = ""
    artifacts: list[str] = []
    error: str | None = None
    payload: dict[str, Any] = {}


class Step(ABC):
    """Abstract workflow primitive."""

    name: str = "Step"

    def __init__(self, **kwargs: Any) -> None:
        self.step_uid: str = kwargs.pop("step_uid", None) or str(uuid.uuid4())
        self.kwargs = kwargs

    async def execute(self, ctx: ExecContext) -> StepResult:
        started = time.time()
        try:
            result = await self._run(ctx)
        except Exception as exc:
            result = StepResult(success=False, summary=str(exc), error=type(exc).__name__)
        finished = time.time()
        ctx.state.completed_steps.append(
            StepRecord(
                step_uid=self.step_uid,
                name=self.name,
                started_at=started,
                finished_at=finished,
                success=result.success,
                summary=result.summary,
            )
        )
        return result

    @abstractmethod
    async def _run(self, ctx: ExecContext) -> StepResult: ...

    # serialization for state.pending_steps
    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "step_uid": self.step_uid, "kwargs": self.kwargs}


# ---------------------------------------------------------------------------
# Concrete steps — most are thin shells that delegate to adapter packages.
# The real bodies land in Phase 2/3/4/5/6 commits.
# ---------------------------------------------------------------------------


class EnvironmentCheck(Step):
    name = "EnvironmentCheck"

    async def _run(self, ctx: ExecContext) -> StepResult:
        from frida_layer.runner import probe_device
        from objection_layer.runner import probe_objection

        device_ok = probe_device(ctx.state.target.device_id)
        objection_ok = probe_objection()
        ok = device_ok and objection_ok
        return StepResult(
            success=ok,
            summary=f"device={device_ok} objection={objection_ok}",
            payload={"device_ok": device_ok, "objection_ok": objection_ok},
        )


class LaunchTarget(Step):
    name = "LaunchTarget"

    async def _run(self, ctx: ExecContext) -> StepResult:
        from frida_layer.runner import FridaRunner

        runner = ctx.extras.get("frida_runner") or FridaRunner.from_state(ctx.state)
        await runner.spawn_and_attach()
        ctx.extras["frida_runner"] = runner
        return StepResult(summary=f"attached pid={runner.pid}")


class InstallHook(Step):
    name = "InstallHook"

    async def _run(self, ctx: ExecContext) -> StepResult:
        runner = ctx.extras.get("frida_runner")
        if not runner:
            return StepResult(success=False, summary="no frida runner in context")
        hook = self.kwargs["hook"]
        runner.load_hook(hook)
        return StepResult(summary=f"loaded {hook}")


class ObjectionRecon(Step):
    name = "ObjectionRecon"

    async def _run(self, ctx: ExecContext) -> StepResult:
        from objection_layer.runner import ObjectionRunner

        runner = ObjectionRunner.from_state(ctx.state)
        result = runner.run_script("recon")
        ctx.store.write_artifact("recon.json", result.parsed_json)
        return StepResult(summary=f"recon classes={result.summary_count}", payload=result.payload)


class ObservePassive(Step):
    name = "ObservePassive"

    async def _run(self, ctx: ExecContext) -> StepResult:
        import anyio

        duration = float(self.kwargs.get("duration", 60))
        await anyio.sleep(duration)
        return StepResult(summary=f"observed {duration}s")


class MapEndpoints(Step):
    name = "MapEndpoints"

    async def _run(self, ctx: ExecContext) -> StepResult:
        from urllib.parse import urlparse

        seen: dict[tuple[str, str, str], list[str]] = {}
        for flow in ctx.query.flows():
            u = urlparse(flow["request"]["url"])
            key = (u.hostname or "", flow["request"]["method"], _template(u.path or ""))
            seen.setdefault(key, []).append(flow["flow_id"])
        ctx.store.write_artifact(
            "endpoints.json",
            _to_json({f"{h} {m} {p}": ids for (h, m, p), ids in seen.items()}),
        )
        return StepResult(summary=f"endpoints={len(seen)}", payload={"count": len(seen)})


class DetectAuthPattern(Step):
    name = "DetectAuthPattern"

    async def _run(self, ctx: ExecContext) -> StepResult:
        from mitm.client import MitmClient

        client: MitmClient = ctx.extras["mitm_client"]
        pattern = await client.detect_auth()
        ctx.store.write_artifact("auth_pattern.json", pattern.model_dump_json(indent=2))
        return StepResult(summary=f"auth={pattern.scheme}", payload=pattern.model_dump())


class CorrelateRange(Step):
    name = "CorrelateRange"

    async def _run(self, ctx: ExecContext) -> StepResult:
        from .correlate import Correlator

        correlator = ctx.extras.get("correlator") or Correlator(ctx.store)
        corrs = correlator.replay_from_store()
        return StepResult(summary=f"correlations={len(corrs)}", payload={"count": len(corrs)})


class RunModule(Step):
    name = "RunModule"

    async def _run(self, ctx: ExecContext) -> StepResult:
        import importlib

        module_name = self.kwargs["module"]
        module = importlib.import_module(f"api.{module_name}")
        cls = next(
            getattr(module, attr)
            for attr in dir(module)
            if attr.endswith("Module") and isinstance(getattr(module, attr), type)
        )
        from api.base import ModuleInput

        inp = ModuleInput(
            run_dir=ctx.store.run_dir,
            baseline_flow_ids=self.kwargs.get("baseline_flow_ids", []),
            session_pool=ctx.state.sessions,
            mitm_mcp=ctx.extras["mitm_client"],
            config=self.kwargs.get("config", {}),
        )
        result = await cls().run(inp)
        for f in result.findings:
            ctx.store.append("findings", f)
        return StepResult(
            summary=f"{module_name}: {len(result.findings)} findings",
            payload={"findings": len(result.findings), "coverage": result.coverage.model_dump()},
        )


class GenerateReport(Step):
    name = "GenerateReport"

    async def _run(self, ctx: ExecContext) -> StepResult:
        from .reporter import render_run

        n_findings = render_run(ctx.store.run_dir)
        return StepResult(summary=f"rendered {n_findings} findings")


class RenderFindings(GenerateReport):
    """Alias so `is_terminal` (which looks for 'RenderFindings') wraps the report step."""

    name = "RenderFindings"


def _template(path: str) -> str:
    """Replace numeric and UUID-looking segments with `{id}` to dedupe endpoints."""
    import re

    segs = []
    for seg in path.split("/"):
        if not seg:
            segs.append(seg)
            continue
        if seg.isdigit():
            segs.append("{id}")
        elif re.fullmatch(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", seg):
            segs.append("{uuid}")
        elif re.fullmatch(r"[A-Za-z0-9_-]{16,}", seg):
            segs.append("{token}")
        else:
            segs.append(seg)
    return "/".join(segs)


def _to_json(obj: Any) -> str:
    import json

    return json.dumps(obj, indent=2, default=str)


__all__ = [
    "Step",
    "StepResult",
    "ExecContext",
    "EnvironmentCheck",
    "LaunchTarget",
    "InstallHook",
    "ObjectionRecon",
    "ObservePassive",
    "MapEndpoints",
    "DetectAuthPattern",
    "CorrelateRange",
    "RunModule",
    "GenerateReport",
    "RenderFindings",
]
