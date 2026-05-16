"""Engagement runner — the main async loop.

Spawns Frida and MITM, registers tasks that ingest into the EventStore +
Correlator, then ticks the planner until terminal.
"""

from __future__ import annotations

import asyncio
import contextlib
from dataclasses import dataclass
from pathlib import Path

import structlog

from . import finder
from .correlate import Correlator
from .frida_flow_normalizer import FridaFlowNormalizer
from .planner import Planner
from .query import RunQuery
from .schema import EngagementState
from .state import bootstrap_state, save_state
from .steps import ExecContext
from .store import EventStore

log = structlog.get_logger(__name__)


@dataclass
class EngagementConfig:
    bundle_id: str
    device_id: str | None = None
    budget_seconds: int = 1800
    runs_root: Path = Path("runs")
    mitm_port: int = 8080


async def run_engagement(cfg: EngagementConfig) -> EngagementState:
    state = bootstrap_state(
        cfg.bundle_id, device_id=cfg.device_id, budget_seconds=cfg.budget_seconds
    )
    run_dir = cfg.runs_root / state.run_id
    store = EventStore(run_dir)
    save_state(state, run_dir)
    log.info("engagement.start", run_id=state.run_id, bundle=cfg.bundle_id)

    correlator = Correlator(store)
    normalizer = FridaFlowNormalizer()
    query = RunQuery(run_dir)

    extras: dict[str, object] = {"correlator": correlator, "frida_flow_normalizer": normalizer}

    async with contextlib.AsyncExitStack() as stack:
        # Lazy imports to keep cold-start cheap and let modules be stub-friendly.
        from frida_layer.runner import FridaRunner
        from mitm.client import MitmClient

        frida_runner = FridaRunner.from_state(state)
        mitm_client = await stack.enter_async_context(
            MitmClient.connect(port=cfg.mitm_port, run_dir=run_dir)
        )
        extras["frida_runner"] = frida_runner
        extras["mitm_client"] = mitm_client

        # Two background tasks: pump Frida + MITM events into store and correlator.
        async def pump_frida() -> None:
            async for ev in frida_runner.stream_events():
                store.append("frida_events", ev)
                correlator.ingest_frida(ev)
                # Frida-captured HTTP traffic (NSURLSession / NSURLConnection)
                # is normalized into MitmFlow records so it feeds correlator,
                # endpoint_map, finders, and replay alongside real mitm flows.
                for synthetic in normalizer.ingest(ev):
                    store.append("mitm_flows", synthetic)
                    correlator.ingest_flow(synthetic)

        async def pump_mitm() -> None:
            async for flow in mitm_client.stream_flows():
                store.append("mitm_flows", flow)
                correlator.ingest_flow(flow)

        pump_tasks = [
            asyncio.create_task(pump_frida(), name="pump_frida"),
            asyncio.create_task(pump_mitm(), name="pump_mitm"),
        ]
        stack.push_async_callback(_cancel_tasks, pump_tasks)

        planner = Planner(state, query)
        try:
            while not state.is_terminal():
                step = planner.next_step()
                ctx = ExecContext(state=state, store=store, query=query, extras=extras)
                result = await step.execute(ctx)
                save_state(state, run_dir)
                for finding in finder.run_all(query, state, run_dir=run_dir):
                    store.append("findings", finding)
                log.info(
                    "engagement.step",
                    step=step.name,
                    success=result.success,
                    summary=result.summary,
                )
        finally:
            log.info("engagement.end", run_id=state.run_id, phase=state.phase.value)
            save_state(state, run_dir)

    return state


async def _cancel_tasks(tasks: list[asyncio.Task]) -> None:
    for t in tasks:
        t.cancel()
    await asyncio.gather(*tasks, return_exceptions=True)


__all__ = ["run_engagement", "EngagementConfig"]
