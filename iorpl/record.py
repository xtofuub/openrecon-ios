"""Recording — capture an iOS app session into a .iorpl archive.

Two recording modes:

1. **Live** — run a full openrecon engagement (Frida + mitm + planner),
   then snapshot the resulting run directory into a .iorpl archive.
   Requires a jailbroken device + frida-server. Most thorough.

2. **From-disk** — take an *existing* openrecon run dir (already recorded)
   and bundle it into a .iorpl. No device needed. Useful for converting
   historical runs into replay artifacts.

The CLI (``iorpl record``) chooses Live by default; ``iorpl import`` calls
from-disk mode explicitly.
"""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path

from .format import SessionArchive

log = logging.getLogger(__name__)


def record_from_run_dir(
    run_dir: str | Path,
    *,
    target_bundle: str,
    output: str | Path,
    description: str = "",
    tags: list[str] | None = None,
) -> Path:
    """Convert an existing openrecon run dir into a .iorpl archive."""
    session = SessionArchive.from_run_dir(run_dir, target_bundle=target_bundle, description=description)
    if tags:
        session.meta.tags = list(tags)
    return SessionArchive.save(session, output)


async def record_live(
    *,
    target_bundle: str,
    output: str | Path,
    device: str | None = None,
    budget_seconds: int = 600,
    runs_root: str | Path = "runs",
    description: str = "",
    use_mitm: bool = False,
    hooks: str = "essential",
) -> Path:
    """Run a fresh openrecon engagement, then archive its run dir.

    This wraps ``agent.runner.run_engagement`` — see that module for the
    behavior of each kwarg. ``hooks="essential"`` keeps the attach surface
    small so hardened apps are less likely to self-terminate. ``use_mitm``
    defaults to False because the most common iorpl record path is
    *no proxy* (capture happens via the Frida body tracers).
    """
    from agent.runner import EngagementConfig, run_engagement

    cfg = EngagementConfig(
        bundle_id=target_bundle,
        device_id=None if (device in (None, "usb", "local", "auto", "")) else device,
        budget_seconds=budget_seconds,
        runs_root=Path(runs_root),
        use_mitm=use_mitm,
        hooks=hooks,
    )
    log.info("iorpl.record.start", bundle=target_bundle, budget=budget_seconds)
    state = await run_engagement(cfg)
    run_dir = Path(runs_root) / state.run_id
    log.info("iorpl.record.engagement_done", run_dir=str(run_dir), phase=state.phase.value)
    return record_from_run_dir(
        run_dir,
        target_bundle=target_bundle,
        output=output,
        description=description or f"Live engagement run_id={state.run_id}",
    )


def record_live_sync(**kwargs) -> Path:
    return asyncio.run(record_live(**kwargs))


__all__ = ["record_from_run_dir", "record_live", "record_live_sync"]
