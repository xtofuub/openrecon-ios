"""`lolmcp` CLI entrypoint.

Subcommands:
    run        — start an autonomous engagement
    doctor     — verify environment (frida-server, objection, mitmproxy, vendor)
    report     — render or re-render a run's findings
    replay     — replay a single finding's reproduction steps
    correlate  — recompute correlations.jsonl for a run
"""

from __future__ import annotations

import asyncio
import shutil
import sys
from pathlib import Path

import click

from .runner import EngagementConfig, run_engagement


@click.group()
def main() -> None:
    """Autonomous iOS security research platform."""


@main.command()
@click.option("--target", required=True, help="Target bundle id, e.g. com.example.foo")
@click.option("--device", default=None, help="Frida device id (defaults to first USB).")
@click.option("--budget", default=1800, type=int, help="Wall-clock budget in seconds.")
@click.option("--runs-root", default="runs", type=click.Path(), help="Where run dirs go.")
def run(target: str, device: str | None, budget: int, runs_root: str) -> None:
    """Start an autonomous engagement."""
    cfg = EngagementConfig(
        bundle_id=target,
        device_id=device,
        budget_seconds=budget,
        runs_root=Path(runs_root),
    )
    state = asyncio.run(run_engagement(cfg))
    click.echo(f"run_id={state.run_id} phase={state.phase.value}")


@main.command()
def doctor() -> None:
    """Verify environment and report tool status."""
    checks: list[tuple[str, bool, str]] = []

    checks.append(("python", sys.version_info >= (3, 12), f"version={sys.version.split()[0]}"))
    checks.append(("frida-tools", shutil.which("frida") is not None, shutil.which("frida") or "missing"))
    checks.append(("objection", shutil.which("objection") is not None, shutil.which("objection") or "missing"))
    checks.append(("mitmdump", shutil.which("mitmdump") is not None, shutil.which("mitmdump") or "missing"))

    vendor = Path("mitm/vendor")
    checks.append(("mitm/vendor vendored", vendor.exists(), str(vendor)))
    skills = Path("skills/_upstream/anthropic-cybersecurity-skills")
    checks.append(("anthropic skills vendored", skills.exists(), str(skills)))

    ok = True
    for name, passed, detail in checks:
        mark = "OK " if passed else "X  "
        click.echo(f"{mark} {name:<32} {detail}")
        if not passed:
            ok = False

    if not ok:
        click.echo("\nOne or more checks failed. See docs/roadmap.md for setup.")
        sys.exit(1)


@main.command()
@click.argument("run_id")
@click.option("--runs-root", default="runs", type=click.Path(), help="Where run dirs go.")
def report(run_id: str, runs_root: str) -> None:
    """Re-render a run's findings (Markdown + JSON)."""
    from .reporter import render_run

    run_dir = Path(runs_root) / run_id
    if not run_dir.exists():
        click.echo(f"no run at {run_dir}", err=True)
        sys.exit(2)
    n = render_run(run_dir)
    click.echo(f"rendered {n} findings to {run_dir / 'findings'}")


@main.command()
@click.argument("run_id")
@click.option("--runs-root", default="runs", type=click.Path(), help="Where run dirs go.")
def correlate(run_id: str, runs_root: str) -> None:
    """Recompute correlations.jsonl from frida_events.jsonl + mitm_flows.jsonl."""
    from .correlate import Correlator
    from .store import EventStore

    run_dir = Path(runs_root) / run_id
    store = EventStore(run_dir)
    corrs = Correlator(store).replay_from_store()
    click.echo(f"wrote {len(corrs)} correlations")


@main.command()
@click.argument("finding_id")
@click.option("--runs-root", default="runs", type=click.Path(), help="Where run dirs go.")
def replay(finding_id: str, runs_root: str) -> None:
    """Replay a finding's reproduction steps."""
    # Phase 7 wires this through to mitm.client.replay_flow per ReproStep.
    click.echo(f"TODO: replay {finding_id} (Phase 7)", err=True)
    sys.exit(64)


if __name__ == "__main__":  # pragma: no cover
    main()
