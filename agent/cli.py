"""`openrecon` CLI entrypoint.

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
@click.option("--runs-root", default="runs", type=click.Path(), help="Where run dirs go.")
@click.option("--json", "as_json", is_flag=True, help="Emit JSON instead of a table.")
def runs(runs_root: str, as_json: bool) -> None:
    """List all engagement runs with severity counts and phase."""
    import json as _json

    from .runs import list_runs

    summaries = list_runs(Path(runs_root))
    if as_json:
        click.echo(_json.dumps([s.as_dict() for s in summaries], indent=2, default=str))
        return
    if not summaries:
        click.echo(f"no runs under {runs_root}")
        return
    click.echo(f"{'run_id':<28}{'bundle':<30}{'phase':<10}{'flows':>7}{'findings':>10}")
    click.echo("-" * 85)
    for s in summaries:
        bundle = (s.bundle_id or "-")[:28]
        phase = (s.phase or "-")[:8]
        click.echo(
            f"{s.run_id[:26]:<28}{bundle:<30}{phase:<10}{s.flows:>7}{s.findings_total:>10}"
        )


@main.command()
@click.argument("run_id")
@click.option("--runs-root", default="runs", type=click.Path(), help="Where run dirs go.")
@click.option("--out", default=None, type=click.Path(), help="Output path (default: runs/<id>.tar.gz).")
def export(run_id: str, runs_root: str, out: str | None) -> None:
    """Bundle a run directory into a shareable tar.gz archive."""
    from .export import export_run

    run_dir = Path(runs_root) / run_id
    if not run_dir.exists():
        click.echo(f"no run at {run_dir}", err=True)
        sys.exit(2)
    out_path = export_run(run_dir, Path(out) if out else None)
    click.echo(str(out_path))


@main.command()
@click.argument("run_a")
@click.argument("run_b")
@click.option("--runs-root", default="runs", type=click.Path(), help="Where run dirs go.")
@click.option("--json", "as_json", is_flag=True, help="Emit JSON instead of Markdown.")
@click.option("--write", "write_report", is_flag=True, help="Write diff_<a>_<b>.md to disk.")
def diff(run_a: str, run_b: str, runs_root: str, as_json: bool, write_report: bool) -> None:
    """Compare two engagements — new/resolved findings, endpoint coverage delta."""
    import json as _json

    from .diff import diff_runs, render_diff

    root = Path(runs_root)
    a = root / run_a
    b = root / run_b
    for d in (a, b):
        if not d.exists():
            click.echo(f"no run at {d}", err=True)
            sys.exit(2)
    result = diff_runs(a, b)
    if as_json:
        click.echo(_json.dumps(result.as_dict(), indent=2, default=str))
    else:
        click.echo(render_diff(result))
    if write_report:
        out = root / f"diff_{run_a}_{run_b}.md"
        out.write_text(render_diff(result), encoding="utf-8")
        click.echo(f"wrote {out}", err=True)


@main.command()
@click.argument("finding_id")
@click.option("--runs-root", default="runs", type=click.Path(), help="Where run dirs go.")
@click.option("--write", "write_report", is_flag=True, help="Write replay_<id>.md next to the finding.")
def replay(finding_id: str, runs_root: str, write_report: bool) -> None:
    """Replay a finding's reproduction steps and report whether the issue still reproduces."""
    import json as _json

    from .replay import locate_finding, render_report, run_replay_sync

    runs_root_path = Path(runs_root)
    if not runs_root_path.exists():
        click.echo(f"no runs at {runs_root_path}", err=True)
        sys.exit(2)
    try:
        run_dir, _ = locate_finding(runs_root_path, finding_id)
    except LookupError as exc:
        click.echo(str(exc), err=True)
        sys.exit(3)
    report = run_replay_sync(finding_id, runs_root_path)
    click.echo(_json.dumps(report.as_dict(), indent=2, default=str))
    if write_report:
        out = run_dir / "findings" / f"replay_{finding_id}.md"
        out.write_text(render_report(report), encoding="utf-8")
        click.echo(f"wrote {out}", err=True)
    sys.exit(0 if report.overall in ("reproduced", "ok") else 1)


if __name__ == "__main__":  # pragma: no cover
    main()
