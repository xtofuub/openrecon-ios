"""iorpl - Click CLI entry-point.

Sub-commands:

    iorpl record     run a fresh engagement, save the session as .iorpl
    iorpl import     turn an existing openrecon run dir into a .iorpl
    iorpl inspect    summarize a .iorpl archive (target, counts, endpoints)
    iorpl run        execute a suite YAML against a .iorpl archive
    iorpl report     render results.jsonl into Markdown / HTML
    iorpl suites     list the built-in suites
    iorpl mutations  list the built-in mutations

The CLI is intentionally small — one verb per file under ``iorpl/`` — so
power users can also drive the same primitives from Python via the public
API exposed in ``iorpl/__init__.py``.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import click

# Force UTF-8 on stdout/stderr so the report renderer and free-form notes
# (which contain arrows, em-dashes, and non-ASCII identifiers from recorded
# flows) survive Windows' cp1252 default.
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

from .format import SessionArchive
from .mutations import BUILTIN_MUTATIONS
from .record import record_from_run_dir, record_live_sync
from .replay import ReplayEngine
from .report import load_results, render_html, render_markdown
from .suite import load_suite

# Bundled suites ship under iorpl/suites/.
_SUITES_DIR = Path(__file__).resolve().parent / "suites"


@click.group()
@click.version_option(package_name=None, prog_name="iorpl", version="0.1.0")
def cli() -> None:
    """iOSReplay — record, mutate, replay iOS app sessions for bug bounty work."""


# ── record / import ────────────────────────────────────────────────────────


@cli.command()
@click.option("--target", required=True, help="Target bundle id, e.g. com.example.app")
@click.option("--device", default=None, help="Frida device id (or 'usb' / 'local').")
@click.option("--budget", default=600, type=int, help="Wall-clock budget in seconds.")
@click.option("--output", "-o", required=True, type=click.Path(), help="Output .iorpl path.")
@click.option("--description", default="", help="Free-text description stored in the archive.")
@click.option("--mitm/--no-mitm", "use_mitm", default=False, help="Run mitmproxy alongside (default: no).")
@click.option(
    "--hooks",
    default="essential",
    help="Hook preset: 'essential' (default), 'all', 'none', or comma list of .js filenames.",
)
@click.option("--runs-root", default="runs", type=click.Path(), help="openrecon runs dir (for intermediate state).")
def record(
    target: str,
    device: str | None,
    budget: int,
    output: str,
    description: str,
    use_mitm: bool,
    hooks: str,
    runs_root: str,
) -> None:
    """Run a fresh engagement, save the captured session as .iorpl."""
    path = record_live_sync(
        target_bundle=target,
        output=output,
        device=device,
        budget_seconds=budget,
        runs_root=runs_root,
        description=description,
        use_mitm=use_mitm,
        hooks=hooks,
    )
    click.echo(str(path))


@cli.command(name="import")
@click.argument("run_dir", type=click.Path(exists=True, file_okay=False))
@click.option("--target", required=True, help="Target bundle id, e.g. com.example.app")
@click.option("--output", "-o", required=True, type=click.Path(), help="Output .iorpl path.")
@click.option("--description", default="", help="Free-text description.")
@click.option("--tag", "tags", multiple=True, help="Add a tag (repeatable).")
def import_run(run_dir: str, target: str, output: str, description: str, tags: tuple[str, ...]) -> None:
    """Bundle an existing openrecon run dir into a .iorpl archive."""
    path = record_from_run_dir(
        run_dir,
        target_bundle=target,
        output=output,
        description=description,
        tags=list(tags),
    )
    click.echo(str(path))


# ── inspect ────────────────────────────────────────────────────────────────


@cli.command()
@click.argument("session_path", type=click.Path(exists=True, dir_okay=False))
@click.option("--json", "as_json", is_flag=True, help="Emit JSON instead of a human summary.")
def inspect(session_path: str, as_json: bool) -> None:
    """Print summary of a .iorpl session."""
    session = SessionArchive.load(session_path)
    payload = {
        "schema_version": session.meta.schema_version,
        "target_bundle": session.meta.target_bundle,
        "device_id": session.meta.device_id,
        "recorded_at": session.meta.recorded_at,
        "description": session.meta.description,
        "tags": session.meta.tags,
        "flow_count": session.flow_count(),
        "frida_event_count": len(session.frida_events),
        "endpoint_count": session.endpoint_count(),
        "artifact_names": sorted(session.artifacts),
    }
    if as_json:
        click.echo(json.dumps(payload, indent=2, default=str))
        return
    click.echo(f"target:    {payload['target_bundle']}")
    click.echo(f"recorded:  {payload['recorded_at']}")
    if payload["description"]:
        click.echo(f"desc:      {payload['description']}")
    click.echo(f"flows:     {payload['flow_count']}")
    click.echo(f"frida:     {payload['frida_event_count']} events")
    click.echo(f"endpoints: {payload['endpoint_count']}")
    if payload["artifact_names"]:
        click.echo(f"artifacts: {', '.join(payload['artifact_names'][:6])}{'...' if len(payload['artifact_names']) > 6 else ''}")


# ── run / report ───────────────────────────────────────────────────────────


@cli.command()
@click.argument("session_path", type=click.Path(exists=True, dir_okay=False))
@click.option("--suite", "suite_path", required=True, type=click.Path(), help="Suite YAML path or builtin name.")
@click.option("--output", "-o", default="results.jsonl", type=click.Path(), help="Where to stream results.")
@click.option("--timeout", default=30.0, type=float, help="Per-request httpx timeout (seconds).")
@click.option("--verify-tls/--no-verify-tls", default=False, help="Verify TLS certs.")
def run(session_path: str, suite_path: str, output: str, timeout: float, verify_tls: bool) -> None:
    """Replay session_path through the suite, write verdicts to results.jsonl."""
    suite_file = _resolve_suite(suite_path)
    session = SessionArchive.load(session_path)
    suite = load_suite(suite_file)
    engine = ReplayEngine(session, suite, output_path=output, timeout=timeout, verify_tls=verify_tls)
    results = engine.run_sync()
    total = len(results)
    bypassed = sum(1 for r in results if r.verdict in ("auth_bypassed", "leak_detected"))
    click.echo(f"ran {total} mutations; {bypassed} confirmed findings -> {output}")


@cli.command()
@click.argument("results_path", type=click.Path(exists=True))
@click.option("--format", "fmt", default="md", type=click.Choice(["md", "html"]), help="Output format.")
@click.option("--output", "-o", default=None, type=click.Path(), help="Write to file instead of stdout.")
@click.option("--suite-name", default="", help="Optional suite name for the report header.")
def report(results_path: str, fmt: str, output: str | None, suite_name: str) -> None:
    """Render results.jsonl as a Markdown or HTML report."""
    results = load_results(results_path)
    text = (
        render_html(results, suite_name=suite_name)
        if fmt == "html"
        else render_markdown(results, suite_name=suite_name)
    )
    if output:
        Path(output).write_text(text, encoding="utf-8")
        click.echo(output)
    else:
        click.echo(text)


# ── browse ────────────────────────────────────────────────────────────────


@cli.group()
def suites() -> None:
    """Inspect the bundled YAML suites."""


@suites.command(name="list")
def suites_list() -> None:
    if not _SUITES_DIR.exists():
        click.echo("(no bundled suites)")
        return
    for f in sorted(_SUITES_DIR.glob("*.yaml")):
        click.echo(f.stem)


@suites.command(name="show")
@click.argument("name")
def suites_show(name: str) -> None:
    path = _SUITES_DIR / f"{name}.yaml"
    if not path.exists():
        raise click.ClickException(f"no bundled suite {name!r}; try `iorpl suites list`")
    click.echo(path.read_text(encoding="utf-8"))


@cli.group()
def mutations() -> None:
    """Inspect available mutations."""


@mutations.command(name="list")
def mutations_list() -> None:
    for name, mut in sorted(BUILTIN_MUTATIONS.items()):
        click.echo(f"{name:<48}{mut.description}")


# ── helpers ────────────────────────────────────────────────────────────────


def _resolve_suite(path_or_name: str) -> Path:
    """Accept ``--suite idor.yaml`` (path) or ``--suite idor`` (builtin name)."""
    p = Path(path_or_name)
    if p.exists():
        return p
    builtin = _SUITES_DIR / f"{path_or_name}.yaml"
    if builtin.exists():
        return builtin
    raise click.ClickException(
        f"suite not found: {path_or_name!r}. Try `iorpl suites list` or pass an absolute path."
    )


if __name__ == "__main__":  # pragma: no cover
    cli()
