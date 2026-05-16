"""``iorpl-mcp`` — FastMCP stdio server.

Exposes the same operations as the CLI so AI agents can drive the full
record→replay→report loop without a shell. Each tool returns JSON.

Tools:
    iorpl_record            run an engagement, save .iorpl
    iorpl_import            convert an openrecon run dir to .iorpl
    iorpl_inspect           summarize a .iorpl
    iorpl_run               replay a suite against a session
    iorpl_report            render results
    iorpl_list_mutations    list every registered mutation
    iorpl_list_suites       list bundled suites
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from mcp.server.fastmcp import FastMCP

from .format import SessionArchive
from .mutations import BUILTIN_MUTATIONS
from .record import record_from_run_dir, record_live
from .replay import ReplayEngine
from .report import load_results, render_html, render_markdown
from .suite import load_suite

logging.basicConfig(level=logging.INFO, format="%(asctime)s [iorpl-mcp] %(levelname)s %(message)s")
log = logging.getLogger("iorpl-mcp")

mcp = FastMCP("iOSReplay — record/replay iOS app sessions")

_SUITES_DIR = Path(__file__).resolve().parent / "suites"


def _ok(payload: Any) -> str:
    return json.dumps(payload, default=str)


def _err(message: str) -> str:
    return json.dumps({"ok": False, "error": message})


# ── record / import ────────────────────────────────────────────────────────


@mcp.tool()
async def iorpl_record(
    target: str,
    output: str,
    device: str | None = None,
    budget_seconds: int = 600,
    description: str = "",
    use_mitm: bool = False,
    hooks: str = "essential",
    runs_root: str = "runs",
) -> str:
    """Run a fresh engagement, save as .iorpl. Returns the archive path."""
    try:
        path = await record_live(
            target_bundle=target,
            output=output,
            device=device,
            budget_seconds=budget_seconds,
            runs_root=runs_root,
            description=description,
            use_mitm=use_mitm,
            hooks=hooks,
        )
        return _ok({"path": str(path)})
    except Exception as exc:
        return _err(f"{type(exc).__name__}: {exc}")


@mcp.tool()
async def iorpl_import(
    run_dir: str,
    target: str,
    output: str,
    description: str = "",
    tags: list[str] | None = None,
) -> str:
    """Convert an openrecon run dir into a .iorpl archive."""
    try:
        path = record_from_run_dir(
            run_dir,
            target_bundle=target,
            output=output,
            description=description,
            tags=list(tags or []),
        )
        return _ok({"path": str(path)})
    except Exception as exc:
        return _err(f"{type(exc).__name__}: {exc}")


# ── inspect ────────────────────────────────────────────────────────────────


@mcp.tool()
async def iorpl_inspect(session_path: str) -> str:
    """Summarize a .iorpl archive: target, counts, endpoints, artifacts."""
    try:
        session = SessionArchive.load(session_path)
    except Exception as exc:
        return _err(f"{type(exc).__name__}: {exc}")
    return _ok(
        {
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
    )


# ── run / report ───────────────────────────────────────────────────────────


@mcp.tool()
async def iorpl_run(
    session_path: str,
    suite: str,
    output: str = "results.jsonl",
    http_timeout_seconds: float = 30.0,
    verify_tls: bool = False,
) -> str:
    """Replay a session through a suite. ``suite`` accepts path or builtin name."""
    try:
        suite_file = _resolve_suite(suite)
        session = SessionArchive.load(session_path)
        suite_obj = load_suite(suite_file)
        engine = ReplayEngine(
            session,
            suite_obj,
            output_path=output,
            timeout=http_timeout_seconds,
            verify_tls=verify_tls,
        )
        results = await engine.run()
        return _ok(
            {
                "ran": len(results),
                "results_path": str(Path(output).resolve()),
                "verdicts": _count_verdicts(results),
            }
        )
    except Exception as exc:
        return _err(f"{type(exc).__name__}: {exc}")


@mcp.tool()
async def iorpl_report(results_path: str, format: str = "md", suite_name: str = "") -> str:
    """Render results.jsonl (or a directory containing it) as Markdown / HTML."""
    try:
        results = load_results(results_path)
        if format == "html":
            text = render_html(results, suite_name=suite_name)
        else:
            text = render_markdown(results, suite_name=suite_name)
        return _ok({"format": format, "report": text, "count": len(results)})
    except Exception as exc:
        return _err(f"{type(exc).__name__}: {exc}")


# ── browse ────────────────────────────────────────────────────────────────


@mcp.tool()
async def iorpl_list_mutations() -> str:
    return _ok(
        {
            "mutations": [
                {"name": n, "description": m.description}
                for n, m in sorted(BUILTIN_MUTATIONS.items())
            ]
        }
    )


@mcp.tool()
async def iorpl_list_suites() -> str:
    if not _SUITES_DIR.exists():
        return _ok({"suites": []})
    return _ok({"suites": sorted(p.stem for p in _SUITES_DIR.glob("*.yaml"))})


# ── helpers ────────────────────────────────────────────────────────────────


def _resolve_suite(path_or_name: str) -> Path:
    p = Path(path_or_name)
    if p.exists():
        return p
    builtin = _SUITES_DIR / f"{path_or_name}.yaml"
    if builtin.exists():
        return builtin
    raise FileNotFoundError(f"suite not found: {path_or_name!r}")


def _count_verdicts(results: list) -> dict[str, int]:
    counts: dict[str, int] = {}
    for r in results:
        counts[r.verdict] = counts.get(r.verdict, 0) + 1
    return counts


def run_stdio() -> None:
    mcp.run("stdio")


def main() -> None:
    """Console entry-point: ``iorpl-mcp``."""
    run_stdio()


if __name__ == "__main__":  # pragma: no cover
    run_stdio()
