"""openrecon-install-mcp — register openrecon's MCP servers with AI agents.

Detects the config files used by popular AI coding agents (Claude Code,
Codex CLI, OpenCode, Cursor, Windsurf, Cline) and writes / merges entries
for the three openrecon MCP servers:

    openrecon-mitm     — vendored mitmproxy-mcp (always available)
    openrecon-r2       — radare2 static analysis (requires `pip install -e .[r2]`)
    openrecon-r2frida  — r2frida live process (requires `r2pm -ci r2frida`)

Usage:
    # Interactive — prompts for each detected agent
    openrecon-install-mcp

    # Non-interactive — comma-separated list, or `all`
    openrecon-install-mcp --agents claude,codex,opencode
    openrecon-install-mcp --agents all
    openrecon-install-mcp --agents all --yes              # skip confirmation

    # Preview only — don't write anything
    openrecon-install-mcp --dry-run

The installer is idempotent: re-running updates the openrecon-* entries in
place without touching unrelated config. Each write is preceded by a
backup of the original file at ``<path>.openrecon.bak`` (one per file,
overwritten only the first time openrecon sees that file).
"""

from __future__ import annotations

import json
import os
import shutil
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import click

# ── Configuration schema ────────────────────────────────────────────────────


def _repo_root() -> Path:
    """Best-effort repo root — used to seed the mitm server's PYTHONPATH.

    The installer is invoked after `pip install -e .` so the repo lives at
    a known location. We resolve relative to this file (which lives under
    ``agent/install_mcp.py``).
    """
    return Path(__file__).resolve().parents[1]


def _server_blocks() -> dict[str, dict[str, Any]]:
    root = _repo_root()
    vendor_src = root / "mitm" / "vendor" / "src"
    return {
        "openrecon-mitm": {
            "command": sys.executable,
            "args": ["-m", "mitmproxy_mcp.core.server"],
            "env": {
                "PYTHONPATH": os.pathsep.join([str(vendor_src), str(root)]),
                "openrecon_RUN_DIR": "runs/_default",
            },
        },
        "openrecon-r2": {
            "command": "r2-mcp",
            "args": [],
        },
        "openrecon-r2frida": {
            "command": "r2frida-mcp",
            "args": [],
        },
        "iorpl": {
            "command": "iorpl-mcp",
            "args": [],
        },
    }


# ── Agent targets ───────────────────────────────────────────────────────────


@dataclass
class AgentTarget:
    """One agent's config file + the JSON path under which mcpServers live."""

    key: str
    label: str
    path: Path
    # Dotted path to the dict that holds server entries. Most agents use
    # ``mcpServers`` at the root. Codex CLI's TOML differs; we handle that
    # case via a separate writer.
    container: str = "mcpServers"
    fmt: str = "json"  # json | toml


def _windows_appdata() -> Path:
    return Path(os.environ.get("APPDATA") or Path.home() / "AppData" / "Roaming")


def _agent_targets() -> list[AgentTarget]:
    home = Path.home()
    is_win = os.name == "nt"
    targets: list[AgentTarget] = [
        # Claude Code — user-level settings.json. Project-level (./.claude/settings.json)
        # is left untouched so the per-repo registration in this repo's
        # .claude/settings.json keeps working independently.
        AgentTarget(
            key="claude",
            label="Claude Code (user settings)",
            path=home / ".claude" / "settings.json",
        ),
        AgentTarget(
            key="cursor",
            label="Cursor",
            path=home / ".cursor" / "mcp.json",
        ),
        AgentTarget(
            key="windsurf",
            label="Windsurf",
            path=home / ".codeium" / "windsurf" / "mcp_config.json",
        ),
        AgentTarget(
            key="cline",
            label="Cline (VS Code)",
            path=(
                _windows_appdata() / "Code" / "User" / "globalStorage"
                / "saoudrizwan.claude-dev" / "settings" / "cline_mcp_settings.json"
                if is_win
                else home / "Library" / "Application Support" / "Code" / "User"
                / "globalStorage" / "saoudrizwan.claude-dev" / "settings"
                / "cline_mcp_settings.json"
            ),
        ),
        AgentTarget(
            key="opencode",
            label="OpenCode",
            path=(
                _windows_appdata() / "opencode" / "config.json"
                if is_win
                else home / ".config" / "opencode" / "config.json"
            ),
            container="mcp",
        ),
        AgentTarget(
            key="codex",
            label="Codex CLI",
            path=home / ".codex" / "config.toml",
            container="mcp_servers",
            fmt="toml",
        ),
        AgentTarget(
            key="continue",
            label="Continue (VS Code)",
            path=home / ".continue" / "config.json",
            container="mcpServers",
        ),
        AgentTarget(
            key="zed",
            label="Zed",
            path=home / ".config" / "zed" / "settings.json",
            container="context_servers",
        ),
    ]
    return targets


# ── JSON I/O ────────────────────────────────────────────────────────────────


def _read_json_if_exists(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        # Some agents (notably VS Code) tolerate JSONC. Strip simple
        # `// ...` line comments before retrying so we don't clobber config.
        raw = path.read_text(encoding="utf-8")
        cleaned = "\n".join(
            line for line in raw.splitlines() if not line.lstrip().startswith("//")
        )
        try:
            return json.loads(cleaned)
        except json.JSONDecodeError as exc:
            raise click.ClickException(
                f"could not parse {path}: {exc}. Fix the file or pass --skip {path.name}."
            ) from exc
    except OSError as exc:
        raise click.ClickException(f"could not read {path}: {exc}") from exc


def _write_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


# ── TOML I/O (Codex CLI) ────────────────────────────────────────────────────


def _read_toml_if_exists(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        import tomllib  # py311+
    except ImportError:  # pragma: no cover
        raise click.ClickException("Python 3.11+ required for Codex TOML support") from None
    try:
        return tomllib.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise click.ClickException(f"could not parse {path}: {exc}") from exc


def _write_toml(path: Path, data: dict[str, Any]) -> None:
    """Hand-roll a minimal TOML writer for the Codex schema we generate.

    We only need `[mcp_servers.<name>]` tables with simple key/value fields,
    plus a nested `env` table. Avoiding a third-party writer dep keeps the
    install lean.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    lines: list[str] = []
    other = {k: v for k, v in data.items() if k != "mcp_servers"}
    for k, v in other.items():
        lines.append(_toml_kv(k, v))
    servers = data.get("mcp_servers") or {}
    for name, body in servers.items():
        lines.append("")
        lines.append(f"[mcp_servers.{name}]")
        for key, val in body.items():
            if key == "env" and isinstance(val, dict):
                continue
            lines.append(_toml_kv(key, val))
        env = body.get("env")
        if isinstance(env, dict) and env:
            lines.append("")
            lines.append(f"[mcp_servers.{name}.env]")
            for ek, ev in env.items():
                lines.append(_toml_kv(ek, ev))
    path.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")


def _toml_kv(key: str, value: Any) -> str:
    if isinstance(value, bool):
        return f"{key} = {'true' if value else 'false'}"
    if isinstance(value, int):
        return f"{key} = {value}"
    if isinstance(value, list):
        items = ", ".join(json.dumps(str(v)) for v in value)
        return f"{key} = [{items}]"
    return f"{key} = {json.dumps(str(value))}"


# ── Merge logic ─────────────────────────────────────────────────────────────


def _merge_servers(existing_container: Any, servers: dict[str, dict[str, Any]]) -> dict[str, Any]:
    """Return the new container dict with openrecon-* entries upserted."""
    if not isinstance(existing_container, dict):
        merged: dict[str, Any] = {}
    else:
        merged = dict(existing_container)
    for name, block in servers.items():
        merged[name] = block
    return merged


def _apply(target: AgentTarget, servers: dict[str, dict[str, Any]], dry_run: bool) -> str:
    if target.fmt == "toml":
        data = _read_toml_if_exists(target.path)
        existing = data.get(target.container)
        merged = _merge_servers(existing, servers)
        data[target.container] = merged
        if dry_run:
            return f"[dry-run] would write {target.path}"
        _backup_once(target.path)
        _write_toml(target.path, data)
        return f"wrote {target.path}"
    # JSON path
    data = _read_json_if_exists(target.path)
    existing = data.get(target.container)
    merged = _merge_servers(existing, servers)
    data[target.container] = merged
    if dry_run:
        return f"[dry-run] would write {target.path}"
    _backup_once(target.path)
    _write_json(target.path, data)
    return f"wrote {target.path}"


def _backup_once(path: Path) -> None:
    if not path.exists():
        return
    backup = path.with_suffix(path.suffix + ".openrecon.bak")
    if backup.exists():
        return
    try:
        shutil.copy2(path, backup)
    except OSError:
        pass


# ── CLI ─────────────────────────────────────────────────────────────────────


@click.command(name="openrecon-install-mcp")
@click.option(
    "--agents",
    "agents",
    default=None,
    help=(
        "Comma-separated agent keys to install to. "
        "Available: claude, cursor, windsurf, cline, opencode, codex, continue, zed, all. "
        "If omitted, the installer is interactive."
    ),
)
@click.option("--yes", "skip_confirm", is_flag=True, help="Skip confirmation prompts.")
@click.option("--dry-run", "dry_run", is_flag=True, help="Show what would change; write nothing.")
@click.option(
    "--include-r2/--no-include-r2",
    default=True,
    help="Register openrecon-r2 and openrecon-r2frida (default: yes).",
)
def main(
    agents: str | None,
    skip_confirm: bool,
    dry_run: bool,
    include_r2: bool,
) -> None:
    """Register openrecon's MCP servers with the AI agents you use."""
    targets = _agent_targets()

    selected = _select_agents(agents, targets, skip_confirm)
    if not selected:
        click.echo("no agents selected; nothing to do")
        return

    servers = _server_blocks()
    if not include_r2:
        servers.pop("openrecon-r2", None)
        servers.pop("openrecon-r2frida", None)

    click.echo("\nwill register:")
    for name in servers:
        click.echo(f"  - {name}")
    click.echo("\ninto:")
    for t in selected:
        marker = "(will create)" if not t.path.exists() else "(will update)"
        click.echo(f"  - {t.label:<32} {t.path}  {marker}")
    click.echo()

    if not (skip_confirm or dry_run):
        if not click.confirm("proceed?", default=True):
            click.echo("aborted")
            return

    for t in selected:
        try:
            msg = _apply(t, servers, dry_run=dry_run)
            click.echo(f"  [ok]{t.key}: {msg}")
        except click.ClickException as exc:
            click.echo(f"  [err]{t.key}: {exc.message}", err=True)
        except Exception as exc:  # pragma: no cover
            click.echo(f"  [err]{t.key}: {type(exc).__name__}: {exc}", err=True)

    if dry_run:
        click.echo("\n(dry-run; nothing written)")
    else:
        click.echo("\ndone. Restart the affected agents to pick up the new servers.")

    if not include_r2:
        return
    click.echo(
        "\nNote: r2 / r2frida servers need their tooling on PATH:\n"
        "  pip install -e .[r2]   # r2pipe Python bindings\n"
        "  # macOS/Linux: build r2 from source - https://github.com/radareorg/radare2\n"
        "  # Windows:     scoop install radare2\n"
        "  r2pm -ci r2frida       # for the live-process server"
    )


def _select_agents(
    agents_arg: str | None,
    targets: list[AgentTarget],
    skip_confirm: bool,
) -> list[AgentTarget]:
    by_key = {t.key: t for t in targets}
    if agents_arg:
        if agents_arg.strip().lower() == "all":
            return targets
        names = [n.strip() for n in agents_arg.split(",") if n.strip()]
        unknown = [n for n in names if n not in by_key]
        if unknown:
            raise click.ClickException(
                f"unknown agent(s): {', '.join(unknown)}. "
                f"Pick from: {', '.join(by_key)} or 'all'."
            )
        return [by_key[n] for n in names]

    # Interactive
    click.echo("openrecon — MCP server installer")
    click.echo("================================\n")
    click.echo("Pick the agents to register the openrecon MCP servers with:\n")
    chosen: list[AgentTarget] = []
    for t in targets:
        present_marker = "(found)" if t.path.exists() else "(not present yet — will be created)"
        default = t.path.exists()
        if skip_confirm:
            if default:
                chosen.append(t)
            continue
        if click.confirm(f"  {t.label:<28} {present_marker}", default=default):
            chosen.append(t)
    return chosen


if __name__ == "__main__":  # pragma: no cover
    main()


__all__ = ["main"]
