"""r2frida-mcp — FastMCP stdio server for live process inspection via r2frida.

Pairs r2 with Frida so callers get r2's analysis surface (cross-refs, search,
disassembly, scripting) against a live iOS process. Useful for things Frida
alone can't do cleanly: byte-pattern scanning of the live heap, fast symbol
resolution across all loaded modules, etc.

Tools (short names):
    r2f_attach           Attach to a target (pid or bundle id).
    r2f_detach           Detach an attachment.
    r2f_sessions         List active attachments.
    r2f_modules          List loaded modules with base/size.
    r2f_classes          Live ObjC classes (optionally filtered).
    r2f_methods          Methods of a class.
    r2f_resolve          Resolve a symbol → address.
    r2f_search_heap      Byte-pattern search on heap regions.
    r2f_search_string    String search on heap regions.
    r2f_memdump          Read process memory (hex or b64).
    r2f_trace            Trace a method / address (stalker-based).
    r2f_trace_stop       Stop a trace.
    r2f_traces           List active traces.
    r2f_disasm           Disassemble at an address.
    r2f_eval             Run inline frida JS via `:eval`.
    r2f_cmd              Escape hatch — raw r2 / r2frida command.

Run standalone:
    r2frida-mcp                       # stdio server
    python -m r2frida_mcp.server      # same
"""

from __future__ import annotations

import json
import logging
from typing import Any

from mcp.server.fastmcp import FastMCP

from .session import R2FridaSession, R2FridaSessionError

logging.basicConfig(level=logging.INFO, format="%(asctime)s [r2frida-mcp] %(levelname)s %(message)s")
log = logging.getLogger("r2frida-mcp")

mcp = FastMCP("r2frida Live Process Inspector")


def _resolve_session(target: str | None, device: str | None) -> R2FridaSession:
    if target:
        return R2FridaSession.get_or_attach(target, device)
    open_keys = list(R2FridaSession._registry.keys())  # noqa: SLF001
    if not open_keys:
        raise R2FridaSessionError("no r2frida session attached; call r2f_attach first")
    if len(open_keys) > 1:
        raise R2FridaSessionError(
            f"multiple sessions attached ({open_keys}); pass target explicitly"
        )
    return R2FridaSession._registry[open_keys[0]]  # noqa: SLF001


def _ok(payload: Any) -> str:
    return json.dumps(payload, default=str)


def _err(message: str) -> str:
    return json.dumps({"ok": False, "error": message})


# ── Lifecycle ──────────────────────────────────────────────────────────────


@mcp.tool()
async def r2f_attach(target: str, device: str | None = None) -> str:
    """Attach to a process. ``target`` = pid (string) or bundle id.

    ``device`` is the frida device id (``frida-ls-devices`` to enumerate);
    leave ``None`` to use the USB device.
    """
    try:
        session = R2FridaSession.get_or_attach(target, device)
        return _ok(
            {
                "attached": True,
                "target": session.target,
                "device": session.device or "usb",
                "info": session.cmdj(":i") if session._pipe else None,  # noqa: SLF001
            }
        )
    except R2FridaSessionError as exc:
        return _err(str(exc))


@mcp.tool()
async def r2f_detach(target: str, device: str | None = None) -> str:
    """Detach from a process."""
    key = R2FridaSession._key(target, device)  # noqa: SLF001
    with R2FridaSession._registry_lock:  # noqa: SLF001
        session = R2FridaSession._registry.pop(key, None)  # noqa: SLF001
    if session is None:
        return _err(f"no session attached for {key}")
    session.detach()
    return _ok({"detached": key})


@mcp.tool()
async def r2f_sessions() -> str:
    """List active r2frida sessions."""
    keys = list(R2FridaSession._registry.keys())  # noqa: SLF001
    return _ok({"count": len(keys), "sessions": keys})


# ── Modules / classes / symbols ────────────────────────────────────────────


@mcp.tool()
async def r2f_modules(target: str | None = None, device: str | None = None) -> str:
    """List loaded modules with base address and size."""
    try:
        session = _resolve_session(target, device)
        return _ok({"modules": session.cmdj(":dmmj") or []})
    except R2FridaSessionError as exc:
        return _err(str(exc))


@mcp.tool()
async def r2f_classes(
    filter: str | None = None,
    target: str | None = None,
    device: str | None = None,
) -> str:
    """Enumerate live ObjC classes. ``filter`` narrows by substring."""
    try:
        session = _resolve_session(target, device)
        cmd = f":icj {filter}" if filter else ":icj"
        return _ok({"classes": session.cmdj(cmd) or []})
    except R2FridaSessionError as exc:
        return _err(str(exc))


@mcp.tool()
async def r2f_methods(
    class_name: str,
    target: str | None = None,
    device: str | None = None,
) -> str:
    """List selectors for a single ObjC class."""
    try:
        session = _resolve_session(target, device)
        return _ok({"class": class_name, "methods": session.cmdj(f":icj+ {class_name}") or []})
    except R2FridaSessionError as exc:
        return _err(str(exc))


@mcp.tool()
async def r2f_resolve(
    symbol: str,
    target: str | None = None,
    device: str | None = None,
) -> str:
    """Resolve a symbol to an address (e.g. ``-[NSString stringWithUTF8String:]``)."""
    try:
        session = _resolve_session(target, device)
        return _ok({"symbol": symbol, "result": session.cmd(f":isa {symbol}")})
    except R2FridaSessionError as exc:
        return _err(str(exc))


# ── Memory ─────────────────────────────────────────────────────────────────


@mcp.tool()
async def r2f_search_heap(
    pattern: str,
    target: str | None = None,
    device: str | None = None,
) -> str:
    """Byte-pattern search on heap-allocated regions. Hex pattern."""
    try:
        session = _resolve_session(target, device)
        return _ok({"pattern": pattern, "hits": session.cmdj(f":/xj {pattern}") or []})
    except R2FridaSessionError as exc:
        return _err(str(exc))


@mcp.tool()
async def r2f_search_string(
    needle: str,
    target: str | None = None,
    device: str | None = None,
) -> str:
    """String search across live process memory."""
    try:
        session = _resolve_session(target, device)
        return _ok({"needle": needle, "hits": session.cmdj(f":/j {needle}") or []})
    except R2FridaSessionError as exc:
        return _err(str(exc))


@mcp.tool()
async def r2f_memdump(
    address: str,
    size: int = 256,
    encoding: str = "hex",
    target: str | None = None,
    device: str | None = None,
) -> str:
    """Read ``size`` bytes from ``address``. ``encoding`` ∈ {hex, b64}."""
    if encoding not in ("hex", "b64"):
        return _err(f"unknown encoding {encoding!r}; pick hex|b64")
    try:
        session = _resolve_session(target, device)
        # `:px <size> @ <address>` prints hex dump.
        out = session.cmd(f":px {size} @ {address}")
        return _ok({"address": address, "size": size, "encoding": "hex", "dump": out})
    except R2FridaSessionError as exc:
        return _err(str(exc))


# ── Tracing ────────────────────────────────────────────────────────────────


@mcp.tool()
async def r2f_trace(
    target_selector: str,
    target: str | None = None,
    device: str | None = None,
) -> str:
    """Start a trace on a selector or address (``:dt <target>``)."""
    try:
        session = _resolve_session(target, device)
        return _ok({"trace": target_selector, "result": session.cmd(f":dt {target_selector}")})
    except R2FridaSessionError as exc:
        return _err(str(exc))


@mcp.tool()
async def r2f_trace_stop(
    target_selector: str,
    target: str | None = None,
    device: str | None = None,
) -> str:
    """Stop a trace (``:dt- <target>``)."""
    try:
        session = _resolve_session(target, device)
        return _ok({"stopped": target_selector, "result": session.cmd(f":dt- {target_selector}")})
    except R2FridaSessionError as exc:
        return _err(str(exc))


@mcp.tool()
async def r2f_traces(target: str | None = None, device: str | None = None) -> str:
    """List active traces."""
    try:
        session = _resolve_session(target, device)
        return _ok({"traces": session.cmd(":dt")})
    except R2FridaSessionError as exc:
        return _err(str(exc))


# ── Code ───────────────────────────────────────────────────────────────────


@mcp.tool()
async def r2f_disasm(
    address: str,
    count: int = 32,
    target: str | None = None,
    device: str | None = None,
) -> str:
    """Disassemble ``count`` instructions at ``address`` in the live process."""
    try:
        session = _resolve_session(target, device)
        return _ok(
            {
                "address": address,
                "count": count,
                "instructions": session.cmdj(f"pdj {count} @ {address}") or [],
            }
        )
    except R2FridaSessionError as exc:
        return _err(str(exc))


# ── Escape hatches ─────────────────────────────────────────────────────────


@mcp.tool()
async def r2f_eval(
    js: str,
    target: str | None = None,
    device: str | None = None,
) -> str:
    """Run inline Frida JS via r2frida's ``:eval``. Use for one-shot scripts."""
    try:
        session = _resolve_session(target, device)
        return _ok({"js": js, "result": session.cmd(f":eval {js}")})
    except R2FridaSessionError as exc:
        return _err(str(exc))


@mcp.tool()
async def r2f_cmd(
    command: str,
    parse_json: bool = False,
    target: str | None = None,
    device: str | None = None,
) -> str:
    """Escape hatch — raw r2 / r2frida command. Prefix with ``:`` for r2frida."""
    try:
        session = _resolve_session(target, device)
        if parse_json:
            return _ok({"command": command, "result": session.cmdj(command)})
        return _ok({"command": command, "result": session.cmd(command)})
    except R2FridaSessionError as exc:
        return _err(str(exc))


# ── Entrypoint ─────────────────────────────────────────────────────────────


def run_stdio() -> None:
    mcp.run("stdio")


if __name__ == "__main__":  # pragma: no cover
    run_stdio()
