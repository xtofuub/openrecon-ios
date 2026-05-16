"""r2-mcp — FastMCP stdio server exposing radare2 static-analysis tools.

Tools (short names, mirroring frida-flex conventions):
    r2_open               Open a binary and run analysis.
    r2_info               Bin/arch/section summary.
    r2_functions          Function list with offsets, sizes, callrefs.
    r2_strings            Strings from data sections + whole binary.
    r2_xrefs              Cross-references to/from an address or symbol.
    r2_imports            Imported symbols.
    r2_exports            Exported symbols.
    r2_classes            ObjC class layout parsed from the Mach-O.
    r2_methods            Methods of a single ObjC class.
    r2_entitlements       Extract entitlements from LC_CODE_SIGNATURE.
    r2_decompile          Decompiled pseudocode (r2dec / r2ghidra if loaded).
    r2_disasm             Disassembly of a function or address range.
    r2_search_bytes       Byte-pattern search across the binary.
    r2_search_string      String search.
    r2_cmd                Escape hatch — run an arbitrary r2 command.
    r2_close              Close a session (registry eviction).

Sessions are keyed by absolute binary path so concurrent tool calls against
the same binary share analysis state. The first ``r2_open`` for a binary pays
the ``aaa`` cost; subsequent calls reuse it.

Run standalone:
    r2-mcp                    # stdio server, registered in .claude/settings.json
    python -m r2_mcp.server   # same
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from mcp.server.fastmcp import FastMCP

from .session import R2Session, R2SessionError

logging.basicConfig(level=logging.INFO, format="%(asctime)s [r2-mcp] %(levelname)s %(message)s")
log = logging.getLogger("r2-mcp")

mcp = FastMCP("radare2 Static Analyzer")


def _resolve_session(binary_path: str | None) -> R2Session:
    """Pick the session matching ``binary_path`` or the only open one."""
    if binary_path:
        return R2Session.get_or_open(binary_path)
    open_paths = list(R2Session._registry.keys())  # noqa: SLF001 — internal registry
    if not open_paths:
        raise R2SessionError(
            "no r2 session is open; call r2_open with a binary path first"
        )
    if len(open_paths) > 1:
        raise R2SessionError(
            f"multiple sessions open ({len(open_paths)}); pass binary_path explicitly: {open_paths}"
        )
    return R2Session._registry[open_paths[0]]  # noqa: SLF001


def _ok(payload: Any) -> str:
    return json.dumps(payload, default=str)


def _err(message: str) -> str:
    return json.dumps({"ok": False, "error": message})


# ── Lifecycle ──────────────────────────────────────────────────────────────


@mcp.tool()
async def r2_open(binary_path: str, analyze: bool = True) -> str:
    """Open a binary for analysis. Returns bin info + arch + sections.

    ``analyze=True`` runs ``aaa`` (recommended for most queries). Set ``False``
    to skip the expensive pass when you only need string / import data.
    """
    try:
        session = R2Session.get_or_open(binary_path)
        if analyze:
            session.ensure_analyzed()
        info = session.info()
        return _ok(
            {
                "binary_path": str(session.binary_path),
                "analyzed": session._analyzed,  # noqa: SLF001
                "fat": session.is_fat_binary(),
                "info": info,
            }
        )
    except R2SessionError as exc:
        return _err(str(exc))


@mcp.tool()
async def r2_close(binary_path: str) -> str:
    """Close a session. Subsequent tool calls for the same path will re-open."""
    key = str(Path(binary_path).resolve())
    with R2Session._registry_lock:  # noqa: SLF001
        session = R2Session._registry.pop(key, None)
    if session is None:
        return _err(f"no session open for {key}")
    session.close()
    return _ok({"closed": key})


# ── Inspection ─────────────────────────────────────────────────────────────


@mcp.tool()
async def r2_info(binary_path: str | None = None) -> str:
    """Bin info: format, arch, bits, endianness, entry point, sections."""
    try:
        session = _resolve_session(binary_path)
        return _ok(
            {
                "info": session.info(),
                "sections": session.cmdj("iSj") or [],
                "segments": session.cmdj("iSSj") or [],
            }
        )
    except R2SessionError as exc:
        return _err(str(exc))


@mcp.tool()
async def r2_functions(binary_path: str | None = None, limit: int = 500) -> str:
    """Function list: name, offset, size, callrefs, complexity.

    Sorted by offset. ``limit`` caps the result to avoid context blowup; pass
    a large number or ``-1`` to disable the cap.
    """
    try:
        session = _resolve_session(binary_path)
        session.ensure_analyzed()
        fns = session.cmdj("aflj") or []
        if limit > 0 and len(fns) > limit:
            fns = fns[:limit]
        slim = [
            {
                "name": f.get("name"),
                "offset": f.get("offset"),
                "size": f.get("size"),
                "nbbs": f.get("nbbs"),
                "stack": f.get("stackframe"),
                "complexity": f.get("cc"),
                "calltype": f.get("calltype"),
            }
            for f in fns
        ]
        return _ok({"count": len(slim), "functions": slim})
    except R2SessionError as exc:
        return _err(str(exc))


@mcp.tool()
async def r2_strings(binary_path: str | None = None, min_len: int = 4, whole: bool = False) -> str:
    """Strings from the binary. ``whole=True`` scans every byte (slower)."""
    try:
        session = _resolve_session(binary_path)
        cmd = "izzj" if whole else "izj"
        strings = session.cmdj(cmd) or []
        out = [
            {"vaddr": s.get("vaddr"), "paddr": s.get("paddr"), "type": s.get("type"), "string": s.get("string")}
            for s in strings
            if isinstance(s, dict) and len(str(s.get("string") or "")) >= min_len
        ]
        return _ok({"count": len(out), "strings": out})
    except R2SessionError as exc:
        return _err(str(exc))


@mcp.tool()
async def r2_xrefs(target: str, direction: str = "to", binary_path: str | None = None) -> str:
    """Cross-references. ``direction`` ∈ {to, from}. ``target`` = symbol or hex offset."""
    try:
        session = _resolve_session(binary_path)
        session.ensure_analyzed()
        cmd = "axtj" if direction == "to" else "axfj"
        refs = session.cmdj(f"{cmd} @ {target}") or []
        return _ok({"target": target, "direction": direction, "count": len(refs), "xrefs": refs})
    except R2SessionError as exc:
        return _err(str(exc))


@mcp.tool()
async def r2_imports(binary_path: str | None = None) -> str:
    """Imported symbols (functions, libraries)."""
    try:
        session = _resolve_session(binary_path)
        return _ok({"imports": session.cmdj("iij") or []})
    except R2SessionError as exc:
        return _err(str(exc))


@mcp.tool()
async def r2_exports(binary_path: str | None = None) -> str:
    """Exported symbols."""
    try:
        session = _resolve_session(binary_path)
        return _ok({"exports": session.cmdj("iEj") or []})
    except R2SessionError as exc:
        return _err(str(exc))


@mcp.tool()
async def r2_classes(binary_path: str | None = None) -> str:
    """ObjC class layout parsed from the Mach-O __objc_classlist section.

    Returns one entry per class with its methods and ivars. Static — does not
    require the app to be running.
    """
    try:
        session = _resolve_session(binary_path)
        return _ok({"classes": session.cmdj("icj") or []})
    except R2SessionError as exc:
        return _err(str(exc))


@mcp.tool()
async def r2_methods(class_name: str, binary_path: str | None = None) -> str:
    """Methods of a single ObjC class."""
    try:
        session = _resolve_session(binary_path)
        # `ic <name>` is non-JSON; filter from `icj` instead.
        classes = session.cmdj("icj") or []
        for c in classes:
            if c.get("classname") == class_name or c.get("name") == class_name:
                return _ok({"class": class_name, "methods": c.get("methods") or []})
        return _err(f"class {class_name!r} not found")
    except R2SessionError as exc:
        return _err(str(exc))


@mcp.tool()
async def r2_entitlements(binary_path: str | None = None) -> str:
    """Extract entitlements (LC_CODE_SIGNATURE blob, parsed XML plist)."""
    try:
        session = _resolve_session(binary_path)
        # r2's `iE` lists exports; for entitlements we read the CMS / signature.
        # Best-portable approach: read the signature blob and search for the
        # embedded plist marker '<?xml'.
        raw = session.cmd("iX")
        ents = ""
        if "<?xml" in raw:
            ents = raw[raw.index("<?xml") :]
            # Trim trailing non-XML bytes.
            if "</plist>" in ents:
                ents = ents[: ents.index("</plist>") + len("</plist>")]
        return _ok({"raw_signature_dump": raw[:4000], "entitlements_xml": ents})
    except R2SessionError as exc:
        return _err(str(exc))


@mcp.tool()
async def r2_decompile(target: str, engine: str = "auto", binary_path: str | None = None) -> str:
    """Decompiled pseudocode for a function. ``target`` = symbol or address.

    ``engine`` ∈ {auto, pdc, r2dec, r2ghidra}. ``pdc`` is r2's native
    pseudo-disassembly (no external dep). ``r2dec`` and ``r2ghidra`` require
    those plugins installed via ``r2pm -ci r2dec`` / ``r2pm -ci r2ghidra``.
    """
    cmd_map = {"pdc": "pdc", "r2dec": "pdd", "r2ghidra": "pdg"}
    try:
        session = _resolve_session(binary_path)
        session.ensure_analyzed()
        if engine == "auto":
            for candidate in ("pdg", "pdd", "pdc"):
                out = session.cmd(f"{candidate} @ {target}")
                if out and "Unknown command" not in out:
                    return _ok({"target": target, "engine": candidate, "pseudocode": out})
            return _err(f"no decompiler available for {target}")
        cmd = cmd_map.get(engine)
        if cmd is None:
            return _err(f"unknown engine {engine!r}; pick: auto, pdc, r2dec, r2ghidra")
        out = session.cmd(f"{cmd} @ {target}")
        return _ok({"target": target, "engine": engine, "pseudocode": out})
    except R2SessionError as exc:
        return _err(str(exc))


@mcp.tool()
async def r2_disasm(target: str, count: int = 64, binary_path: str | None = None) -> str:
    """Disassemble ``count`` instructions starting at ``target``."""
    try:
        session = _resolve_session(binary_path)
        session.ensure_analyzed()
        out = session.cmdj(f"pdj {count} @ {target}") or []
        return _ok({"target": target, "count": len(out), "instructions": out})
    except R2SessionError as exc:
        return _err(str(exc))


@mcp.tool()
async def r2_search_bytes(pattern: str, binary_path: str | None = None) -> str:
    """Byte-pattern search. ``pattern`` is a hex string (e.g., ``"deadbeef"``)."""
    try:
        session = _resolve_session(binary_path)
        hits = session.cmdj(f"/xj {pattern}") or []
        return _ok({"pattern": pattern, "count": len(hits), "hits": hits})
    except R2SessionError as exc:
        return _err(str(exc))


@mcp.tool()
async def r2_search_string(needle: str, binary_path: str | None = None) -> str:
    """String search. Case-sensitive substring across binary strings."""
    try:
        session = _resolve_session(binary_path)
        hits = session.cmdj(f"/j {needle}") or []
        return _ok({"needle": needle, "count": len(hits), "hits": hits})
    except R2SessionError as exc:
        return _err(str(exc))


@mcp.tool()
async def r2_cmd(command: str, binary_path: str | None = None, parse_json: bool = False) -> str:
    """Escape hatch — run a raw r2 command. Use ``parse_json=True`` for ``...j`` commands."""
    try:
        session = _resolve_session(binary_path)
        if parse_json:
            return _ok({"command": command, "result": session.cmdj(command)})
        out = session.cmd(command)
        return _ok({"command": command, "result": out})
    except R2SessionError as exc:
        return _err(str(exc))


# ── Entrypoint ─────────────────────────────────────────────────────────────


def run_stdio() -> None:
    """Run the FastMCP server over stdio."""
    mcp.run("stdio")


if __name__ == "__main__":  # pragma: no cover
    run_stdio()
