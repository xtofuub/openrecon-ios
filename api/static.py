"""Static-analysis helpers — in-process wrapper around r2pipe.

Used by the planner and finder rules to query a dumped Mach-O without paying
the MCP-stdio round-trip cost. Reuses :class:`r2_mcp.session.R2Session` so
the same r2 analysis state is shared with the standalone r2-mcp server.

Typical use:

    from api.static import open_binary, enumerate_strings, find_hardcoded_urls

    sess = open_binary(run_dir / "artifacts" / "app.macho")
    for url in find_hardcoded_urls(sess):
        ...

When r2pipe / radare2 are not installed, every function returns an empty
result and logs a single warning per run. This keeps the rest of the
pipeline working in environments without r2.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)


_URL_RE = re.compile(r"https?://[A-Za-z0-9._\-~:/?#\[\]@!$&'()*+,;=%]+")
_AWS_KEY_RE = re.compile(r"AKIA[0-9A-Z]{16}")
_STRIPE_RE = re.compile(r"(?:sk|pk)_(?:live|test)_[0-9a-zA-Z]{20,}")
_JWT_RE = re.compile(r"eyJ[A-Za-z0-9_\-]{6,}\.[A-Za-z0-9_\-]{6,}\.[A-Za-z0-9_\-]{6,}")


def _try_import_session() -> Any | None:
    try:
        from r2_mcp.session import R2Session
        return R2Session
    except Exception as exc:  # pragma: no cover - environment-dependent
        log.warning("static.r2_unavailable: %s", exc)
        return None


def open_binary(path: Path | str) -> Any | None:
    """Open a binary and return an R2Session, or None if r2pipe isn't installed."""
    R2Session = _try_import_session()
    if R2Session is None:
        return None
    try:
        sess = R2Session.get_or_open(path)
        sess.ensure_analyzed()
        return sess
    except Exception as exc:
        log.warning("static.open_failed path=%s err=%s", path, exc)
        return None


def enumerate_strings(session: Any, min_len: int = 6, whole: bool = True) -> list[str]:
    if session is None:
        return []
    try:
        items = session.cmdj("izzj" if whole else "izj") or []
    except Exception:
        return []
    out: list[str] = []
    for it in items:
        if not isinstance(it, dict):
            continue
        s = it.get("string") or ""
        if isinstance(s, str) and len(s) >= min_len:
            out.append(s)
    return out


def find_hardcoded_urls(session: Any) -> list[str]:
    urls: set[str] = set()
    for s in enumerate_strings(session, min_len=8):
        for m in _URL_RE.findall(s):
            urls.add(m)
    return sorted(urls)


def find_high_entropy_secrets(session: Any) -> dict[str, list[str]]:
    """Pattern-scan binary strings for known secret shapes.

    Returns a mapping of pattern-name → hits. Used by the static finder
    rule downstream.
    """
    hits: dict[str, list[str]] = {"aws": [], "stripe": [], "jwt": []}
    if session is None:
        return hits
    for s in enumerate_strings(session, min_len=20):
        if _AWS_KEY_RE.search(s):
            hits["aws"].append(s)
        if _STRIPE_RE.search(s):
            hits["stripe"].append(s)
        if _JWT_RE.search(s):
            hits["jwt"].append(s)
    return hits


def entitlements_xml(session: Any) -> str | None:
    if session is None:
        return None
    try:
        raw = session.cmd("iX")
    except Exception:
        return None
    if "<?xml" not in raw:
        return None
    xml = raw[raw.index("<?xml"):]
    if "</plist>" in xml:
        xml = xml[: xml.index("</plist>") + len("</plist>")]
    return xml


def imported_symbols(session: Any) -> list[str]:
    if session is None:
        return []
    try:
        items = session.cmdj("iij") or []
    except Exception:
        return []
    return [str(it.get("name") or "") for it in items if isinstance(it, dict)]


def function_names(session: Any) -> list[str]:
    if session is None:
        return []
    try:
        items = session.cmdj("aflj") or []
    except Exception:
        return []
    return [str(it.get("name") or "") for it in items if isinstance(it, dict)]


__all__ = [
    "open_binary",
    "enumerate_strings",
    "find_hardcoded_urls",
    "find_high_entropy_secrets",
    "entitlements_xml",
    "imported_symbols",
    "function_names",
]
