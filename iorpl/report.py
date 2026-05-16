"""Render MutationResult lists into human-readable reports.

Two output formats: Markdown (default, for terminal + GitHub) and HTML
(self-contained, for sharing). The renderer groups results by verdict so
operators see ``leak_detected`` / ``auth_bypassed`` first.

Each confirmed finding also emits a **HackerOne-shaped stub** with title,
severity hint, reproduction steps, and evidence block — copy/paste-ready.
"""

from __future__ import annotations

import base64
import html
import json
from collections import defaultdict
from pathlib import Path
from typing import Any

from .mutations import (
    VERDICT_AUTH_BYPASSED,
    VERDICT_ERROR,
    VERDICT_LEAK_DETECTED,
    VERDICT_NO_DIFF,
    VERDICT_STATUS_CHANGE,
)

# Higher = more interesting; rendering sorts findings by this.
_VERDICT_PRIORITY = {
    VERDICT_AUTH_BYPASSED: 4,
    VERDICT_LEAK_DETECTED: 3,
    VERDICT_STATUS_CHANGE: 2,
    VERDICT_ERROR: 1,
    VERDICT_NO_DIFF: 0,
}

# Mapping to a HackerOne severity guess for the stub.
_SEVERITY_HINT = {
    VERDICT_AUTH_BYPASSED: "Critical",
    VERDICT_LEAK_DETECTED: "High",
    VERDICT_STATUS_CHANGE: "Medium",
    VERDICT_ERROR: "Informational",
    VERDICT_NO_DIFF: "None",
}


def load_results(path: str | Path) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    p = Path(path)
    if p.is_dir():
        p = p / "results.jsonl"
    if not p.exists():
        return out
    with p.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return out


def render_markdown(results: list[dict[str, Any]], *, suite_name: str = "") -> str:
    counts: dict[str, int] = defaultdict(int)
    for r in results:
        counts[r.get("verdict", VERDICT_NO_DIFF)] += 1

    lines: list[str] = []
    lines.append(f"# iorpl replay report{' — ' + suite_name if suite_name else ''}")
    lines.append("")
    lines.append(f"Total mutations executed: **{len(results)}**")
    lines.append("")
    lines.append("| Verdict | Count |")
    lines.append("|---|---|")
    for v in (VERDICT_AUTH_BYPASSED, VERDICT_LEAK_DETECTED, VERDICT_STATUS_CHANGE, VERDICT_ERROR, VERDICT_NO_DIFF):
        lines.append(f"| `{v}` | {counts.get(v, 0)} |")
    lines.append("")

    ranked = sorted(results, key=lambda r: -_VERDICT_PRIORITY.get(r.get("verdict", VERDICT_NO_DIFF), 0))
    for r in ranked:
        verdict = r.get("verdict", VERDICT_NO_DIFF)
        if verdict == VERDICT_NO_DIFF:
            continue
        lines.append(_markdown_one(r))
        lines.append("")

    bypassed = [r for r in results if r.get("verdict") in (VERDICT_AUTH_BYPASSED, VERDICT_LEAK_DETECTED)]
    if bypassed:
        lines.append("---")
        lines.append("")
        lines.append("# HackerOne report stubs")
        lines.append("")
        for r in bypassed:
            lines.append(_hackerone_stub(r))
            lines.append("")
    return "\n".join(lines)


def render_html(results: list[dict[str, Any]], *, suite_name: str = "") -> str:
    md = render_markdown(results, suite_name=suite_name)
    body = html.escape(md).replace("\n", "<br>\n")
    return (
        "<!doctype html>\n<html><head><meta charset='utf-8'>"
        f"<title>iorpl report {html.escape(suite_name)}</title>"
        "<style>body{font-family:ui-monospace,monospace;line-height:1.5;max-width:900px;margin:2em auto;padding:0 1em;}"
        "code,pre{background:#f4f4f4;padding:2px 6px;border-radius:3px;}</style>"
        f"</head><body><pre>{body}</pre></body></html>"
    )


# ── helpers ─────────────────────────────────────────────────────────────────


def _markdown_one(r: dict[str, Any]) -> str:
    req = r.get("mutated_request") or {}
    mut_resp = r.get("mutated_response") or {}
    base_resp = r.get("baseline_response") or {}
    evidence = r.get("evidence") or []
    body_preview = _body_preview(mut_resp.get("body_b64"))
    return (
        f"## `{r.get('verdict')}` · `{r.get('mutation_name')}` · flow `{r.get('flow_id')}`\n\n"
        f"- {req.get('method')} {req.get('url')}\n"
        f"- baseline status: **{(base_resp.get('status') or 0)}** → mutated status: **{(mut_resp.get('status') or 0)}**\n"
        f"- note: {req.get('note', '')}\n"
        f"- evidence: " + (", ".join(evidence) if evidence else "_(none)_") + "\n\n"
        f"```\n{body_preview}\n```"
    )


def _hackerone_stub(r: dict[str, Any]) -> str:
    verdict = r.get("verdict", "")
    severity = _SEVERITY_HINT.get(verdict, "Medium")
    mutation_name = r.get("mutation_name", "?")
    req = r.get("mutated_request") or {}
    mut_resp = r.get("mutated_response") or {}
    base_resp = r.get("baseline_response") or {}
    title = f"{mutation_name} → {verdict} on {req.get('method')} {_short_path(req.get('url'))}"
    repro = (
        f"1. Authenticate to the app and capture the baseline request:\n"
        f"   `{req.get('method')} {req.get('url')}`\n"
        f"2. Modify the request as follows: {req.get('note', 'see attached')}.\n"
        f"3. Re-send the request with the same auth state.\n"
        f"4. Observe: response status **{mut_resp.get('status', 0)}** "
        f"(baseline was **{base_resp.get('status', 0)}**)."
    )
    evidence_block = "\n".join(f"- {e}" for e in (r.get("evidence") or []))
    return (
        f"### Title\n{title}\n\n"
        f"### Severity\n{severity}\n\n"
        f"### Steps to reproduce\n{repro}\n\n"
        f"### Evidence\n{evidence_block or '_(see attached request/response)_'}\n"
    )


def _short_path(url: Any) -> str:
    if not isinstance(url, str):
        return "?"
    from urllib.parse import urlparse

    try:
        p = urlparse(url)
        return p.path or "/"
    except ValueError:
        return url[:80]


def _body_preview(body_b64: Any, *, limit: int = 400) -> str:
    if not isinstance(body_b64, str) or not body_b64:
        return "(no body)"
    try:
        body = base64.b64decode(body_b64).decode("utf-8", "replace")
    except Exception:
        return f"(binary, {len(body_b64)} b64 chars)"
    if len(body) > limit:
        return body[:limit] + f"\n... ({len(body) - limit} more chars)"
    return body


__all__ = ["load_results", "render_html", "render_markdown"]
