"""Render findings to Markdown + JSON using Jinja2 templates.

Idempotent — `lolmcp report <run_id>` re-runs this without rebuilding state.
Validates each Finding JSON against `templates/finding.schema.json`.
"""

from __future__ import annotations

import json
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from .schema import Finding


REPO_ROOT = Path(__file__).resolve().parent.parent
TEMPLATES_DIR = REPO_ROOT / "templates"


def _env() -> Environment:
    return Environment(
        loader=FileSystemLoader(str(TEMPLATES_DIR)),
        autoescape=select_autoescape(disabled_extensions=("md",)),
        keep_trailing_newline=True,
    )


def render_finding(finding: Finding, env: Environment | None = None) -> str:
    env = env or _env()
    template = env.get_template("finding.md.j2")
    return template.render(f=finding)


def render_run(run_dir: Path) -> int:
    """Render every finding under run_dir/findings.jsonl. Returns count."""
    run_dir = Path(run_dir)
    findings_jsonl = run_dir / "findings.jsonl"
    out_dir = run_dir / "findings"
    out_dir.mkdir(exist_ok=True)
    env = _env()
    count = 0
    if not findings_jsonl.exists():
        return 0
    with findings_jsonl.open(encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            finding = Finding.model_validate_json(line)
            (out_dir / f"{finding.finding_id}.json").write_text(
                finding.model_dump_json(indent=2), encoding="utf-8"
            )
            (out_dir / f"{finding.finding_id}.md").write_text(
                render_finding(finding, env), encoding="utf-8"
            )
            count += 1
    _write_index(run_dir)
    return count


def _write_index(run_dir: Path) -> None:
    findings_jsonl = run_dir / "findings.jsonl"
    findings: list[Finding] = []
    if findings_jsonl.exists():
        for line in findings_jsonl.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line:
                findings.append(Finding.model_validate_json(line))
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings.sort(key=lambda f: order.get(f.severity.value, 9))
    env = _env()
    template = env.get_template("report.md.j2")
    (run_dir / "report.md").write_text(template.render(findings=findings), encoding="utf-8")
    (run_dir / "report.json").write_text(
        json.dumps(
            {
                "run_id": findings[0].run_id if findings else None,
                "counts": {sev: sum(1 for f in findings if f.severity.value == sev) for sev in order},
                "findings": [f.model_dump() for f in findings],
            },
            indent=2,
            default=str,
        ),
        encoding="utf-8",
    )


__all__ = ["render_run", "render_finding"]
