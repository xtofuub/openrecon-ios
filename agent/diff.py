"""Cross-run comparison.

Used by `openrecon diff <run_a> <run_b>` to spot regressions or changes between
two engagements against the same target (different app versions, before/after a
fix, etc.).

Compares:
- Endpoint coverage (which endpoints appeared / disappeared)
- Findings (new / resolved / persistent, grouped by severity)
- Counters (flows, frida events, hypotheses)
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .endpoint_map import group_flows


@dataclass
class FindingDelta:
    new: list[dict[str, Any]] = field(default_factory=list)
    resolved: list[dict[str, Any]] = field(default_factory=list)
    persistent: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class EndpointDelta:
    new: list[str] = field(default_factory=list)
    removed: list[str] = field(default_factory=list)
    persistent: list[str] = field(default_factory=list)


@dataclass
class CounterDelta:
    flows: tuple[int, int]
    frida_events: tuple[int, int]
    findings_total: tuple[int, int]
    findings_by_severity: dict[str, tuple[int, int]]


@dataclass
class RunDiff:
    run_a: str
    run_b: str
    endpoints: EndpointDelta
    findings: FindingDelta
    counters: CounterDelta

    def as_dict(self) -> dict[str, Any]:
        return {
            "run_a": self.run_a,
            "run_b": self.run_b,
            "endpoints": {
                "new": self.endpoints.new,
                "removed": self.endpoints.removed,
                "persistent_count": len(self.endpoints.persistent),
            },
            "findings": {
                "new": [_summary(f) for f in self.findings.new],
                "resolved": [_summary(f) for f in self.findings.resolved],
                "persistent": [_summary(f) for f in self.findings.persistent],
            },
            "counters": {
                "flows": list(self.counters.flows),
                "frida_events": list(self.counters.frida_events),
                "findings_total": list(self.counters.findings_total),
                "findings_by_severity": {
                    k: list(v) for k, v in self.counters.findings_by_severity.items()
                },
            },
        }


def diff_runs(run_a: Path, run_b: Path) -> RunDiff:
    flows_a = _load_jsonl(run_a / "mitm_flows.jsonl")
    flows_b = _load_jsonl(run_b / "mitm_flows.jsonl")
    findings_a = _load_jsonl(run_a / "findings.jsonl")
    findings_b = _load_jsonl(run_b / "findings.jsonl")
    frida_a = _line_count(run_a / "frida_events.jsonl")
    frida_b = _line_count(run_b / "frida_events.jsonl")

    endpoints = _diff_endpoints(flows_a, flows_b)
    findings_delta = _diff_findings(findings_a, findings_b)

    counters = CounterDelta(
        flows=(len(flows_a), len(flows_b)),
        frida_events=(frida_a, frida_b),
        findings_total=(len(findings_a), len(findings_b)),
        findings_by_severity=_severity_counters(findings_a, findings_b),
    )

    return RunDiff(
        run_a=run_a.name,
        run_b=run_b.name,
        endpoints=endpoints,
        findings=findings_delta,
        counters=counters,
    )


def _diff_endpoints(flows_a: list[dict], flows_b: list[dict]) -> EndpointDelta:
    keys_a = {_endpoint_key(g) for g in group_flows(flows_a)}
    keys_b = {_endpoint_key(g) for g in group_flows(flows_b)}
    return EndpointDelta(
        new=sorted(keys_b - keys_a),
        removed=sorted(keys_a - keys_b),
        persistent=sorted(keys_a & keys_b),
    )


def _endpoint_key(group: Any) -> str:
    return f"{group.method} {group.host}{group.path_template}"


def _diff_findings(a: list[dict], b: list[dict]) -> FindingDelta:
    """Match findings across runs by (category, title). New/resolved/persistent."""
    by_key_a = {_finding_key(f): f for f in a}
    by_key_b = {_finding_key(f): f for f in b}
    new_keys = set(by_key_b) - set(by_key_a)
    removed_keys = set(by_key_a) - set(by_key_b)
    persistent_keys = set(by_key_a) & set(by_key_b)
    return FindingDelta(
        new=[by_key_b[k] for k in sorted(new_keys)],
        resolved=[by_key_a[k] for k in sorted(removed_keys)],
        persistent=[by_key_b[k] for k in sorted(persistent_keys)],
    )


def _finding_key(f: dict) -> tuple[str, str]:
    return (f.get("category", ""), f.get("title", ""))


def _severity_counters(a: list[dict], b: list[dict]) -> dict[str, tuple[int, int]]:
    out: dict[str, tuple[int, int]] = {}
    for sev in ("critical", "high", "medium", "low", "info"):
        out[sev] = (
            sum(1 for f in a if f.get("severity") == sev),
            sum(1 for f in b if f.get("severity") == sev),
        )
    return out


def _load_jsonl(path: Path) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    if not path.exists():
        return out
    with path.open(encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return out


def _line_count(path: Path) -> int:
    if not path.exists():
        return 0
    with path.open(encoding="utf-8") as fh:
        return sum(1 for line in fh if line.strip())


def _summary(f: dict) -> dict[str, Any]:
    return {
        "finding_id": f.get("finding_id"),
        "severity": f.get("severity"),
        "category": f.get("category"),
        "title": f.get("title"),
    }


def render_diff(diff: RunDiff) -> str:
    lines = [
        f"# Run diff — {diff.run_a} → {diff.run_b}",
        "",
        "## Counters",
        "",
        f"- Flows: {diff.counters.flows[0]} → {diff.counters.flows[1]}",
        f"- Frida events: {diff.counters.frida_events[0]} → {diff.counters.frida_events[1]}",
        f"- Findings: {diff.counters.findings_total[0]} → {diff.counters.findings_total[1]}",
        "",
        "### Findings by severity",
        "",
    ]
    for sev, (a, b) in diff.counters.findings_by_severity.items():
        if a or b:
            lines.append(f"- **{sev}**: {a} → {b}")
    lines += [
        "",
        f"## Endpoints (+{len(diff.endpoints.new)} new, -{len(diff.endpoints.removed)} removed)",
        "",
    ]
    if diff.endpoints.new:
        lines.append("### New")
        for key in diff.endpoints.new:
            lines.append(f"- `{key}`")
        lines.append("")
    if diff.endpoints.removed:
        lines.append("### Removed")
        for key in diff.endpoints.removed:
            lines.append(f"- `{key}`")
        lines.append("")
    lines += [
        f"## Findings (+{len(diff.findings.new)} new, -{len(diff.findings.resolved)} resolved)",
        "",
    ]
    if diff.findings.new:
        lines.append("### New findings")
        for f in diff.findings.new:
            lines.append(f"- **[{f.get('severity', '?')}]** {f.get('category')} — {f.get('title')}")
        lines.append("")
    if diff.findings.resolved:
        lines.append("### Resolved findings (present in A, absent in B)")
        for f in diff.findings.resolved:
            lines.append(f"- **[{f.get('severity', '?')}]** {f.get('category')} — {f.get('title')}")
        lines.append("")
    if diff.findings.persistent:
        lines.append(f"### Persistent findings ({len(diff.findings.persistent)})")
        for f in diff.findings.persistent:
            lines.append(f"- **[{f.get('severity', '?')}]** {f.get('category')} — {f.get('title')}")
    return "\n".join(lines) + "\n"


__all__ = [
    "RunDiff",
    "FindingDelta",
    "EndpointDelta",
    "CounterDelta",
    "diff_runs",
    "render_diff",
]
