"""Generic parameter / header / method mutators."""

from __future__ import annotations

import json
from collections.abc import Iterator
from typing import Any, Protocol

from agent.schema import (
    Evidence,
    Finding,
    ModuleCoverage,
    ModuleResult,
    ReproStep,
    Severity,
)

from .base import ApiModule, ModuleInput, cli_entry, response_diff


class Mutator(Protocol):
    name: str

    def variants(self, flow: dict[str, Any]) -> Iterator[tuple[str, dict[str, Any]]]: ...


class HeaderInjectionMutator:
    name = "header_injection"

    def variants(self, flow: dict[str, Any]) -> Iterator[tuple[str, dict[str, Any]]]:
        payloads = {
            "X-Forwarded-For": "127.0.0.1",
            "X-Original-URL": "/admin",
            "X-Rewrite-URL": "/admin",
            "X-Host": "internal",
            "X-Forwarded-Host": "internal",
            "Host": "internal",
        }
        for header, value in payloads.items():
            yield f"{self.name}:{header}", {"set_headers": {header: value}}


class ContentTypeSwapMutator:
    name = "content_type_swap"

    def variants(self, flow: dict[str, Any]) -> Iterator[tuple[str, dict[str, Any]]]:
        for ct in (
            "application/xml",
            "application/x-www-form-urlencoded",
            "text/plain",
        ):
            yield f"{self.name}:{ct}", {"set_headers": {"Content-Type": ct}}


class MethodSwapMutator:
    name = "method_swap"

    def variants(self, flow: dict[str, Any]) -> Iterator[tuple[str, dict[str, Any]]]:
        current = flow["request"]["method"].upper()
        for method in ("GET", "POST", "PUT", "PATCH", "DELETE"):
            if method == current:
                continue
            yield f"{self.name}:{method}", {"method": method}


class ParamPollutionMutator:
    name = "param_pollution"

    def variants(self, flow: dict[str, Any]) -> Iterator[tuple[str, dict[str, Any]]]:
        from urllib.parse import parse_qsl, urlparse

        parsed = urlparse(flow["request"]["url"])
        for k, _ in parse_qsl(parsed.query):
            yield f"{self.name}:{k}", {"duplicate_query": {k: "1"}}


class TrailingDataMutator:
    name = "trailing_data"

    def variants(self, flow: dict[str, Any]) -> Iterator[tuple[str, dict[str, Any]]]:
        for suffix in ("?", "?#", "/.", "//", ";foo=bar"):
            yield f"{self.name}:{suffix}", {"append_to_url": suffix}


_DEFAULT_MUTATORS: tuple[Mutator, ...] = (
    HeaderInjectionMutator(),
    ContentTypeSwapMutator(),
    MethodSwapMutator(),
    ParamPollutionMutator(),
    TrailingDataMutator(),
)


class TamperModule(ApiModule):
    name = "tamper"
    severity_baseline = Severity.LOW

    async def run(self, inp: ModuleInput) -> ModuleResult:
        findings: list[Finding] = []
        coverage = ModuleCoverage(totals={"flows": 0, "variants": 0})
        mutators = _DEFAULT_MUTATORS

        for flow_id in inp.baseline_flow_ids:
            flow = await _read_flow(inp, flow_id)
            if not flow:
                coverage.skipped.append((flow_id, "flow not found"))
                continue
            coverage.totals["flows"] += 1

            for mutator in mutators:
                for tag, overrides in mutator.variants(flow):
                    coverage.totals["variants"] += 1
                    replay = await inp.mitm_mcp.replay_flow(flow["flow_id"], overrides=overrides)
                    diff = response_diff(flow, replay)
                    if _interesting(diff):
                        findings.append(_finding(inp, flow, replay, mutator.name, tag, diff))
            coverage.tested.append(flow_id)

        return ModuleResult(module=self.name, findings=findings, coverage=coverage)


def _interesting(diff: dict[str, Any]) -> bool:
    if diff.get("status_changed"):
        if (diff.get("status_orig"), diff.get("status_mutated")) == (200, 200):
            return False
        return True
    return bool(diff.get("body_hash_changed"))


def _finding(
    inp: ModuleInput,
    flow: dict[str, Any],
    replay: dict[str, Any],
    mutator: str,
    tag: str,
    diff: dict[str, Any],
) -> Finding:
    sev = (
        Severity.MEDIUM
        if diff.get("status_orig") in (401, 403, 404) and 200 <= (diff.get("status_mutated") or 0) < 300
        else Severity.LOW
    )
    return Finding(
        run_id=str(inp.run_dir.name),
        severity=sev,
        category="api-tampering",
        title=f"Response divergence via {tag}",
        summary=(
            f"{flow['request']['method']} {flow['request']['url']} — "
            f"{tag}: {diff.get('status_orig')} → {diff.get('status_mutated')}"
        ),
        evidence=[
            Evidence(kind="flow", ref=flow["flow_id"], note="baseline"),
            Evidence(kind="flow", ref=replay.get("flow_id", "?"), note=tag),
        ],
        correlated_flows=[flow["flow_id"], replay.get("flow_id", "?")],
        reproduction=[
            ReproStep(
                description=f"Apply {mutator} mutation {tag}",
                primitive="replay_flow",
                args={"flow_id": flow["flow_id"], "overrides": {}},  # filled by mutator
            )
        ],
        tags=[mutator, tag],
        confidence=0.4,
    )


async def _read_flow(inp: ModuleInput, flow_id: str) -> dict[str, Any] | None:
    path = inp.run_dir / "mitm_flows.jsonl"
    if not path.exists():
        return None
    with path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            r = json.loads(line)
            if r["flow_id"] == flow_id:
                return r
    return None


if __name__ == "__main__":  # pragma: no cover
    cli_entry(TamperModule)
