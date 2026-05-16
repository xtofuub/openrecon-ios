"""Auth module — find endpoints that fail open under altered or missing auth."""

from __future__ import annotations

import json
from typing import Any

from agent.schema import (
    Evidence,
    Finding,
    Hypothesis,
    ModuleCoverage,
    ModuleResult,
    ReproStep,
    Severity,
)

from .base import ApiModule, ModuleInput, cli_entry, response_diff

_AUTH_HEADERS = ("authorization", "cookie", "x-api-key", "x-auth-token", "x-session-token")


class AuthModule(ApiModule):
    name = "auth"
    severity_baseline = Severity.HIGH

    async def run(self, inp: ModuleInput) -> ModuleResult:
        findings: list[Finding] = []
        hypotheses: list[Hypothesis] = []
        coverage = ModuleCoverage(totals={"flows": 0, "probes": 0})

        for flow_id in inp.baseline_flow_ids:
            flow = await _read_flow(inp, flow_id)
            if not flow:
                coverage.skipped.append((flow_id, "flow not found"))
                continue
            coverage.totals["flows"] += 1
            present = [h for h in _AUTH_HEADERS if h in {k.lower() for k in flow["request"]["headers"]}]
            if not present:
                # An auth-bearing endpoint with *no* auth header observed is
                # weird; open a hypothesis the planner can probe later.
                hypotheses.append(
                    Hypothesis(
                        claim=(
                            f"{flow['request']['method']} {flow['request']['url']} returned 2xx "
                            "but carried no observed auth header — verify endpoint is intended to be public"
                        ),
                        status="open",
                        tests=[f"replay_with_body_mutation:{flow_id}"],
                        evidence=[Evidence(kind="flow", ref=flow_id, note="no auth header on auth'd flow set")],
                    )
                )
                coverage.skipped.append((flow_id, "no auth header observed"))
                continue

            new_findings = await self._probe_strip(inp, flow, present, coverage)
            findings += new_findings
            new_findings_swap = await self._probe_swap(inp, flow, present, coverage)
            findings += new_findings_swap
            for f in new_findings_swap:
                if "swap-noop" in (f.tags or []):
                    hypotheses.append(
                        Hypothesis(
                            claim=(
                                f"Token swap on {flow['request']['method']} {flow['request']['url']} "
                                "returned identical payload — endpoint may not validate session ownership"
                            ),
                            status="open",
                            tests=[f"replay_with_body_mutation:{flow_id}"],
                            evidence=[Evidence(kind="flow", ref=flow_id, note="swap-noop ambiguity")],
                        )
                    )
            findings += await self._probe_jwt_alg_none(inp, flow, coverage)

            coverage.tested.append(flow_id)

        return ModuleResult(
            module=self.name, findings=findings, hypotheses=hypotheses, coverage=coverage
        )

    async def _probe_strip(
        self,
        inp: ModuleInput,
        flow: dict[str, Any],
        present: list[str],
        coverage: ModuleCoverage,
    ) -> list[Finding]:
        out: list[Finding] = []
        for header in present + ["__all__"]:
            coverage.totals["probes"] += 1
            overrides = (
                {"strip_headers": present} if header == "__all__" else {"strip_headers": [header]}
            )
            replay = await inp.mitm_mcp.replay_flow(flow["flow_id"], overrides=overrides)
            status = (replay.get("response") or {}).get("status", 0)
            if 200 <= status < 300:
                out.append(
                    _finding(
                        inp,
                        flow,
                        replay,
                        title=f"Auth bypass — stripping {header} returns {status}",
                        severity=Severity.HIGH if header == "__all__" else Severity.MEDIUM,
                        kind="strip",
                        detail=header,
                    )
                )
        return out

    async def _probe_swap(
        self,
        inp: ModuleInput,
        flow: dict[str, Any],
        present: list[str],
        coverage: ModuleCoverage,
    ) -> list[Finding]:
        out: list[Finding] = []
        for label, creds in inp.session_pool.items():
            if not (creds.auth_header or creds.cookie or creds.jwt):
                continue
            coverage.totals["probes"] += 1
            overrides: dict[str, Any] = {"set_headers": {}}
            if creds.auth_header:
                overrides["set_headers"]["Authorization"] = creds.auth_header
            if creds.cookie:
                overrides["set_headers"]["Cookie"] = creds.cookie
            replay = await inp.mitm_mcp.replay_flow(flow["flow_id"], overrides=overrides)
            status = (replay.get("response") or {}).get("status", 0)
            if 200 <= status < 300:
                diff = response_diff(flow, replay)
                if diff.get("body_hash_changed"):
                    out.append(
                        _finding(
                            inp,
                            flow,
                            replay,
                            title=f"Cross-session access via {label} credentials",
                            severity=Severity.HIGH,
                            kind="swap",
                            detail=label,
                        )
                    )
                else:
                    out.append(
                        _finding(
                            inp,
                            flow,
                            replay,
                            title=f"Token swap returns same payload as baseline ({label})",
                            severity=Severity.LOW,
                            kind="swap-noop",
                            detail=label,
                        )
                    )
        return out

    async def _probe_jwt_alg_none(
        self, inp: ModuleInput, flow: dict[str, Any], coverage: ModuleCoverage
    ) -> list[Finding]:
        from .token_analysis import jwt_alg_none

        auth = flow["request"]["headers"].get("Authorization") or flow["request"]["headers"].get("authorization")
        if not auth or not auth.lower().startswith("bearer "):
            return []
        coverage.totals["probes"] += 1
        token = auth.split(" ", 1)[1]
        mutated = jwt_alg_none(token)
        if not mutated:
            return []
        replay = await inp.mitm_mcp.replay_flow(
            flow["flow_id"], overrides={"set_headers": {"Authorization": f"Bearer {mutated}"}}
        )
        if 200 <= (replay.get("response") or {}).get("status", 0) < 300:
            return [
                _finding(
                    inp,
                    flow,
                    replay,
                    title="JWT alg=none accepted",
                    severity=Severity.CRITICAL,
                    kind="jwt-alg-none",
                    detail="header.payload. (no sig)",
                )
            ]
        return []


def _finding(
    inp: ModuleInput,
    flow: dict[str, Any],
    replay: dict[str, Any],
    *,
    title: str,
    severity: Severity,
    kind: str,
    detail: str,
) -> Finding:
    return Finding(
        run_id=str(inp.run_dir.name),
        severity=severity,
        category="auth-bypass",
        title=title,
        summary=(
            f"{flow['request']['method']} {flow['request']['url']} returned "
            f"{replay.get('response', {}).get('status')} under {kind}({detail})."
        ),
        evidence=[
            Evidence(kind="flow", ref=flow["flow_id"], note="baseline"),
            Evidence(kind="flow", ref=replay.get("flow_id", "?"), note=f"{kind}: {detail}"),
        ],
        correlated_flows=[flow["flow_id"], replay.get("flow_id", "?")],
        reproduction=[
            ReproStep(
                description=f"Replay baseline with {kind}({detail})",
                primitive="replay_flow",
                args={"flow_id": flow["flow_id"], "overrides": {"strip_headers": [detail]}},
            )
        ],
        tags=["auth", kind],
        confidence=0.75,
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
    cli_entry(AuthModule)
