"""IDOR module — mutate ID-bearing positions, replay, diff.

Horizontal: try other tenants' identifiers.
Vertical: try predictable variants (numeric ±1, base64-y decoded swap).
Negative-control: ensure non-IDOR replays still return 403/404.
"""

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

from .base import (
    ApiModule,
    ModuleInput,
    cli_entry,
    identify_id_positions,
    response_diff,
)

_INTERESTING_RESPONSE_KEYS = (
    "email",
    "username",
    "user_id",
    "id",
    "token",
    "balance",
    "ssn",
    "phone",
    "address",
)


class IdorModule(ApiModule):
    name = "idor"
    severity_baseline = Severity.HIGH

    async def run(self, inp: ModuleInput) -> ModuleResult:
        findings: list[Finding] = []
        hypotheses: list[Hypothesis] = []
        coverage = ModuleCoverage(totals={"flows": 0, "positions": 0, "mutations": 0})

        for flow_id in inp.baseline_flow_ids:
            flow = await _get_flow(inp, flow_id)
            if not flow:
                coverage.skipped.append((flow_id, "flow not found"))
                continue
            coverage.totals["flows"] += 1
            positions = identify_id_positions(flow)
            coverage.totals["positions"] += len(positions)

            for pos in positions:
                for mutation in _mutations_for(pos, inp.session_pool):
                    coverage.totals["mutations"] += 1
                    replay = await inp.mitm_mcp.replay_flow(
                        flow_id, overrides=_overrides_for(pos, mutation, flow)
                    )
                    diff = response_diff(flow, replay)
                    severity = _classify(replay, diff)
                    if severity is None:
                        continue
                    if severity == Severity.LOW:
                        # Ambiguous: 2xx with weak signal. Open a hypothesis
                        # for EXPLOIT-phase re-test instead of a noisy finding.
                        hypotheses.append(
                            Hypothesis(
                                claim=(
                                    f"Endpoint {flow['request']['method']} "
                                    f"{flow['request']['url']} may leak data via "
                                    f"{pos['kind']}={pos.get('key', pos.get('index'))} "
                                    "but evidence is weak — re-test with adjacent IDs"
                                ),
                                status="open",
                                tests=[f"replay_with_body_mutation:{flow_id}"],
                                evidence=[
                                    Evidence(kind="flow", ref=flow_id, note="ambiguous IDOR baseline"),
                                    Evidence(kind="flow", ref=replay.get("flow_id", "?"), note="ambiguous IDOR replay"),
                                ],
                            )
                        )
                        continue
                    findings.append(
                        _make_finding(
                            inp,
                            flow,
                            replay,
                            pos,
                            mutation,
                            diff,
                            severity,
                        )
                    )
            coverage.tested.append(flow_id)

        return ModuleResult(
            module=self.name,
            findings=findings,
            hypotheses=hypotheses,
            coverage=coverage,
        )


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _mutations_for(pos: dict[str, Any], session_pool: dict[str, Any]) -> list[Any]:
    value = pos["value"]
    t = pos["type"]
    mutations: list[Any] = []
    if t == "numeric":
        try:
            n = int(value)
            mutations.extend([str(n + 1), str(n - 1), str(n + 10), "1", "0", str(2**31 - 1)])
        except ValueError:
            pass
    elif t == "uuid":
        mutations.append("00000000-0000-0000-0000-000000000000")
        for cred in session_pool.values():
            if getattr(cred, "identity_id", None):
                mutations.append(cred.identity_id)
    else:
        for cred in session_pool.values():
            if getattr(cred, "identity_id", None):
                mutations.append(cred.identity_id)
    # Deduplicate, keep order.
    seen: set[str] = set()
    out: list[Any] = []
    for m in mutations:
        if m and m != value and m not in seen:
            seen.add(m)
            out.append(m)
    return out


def _overrides_for(pos: dict[str, Any], mutation: Any, flow: dict[str, Any]) -> dict[str, Any]:
    if pos["kind"] == "path":
        from urllib.parse import urlparse

        parsed = urlparse(flow["request"]["url"])
        segs = parsed.path.split("/")
        segs[pos["index"]] = str(mutation)
        new_path = "/".join(segs)
        new_url = f"{parsed.scheme}://{parsed.netloc}{new_path}"
        if parsed.query:
            new_url += f"?{parsed.query}"
        return {"url": new_url}
    if pos["kind"] == "query":
        return {"query": {pos["key"]: str(mutation)}}
    if pos["kind"] == "body":
        return {"body_patch": {pos["key"]: mutation}}
    return {}


def _classify(replay: dict[str, Any], diff: dict[str, Any]) -> Severity | None:
    status = (replay.get("response") or {}).get("status", 0)
    if status in (401, 403, 404):
        return None  # negative control passed
    if status >= 500:
        return Severity.LOW  # server error often interesting but not a clear IDOR
    if 200 <= status < 300:
        body = (replay.get("response") or {}).get("body_b64") or ""
        if not body:
            return Severity.LOW
        try:
            import base64

            decoded = base64.b64decode(body).decode("utf-8", "ignore").lower()
        except Exception:
            decoded = ""
        leak_keys = sum(1 for k in _INTERESTING_RESPONSE_KEYS if k in decoded)
        if leak_keys >= 2:
            return Severity.HIGH
        if leak_keys >= 1 or diff.get("body_size_mutated", 0) > 0:
            return Severity.MEDIUM
        return Severity.LOW
    return None


def _make_finding(
    inp: ModuleInput,
    flow: dict[str, Any],
    replay: dict[str, Any],
    pos: dict[str, Any],
    mutation: Any,
    diff: dict[str, Any],
    severity: Severity,
) -> Finding:
    return Finding(
        run_id=str(inp.run_dir.name),
        severity=severity,
        category="idor",
        title=f"Possible IDOR on {pos['kind']}:{pos.get('key', pos.get('index'))}",
        summary=(
            f"Mutated {pos['kind']} from {pos['value']!r} to {mutation!r} on "
            f"{flow['request']['method']} {flow['request']['url']} — "
            f"response status {replay.get('response', {}).get('status')}"
        ),
        evidence=[
            Evidence(kind="flow", ref=flow["flow_id"], note="baseline"),
            Evidence(
                kind="flow", ref=replay.get("flow_id", "?"), note="mutated response"
            ),
        ],
        correlated_flows=[flow["flow_id"], replay.get("flow_id", "?")],
        reproduction=[
            ReproStep(
                description="Replay the baseline with mutation",
                primitive="replay_flow",
                args={"flow_id": flow["flow_id"], "overrides": _overrides_for(pos, mutation, flow)},
                expected="2xx with another user's data",
            )
        ],
        tags=["idor", pos["type"]],
        confidence=0.7 if severity == Severity.HIGH else 0.5,
    )


async def _get_flow(inp: ModuleInput, flow_id: str) -> dict[str, Any] | None:
    path = inp.run_dir / "mitm_flows.jsonl"
    if not path.exists():
        return None
    with path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            record = json.loads(line)
            if record["flow_id"] == flow_id:
                return record
    return None


if __name__ == "__main__":  # pragma: no cover
    cli_entry(IdorModule)
