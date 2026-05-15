"""Mass assignment module — inject privileged fields, observe acceptance."""

from __future__ import annotations

import base64
import json
from collections.abc import Iterable
from typing import Any

from agent.schema import (
    Evidence,
    Finding,
    ModuleCoverage,
    ModuleResult,
    ReproStep,
    Severity,
)

from .base import ApiModule, ModuleInput, cli_entry


_HIDDEN_CANDIDATES = {
    "is_admin": True,
    "isAdmin": True,
    "role": "admin",
    "roles": ["admin"],
    "permissions": ["*"],
    "owner_id": "{user_b}",
    "tenant_id": "{user_b}",
    "email_verified": True,
    "is_verified": True,
    "verified": True,
    "_id": "{user_b}",
    "internal_flag": True,
    "audit_bypass": True,
}


class MassAssignmentModule(ApiModule):
    name = "mass_assignment"
    severity_baseline = Severity.CRITICAL

    async def run(self, inp: ModuleInput) -> ModuleResult:
        findings: list[Finding] = []
        coverage = ModuleCoverage(totals={"flows": 0, "candidates": 0})

        write_flows = []
        for flow_id in inp.baseline_flow_ids:
            flow = await _read_flow(inp, flow_id)
            if not flow:
                coverage.skipped.append((flow_id, "flow not found"))
                continue
            if flow["request"]["method"].upper() not in {"POST", "PUT", "PATCH"}:
                coverage.skipped.append((flow_id, "not a write flow"))
                continue
            if not _has_json_body(flow):
                coverage.skipped.append((flow_id, "non-JSON body"))
                continue
            write_flows.append(flow)

        visible_fields = _collect_visible_fields(inp)
        write_fields = _collect_write_fields(write_flows)
        candidate_keys = sorted((visible_fields - write_fields) | set(_HIDDEN_CANDIDATES))

        user_b_id = next(
            (s.identity_id for s in inp.session_pool.values() if s.label == "user_b" and s.identity_id),
            None,
        )

        for flow in write_flows:
            coverage.totals["flows"] += 1
            for key in candidate_keys:
                coverage.totals["candidates"] += 1
                value = _value_for(key, user_b_id)
                replay = await inp.mitm_mcp.replay_flow(
                    flow["flow_id"], overrides={"body_patch": {key: value}}
                )
                status = (replay.get("response") or {}).get("status", 0)
                if 200 <= status < 300:
                    findings.append(_finding(inp, flow, replay, key, value))
            coverage.tested.append(flow["flow_id"])

        return ModuleResult(module=self.name, findings=findings, coverage=coverage)


def _collect_visible_fields(inp: ModuleInput) -> set[str]:
    keys: set[str] = set()
    path = inp.run_dir / "mitm_flows.jsonl"
    if not path.exists():
        return keys
    with path.open(encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            r = json.loads(line)
            if r["request"]["method"].upper() != "GET":
                continue
            body = (r.get("response") or {}).get("body_b64")
            if not body:
                continue
            try:
                decoded = base64.b64decode(body).decode("utf-8", "ignore")
                data = json.loads(decoded)
            except Exception:
                continue
            keys |= _walk_keys(data)
    return keys


def _collect_write_fields(flows: Iterable[dict[str, Any]]) -> set[str]:
    out: set[str] = set()
    for flow in flows:
        body_b64 = flow["request"].get("body_b64")
        if not body_b64:
            continue
        try:
            decoded = base64.b64decode(body_b64).decode("utf-8", "ignore")
            data = json.loads(decoded)
        except Exception:
            continue
        out |= _walk_keys(data)
    return out


def _walk_keys(node: Any, out: set[str] | None = None) -> set[str]:
    out = out if out is not None else set()
    if isinstance(node, dict):
        for k, v in node.items():
            out.add(k)
            _walk_keys(v, out)
    elif isinstance(node, list):
        for item in node:
            _walk_keys(item, out)
    return out


def _has_json_body(flow: dict[str, Any]) -> bool:
    ct = ""
    for k, v in flow["request"]["headers"].items():
        if k.lower() == "content-type":
            ct = v.lower()
            break
    return "json" in ct


def _value_for(key: str, user_b_id: str | None) -> Any:
    if key in _HIDDEN_CANDIDATES:
        v = _HIDDEN_CANDIDATES[key]
        if isinstance(v, str) and "{user_b}" in v:
            return user_b_id or "00000000-0000-0000-0000-000000000000"
        return v
    return True


def _finding(
    inp: ModuleInput, flow: dict[str, Any], replay: dict[str, Any], key: str, value: Any
) -> Finding:
    return Finding(
        run_id=str(inp.run_dir.name),
        severity=Severity.CRITICAL,
        category="mass-assignment",
        title=f"Field `{key}` accepted on {flow['request']['method']} {flow['request']['url']}",
        summary=(
            f"Injected `{key}={value!r}` and the server returned "
            f"{replay.get('response', {}).get('status')}. Confirm via GET that the field persisted."
        ),
        evidence=[
            Evidence(kind="flow", ref=flow["flow_id"], note="baseline"),
            Evidence(
                kind="flow", ref=replay.get("flow_id", "?"), note=f"injected {key}={value!r}"
            ),
        ],
        correlated_flows=[flow["flow_id"], replay.get("flow_id", "?")],
        reproduction=[
            ReproStep(
                description="Replay write with injected field",
                primitive="replay_flow",
                args={"flow_id": flow["flow_id"], "overrides": {"body_patch": {key: value}}},
                expected="2xx and the field is reflected on subsequent GET",
            )
        ],
        tags=["mass-assignment", key],
        confidence=0.55,  # needs confirmation
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
    cli_entry(MassAssignmentModule)
