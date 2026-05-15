"""Finding generator — pattern rules over correlations and module output.

Each rule is a small class with `match(query, state) -> list[Finding]`. They
compose: a single observation can trigger multiple rules. Findings are
deduplicated by `(category, correlated_flows_sorted)`.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Protocol

from .query import RunQuery
from .schema import (
    EngagementState,
    Evidence,
    Finding,
    ReproStep,
    Severity,
)


class FindingRule(Protocol):
    name: str

    def match(self, q: RunQuery, state: EngagementState) -> list[Finding]: ...


class AuthHeaderInferenceRule:
    """Find headers that appear on all auth'd flows and 401/403 when absent."""

    name = "AuthHeaderInference"

    def match(self, q: RunQuery, state: EngagementState) -> list[Finding]:
        findings: list[Finding] = []
        candidates = ("authorization", "x-api-key", "x-auth-token", "x-session-token")
        flows = list(q.flows())
        if not flows:
            return findings
        for header in candidates:
            with_header = [
                f for f in flows if header in {k.lower() for k in f["request"]["headers"]}
            ]
            without = [
                f for f in flows if header not in {k.lower() for k in f["request"]["headers"]}
            ]
            if not with_header or not without:
                continue
            unauth_in_without = [
                f for f in without if f.get("response", {}).get("status") in (401, 403)
            ]
            if not unauth_in_without:
                continue
            ratio = len(with_header) / max(1, len(flows))
            if ratio < 0.5:
                continue
            evidence = [
                Evidence(kind="flow", ref=f["flow_id"], note="auth'd")
                for f in with_header[:3]
            ] + [
                Evidence(kind="flow", ref=f["flow_id"], note="401/403 without header")
                for f in unauth_in_without[:3]
            ]
            findings.append(
                Finding(
                    run_id=state.run_id,
                    severity=Severity.INFO,
                    category="auth-mechanism",
                    title=f"Header `{header}` appears to be the auth token",
                    summary=(
                        f"Observed on {len(with_header)}/{len(flows)} flows. "
                        f"{len(unauth_in_without)} flows without the header returned 401/403."
                    ),
                    evidence=evidence,
                    confidence=min(0.95, 0.6 + ratio * 0.4),
                )
            )
        return findings


class HookedCryptoAsSignatureRule:
    """If CommonCrypto HMAC output appears as a request header value, infer signing."""

    name = "HookedCryptoAsSignature"

    def match(self, q: RunQuery, state: EngagementState) -> list[Finding]:
        findings: list[Finding] = []
        crypto_events = q.frida_events_by_method("CCHmac", "+[CCHmac hmac]")  # placeholder
        if not crypto_events:
            return findings
        candidate_headers = ("x-signature", "x-sign", "x-sig", "x-hmac")
        flows = list(q.flows())
        for ev in crypto_events:
            ret = (ev.get("ret") or {}).get("preview") or ""
            if not ret:
                continue
            for flow in flows:
                for k, v in flow["request"]["headers"].items():
                    if k.lower() in candidate_headers and ret in v:
                        findings.append(
                            Finding(
                                run_id=state.run_id,
                                severity=Severity.INFO,
                                category="client-side-signing",
                                title=f"Header `{k}` derives from CommonCrypto output",
                                summary="Re-implementing this signature enables offline replay.",
                                evidence=[
                                    Evidence(kind="frida_event", ref=ev["event_id"]),
                                    Evidence(kind="flow", ref=flow["flow_id"]),
                                ],
                                reproduction=[
                                    ReproStep(
                                        description="Replay the flow",
                                        primitive="replay_flow",
                                        args={"flow_id": flow["flow_id"]},
                                    )
                                ],
                                confidence=0.7,
                            )
                        )
                        break
        return findings


class CrossTenantLeakRule:
    """Flag findings emitted by api/idor that contain a known user_b identifier."""

    name = "CrossTenantLeak"

    def match(self, q: RunQuery, state: EngagementState) -> list[Finding]:
        out: list[Finding] = []
        user_b = state.sessions.get("user_b")
        if not user_b or not user_b.identity_id:
            return out
        idor_findings = q.findings(category="idor")
        for f in idor_findings:
            evidence_text = " ".join([e.get("note") or "" for e in f.get("evidence", [])])
            if user_b.identity_id in evidence_text:
                f["severity"] = Severity.CRITICAL.value
                out.append(Finding.model_validate(f))
        return out


DEFAULT_RULES: tuple[FindingRule, ...] = (
    AuthHeaderInferenceRule(),
    HookedCryptoAsSignatureRule(),
    CrossTenantLeakRule(),
)


def run_all(q: RunQuery, state: EngagementState, rules: Iterable[FindingRule] | None = None) -> list[Finding]:
    rules = list(rules) if rules is not None else list(DEFAULT_RULES)
    seen: set[tuple[str, tuple[str, ...]]] = set()
    out: list[Finding] = []
    for rule in rules:
        for finding in rule.match(q, state):
            key = (finding.category, tuple(sorted(finding.correlated_flows)))
            if key in seen:
                continue
            seen.add(key)
            out.append(finding)
    return out


__all__ = ["FindingRule", "run_all", "DEFAULT_RULES"]
