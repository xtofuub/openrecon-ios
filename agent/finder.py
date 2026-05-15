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


class EndpointWithoutAuthRule:
    """Surface endpoints that *only* ever return 2xx without any auth header."""

    name = "EndpointWithoutAuth"

    def match(self, q: RunQuery, state: EngagementState) -> list[Finding]:
        from .endpoint_map import group_flows

        findings: list[Finding] = []
        flows = list(q.flows())
        if not flows:
            return findings
        groups = group_flows(flows)
        for group in groups:
            if group.auth_headers_seen:
                continue  # at least one flow had auth — skip
            if not any(200 <= s < 300 for s in group.status_counts):
                continue
            if group.host.endswith(".apple.com") or "captive" in group.path_template:
                continue
            findings.append(
                Finding(
                    run_id=state.run_id,
                    severity=Severity.LOW,
                    category="auth-mechanism",
                    title=(
                        f"Endpoint serves 2xx without any observed auth header — "
                        f"{group.method} {group.host}{group.path_template}"
                    ),
                    summary=(
                        f"{sum(group.status_counts.values())} flows observed; "
                        f"no Authorization / Cookie / API-Key headers on any of them."
                    ),
                    evidence=[Evidence(kind="flow", ref=fid) for fid in group.flow_ids[:3]],
                    correlated_flows=group.flow_ids[:3],
                    confidence=0.5,
                    tags=["endpoint", "no-auth"],
                )
            )
        return findings


class ClientSideValidationBypassRule:
    """If a flow with a 4xx baseline produces a 2xx after replay, that's suspicious.

    Heuristic: scan the captured flows for replay artifacts. The replay marker is
    a `tags` entry containing 'replayed' (set by api/ modules when emitting test
    traffic). When we see a 2xx replay for a 4xx baseline at the same endpoint,
    record an informational finding.
    """

    name = "ClientSideValidationBypass"

    def match(self, q: RunQuery, state: EngagementState) -> list[Finding]:
        findings: list[Finding] = []
        flows = list(q.flows())
        baseline_by_endpoint: dict[tuple[str, str, str], list[dict]] = {}
        replays_by_endpoint: dict[tuple[str, str, str], list[dict]] = {}
        from urllib.parse import urlparse

        from .endpoint_map import template_path

        for flow in flows:
            req = flow.get("request") or {}
            u = urlparse(req.get("url", ""))
            key = (u.hostname or "", (req.get("method") or "").upper(), template_path(u.path or "/"))
            tags = flow.get("tags") or []
            if "replayed" in tags:
                replays_by_endpoint.setdefault(key, []).append(flow)
            else:
                baseline_by_endpoint.setdefault(key, []).append(flow)

        for key, baselines in baseline_by_endpoint.items():
            if all((b.get("response") or {}).get("status", 0) < 400 for b in baselines):
                continue
            replays = replays_by_endpoint.get(key, [])
            successful_replays = [r for r in replays if 200 <= (r.get("response") or {}).get("status", 0) < 300]
            if not successful_replays:
                continue
            host, method, template = key
            findings.append(
                Finding(
                    run_id=state.run_id,
                    severity=Severity.MEDIUM,
                    category="client-side-validation-bypass",
                    title=f"4xx baseline → 2xx replay on {method} {host}{template}",
                    summary=(
                        f"{len(baselines)} baseline 4xx flow(s) and "
                        f"{len(successful_replays)} successful replay(s) at the same endpoint. "
                        "Server may accept what the client previously refused — potential validation bypass."
                    ),
                    evidence=[
                        *[Evidence(kind="flow", ref=b["flow_id"], note="baseline 4xx") for b in baselines[:2]],
                        *[Evidence(kind="flow", ref=r["flow_id"], note="replay 2xx") for r in successful_replays[:2]],
                    ],
                    correlated_flows=[b["flow_id"] for b in baselines[:2]] + [r["flow_id"] for r in successful_replays[:2]],
                    confidence=0.6,
                    tags=["bypass", "client-validation"],
                )
            )
        return findings


DEFAULT_RULES: tuple[FindingRule, ...] = (
    AuthHeaderInferenceRule(),
    HookedCryptoAsSignatureRule(),
    CrossTenantLeakRule(),
    EndpointWithoutAuthRule(),
    ClientSideValidationBypassRule(),
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
