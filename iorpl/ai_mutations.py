"""LLM-driven creative mutations.

The built-in mutation library in ``iorpl.mutations`` is deterministic — it
catches the bounty-shaped *classes* (IDOR swap, JWT alg=none, mass-assignment,
verb tampering). Logic / business-rule bugs need creativity: a coupon
endpoint that should never accept negative amounts, a state-machine API
that shouldn't accept "paid" without payment, an org_id that shouldn't be
modifiable mid-update.

``LLMCreativeMutation`` asks Claude to propose context-specific attacks
given the recorded baseline request. The model returns a JSON list of
``{url, method, headers, body, rationale}`` candidates which we materialize
as ``MutatedRequest`` instances. The standard verdict logic applies — a
200 with leak markers is still a finding, regardless of who proposed the
mutation.

Cost model: one API call per (flow, mutation invocation). Suites typically
opt-in via ``mutations: [llm_creative]`` so the deterministic mutations
remain free.

Requires ``ANTHROPIC_API_KEY`` in the environment. Falls back to an empty
mutation list (and logs a warning) when the SDK / key is missing so suites
don't crash in CI.
"""

from __future__ import annotations

import base64
import json
import logging
import os
from collections.abc import Iterable
from typing import Any

from .mutations import (
    BUILTIN_MUTATIONS,
    MutatedRequest,
    Mutation,
    MutationContext,
    register,
)

log = logging.getLogger(__name__)

# Number of candidates we ask the model for per flow. Higher = more coverage
# + more cost. 6 is enough to surface 1-2 winning ideas for a typical API.
_DEFAULT_N_CANDIDATES = 6

# Cap on baseline body size sent to the model — large blobs waste tokens.
_BODY_TOKEN_CAP_BYTES = 8 * 1024

_SYSTEM_PROMPT = """You are an iOS security researcher. Given a recorded HTTP
request from an iOS app's API client, propose creative business-logic and
authorization-bypass attacks SPECIFIC to this endpoint's likely semantics.

Focus on bugs a deterministic fuzzer would MISS:
- Business-rule violations (negative prices, zero-amount transfers, payments
  marked complete without a real payment flow, free tier accessing paid
  features, expired-coupon reuse, gift-card double-spend).
- State-machine confusion (calling a "finalize" step without the prior step,
  cancelling someone else's in-flight order, transitioning out of order).
- Cross-tenant data writes (changing owner_id, org_id, parent resource on
  PUT/PATCH to claim someone else's records).
- Role / permission array manipulation (adding 'admin' to a permissions
  array, swapping role_id, escalating user_type).
- Hidden parameter discovery (admin-only query params, debug=1, dry_run=0,
  ignore_validation=true).
- Identifier shape confusion (string where int expected, array where scalar
  expected, JSON nested object that bypasses scalar checks).

Output STRICT JSON: an array of candidate mutations. Each candidate is an
object with exactly these keys:
  - url       (string, full URL)
  - method    (string, HTTP verb)
  - headers   (object, full header set including any unchanged from baseline)
  - body      (string or null; null for GET, JSON-encoded string for POST/PUT)
  - rationale (string, one sentence: what bug this targets and why)

Hard rules:
- Output ONLY the JSON array. No prose, no markdown fences, no explanation.
- Keep auth headers IDENTICAL to the baseline so we test the endpoint, not
  the credentials.
- Never propose mutations against third-party SDK hosts (sentry.io, intercom,
  revenuecat, posthog, fb.com, expo.dev) — only the app's own backend.
- Return at most {n} candidates.
"""


class LLMCreativeMutation(Mutation):
    name = "llm_creative"
    description = (
        "Ask Claude to propose context-specific business-logic and auth-bypass "
        "attacks for each baseline request. Needs ANTHROPIC_API_KEY."
    )

    def __init__(
        self,
        *,
        model: str = "claude-opus-4-7",
        max_candidates: int = _DEFAULT_N_CANDIDATES,
        max_tokens: int = 2048,
    ) -> None:
        self.model = model
        self.max_candidates = max_candidates
        self.max_tokens = max_tokens

    def apply(self, flow: dict[str, Any], ctx: MutationContext) -> Iterable[MutatedRequest]:
        try:
            from anthropic import Anthropic
        except ImportError:  # pragma: no cover - env dependent
            log.warning("llm_creative.anthropic_sdk_missing")
            return []
        api_key = os.environ.get("ANTHROPIC_API_KEY")
        if not api_key:
            log.warning("llm_creative.no_api_key")
            return []

        request = flow.get("request") or {}
        baseline_payload = _baseline_summary(flow)
        if not baseline_payload:
            return []

        client = Anthropic(api_key=api_key)
        try:
            response = client.messages.create(
                model=self.model,
                max_tokens=self.max_tokens,
                system=_SYSTEM_PROMPT.format(n=self.max_candidates),
                messages=[
                    {
                        "role": "user",
                        "content": "Baseline request:\n" + json.dumps(baseline_payload, indent=2),
                    }
                ],
            )
        except Exception as exc:
            log.warning("llm_creative.api_call_failed error=%s", exc)
            return []

        text = _first_text_block(response)
        candidates = _parse_candidates(text)
        out: list[MutatedRequest] = []
        for cand in candidates[: self.max_candidates]:
            try:
                out.append(_candidate_to_request(cand, fallback=request))
            except Exception as exc:
                log.warning("llm_creative.candidate_skipped error=%s", exc)
                continue
        return out


# ── helpers ────────────────────────────────────────────────────────────────


def _baseline_summary(flow: dict[str, Any]) -> dict[str, Any] | None:
    """Minimum payload sent to the model: url, method, headers, body preview."""
    request = flow.get("request") or {}
    url = request.get("url")
    if not isinstance(url, str) or not url:
        return None
    body_text: str | None = None
    body_b64 = request.get("body_b64")
    if isinstance(body_b64, str) and body_b64:
        try:
            raw = base64.b64decode(body_b64)
            if len(raw) <= _BODY_TOKEN_CAP_BYTES:
                body_text = raw.decode("utf-8", "replace")
        except Exception:
            body_text = None

    response = flow.get("response") or {}
    response_summary: dict[str, Any] = {"status": response.get("status", 0)}
    response_b64 = response.get("body_b64")
    if isinstance(response_b64, str) and response_b64:
        try:
            raw = base64.b64decode(response_b64)
            if len(raw) <= _BODY_TOKEN_CAP_BYTES:
                response_summary["body"] = raw.decode("utf-8", "replace")
        except Exception:
            pass

    return {
        "url": url,
        "method": request.get("method", "GET"),
        "headers": request.get("headers") or {},
        "body": body_text,
        "baseline_response": response_summary,
    }


def _first_text_block(response: Any) -> str:
    try:
        for block in response.content:
            if getattr(block, "type", "") == "text":
                return str(block.text)
    except Exception:
        return ""
    return ""


def _parse_candidates(text: str) -> list[dict[str, Any]]:
    """Extract the JSON array from the model's reply, tolerating stray prose."""
    text = text.strip()
    if not text:
        return []
    start = text.find("[")
    end = text.rfind("]")
    if start == -1 or end == -1 or end <= start:
        return []
    snippet = text[start : end + 1]
    try:
        data = json.loads(snippet)
    except json.JSONDecodeError:
        return []
    if not isinstance(data, list):
        return []
    return [c for c in data if isinstance(c, dict)]


def _candidate_to_request(cand: dict[str, Any], *, fallback: dict[str, Any]) -> MutatedRequest:
    url = str(cand.get("url") or fallback.get("url") or "")
    method = str(cand.get("method") or fallback.get("method") or "GET").upper()
    headers = cand.get("headers")
    if not isinstance(headers, dict):
        headers = dict(fallback.get("headers") or {})
    headers = {str(k): str(v) for k, v in headers.items()}
    body_obj = cand.get("body")
    body: bytes | None = None
    if isinstance(body_obj, str) and body_obj:
        body = body_obj.encode("utf-8")
    elif isinstance(body_obj, (dict, list)):
        body = json.dumps(body_obj).encode("utf-8")
    rationale = str(cand.get("rationale") or "(no rationale provided)")
    return MutatedRequest(
        url=url,
        method=method,
        headers=headers,
        body=body,
        note=f"LLM-creative: {rationale}",
    )


# Single shared instance is fine — the class is stateless aside from the
# constructor args, and we register lazily so deterministic suites work
# without the anthropic SDK installed.

if "llm_creative" not in BUILTIN_MUTATIONS:
    register(LLMCreativeMutation())


__all__ = ["LLMCreativeMutation"]
