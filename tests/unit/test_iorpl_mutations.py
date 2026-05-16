"""iorpl built-in mutations — each produces the right shape."""

from __future__ import annotations

import base64
import json

from iorpl.mutations import (
    BUILTIN_MUTATIONS,
    VERDICT_AUTH_BYPASSED,
    VERDICT_NO_DIFF,
    MutationContext,
)


def _flow(url="https://api.example.com/v1/users/42", method="GET", headers=None, body=None):
    return {
        "flow_id": "baseline",
        "request": {
            "url": url,
            "method": method,
            "headers": headers or {"Authorization": "Bearer x"},
            "body_b64": base64.b64encode(body).decode() if body else None,
        },
        "response": {"status": 200, "headers": {}, "body_b64": None},
    }


def test_swap_user_id_yields_swap_per_pool_entry():
    flow = _flow()
    ctx = MutationContext(session_pool={"user_b": {"identity_id": "99"}})
    out = list(BUILTIN_MUTATIONS["swap_user_id"].apply(flow, ctx))
    assert any("99" in r.url for r in out)
    assert all(r.method == "GET" for r in out)


def test_swap_user_id_skips_when_session_pool_empty():
    out = list(BUILTIN_MUTATIONS["swap_user_id"].apply(_flow(), MutationContext()))
    assert out == []


def test_integer_overflow_id_replaces_numeric_path_segments():
    out = list(BUILTIN_MUTATIONS["integer_overflow_id"].apply(_flow(), MutationContext()))
    boundaries = {r.url.rsplit("/", 1)[-1] for r in out}
    assert "0" in boundaries
    assert "-1" in boundaries
    assert "2147483647" in boundaries


def test_strip_auth_removes_authorization_header():
    flow = _flow(headers={"Authorization": "Bearer x", "Cookie": "c=1", "User-Agent": "x"})
    out = list(BUILTIN_MUTATIONS["strip_auth"].apply(flow, MutationContext()))
    assert len(out) == 1
    assert "Authorization" not in out[0].headers
    assert "Cookie" not in out[0].headers
    assert out[0].headers.get("User-Agent") == "x"


def test_strip_auth_verdict_flags_auth_bypass_on_2xx():
    flow = _flow()
    mutated = {"status": 200, "headers": {}, "body_b64": None}
    mut = BUILTIN_MUTATIONS["strip_auth"]
    req = next(iter(mut.apply(flow, MutationContext())))
    verdict, evidence = mut.verdict(flow, mutated, req)
    assert verdict == VERDICT_AUTH_BYPASSED
    assert evidence


def test_jwt_alg_none_sets_none_alg_and_empty_signature():
    header = base64.urlsafe_b64encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode()).rstrip(b"=").decode()
    payload = base64.urlsafe_b64encode(json.dumps({"sub": "u"}).encode()).rstrip(b"=").decode()
    token = f"{header}.{payload}.signature"
    flow = _flow(headers={"Authorization": f"Bearer {token}"})
    out = list(BUILTIN_MUTATIONS["jwt_alg_none"].apply(flow, MutationContext()))
    assert len(out) == 1
    new_auth = out[0].headers["Authorization"]
    assert new_auth.endswith(".")
    new_token = new_auth.split(" ", 1)[1]
    new_header = json.loads(base64.urlsafe_b64decode(new_token.split(".")[0] + "==="))
    assert new_header["alg"] == "none"


def test_mass_assignment_injects_privileged_fields():
    body = json.dumps({"name": "alice"}).encode()
    flow = _flow(method="POST", body=body)
    out = list(BUILTIN_MUTATIONS["mass_assignment_inject_privileged_fields"].apply(flow, MutationContext()))
    assert len(out) == 1
    injected = json.loads(out[0].body.decode())
    assert injected["name"] == "alice"
    assert injected["is_admin"] is True
    assert injected["role"] == "admin"


def test_method_swap_only_runs_on_get():
    out_get = list(BUILTIN_MUTATIONS["method_swap"].apply(_flow(method="GET"), MutationContext()))
    out_post = list(BUILTIN_MUTATIONS["method_swap"].apply(_flow(method="POST"), MutationContext()))
    assert {r.method for r in out_get} >= {"DELETE", "PUT", "PATCH"}
    assert out_post == []


def test_path_extra_admin_segment_appends_known_probes():
    out = list(BUILTIN_MUTATIONS["path_extra_admin_segment"].apply(_flow(), MutationContext()))
    assert any(r.url.endswith("/admin") for r in out)
    assert any(r.url.endswith("/.env") for r in out)


def test_jwt_expired_replay_rewrites_exp_only_for_jwt():
    flow = _flow(headers={"Authorization": "Bearer not-a-jwt"})
    out = list(BUILTIN_MUTATIONS["jwt_expired_replay"].apply(flow, MutationContext()))
    assert out == []


def test_default_verdict_returns_no_diff_when_status_matches():
    mut = BUILTIN_MUTATIONS["method_swap"]
    baseline = _flow()
    mutated = {"status": 200, "headers": {}, "body_b64": None}
    req = next(iter(mut.apply(_flow(method="GET"), MutationContext())))
    verdict, _ = mut.verdict(baseline, mutated, req)
    assert verdict == VERDICT_NO_DIFF
