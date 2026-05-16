"""Secret-store finder rules — keychain / cookies / userdefaults."""

from __future__ import annotations

import json

from agent.finders_secrets import (
    CookieSecurityRule,
    KeychainSecretLeakRule,
    UserDefaultsLeakRule,
)
from agent.query import RunQuery
from agent.schema import EngagementState, TargetMeta


def _state() -> EngagementState:
    return EngagementState(run_id="r1", target=TargetMeta(bundle_id="com.example"))


def _seed_frida(run_dir, event):
    path = run_dir / "frida_events.jsonl"
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(event) + "\n")


def test_keychain_jwt_detected(run_dir):
    jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NSJ9.signature_part_123"
    _seed_frida(
        run_dir,
        {
            "event_id": "e1",
            "ts": 1.0,
            "pid": 1,
            "cls": "Keychain",
            "method": "dump",
            "hook_source": "keychain_full_dump.js",
            "extra": {"service": "app", "account": "u", "value": jwt},
        },
    )
    findings = KeychainSecretLeakRule().match(RunQuery(run_dir), _state())
    assert any("JWT" in f.title for f in findings)
    assert all(f.severity.value == "high" for f in findings)


def test_cookie_missing_secure_flag_flagged(run_dir):
    _seed_frida(
        run_dir,
        {
            "event_id": "e1",
            "ts": 1.0,
            "pid": 1,
            "cls": "NSHTTPCookieStorage",
            "method": "dump",
            "hook_source": "nshttpcookiestorage_tracer.js",
            "extra": {
                "op": "dump",
                "cookie": {
                    "name": "sessionId",
                    "value": "abc123",
                    "domain": "api.example.com",
                    "isSecure": False,
                    "isHTTPOnly": True,
                },
            },
        },
    )
    findings = CookieSecurityRule().match(RunQuery(run_dir), _state())
    assert findings
    assert "Secure" in findings[0].summary


def test_userdefaults_aws_key_detected(run_dir):
    _seed_frida(
        run_dir,
        {
            "event_id": "e1",
            "ts": 1.0,
            "pid": 1,
            "cls": "NSUserDefaults",
            "method": "dump",
            "hook_source": "nsuserdefaults_tracer.js",
            "extra": {
                "op": "dump",
                "entries": {"aws_credentials": "AKIAIOSFODNN7EXAMPLE"},
            },
        },
    )
    findings = UserDefaultsLeakRule().match(RunQuery(run_dir), _state())
    assert any("AWS_AKID" in f.title for f in findings)


def test_userdefaults_pii_email_detected(run_dir):
    _seed_frida(
        run_dir,
        {
            "event_id": "e1",
            "ts": 1.0,
            "pid": 1,
            "cls": "NSUserDefaults",
            "method": "dump",
            "hook_source": "nsuserdefaults_tracer.js",
            "extra": {"op": "dump", "entries": {"user_email": "alice@example.com"}},
        },
    )
    findings = UserDefaultsLeakRule().match(RunQuery(run_dir), _state())
    assert any("EMAIL" in f.title for f in findings)
