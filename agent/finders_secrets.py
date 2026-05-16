"""Finder rules over secret-store tracer events (keychain, cookies, defaults).

Each rule consumes a specific tracer's output and emits Findings when known
secret shapes (JWT, AWS keys, Stripe keys, high-entropy tokens, PII) appear
in storage that the app is reading or writing at runtime. Adding a rule here
turns a previously orphan tracer into an autonomy gain — the planner just
has to load the hook and findings appear automatically.

Patterns are intentionally conservative: each match must satisfy *both* a
shape regex (e.g. JWT three-part dot pattern) and a length / entropy floor,
to keep false-positive rates low on a 30-minute engagement.
"""

from __future__ import annotations

import math
import re
from collections.abc import Iterable
from typing import Any

from .query import RunQuery
from .schema import EngagementState, Evidence, Finding, Severity

# ── Pattern catalogue ──────────────────────────────────────────────────────


_JWT_RE = re.compile(r"eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}")
_AWS_AKID_RE = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
_AWS_SECRET_RE = re.compile(r"\b[A-Za-z0-9+/]{40}\b")  # weak; use with context
_STRIPE_RE = re.compile(r"\b(sk|pk|rk)_(live|test)_[0-9a-zA-Z]{20,}\b")
_GITHUB_PAT_RE = re.compile(r"\bghp_[A-Za-z0-9]{36}\b|\bgithub_pat_[A-Za-z0-9_]{82}\b")
_SLACK_RE = re.compile(r"\bxox[abprs]-[A-Za-z0-9\-]{10,}\b")
_GENERIC_API_KEY_RE = re.compile(r"\b[A-Za-z0-9_\-]{32,}\b")

_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")
_PHONE_RE = re.compile(r"\b\+?[0-9]{1,3}[\s\-]?\(?[0-9]{3}\)?[\s\-]?[0-9]{3}[\s\-]?[0-9]{4}\b")
_SSN_RE = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts: dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = float(len(s))
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _scan_secret(value: str) -> list[tuple[str, str]]:
    """Return list of (label, matched_substring). High-precision matches only."""
    if not isinstance(value, str) or len(value) < 16:
        return []
    hits: list[tuple[str, str]] = []
    for label, pattern in (
        ("jwt", _JWT_RE),
        ("aws_akid", _AWS_AKID_RE),
        ("stripe", _STRIPE_RE),
        ("github_pat", _GITHUB_PAT_RE),
        ("slack", _SLACK_RE),
    ):
        m = pattern.search(value)
        if m:
            hits.append((label, m.group(0)))
    return hits


def _scan_pii(value: str) -> list[tuple[str, str]]:
    if not isinstance(value, str):
        return []
    hits: list[tuple[str, str]] = []
    for label, pattern in (("email", _EMAIL_RE), ("phone", _PHONE_RE), ("ssn", _SSN_RE)):
        m = pattern.search(value)
        if m:
            hits.append((label, m.group(0)))
    return hits


def _redact(value: str, *, keep: int = 4) -> str:
    if not isinstance(value, str) or len(value) <= keep:
        return "***"
    return value[:keep] + "***" + str(len(value) - keep)


def _walk_strings(node: Any) -> Iterable[str]:
    """Yield every string leaf in a nested dict/list structure."""
    if isinstance(node, str):
        yield node
    elif isinstance(node, dict):
        for v in node.values():
            yield from _walk_strings(v)
    elif isinstance(node, list):
        for v in node:
            yield from _walk_strings(v)


# ── Rules ──────────────────────────────────────────────────────────────────


class KeychainSecretLeakRule:
    """Find recognizable secrets in keychain items the app touched."""

    name = "KeychainSecretLeak"

    def match(self, q: RunQuery, state: EngagementState) -> list[Finding]:
        findings: list[Finding] = []
        for ev in q.frida_events_by_hook("keychain_full_dump.js"):
            extra = ev.get("extra") or {}
            for value in _walk_strings(extra):
                for label, match in _scan_secret(value):
                    findings.append(
                        Finding(
                            run_id=state.run_id,
                            severity=Severity.HIGH,
                            category="secret-in-keychain",
                            title=f"Keychain item contains a {label.upper()} secret",
                            summary=(
                                f"Hook keychain_full_dump.js observed a value matching the {label} "
                                f"shape. Value preview: {_redact(match)}."
                            ),
                            evidence=[Evidence(kind="frida_event", ref=str(ev.get("event_id") or ""), note=f"{label} match")],
                            confidence=0.85,
                            tags=["keychain", "secret", label],
                        )
                    )
        return findings


class CookieSecurityRule:
    """Surface cookies that look sensitive but lack Secure / HttpOnly flags."""

    name = "CookieSecurity"

    SESSION_HINTS = ("session", "auth", "token", "sid", "jwt", "id", "csrf")

    def match(self, q: RunQuery, state: EngagementState) -> list[Finding]:
        findings: list[Finding] = []
        flagged: set[tuple[str, str]] = set()
        for ev in q.frida_events_by_hook("nshttpcookiestorage_tracer.js"):
            extra = ev.get("extra") or {}
            cookie = extra.get("cookie") or {}
            name = str(cookie.get("name") or "").lower()
            domain = str(cookie.get("domain") or "")
            if not name:
                continue
            looks_sensitive = any(h in name for h in self.SESSION_HINTS) or bool(
                _scan_secret(str(cookie.get("value") or ""))
            )
            is_secure = str(cookie.get("isSecure")) == "True" or cookie.get("isSecure") is True
            is_http_only = str(cookie.get("isHTTPOnly")) == "True" or cookie.get("isHTTPOnly") is True
            problems: list[str] = []
            if looks_sensitive and not is_secure:
                problems.append("missing Secure flag")
            if looks_sensitive and not is_http_only:
                problems.append("missing HttpOnly flag")
            if not problems:
                continue
            key = (name, domain)
            if key in flagged:
                continue
            flagged.add(key)
            findings.append(
                Finding(
                    run_id=state.run_id,
                    severity=Severity.MEDIUM,
                    category="cookie-security",
                    title=f"Cookie `{name}` on `{domain}` has weak flags",
                    summary=f"{', '.join(problems)}.",
                    evidence=[Evidence(kind="frida_event", ref=str(ev.get("event_id") or ""), note="cookie")],
                    confidence=0.7,
                    tags=["cookie", *problems],
                )
            )
        return findings


class UserDefaultsLeakRule:
    """Find secrets and PII stored in NSUserDefaults (plaintext on disk)."""

    name = "UserDefaultsLeak"

    def match(self, q: RunQuery, state: EngagementState) -> list[Finding]:
        findings: list[Finding] = []
        seen_secrets: set[tuple[str, str]] = set()
        seen_pii: set[tuple[str, str]] = set()
        for ev in q.frida_events_by_hook("nsuserdefaults_tracer.js"):
            extra = ev.get("extra") or {}
            entries = extra.get("entries") or {}
            single_key = str(extra.get("key") or "")
            single_value = extra.get("value")
            iter_pairs: list[tuple[str, Any]] = []
            if isinstance(entries, dict) and entries:
                iter_pairs.extend(entries.items())
            if single_key:
                iter_pairs.append((single_key, single_value))
            for key, value in iter_pairs:
                key_s = str(key)
                for s in _walk_strings(value):
                    for label, match in _scan_secret(s):
                        marker = (label, key_s)
                        if marker in seen_secrets:
                            continue
                        seen_secrets.add(marker)
                        findings.append(
                            Finding(
                                run_id=state.run_id,
                                severity=Severity.HIGH,
                                category="secret-in-userdefaults",
                                title=f"NSUserDefaults key `{key_s}` holds a {label.upper()} secret",
                                summary=(
                                    "NSUserDefaults is plaintext on disk — secrets here are recoverable "
                                    f"by any backup. Value preview: {_redact(match)}."
                                ),
                                evidence=[Evidence(kind="frida_event", ref=str(ev.get("event_id") or ""), note=label)],
                                confidence=0.9,
                                tags=["userdefaults", "secret", label],
                            )
                        )
                    for label, match in _scan_pii(s):
                        marker = (label, key_s)
                        if marker in seen_pii:
                            continue
                        seen_pii.add(marker)
                        # Higher entropy / longer string is more likely a real secret leak.
                        ent = _shannon_entropy(match)
                        sev = Severity.MEDIUM if ent > 3.0 else Severity.LOW
                        findings.append(
                            Finding(
                                run_id=state.run_id,
                                severity=sev,
                                category="pii-in-userdefaults",
                                title=f"NSUserDefaults key `{key_s}` holds {label.upper()}",
                                summary=(
                                    f"Plaintext PII observed. Value preview: {_redact(match)}."
                                ),
                                evidence=[Evidence(kind="frida_event", ref=str(ev.get("event_id") or ""), note=label)],
                                confidence=0.7,
                                tags=["userdefaults", "pii", label],
                            )
                        )
        return findings


class StaticBinarySecretsRule:
    """If a decrypted binary dump is available, scan its strings for secrets."""

    name = "StaticBinarySecrets"

    def match(self, q: RunQuery, state: EngagementState) -> list[Finding]:
        path_str = (state.target.binary_path or "").strip()
        if not path_str:
            return []
        from pathlib import Path

        binary = Path(path_str)
        if not binary.is_absolute():
            binary = q.run_dir / binary
        if not binary.exists():
            return []
        try:
            from api.static import find_hardcoded_urls, find_high_entropy_secrets, open_binary
        except Exception:
            return []
        sess = open_binary(binary)
        if sess is None:
            return []
        findings: list[Finding] = []
        secrets = find_high_entropy_secrets(sess)
        for label, hits in secrets.items():
            for hit in hits[:5]:
                findings.append(
                    Finding(
                        run_id=state.run_id,
                        severity=Severity.HIGH,
                        category="hardcoded-secret",
                        title=f"Hard-coded {label.upper()} secret in binary",
                        summary=(
                            "Static scan of the decrypted Mach-O found a string matching the "
                            f"{label} shape. Value preview: {_redact(hit)}."
                        ),
                        evidence=[Evidence(kind="artifact", ref="artifacts/app.macho", note=label)],
                        confidence=0.8,
                        tags=["static", "secret", label],
                    )
                )
        urls = find_hardcoded_urls(sess)
        if urls:
            findings.append(
                Finding(
                    run_id=state.run_id,
                    severity=Severity.INFO,
                    category="hardcoded-endpoints",
                    title=f"{len(urls)} hard-coded URLs in binary",
                    summary=(
                        "URLs literal in the binary often reveal staging hosts, debug endpoints, "
                        "or third-party services worth probing."
                    ),
                    evidence=[Evidence(kind="artifact", ref="artifacts/app.macho", note=u) for u in urls[:6]],
                    confidence=0.6,
                    tags=["static", "url", "recon"],
                )
            )
        return findings


__all__ = [
    "KeychainSecretLeakRule",
    "CookieSecurityRule",
    "UserDefaultsLeakRule",
    "StaticBinarySecretsRule",
]
