"""OWASP Mobile Top 10 (2024) → openrecon finding category mapping.

Used by the reporter to enrich Markdown output and the JSON report. Keeps the
mapping small and explicit — when a new category is added to a finding rule,
extend `CATEGORY_TO_OWASP` here too.

Reference: https://owasp.org/www-project-mobile-top-10/
"""

from __future__ import annotations

from typing import Final

# 2024 OWASP Mobile Top 10
M01 = ("M1", "Improper Credential Usage")
M02 = ("M2", "Inadequate Supply Chain Security")
M03 = ("M3", "Insecure Authentication/Authorization")
M04 = ("M4", "Insufficient Input/Output Validation")
M05 = ("M5", "Insecure Communication")
M06 = ("M6", "Inadequate Privacy Controls")
M07 = ("M7", "Insufficient Binary Protections")
M08 = ("M8", "Security Misconfiguration")
M09 = ("M9", "Insecure Data Storage")
M10 = ("M10", "Insufficient Cryptography")


CATEGORY_TO_OWASP: Final[dict[str, tuple[tuple[str, str], ...]]] = {
    "idor": (M03,),
    "auth-bypass": (M03, M01),
    "auth-mechanism": (M03,),
    "mass-assignment": (M03, M04),
    "api-tampering": (M04, M08),
    "graphql": (M03, M04),
    "token-weakness": (M01, M10),
    "client-side-signing": (M10, M07),
}


def owasp_for_category(category: str) -> list[tuple[str, str]]:
    """Return zero or more (Mx, title) tuples for a finding category."""
    return list(CATEGORY_TO_OWASP.get(category, ()))


def annotate_finding(finding: dict) -> dict:
    """Return a copy of `finding` with an `owasp` field added if known."""
    category = finding.get("category") or ""
    mapped = owasp_for_category(category)
    if not mapped:
        return finding
    out = dict(finding)
    out["owasp"] = [{"id": code, "title": title} for code, title in mapped]
    return out


__all__ = [
    "CATEGORY_TO_OWASP",
    "owasp_for_category",
    "annotate_finding",
]
