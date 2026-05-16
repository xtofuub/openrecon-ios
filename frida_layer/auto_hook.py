"""Decide which hooks to load based on the target's framework signatures."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class HookDecision:
    hooks: list[str]
    reasons: dict[str, str]


_DEFAULT_HOOKS = (
    "ssl_pinning_bypass.js",
    "jailbreak_bypass.js",
    "url_session_tracer.js",
    "url_session_body_tracer.js",
    "ns_url_connection_tracer.js",
    "commoncrypto_tracer.js",
    "keychain_full_dump.js",
    "nshttpcookiestorage_tracer.js",
    "nsuserdefaults_tracer.js",
)


def decide_hooks(class_list: list[str]) -> HookDecision:
    hooks: list[str] = list(_DEFAULT_HOOKS)
    reasons: dict[str, str] = {h: "default" for h in hooks}
    classes = set(class_list)

    if any(c.startswith("WKWebView") or "WKWebView" in c for c in classes):
        hooks.append("wkwebview_js_tracer.js")
        reasons["wkwebview_js_tracer.js"] = "WKWebView present"
    if any("Pinning" in c or "CertValidator" in c for c in classes):
        reasons.setdefault("ssl_pinning_bypass.js", "explicit pinning class detected")
    if "LAContext" in classes:
        hooks.append("biometrics_tracer.js")
        reasons["biometrics_tracer.js"] = "LocalAuthentication present"
    if any(c.startswith("AF") for c in classes):
        reasons.setdefault("ssl_pinning_bypass.js", "AFNetworking present")

    seen: set[str] = set()
    deduped: list[str] = []
    for h in hooks:
        if h not in seen:
            seen.add(h)
            deduped.append(h)
    return HookDecision(hooks=deduped, reasons=reasons)


__all__ = ["decide_hooks", "HookDecision"]
