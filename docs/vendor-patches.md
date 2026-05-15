# Vendor Patches

We track every divergence from upstream here. Carry these forward on every `git subtree pull`.

## `mitm/vendor` ← `snapspecter/mitmproxy-mcp`

### Active patches

| Patch | Location | Description |
|---|---|---|
| Path-traversal guard on `load_traffic_file` | `src/mitmproxy_mcp/core/server.py:390` | Adds an env-gated check: if `MITMPROXY_MCP_ALLOWED_ROOT` or `LOLMCP_RUN_DIR` is set, `file_path` is resolved and must live under that root. Without the env var, behavior is identical to upstream — additive, no breaking change. Mirrors the client-side guard `mitm/client.py` enforces. |

### Known gaps to evaluate

| Issue | Location | Status | Action |
|---|---|---|---|
| iOS-specific CA installation | none | upstream doesn't help | Add `ios_install_ca` tool in `mitm/addons/` (planned, Phase 3) |
| WiFi proxy config push | none | upstream doesn't help | Add `ios_set_wifi_proxy` tool via libimobiledevice (planned) |

### Re-syncing upstream

```bash
git subtree pull --prefix=mitm/vendor https://github.com/snapspecter/mitmproxy-mcp main --squash
```

After pull:
1. Re-read each entry in **Active patches** above and ensure it still applies.
2. Run `pytest mitm/vendor/tests` and our `tests/test_mitm_integration.py`.
3. If a patch failed to merge, rebuild it manually and update the line numbers here.

---

## `skills/_upstream/anthropic-cybersecurity-skills` ← `mukul975/Anthropic-Cybersecurity-Skills`

### Active patches

_None — the upstream is read-only knowledge. We never modify it in place._

### How we extend it

Local extensions live in `skills/<wrapper>/SKILL.md` and reference the upstream files by relative path. If upstream renames `references/workflows.md`, update the wrapper SKILL.md, don't edit the upstream copy.

### Re-syncing upstream

```bash
git subtree pull --prefix=skills/_upstream/anthropic-cybersecurity-skills \
    https://github.com/mukul975/Anthropic-Cybersecurity-Skills main --squash
```

After pull:
1. Re-read `skills/reverse-engineering-ios-app-with-frida/SKILL.md` and `skills/analyzing-ios-app-security-with-objection/SKILL.md` to confirm referenced paths still resolve.
2. Run `openrecon doctor` — it includes a vendored-skill presence check.
