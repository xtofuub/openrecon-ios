# iorpl — Playwright for iOS bug bounty

[![CI](https://github.com/xtofuub/openrecon-ios/actions/workflows/ci.yml/badge.svg)](https://github.com/xtofuub/openrecon-ios/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.12%E2%80%933.13-blue)
![License: MIT](https://img.shields.io/badge/license-MIT-green)
![Tests](https://img.shields.io/badge/tests-192%20passing-brightgreen)

**Record one iOS app session. Replay it against a library of bug-bounty-shaped mutations. Get a HackerOne report.**

iorpl turns the manual loop (open Burp → intercept → copy to Repeater → mutate one field → eyeball response → repeat) into one deterministic pass — and an AI-driven creative pass on top.

> Use only against targets you own or are explicitly authorized to test.

---

## What it does

| Step | Command | Output |
|---|---|---|
| **1. Record** an interaction with an iOS app | `iorpl record --target com.example.app -o session.iorpl` | `.iorpl` archive (portable, tar.gz) |
| **2. Run** mutations against every recorded request | `iorpl run session.iorpl --suite full -o results.jsonl` | JSONL with one verdict per mutation |
| **3. Report** the findings | `iorpl report results.jsonl --format md -o report.md` | Markdown / HTML + ready-to-file HackerOne stubs |

A 90-second recording yields 20–30 captured flows. The `full` suite runs 11 deterministic mutations + 1 LLM-driven mutation against each. That's hundreds of bounty-shaped test cases per run.

## What's in the box

**12 mutations**, each a small Python class with `apply()` and `verdict()`:

| Mutation | Class | Targets |
|---|---|---|
| `swap_user_id` | IDOR | Cross-tenant ID substitution via session pool |
| `integer_overflow_id` | IDOR | 0, -1, 2³¹-1, 2⁶³-1 on numeric IDs |
| `strip_auth` | Auth | Remove Authorization / Cookie / X-API-Key / etc. |
| `jwt_alg_none` | JWT | Rewrite Bearer JWT with `alg=none` |
| `jwt_rs256_to_hs256_confusion` | JWT | Sign payload HS256 with the server's public key |
| `jwt_expired_replay` | JWT | Rewrite `exp` one hour in the past |
| `mass_assignment_inject_privileged_fields` | Mass-assignment | Inject `role`, `is_admin`, `permissions`, … into JSON bodies |
| `method_swap` | Tampering | Try DELETE / PUT / PATCH / POST on a GET |
| `verb_tunnel_override` | Tampering | `X-HTTP-Method-Override: DELETE` |
| `content_type_swap` | Tampering | `application/json` → `application/xml` |
| `path_extra_admin_segment` | Path | Append `/admin`, `/.env`, `/swagger`, … |
| `llm_creative` | Logic | Claude proposes context-specific business-logic + authz attacks |

**5 bundled YAML suites**: `idor`, `auth`, `mass_assignment`, `tamper`, `full`, `llm` (`iorpl suites list`).

**4 MCP servers** so AI agents can drive everything without a shell:

| Server | Console script | Required |
|---|---|---|
| `iorpl` | `iorpl-mcp` | always |
| `openrecon-mitm` (vendored mitmproxy-mcp) | `python -m mitmproxy_mcp.core.server` | always |
| `openrecon-r2` (radare2 static analysis) | `r2-mcp` | optional |
| `openrecon-r2frida` (live process via r2 + frida) | `r2frida-mcp` | optional |

---

## Install

```bash
git clone https://github.com/xtofuub/openrecon-ios
cd openrecon-ios

pip install -e .                 # core
pip install -e .[r2]             # optional: radare2 static analysis tools

# Optional: r2frida plugin for live-process introspection
r2pm -ci r2frida
```

**Prerequisites:** Python 3.12–3.13 · jailbroken iOS device with `frida-server` over USB · `mitmdump` on PATH.

## Register MCP servers with every agent in one command

```bash
openrecon-install-mcp                    # interactive — pick from a checklist
openrecon-install-mcp --agents all       # write to every detected agent
openrecon-install-mcp --agents claude,codex,cursor,opencode
openrecon-install-mcp --dry-run          # preview, write nothing
```

Supported: **Claude Code · Cursor · Windsurf · Cline · OpenCode · Codex CLI · Continue · Zed**. Idempotent; backs up each config to `<file>.openrecon.bak`.

---

## Quickstart

```bash
# 1. Verify your environment
openrecon doctor --device usb

# 2. Record a 5-minute session (use the app on the phone while this runs)
iorpl record --target com.example.app --device usb --budget 300 -o session.iorpl

# 3. Inspect what was captured
iorpl inspect session.iorpl

# 4. Edit a suite — set user_b's identity_id to a real sibling tenant
iorpl suites show idor > my-idor.yaml
$EDITOR my-idor.yaml

# 5. Run + report
iorpl run session.iorpl --suite my-idor.yaml -o results.jsonl
iorpl report results.jsonl --format md -o report.md
```

A worked example with real Wobo app findings (Intercom mass-assignment, RevenueCat user enumeration) lives in [docs/iorpl.md](docs/iorpl.md).

---

## Why this exists

Today's iOS bounty workflow:
1. Set up Burp/mitmproxy, intercept app traffic — 30 min
2. Pick an endpoint, copy-paste into Repeater
3. Mutate one field, send, eyeball response
4. Repeat for every endpoint, every mutation type
5. Lose your place when the app refreshes its session

Manual. Slow. **80% of disclosed iOS bounties are deterministic shapes** (IDOR swap, JWT alg=none, strip auth, mass assignment). The same 10 mutations on every app.

iorpl flips it:

- **Record once, replay forever.** Re-run the same suite when the app updates → instant regression test.
- **Coverage at scale.** 23 flows × 12 mutations = 276 test cases per minute. Manually impossible.
- **Bounty knowledge as code.** YAML suites encode hunter playbooks. Share across team.
- **AI-driven.** MCP server means Claude / Codex can drive the whole loop. Record → run → read verdicts → file HackerOne stub.
- **Defense too.** CI runs `iorpl run` against staging before release. Catches bounty-shaped bugs before they ship.
- **Logic bugs covered.** `llm_creative` mutation asks Claude for context-specific business-logic attacks per endpoint.

**50× faster** than manual for the same coverage on the deterministic classes — and the AI-driven mutations cover the creative class too.

---

## Architecture

```
iorpl  (record → run → report)
   │
   ├─ records via the openrecon engagement runner
   │    (frida_layer/  •  mitm/  •  api/  •  agent/)
   │
   ├─ replays via httpx + the mutation library (iorpl/mutations + ai_mutations)
   │
   └─ exposes everything via 4 stdio MCP servers
        iorpl-mcp  •  openrecon-mitm  •  r2-mcp  •  r2frida-mcp
```

Full layered model: [docs/architecture.md](docs/architecture.md).

---

## Docs

| Doc | Read when |
|---|---|
| [iorpl.md](docs/iorpl.md) | Full user guide — archive format, verdict semantics, custom mutations, YAML reference. |
| [architecture.md](docs/architecture.md) | How the pieces fit. iorpl on top, engagement runner + MCP servers underneath. |
| [mcp.md](docs/mcp.md) | All four MCP servers — install, tool catalogue, troubleshooting. |
| [docs/index.md](docs/index.md) | Top-level nav + repo file map. |

---

## License

MIT for original code in this repo.

Vendored upstream projects retain their own licenses:

- `mitm/vendor/` — [`snapspecter/mitmproxy-mcp`](https://github.com/snapspecter/mitmproxy-mcp) (MIT)
- `skills/_upstream/` — [`anthropic-cybersecurity-skills`](https://github.com/anthropics/anthropic-cybersecurity-skills) (Anthropic Skills License)
