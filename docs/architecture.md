# Architecture

## Context

iOS bug-bounty work today means juggling four tools by hand: Frida for runtime hooks, Objection for fast recon, a proxy (Burp / mitmproxy) for HTTPS, and ad-hoc scripts to test IDOR / auth / mass assignment. The hand-stitching is the bottleneck — by the time you've correlated "method X produced request Y," you've lost ten minutes per endpoint.

`openrecon` collapses the loop. Claude Code drives one autonomous pipeline that hooks the app, captures the traffic, correlates the two, and tests common API bug classes — emitting structured findings the operator can review or hand to a write-up.

## Design constraints

1. **Reuse over rewrite** — vendor the two Anthropic iOS skills and `snapspecter/mitmproxy-mcp`. Add adapters, don't reimplement.
2. **Everything is JSON** — every step writes machine-readable artifacts. The planner reasons over them; the operator scans them.
3. **Modular** — each `api/` module runs standalone (`python -m api.idor --run-dir runs/<id>`). The planner is a thin orchestrator over composable steps.
4. **Append-only event log** — JSONL on disk is the source of truth. Indexes are rebuildable. Crash-safe by construction.
5. **Jailbroken-first** — assume `frida-server` over USB. Non-JB Gadget paths are stubs we'll grow if needed.
6. **No safety gate** — the operator owns scope. We don't gate on `engagement.yaml`.
7. **No UI** — Phase 1–7 are CLI + Claude Code only. Visual review happens through the Markdown reports.

## Layered model

```
                              ┌────────────────────────────┐
                              │     Claude Code (LLM)      │
                              │  reads JSON, picks steps,  │
                              │   summarizes findings      │
                              └──────────────┬─────────────┘
                                             │ MCP tools + skill knowledge
                                             ▼
              ┌──────────────────────────────────────────────────────────┐
              │                   agent/   (Python)                      │
              │  planner • workflow engine • correlator • finder         │
              │            JSONL event store • RunQuery                  │
              └─────┬─────────────┬─────────────┬───────────────┬────────┘
                    │             │             │               │
                    ▼             ▼             ▼               ▼
            ┌────────────┐ ┌──────────────┐ ┌──────────┐ ┌──────────────┐
            │ frida_layer│ │objection_layer│ │   mitm   │ │     api/     │
            │ hooks + py │ │  scripts+py  │ │vendored  │ │  idor, auth, │
            │            │ │              │ │mcp +addon│ │  tamper, ... │
            └─────┬──────┘ └──────┬───────┘ └────┬─────┘ └──────┬───────┘
                  │               │              │              │
                  ▼               ▼              ▼              ▼
              ┌─────────────────────────────────────────────────┐
              │            iOS device (jailbroken)              │
              │     frida-server   •   target app  •  HTTPS     │
              └─────────────────────────────────────────────────┘
```

## Module responsibilities

### `agent/` — the brain
- `schema.py` — Pydantic v2 models for `FridaEvent`, `MitmFlow`, `Correlation`, `Finding`, `EngagementState`, all step types.
- `store.py` — append-only JSONL store + SQLite indexes (`by_flow`, `by_method`, FTS5).
- `correlate.py` — sliding-window scorer linking Frida events to MITM flows.
- `query.py` — read-only API the planner uses: `method_for_flow`, `flows_by_method`, `correlations_for_flow`, FTS search.
- `state.py` — `EngagementState`, `Hypothesis`, `Budget`, `StepRecord`.
- `steps.py` — workflow primitives (`LaunchTarget`, `InstallHook`, `TraceClass`, `ObservePassive`, `ReplayWithMutation`, `RunModule`, `DiffResponses`, `GenerateFinding`).
- `planner.py` — rule-based decision loop with LLM fallback for novel steps.
- `finder.py` — pattern rules that emit `Finding`s from correlations.
- `runner.py` — the async engagement loop.
- `cli.py` — `openrecon run|doctor|report|replay`.

### `frida_layer/` — runtime hooking
- `hooks/` — JS hook library (one file per concern: `url_session_tracer.js`, `ssl_pinning_bypass.js`, `keychain_dump.js`, `jailbreak_bypass.js`, `commoncrypto_tracer.js`, `cffi_arg_tracer.js`).
- `runner.py` — wraps `frida` Python API: spawn, attach, load script, stream messages as `FridaEvent`s into the store.
- `auto_hook.py` — read class list from `ObjC.classes`, pick which hooks to apply based on framework signatures (URLSession / WKWebView / CommonCrypto present → load tracer; biometrics framework → load `LAContext` hook).

### `objection_layer/` — high-level recon
- `scripts/` — Objection command sequences (`.objection` files) for recon, SSL pinning check, keychain dump, jailbreak detection inspection, user-defaults dump, filesystem walk.
- `runner.py` — invoke `objection` CLI with a target, run a script, parse output into structured records.

### `mitm/` — traffic layer
- `vendor/` — `git subtree` of `snapspecter/mitmproxy-mcp`. Read-only mirror; local patches recorded in `docs/vendor-patches.md`.
- `client.py` — async MCP client (stdio transport) that the planner uses to call the vendored tools.
- `addons/correlation_emitter.py` — mitmproxy addon. For each flow, writes a `MitmFlow` to `runs/<id>/mitm_flows.jsonl` and emits a JSON line on a control fd so the `correlator` ingests it live.
- `addons/ios_filter.py` — drop telemetry hosts (Crashlytics, Sentry, Apple analytics) by default; keep a `--strict` mode for full capture.
- `replay/` — wrappers around the vendor's `replay_flow` that add iOS-aware defaults (right User-Agent, device locale).

### `api/` — bug-bounty modules
- `base.py` — `ModuleInput`, `ModuleResult`, `ApiModule` protocol, `MitmClient` thin wrapper.
- `idor.py` — mutate object IDs, replay, diff. Cross-tenant token-aware.
- `auth.py` — strip / swap / downgrade tokens. Per-endpoint sweep.
- `mass_assignment.py` — diff GET response keys against POST/PUT body keys; inject privileged candidates.
- `tamper.py` — header injection, content-type swap, method swap, parameter pollution.
- `graphql.py` — introspection probe, depth abuse, alias bypass, batch smuggling.
- `token_analysis.py` — JWT decode + `alg:none`, key confusion, signature stripping, expiry abuse.

### `skills/` — knowledge layer
- `_upstream/anthropic-cybersecurity-skills/` — vendored. Provides the procedural workflows we extend.
- `reverse-engineering-ios-app-with-frida/SKILL.md` — thin wrapper. Frontmatter `name`, `description`; body delegates to upstream files via relative paths.
- `analyzing-ios-app-security-with-objection/SKILL.md` — ditto.
- `ios-security-research/SKILL.md` — the top-level orchestrator skill. Triggers on iOS bug-bounty / pentest engagement language. Tells Claude Code to use the planner and the modules.

## Data flow (a single engagement)

```
operator: openrecon run --target com.example.foo --device usb
     │
     ▼
agent/runner.py
  ├─ frida_layer.runner.spawn_and_attach() ──► writes frida_events.jsonl
  ├─ mitm.client.start_proxy()             ──► writes mitm_flows.jsonl
  ├─ agent/correlate.py (async task)       ──► writes correlations.jsonl
  └─ planner loop:
       phase=passive   → ObservePassive(60s)
       phase=mapping   → MapEndpoints, DetectAuthPattern
       phase=active    → RunModule(idor), RunModule(auth), ...
                                  │
                                  ▼   each module appends findings.jsonl
       phase=report    → render templates/ → runs/<id>/findings/*.{md,json}
```

## Why these particular boundaries

- **Vendor mitmproxy-mcp instead of re-implementing the proxy MCP.** It already exposes 20+ well-designed tools (`replay_flow`, `extract_from_flow`, `fuzz_endpoint`, `detect_auth_pattern`, `set_session_variable`). Our value-add is the iOS-aware adapter, the correlation emitter, and the bug-bounty modules — not the proxy plumbing.
- **Separate `frida_layer` from `frida` (pypi).** The PyPI `frida` package owns that import name. Our orchestrator must not collide.
- **Correlation as its own module, not bolted onto the mitmproxy addon.** The addon is hot-path. Correlation needs the Frida side too. Keeping it in `agent/correlate.py` lets us replay correlations offline from JSONL after a crash.
- **Bug-bounty modules read from the run directory, not from a long-running process.** Means each module is testable in isolation, the planner can re-run any module any number of times, and the operator can run them by hand.

## Known patches against the vendor

| File | Patch | Reason |
|---|---|---|
| `mitm/vendor/src/mitmproxy_mcp/core/server.py:324` | sanitize `file_path` in `load_traffic_file` (path traversal) | Upstream issue #16, open. |

Recorded in `docs/vendor-patches.md` after vendoring. Carry them forward on every `git subtree pull`.

## Future scope (deliberately deferred)

- Android (Frida + Objection support it — would need a parallel `android_layer/`).
- A web UI for engagement review.
- A persistent multi-engagement database (today: per-run directories).
- Non-jailbroken Gadget IPA repackaging as a first-class path (stubbed only).
