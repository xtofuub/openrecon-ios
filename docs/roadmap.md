# Roadmap

Seven phases. Each phase has an exit criterion — a thing the platform can do that it couldn't before. Phases are mostly sequential, but Frida/Objection (Phase 2) and MITMProxy (Phase 3) can be parallel since they don't share files.

---

## Phase 1 — Foundation  *(this commit)*

**Goal:** clean repo, vendored upstreams, docs, conventions.

- [x] Repo skeleton (top-level dirs, `__init__.py`s, stubs)
- [x] `pyproject.toml`, `.gitignore`, `README.md`, `CLAUDE.md`
- [x] `docs/architecture.md`, `docs/roadmap.md`, `docs/workflows.md`
- [x] `docs/mcp-integration.md`, `docs/frida-objection-integration.md`, `docs/bug-bounty-modules.md`
- [x] `agent/schema.py` — Pydantic models for every event and finding
- [x] `agent/store.py` — JSONL store skeleton
- [x] `templates/finding.md.j2`, `templates/finding.schema.json`, `templates/engagement.example.yaml`
- [x] `skills/ios-security-research/SKILL.md` — top-level orchestrator
- [x] `skills/<frida|objection>/SKILL.md` — wrappers around upstream
- [x] `.claude/settings.json` — MCP server registration (mitmproxy-mcp vendored)
- [ ] `git subtree add` for `mitm/vendor` and `skills/_upstream/`  *(run after merging this commit)*

**Exit:** `openrecon doctor` runs and reports environment + vendored projects status.

---

## Phase 2 — Frida + Objection integration

**Goal:** the platform can attach to an iOS app, run a recon suite, and stream structured events into the run directory.

- [ ] `frida_layer/hooks/url_session_tracer.js` — log NSURLSession / WKWebView requests with class, method, args, response.
- [ ] `frida_layer/hooks/ssl_pinning_bypass.js` — composite bypass (AFNetworking, TrustKit, NSURLSession delegate, SecTrustEvaluate).
- [ ] `frida_layer/hooks/keychain_dump.js` — enumerate keychain on attach.
- [ ] `frida_layer/hooks/jailbreak_bypass.js` — common detection routines.
- [ ] `frida_layer/hooks/commoncrypto_tracer.js` — log every HMAC/AES/SHA op with inputs and outputs.
- [ ] `frida_layer/runner.py` — `spawn`, `attach`, `load_script`, message-pump to `FridaEvent` JSONL.
- [ ] `frida_layer/auto_hook.py` — read `ObjC.classes`, decide which hooks to load.
- [ ] `objection_layer/scripts/recon.objection` — env, plist, classes, plugins, frameworks.
- [ ] `objection_layer/scripts/ssl_pinning_check.objection` — observed pinning surface.
- [ ] `objection_layer/scripts/keychain_dump.objection`
- [ ] `objection_layer/scripts/jailbreak_detection.objection`
- [ ] `objection_layer/runner.py` — invoke `objection`, capture stdout, normalize to records.

**Exit:** `openrecon run --target <bid>` produces `frida_events.jsonl` with ≥100 events on a test app.

---

## Phase 3 — MITMProxy MCP integration

**Goal:** the proxy is part of the autonomous loop, not a sidecar tool.

- [ ] `git subtree add --prefix=mitm/vendor https://github.com/snapspecter/mitmproxy-mcp main --squash`
- [ ] Patch path-traversal in `mitm/vendor/src/mitmproxy_mcp/core/server.py:324`. Record in `docs/vendor-patches.md`.
- [x] `mitm/client.py` — async MCP stdio client; wraps `start_proxy`, `replay_flow`, `extract_from_flow`, `fuzz_endpoint`, `detect_auth_pattern`, `set_session_variable`, `export_openapi_spec`.
- [x] `tests/test_mitm_integration.py` — HAR-backed MCP stdio integration coverage for `start_proxy`, `load_traffic_file`, `inspect_flow`, `extract_from_flow`, `detect_auth_pattern`, `replay_flow`, `export_openapi_spec`, and run-dir import guarding.
- [ ] `mitm/addons/correlation_emitter.py` — per-flow JSONL emitter to `runs/<id>/mitm_flows.jsonl`.
- [ ] `mitm/addons/ios_filter.py` — Crashlytics/Sentry/analytics drop, `--strict` keeps everything.
- [x] `mitm/replay/ios.py` — iOS-aware replay (User-Agent, locale, device headers).
- [x] `.claude/settings.json` — register the vendored MCP server.

**Exit:** Claude Code can `start_proxy`, `replay_flow` from the session, and every captured flow appears in the run directory.

---

## Phase 4 — Correlation engine

**Goal:** every flow has at least one scored Frida event attached.

- [ ] `agent/correlate.py` — `Correlator` class with the scoring algorithm in [bug-bounty-modules.md](bug-bounty-modules.md#scoring).
- [ ] `agent/query.py` — `RunQuery` (FTS5, by-flow, by-method, by-endpoint, by-correlation).
- [ ] `agent/store.py` (complete) — SQLite indexes rebuilt incrementally.
- [ ] `tests/test_correlate.py` — fixture-based tests with synthetic Frida + MITM events.

**Exit:** on a recorded run, `openrecon correlate runs/<id>` produces correlations.jsonl with ≥0.45 average confidence on flows that have a matching hook.

---

## Phase 5 — Bug-bounty modules

**Goal:** each module runs standalone against a recorded run and emits findings.

- [ ] `api/base.py` — protocol + `MitmClient` thin wrapper.
- [ ] `api/idor.py`
- [ ] `api/auth.py`
- [ ] `api/mass_assignment.py`
- [ ] `api/tamper.py`
- [ ] `api/graphql.py`
- [ ] `api/token_analysis.py`
- [ ] `tests/test_<each>.py`

**Exit:** `python -m api.idor --run-dir runs/<id> --baseline <flow_id>` produces ≥1 finding (real or negative-control) per module.

---

## Phase 6 — Autonomous agent behavior

**Goal:** the planner runs a full engagement end-to-end without operator intervention.

- [ ] `agent/state.py` — `EngagementState`, `Hypothesis`, `Budget`.
- [ ] `agent/steps.py` — every workflow primitive.
- [ ] `agent/planner.py` — rule-based loop + LLM fallback (Anthropic SDK).
- [ ] `agent/finder.py` — pattern rules (`AuthHeaderInference`, `HookedCryptoAsSignature`, `CrossTenantLeak`).
- [ ] `agent/runner.py` — full async engagement loop with crash recovery.

**Exit:** unattended `openrecon run --target <bid> --budget 30m` produces a report directory with ≥3 findings categories tested.

---

## Phase 7 — Reporting and exports

**Goal:** findings are review-ready and embeddable in HackerOne / Bugcrowd / private reports.

- [ ] `templates/finding.md.j2` — Markdown with reproduction steps, evidence flow_ids, runtime context, severity reasoning.
- [ ] `templates/finding.schema.json` — strict JSON schema; CI validates.
- [ ] `agent/cli.py` — `openrecon report <run_id>` collates findings, generates `report.md` + `report.json` + `evidence/` bundle.
- [ ] Optional: `openrecon replay <finding_id>` re-executes the reproduction steps and confirms the issue still reproduces.

**Exit:** generated reports validate against the JSON schema and render correctly with reproduction steps a human can follow.

---

## First code files to create (this commit)

In execution order:

1. `pyproject.toml`, `.gitignore`, `README.md`, `CLAUDE.md`  *(done)*
2. `docs/{architecture,roadmap,workflows,mcp-integration,frida-objection-integration,bug-bounty-modules}.md`
3. `agent/schema.py` — the type system everything else depends on
4. `agent/store.py` — append-only JSONL store
5. `agent/state.py` — `EngagementState` stub
6. `agent/correlate.py` — `Correlator` interface + scoring sketch
7. `agent/query.py` — `RunQuery` skeleton
8. `agent/steps.py` — workflow primitive base classes
9. `agent/planner.py` — `Planner.next_step()` skeleton
10. `agent/finder.py` — rule protocol
11. `agent/runner.py` — engagement loop skeleton
12. `agent/cli.py` — `openrecon run|doctor|report|replay`
13. `api/base.py` + each module as a stub with a `TODO` body and a working CLI
14. `frida_layer/runner.py`, `frida_layer/auto_hook.py`, hook JS placeholders
15. `objection_layer/runner.py` + script placeholders
16. `mitm/client.py`, `mitm/addons/correlation_emitter.py`, `mitm/addons/ios_filter.py`
17. `templates/` + `skills/` + `.claude/`
18. `git subtree add` for `mitm/vendor` and `skills/_upstream/`

## Milestone summary

| Milestone | Exit criterion | Effort estimate |
|---|---|---|
| M1: Phase 1 done | `openrecon doctor` runs | 1 commit |
| M2: Phase 2 done | Frida events stream from a real device | 2–3 days work |
| M3: Phase 3 done | MITM flows stream via the vendored MCP | 1–2 days |
| M4: Phase 4 done | Correlations cover ≥80% of flows on test app | 2–3 days |
| M5: Phase 5 done | All seven modules produce findings on intentionally vulnerable target | 4–6 days |
| M6: Phase 6 done | Unattended 30-minute engagement | 3–5 days |
| M7: Phase 7 done | Reports validate against schema | 2 days |
