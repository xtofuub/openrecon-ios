# Roadmap

Seven phases. Each phase has an exit criterion — a thing the platform can do that it couldn't before. Phases are mostly sequential, but Frida/Objection (Phase 2) and MITMProxy (Phase 3) can be parallel since they don't share files.

**Current state:** Phases 1, 3, 4, 5, 6, 7 implemented in code with 92 passing tests. Phase 2 needs a jailbroken iOS device for hardware validation — code is in place, only field-test left.

---

## Phase 1 — Foundation ✅

**Goal:** clean repo, vendored upstreams, docs, conventions.

- [x] Repo skeleton (top-level dirs, `__init__.py`s, stubs)
- [x] `pyproject.toml`, `.gitignore`, `README.md`, `CLAUDE.md`
- [x] `docs/architecture.md`, `docs/roadmap.md`, `docs/workflows.md`
- [x] `docs/mcp-integration.md`, `docs/frida-objection-integration.md`, `docs/bug-bounty-modules.md`, `docs/vendor-patches.md`
- [x] `agent/schema.py` — Pydantic models for every event and finding
- [x] `agent/store.py` — JSONL store + SQLite FTS5 indexes
- [x] `templates/finding.md.j2`, `templates/report.md.j2`, `templates/finding.schema.json`, `templates/engagement.example.yaml`
- [x] `skills/ios-security-research/SKILL.md` — top-level orchestrator
- [x] `skills/<frida|objection>/SKILL.md` — wrappers around upstream
- [x] `.claude/settings.json` — MCP server registration + slash commands
- [x] `git subtree add` for `mitm/vendor` and `skills/_upstream/anthropic-cybersecurity-skills`

**Exit:** `openrecon doctor` runs and reports environment + vendored projects status. ✅

---

## Phase 2 — Frida + Objection integration 🟡 (code done, hardware test pending)

**Goal:** the platform can attach to an iOS app, run a recon suite, and stream structured events into the run directory.

- [x] `frida_layer/hooks/url_session_tracer.js` — log NSURLSession / WKWebView requests with class, method, args, response.
- [x] `frida_layer/hooks/ssl_pinning_bypass.js` — composite bypass (AFNetworking, TrustKit, NSURLSession delegate, SecTrustEvaluate).
- [x] `frida_layer/hooks/keychain_dump.js` — enumerate keychain on attach.
- [x] `frida_layer/hooks/jailbreak_bypass.js` — common detection routines.
- [x] `frida_layer/hooks/commoncrypto_tracer.js` — log every HMAC op with inputs and outputs.
- [x] `frida_layer/runner.py` — `spawn`, `attach`, `load_script`, message-pump to `FridaEvent` JSONL.
- [x] `frida_layer/auto_hook.py` — read `ObjC.classes`, decide which hooks to load.
- [x] `objection_layer/scripts/recon.objection` — env, plist, classes, plugins, frameworks.
- [x] `objection_layer/scripts/ssl_pinning_check.objection` — observed pinning surface.
- [x] `objection_layer/scripts/keychain_dump.objection`
- [x] `objection_layer/scripts/jailbreak_detection.objection`
- [x] `objection_layer/scripts/userdefaults_dump.objection`, `cookies_dump.objection`
- [x] `objection_layer/runner.py` — invoke `objection`, capture stdout, normalize to records.
- [ ] **Hardware test:** validate against a real jailbroken iOS device with `frida-server` over USB.
- [ ] **Hardware tune:** confirm hook coverage on a real app (URLSession, AFNetworking, TrustKit, WKWebView paths).

**Exit:** `openrecon run --target <bid>` produces `frida_events.jsonl` with ≥100 events on a test app.

---

## Phase 3 — MITMProxy MCP integration ✅

**Goal:** the proxy is part of the autonomous loop, not a sidecar tool.

- [x] `git subtree add --prefix=mitm/vendor https://github.com/snapspecter/mitmproxy-mcp main --squash`
- [x] `mitm/client.py` — async MCP stdio client; wraps `start_proxy`, `replay_flow`, `extract_from_flow`, `fuzz_endpoint`, `detect_auth_pattern`, `set_session_variable`, `export_openapi_spec`, `load_traffic_file`. Run-dir import guarding enforced client-side.
- [x] `tests/integration/test_mitm_client.py` — HAR-backed MCP stdio integration coverage.
- [x] `mitm/addons/correlation_emitter.py` — per-flow JSONL emitter to `runs/<id>/mitm_flows.jsonl`.
- [x] `mitm/addons/ios_filter.py` — Crashlytics/Sentry/analytics drop, `LOLMCP_IOS_STRICT=1` keeps everything.
- [x] `mitm/replay/ios.py` — iOS-aware replay (User-Agent, locale, device headers).
- [x] `.claude/settings.json` — register the vendored MCP server.
- [ ] **Vendor patch audit:** verify `load_traffic_file` path-traversal posture per `docs/vendor-patches.md`. Client-side guard exists; vendor-side untouched.

**Exit:** Claude Code can `start_proxy`, `replay_flow` from the session, and every captured flow appears in the run directory. ✅

---

## Phase 4 — Correlation engine ✅

**Goal:** every flow has at least one scored Frida event attached.

- [x] `agent/correlate.py` — `Correlator` with 6-signal weighted scoring (temporal, url_substring, body_match, thread_proximity, stack_url, arg_type_hint).
- [x] `agent/query.py` — `RunQuery` (FTS5, by-flow, by-method, by-endpoint, by-correlation).
- [x] `agent/store.py` — SQLite indexes rebuilt incrementally + `rebuild_indexes()`.
- [x] `tests/unit/test_correlator.py` — fixture-based tests with synthetic events.
- [x] `tests/unit/test_query.py` — flow lookups, FTS, correlations-for-flow.
- [x] `tests/unit/test_store.py` — append, read, index population, rebuild.

**Exit:** `openrecon correlate runs/<id>` produces correlations.jsonl. Score threshold tunable in `CorrelationConfig`. ✅

---

## Phase 5 — Bug-bounty modules ✅

**Goal:** each module runs standalone against a recorded run and emits findings.

- [x] `api/base.py` — `ApiModule` protocol, `ModuleInput`, `ModuleResult`, `MitmClientLike`, `identify_id_positions`, `response_diff`, `cli_entry`.
- [x] `api/idor.py` — mutate path/query/body IDs, cross-session swap, classify response.
- [x] `api/auth.py` — strip, swap, JWT alg=none probes.
- [x] `api/mass_assignment.py` — diff GET vs POST keys, inject privileged candidates.
- [x] `api/tamper.py` — header injection, content-type swap, method swap, param pollution, trailing data.
- [x] `api/graphql.py` — introspection, depth abuse, alias bypass, batch smuggling.
- [x] `api/token_analysis.py` — JWT decode, alg=none, signature strip, expiry abuse, helpers.
- [x] `tests/modules/test_{idor,auth,mass_assignment,tamper,graphql,token_analysis}.py`.

**Exit:** `python -m api.<name> --run-dir runs/<id> --baseline <flow_id>` produces structured findings per module. ✅

---

## Phase 6 — Autonomous agent behavior ✅

**Goal:** the planner runs a full engagement end-to-end without operator intervention.

- [x] `agent/state.py` — `EngagementState`, `Hypothesis`, `Budget`, save/load helpers.
- [x] `agent/steps.py` — `Step` base + `EnvironmentCheck`, `LaunchTarget`, `InstallHook`, `ObjectionRecon`, `ObservePassive`, `MapEndpoints`, `DetectAuthPattern`, `CorrelateRange`, `RunModule`, `GenerateReport`, `RenderFindings`.
- [x] `agent/planner.py` — rule-driven phase machine (bootstrap → passive → mapping → active → exploit → report) with deterministic transitions.
- [x] `agent/llm.py` — optional Anthropic SDK fallback. Off by default; opt-in via `ANTHROPIC_API_KEY` or `Planner(enable_llm=True)`. Parses JSON action proposals into typed Steps. Safe no-op when SDK or key is missing.
- [x] `agent/finder.py` — pattern rules (`AuthHeaderInferenceRule`, `HookedCryptoAsSignatureRule`, `CrossTenantLeakRule`, `EndpointWithoutAuthRule`, `ClientSideValidationBypassRule`) with dedupe by `(category, sorted(flows))`.
- [x] `agent/endpoint_map.py` — `template_path()` canonicalizes URL paths (`/users/42` → `/users/{id}`); `group_flows()` buckets flows into deduplicated endpoint records.
- [x] `agent/runner.py` — full async engagement loop with crash recovery via `state.json` snapshot after every step.
- [x] `tests/orchestration/test_{planner,finder,llm}.py`.

**Exit:** unattended `openrecon run --target <bid> --budget 1800` walks all phases. ✅

---

## Phase 7 — Reporting and exports ✅

**Goal:** findings are review-ready and embeddable in HackerOne / Bugcrowd / private reports.

- [x] `templates/finding.md.j2` — Markdown with reproduction steps, evidence flow_ids, runtime context, severity reasoning.
- [x] `templates/report.md.j2` — top-level TOC grouped by severity.
- [x] `templates/finding.schema.json` — strict JSON schema. Validated in tests via `jsonschema`.
- [x] `agent/reporter.py` — renders per-finding `.md` + `.json` and `report.{md,json}` index.
- [x] `agent/cli.py` — `openrecon report <run_id>` collates findings, `openrecon replay <finding_id>` executes repro steps, `openrecon runs` lists engagements, `openrecon export <run_id>` produces a tar.gz bundle with MANIFEST.json (sha256 per file).
- [x] `agent/replay.py` — walks `ReproStep` entries, classifies overall as reproduced / no-repro / partial / error.
- [x] `agent/runs.py` — engagement enumeration + per-run summaries.
- [x] `agent/export.py` — shareable bundle export, SQLite indexes excluded (rebuildable).
- [x] `agent/owasp_mapping.py` — OWASP Mobile Top 10 (2024) annotation. Reporter writes `owasp` field into per-finding JSON and renders an OWASP block in Markdown.
- [x] `tests/orchestration/test_{reporter,replay}.py`, `tests/unit/test_{runs,export,owasp_mapping,endpoint_map}.py`.

**Exit:** generated reports validate against the JSON schema and render correctly. ✅

---

## What's actually left

| Gap | Where | How to close |
|---|---|---|
| Hardware-side Frida validation | Phase 2 | Plug in jailbroken iOS device with `frida-server`, run `openrecon doctor` then `openrecon run --target <bundle_id>`. Iterate on hooks in `frida_layer/hooks/` until ≥100 events stream. |
| Real-device end-to-end smoke | Phase 2 + Phase 6 | Run against an intentionally vulnerable app (e.g. DVIA-v2). Confirm planner walks all phases and finds ≥1 real bug. |

## Test coverage

92 tests passing across:
- `tests/unit/` — schema round-trips, store + SQLite indexes, correlator scoring, query API.
- `tests/modules/` — all 7 api/ modules with `FakeMitmClient` + fixture flows.
- `tests/orchestration/` — planner phase transitions, finder rules, reporter render + schema, replay command, LLM proposer parsing.
- `tests/integration/` — MCP stdio client end-to-end with a HAR-backed fixture server, iOS replay profile headers.

## Milestone summary

| Milestone | Exit criterion | Status |
|---|---|---|
| M1: Phase 1 done | `openrecon doctor` runs | ✅ |
| M2: Phase 2 done | Frida events stream from a real device | 🟡 code ready, needs hardware |
| M3: Phase 3 done | MITM flows stream via the vendored MCP | ✅ |
| M4: Phase 4 done | Correlator + store + query + tests | ✅ |
| M5: Phase 5 done | All seven modules produce findings | ✅ (tested with fakes) |
| M6: Phase 6 done | Unattended engagement loop with LLM fallback | ✅ |
| M7: Phase 7 done | Reports validate against schema; replay command works | ✅ |
