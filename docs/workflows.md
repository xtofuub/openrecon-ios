# Workflows

Workflows are the named sequences the planner orchestrates. Each is a graph of primitives from `agent/steps.py`. They run sequentially within an engagement but each individual workflow can be invoked standalone.

## The five engagement phases

```
bootstrap → passive → mapping → active → exploit → report
```

The planner moves the engagement forward based on triggers (flow counts, hypotheses opened, budget remaining). Each phase corresponds to a workflow.

---

## Workflow 1 — Bootstrap

**Phase:** `bootstrap`. Runs once at start of engagement.

| Step | Primitive | Notes |
|---|---|---|
| 1 | `EnvironmentCheck` | `frida-ps -U` reachable, `objection version`, mitmproxy CA installed on device |
| 2 | `LaunchTarget` | spawn target via `frida.spawn(bundle_id, gating=True)`, attach |
| 3 | `InstallHook(ssl_pinning_bypass.js)` | always-on |
| 4 | `InstallHook(jailbreak_bypass.js)` | always-on |
| 5 | `InstallHook(url_session_tracer.js)` | core tracer |
| 6 | `InstallHook(commoncrypto_tracer.js)` | log crypto for later signature inference |
| 7 | `ObjectionRecon` | env, plist, classes, frameworks → store as artifacts |
| 8 | `frida.resume()` | release the gate |

**Exit:** target running, hooks loaded, MITM proxy intercepting, planner transitions to `passive`.

---

## Workflow 2 — Passive observation

**Phase:** `passive`. Duration: budget-driven (default 90s).

| Step | Primitive | Notes |
|---|---|---|
| 1 | `ObservePassive(duration=90)` | no mutation, just stream events |
| 2 | `CorrelateRange(t_start, t_end)` | force correlation pass at end |
| 3 | `MapEndpoints` | dedupe flows into endpoint table (host, method, path-template) |

Transition trigger: `flows_seen >= 50 AND endpoints >= 3 AND no error in last 30s` → `mapping`.

---

## Workflow 3 — Mapping

**Phase:** `mapping`. Builds the engagement's understanding of the app.

| Step | Primitive | Notes |
|---|---|---|
| 1 | `DetectAuthPattern` | mitm-mcp tool. Records auth headers, token rotation behavior |
| 2 | `ExtractEndpointSchemas` | `extract_from_flow` per endpoint family → infer body/response shape |
| 3 | `IdentifyIdBearingPositions` | URL path segments, query params, JSON keys ending in `_id`/`id` |
| 4 | `IdentifyAuthTokens` | JWTs, opaque bearers, cookies |
| 5 | `ExportOpenApiDraft` | mitm-mcp `export_openapi_spec` for the operator's eyes |
| 6 | `OpenHypotheses` | finder rules generate initial hypotheses, e.g. *header `X-Sig` is signed body* |

Transition trigger: `auth_pattern_detected AND endpoints_classified >= 5` → `active`.

---

## Workflow 4 — Active testing

**Phase:** `active`. Per-module sub-workflows. Modules run in this priority order:

1. `api/auth.py` — cheapest probes, biggest finding leverage.
2. `api/idor.py` — leverages second session if available.
3. `api/mass_assignment.py`
4. `api/tamper.py`
5. `api/graphql.py` — only if GraphQL endpoint detected during mapping.
6. `api/token_analysis.py`

Each module is its own workflow inside the active phase. Module-level workflow:

```
RunModule(name)
  ├─ load baseline flows from query
  ├─ generate test cases per algorithm
  ├─ for each test case:
  │     ├─ ReplayWithMutation
  │     └─ DiffResponses
  ├─ classify results (auth_required / degraded / bypass)
  └─ emit Findings for non-negative results
```

Transition trigger: all available modules run OR `budget_exceeded` → `exploit` (if any high-severity findings) or `report`.

---

## Workflow 5 — Exploit (optional)

**Phase:** `exploit`. Only entered if `findings_by_severity['high'|'critical'] >= 1`.

For each high finding, the planner:
1. Re-replays the bypass to confirm stability.
2. Records the canonical reproduction sequence.
3. Captures auxiliary evidence (response sample, runtime call stack at moment of trigger).
4. Bumps confidence score.

Modules can return early hypotheses ("this might be exploitable but I need a confirmation pass"); the exploit phase confirms them.

---

## Workflow 6 — Report

**Phase:** `report`. Always runs last.

| Step | Primitive | Notes |
|---|---|---|
| 1 | `RenderFindings` | each finding → `findings/<id>.md` (Jinja2 template) + `findings/<id>.json` |
| 2 | `BuildReportIndex` | top-level `report.md` with severity-ordered TOC |
| 3 | `BundleEvidence` | copy referenced flows to `evidence/` for portability |
| 4 | `ValidateSchema` | run `findings/*.json` through `templates/finding.schema.json` |

**Exit:** engagement complete. Operator can `openrecon report <run_id> --open` to view.

---

## Standalone workflows (not part of the engagement loop)

These are invocable independently when the operator wants targeted action.

### `openrecon inspect-class <bundle_id> <class>`
Wraps `objection ios hooking watch class`. Output to stdout + JSONL.

### `openrecon replay <flow_id> [--mutate <strategy>]`
Single-shot mutation + replay. Useful for manual testing during research.

### `openrecon recon <bundle_id>`
Runs the Bootstrap + Mapping workflows and stops. Output: an OpenAPI-ish spec + endpoint table.

### `openrecon report <run_id>`
Re-render an existing run's findings (idempotent, useful after editing templates).

### `openrecon correlate <run_id>`
Re-run correlation over an existing run's JSONL files. Useful when tuning weights.

---

## Output expectations per workflow

| Workflow | Writes to |
|---|---|
| Bootstrap | `artifacts/recon.json`, `frida_events.jsonl` start |
| Passive | `frida_events.jsonl`, `mitm_flows.jsonl`, `correlations.jsonl` |
| Mapping | `artifacts/endpoints.json`, `artifacts/auth_pattern.json`, `artifacts/openapi_draft.yaml`, hypotheses on `state.json` |
| Active | `findings.jsonl` (+ test traffic accumulates in `mitm_flows.jsonl`) |
| Exploit | confirms findings in `findings.jsonl`, adds `reproduction` field |
| Report | `findings/*.md`, `findings/*.json`, `report.md`, `evidence/`, `report.json` |
