# Bug-Bounty Module Plan

Seven modules under `api/`. Each is:

- **Standalone**: `python -m api.<name> --run-dir runs/<id> [--module-args ...]` works without the planner.
- **Pluggable**: implements the `ApiModule` protocol from `api/base.py`. The planner discovers modules via that protocol.
- **Reuse-first**: delegates transport to the vendored `mitmproxy-mcp` (`replay_flow`, `extract_from_flow`, `fuzz_endpoint`, `detect_auth_pattern`, `set_session_variable`).
- **JSON in, JSON out**: reads baseline flows from the run directory, writes findings to `findings.jsonl`.

## Common contract — `api/base.py`

```python
class ModuleInput(BaseModel):
    run_dir: Path
    baseline_flow_ids: list[str]          # filtered + scoped flows the module mutates
    session_pool: dict[str, SessionCreds] # "user_a", "user_b", "anon" → creds
    mitm_mcp: MitmClient                  # client to the vendored MCP server
    config: dict[str, Any] = {}           # module-specific knobs

class ModuleResult(BaseModel):
    module: str
    findings: list[Finding]
    artifacts: list[Artifact]             # flow_ids of generated test traffic
    coverage: ModuleCoverage              # what was tested, what was skipped, reasons

class ApiModule(Protocol):
    name: ClassVar[str]
    severity_baseline: ClassVar[Severity]
    def run(self, inp: ModuleInput) -> ModuleResult: ...
```

`SessionCreds`: `{label, auth_header?, cookie_jar?, jwt?, identity_id?}`. Sessions live in `engagement.yaml` or get inferred during Mapping (e.g. login flow recorded with `set_session_variable`).

## Module 1 — `api/idor.py`

**Goal:** discover horizontal and vertical IDOR.

**Inputs:** baseline flows that return user-scoped data (200 with JSON body referring to an identity).

**Algorithm:**

```
for flow in baseline_flow_ids:
    auth = mitm_mcp.detect_auth(flow)
    id_positions = identify_id_positions(flow.request)
        # URL path segments, query params, JSON body keys matching:
        #   *_id, id, uid, account, owner, tenant, org, group
    for pos in id_positions:
        for mutation in generate_mutations(pos, session_pool):
            replay = mitm_mcp.replay_flow(flow.id, overrides={pos: mutation})
            diff = response_diff(flow.response, replay.response)
            classify(replay, diff) -> {auth_required | empty | data_leaked | echoed}
            if data_leaked:
                emit_finding(category="idor", severity="high", evidence=[flow.id, replay.id])
```

**Mutations:**

| Position type | Mutations |
|---|---|
| numeric | ±1, ±10, ±100, 1, 0, MAX_INT, swap with user_b's id |
| UUID | swap with user_b's known UUIDs; also try predictable variants (v1 timestamp arithmetic) |
| opaque string | swap with user_b's session's same-position values |
| base64-y | decode, swap, re-encode |

**Coverage metric:** `endpoints_tested / endpoints_id_bearing`.

**Findings:**

```json
{
  "category": "idor",
  "severity": "high|medium|low|info",
  "title": "Horizontal IDOR on GET /v1/users/{id}/orders",
  "evidence": {
    "baseline_flow": "...",
    "mutation_flow": "...",
    "mutated_position": "path.users.id",
    "mutated_from": "12345",
    "mutated_to": "12346",
    "response_diff": { ... }
  },
  "reproduction": [ {step}, {step}, ... ]
}
```

## Module 2 — `api/auth.py`

**Goal:** find endpoints that fail open.

**Inputs:** all unique endpoints (deduped per `(host, method, path_template)`).

**Probe matrix:**

| Probe | Modification | Pass criterion |
|---|---|---|
| strip-each-auth | remove one auth-bearing header at a time | response stays 2xx with same body shape |
| strip-all-auth | remove every auth header | 2xx is a finding |
| swap-user-b | substitute user_b's tokens | 2xx with user_a's data persists = downgrade bypass |
| swap-anon | substitute anonymous session | 2xx is a finding |
| jwt-alg-none | if JWT, switch alg to none (unsigned) | accepted = critical |
| header-case | `authorization` (lower) vs `Authorization` | response divergence = parser bug |

**Optimization:** group endpoints by auth pattern (from `detect_auth_pattern`). Only probe one representative per group, but always probe sensitive methods (POST/PUT/DELETE) individually.

**Findings:** category `auth-bypass` (severity inferred from method + data sensitivity).

## Module 3 — `api/mass_assignment.py`

**Goal:** find endpoints that accept fields they shouldn't.

**Algorithm:**

```
visible_fields = union(GET responses for resource family)
writable_fields_seen = union(POST/PUT/PATCH bodies for resource family)
hidden_candidates = visible_fields - writable_fields_seen
hidden_candidates += {"is_admin", "role", "owner_id", "tenant_id",
                     "email_verified", "_id", "id", "uid",
                     "internal_*", "_audit_*"}

for endpoint in writable_endpoints(resource_family):
    for candidate in hidden_candidates:
        body = {**baseline_body, candidate: privileged_value_for(candidate)}
        replay = mitm_mcp.replay_flow(endpoint.flow, overrides={body: body})
        if replay.status in (200, 201, 204):
            # Confirm: re-fetch via GET, see if the field is now set
            follow = re_fetch(endpoint.resource_id)
            if follow.body.get(candidate) == privileged_value_for(candidate):
                emit_finding(severity="critical", title=f"Mass assignment on {endpoint}")
```

`privileged_value_for(candidate)`: bool→True, role→`"admin"`, int→1, string→`"admin"`, *_id→user_b's id.

## Module 4 — `api/tamper.py`

**Goal:** generic mutators across the captured flow set. Cheap, broad, surfaces parser bugs and WAF gaps.

**Mutator strategies** (each is composable):

| Mutator | What it does |
|---|---|
| `HeaderInjectionMutator` | injects `X-Forwarded-For: 127.0.0.1`, `X-Original-URL`, `X-Rewrite-URL`, `X-Host`, `Host` override |
| `ContentTypeSwapMutator` | JSON ↔ XML ↔ `application/x-www-form-urlencoded` ↔ multipart |
| `MethodSwapMutator` | GET↔POST, PUT→PATCH, DELETE→GET, with payload moved appropriately |
| `ParamPollutionMutator` | duplicate keys in query and body (`?id=1&id=2`, `{"id":1,"id":2}`) |
| `TrailingDataMutator` | append `?#`, `;param`, `/.`, double slashes |
| `NullByteMutator` | inject `%00` in path / params |
| `JsonNestingMutator` | deeply nested object as a value (DoS sanity) |
| `UnicodeNormalizationMutator` | NFC ↔ NFD ↔ NFKC on identifiers in URLs |

Each mutator yields `FlowOverride`s. The harness sends every variant via `mitm_mcp.replay_flow`, runs `DiffResponses`, classifies anomalies.

## Module 5 — `api/graphql.py`

Only runs if GraphQL endpoints were detected in mapping (URL ends with `/graphql`, or content-type `application/graphql`, or body has `query`/`mutation` JSON shape).

**Tests:**

1. **Introspection probe** — POST `{ "query": "{ __schema { types { name fields { name type { name } } } } }" }`. If 200 with non-empty `__schema`, finding (info-disclosure or hardening gap).
2. **Depth abuse** — generate `{ a { a { a ... } } }` at depth 1..20; observe 500 / timeout / connection close.
3. **Alias-based rate limit bypass** — `query { a:thing { x } b:thing { x } c:thing { x } ... }`; if rate-limited single calls pass, finding.
4. **Batch smuggling** — POST `[ {query: q1}, {query: q2_unauthorized} ]` if server supports batched format.
5. **Field-level auth gaps** — for each leaf field, query it directly; compare authorized vs anon response.

**Artifacts:** `artifacts/graphql_schema.json` (introspected schema for human review).

## Module 6 — `api/token_analysis.py`

Operates over tokens harvested during mapping (`set_session_variable` records every captured token).

**Tests per JWT:**

1. Decode header and payload, dump claims.
2. Re-sign with `{"alg": "none"}`, empty sig → replay → 2xx = critical.
3. Key confusion (RS256 → HS256 with public key as HMAC secret) → replay.
4. Signature stripping (`header.payload.`) → replay.
5. Expiry abuse — token with `exp` set in the past → replay.
6. `kid` injection — try `../../etc/passwd`, SQL fragments, JWKS URL override.

**Tests per opaque token:**

1. Refresh-token replay after rotation (if `/refresh` endpoint observed).
2. Token-bound checks — same token from different IP / UA.
3. Predictability — sequential token captures, look for incrementing values or low-entropy timestamps.

**Output:** per-token JSON `{token_hash, type, algorithm, claims, vulnerabilities: [{kind, evidence_flow_id}]}`.

## Correlation engine — referenced from all modules

Modules consume correlations through `agent/query.py`. They never compute their own.

### Scoring (recap from architecture)

```
score = 0.20 * gauss(|frida.ts - flow.ts_request|, σ=0.5s)
      + 0.35 * url_substring_match
      + 0.30 * body_match
      + 0.10 * thread_proximity
      + 0.15 * stack_url_match
      + 0.10 * arg_type_hint
```

Accept correlation if `score >= 0.45`. Multiple Frida events can attach to one flow. Tunable in `config/correlation.yaml`.

## Standalone runtime

Every module has a `__main__` block:

```python
if __name__ == "__main__":
    from api.base import cli_entry
    cli_entry(IdorModule)
```

Which gives:

```bash
python -m api.idor --run-dir runs/abc --baseline 7ef3...,9af4... \
                   --session user_a=tests/fixtures/cred_a.json,user_b=tests/fixtures/cred_b.json
```

This is also how the planner invokes them — same code path, just programmatic args.

## What each module does NOT do

- Doesn't open its own MCP server (uses the engagement's `MitmClient`).
- Doesn't talk to the iOS device directly (that's `frida_layer` / `objection_layer`).
- Doesn't decide phase transitions (that's `agent/planner.py`).
- Doesn't render Markdown (that's `templates/`).
- Doesn't store state across invocations (the run directory is the only state).
