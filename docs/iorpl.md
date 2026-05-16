# iOSReplay (`iorpl`) — Playwright for iOS pentest

**One sentence:** record an iOS app session once, replay it forever against a library of bounty-shaped mutations, get HackerOne-ready reports out the other end.

## Why this exists

Every public iOS bounty disclosure fits one of a handful of shapes:

- *IDOR* — swap a user ID, get someone else's data.
- *Auth strip* — remove the Authorization header, server fails open.
- *JWT confusion* — `alg=none`, RS256→HS256, expired tokens accepted.
- *Mass assignment* — body adds `role: admin` and the server writes it through.
- *Verb tampering* — DELETE on a GET endpoint, X-HTTP-Method-Override, content-type swap.
- *Path tampering* — append `/admin`, `/.env`, `/swagger` to known endpoints.

The hard part isn't the mutation — it's getting a clean baseline session and **running every mutation against every authenticated endpoint** without writing a custom Burp suite each time.

`iorpl` makes that loop trivial:

1. `iorpl record` (or `iorpl import` from an existing openrecon run) captures the session into a portable `.iorpl` archive.
2. `iorpl run session.iorpl --suite full` replays every recorded request through every mutation.
3. `iorpl report results.jsonl` renders verdicts grouped by severity, with a HackerOne-ready stub for every confirmed finding.

## Install

```bash
pip install -e .
# now you have:
iorpl --help
iorpl-mcp        # MCP stdio server for AI agents
```

## Five-minute walkthrough

```bash
# 1. Record. Either run a fresh engagement…
iorpl record --target com.example.app --device usb --budget 300 --output session.iorpl

# …or import an existing openrecon run:
iorpl import runs/01ABC... --target com.example.app --output session.iorpl

# 2. Inspect.
iorpl inspect session.iorpl

# 3. List what's available.
iorpl mutations list
iorpl suites list

# 4. Edit a bundled suite — set user_b.identity_id to a sibling tenant.
iorpl suites show idor > my-idor.yaml
$EDITOR my-idor.yaml

# 5. Run.
iorpl run session.iorpl --suite my-idor.yaml --output results.jsonl

# 6. Report.
iorpl report results.jsonl --format md --output report.md
iorpl report results.jsonl --format html --output report.html
```

## Archive format (`.iorpl`)

Tar.gz with a fixed layout:

```
meta.json            schema_version, target_bundle, recorded_at, tags
flows.jsonl          every captured HTTP flow (mitmproxy / Frida synthetic)
frida_events.jsonl   Frida runtime events
auth_state.json      keychain / cookies / NSUserDefaults snapshot
endpoints.json       host × method × path-template summary
notes.md             operator-authored context (optional)
artifacts/<*>        binaries, screenshots, HARs (optional)
```

Read it from any machine with Python; the format intentionally has zero `iorpl` import deps for forward compatibility.

## Built-in mutations

| Name | What it does |
|---|---|
| `swap_user_id` | Replace ID-shaped path segments with another tenant's ID (cross-tenant IDOR). |
| `integer_overflow_id` | Replace numeric IDs with 0, -1, 2^31-1, 2^63-1. |
| `strip_auth` | Remove every recognized auth-bearing header. |
| `jwt_alg_none` | Rewrite a Bearer JWT with `alg=none` + empty signature. |
| `jwt_rs256_to_hs256_confusion` | Sign the existing payload with HS256 using the server's public key as the HMAC secret (provide via `context.extras.rs256_public_key_pem`). |
| `jwt_expired_replay` | Rewrite `exp` to one hour ago; if accepted, expiry isn't enforced. |
| `mass_assignment_inject_privileged_fields` | Inject `role: admin`, `is_admin: true`, etc. into JSON bodies. |
| `method_swap` | Try DELETE / PUT / PATCH / POST against a GET endpoint. |
| `verb_tunnel_override` | Add `X-HTTP-Method-Override: DELETE` to a GET. |
| `content_type_swap` | Swap `application/json` → `application/xml`. |
| `path_extra_admin_segment` | Append `/admin`, `/internal`, `/.env`, `/swagger` to the path. |

Run `iorpl mutations list` for the live list.

## Verdicts

| Verdict | Meaning |
|---|---|
| `auth_bypassed` | Strongest signal — a mutation that *removed* auth (or replaced it with a forged JWT) still got a 2xx response. |
| `leak_detected` | The mutated response contains tokens like `email`, `phone`, `user_id`, etc. that aren't expected. |
| `status_change` | Status code differs from baseline but no clear leak. Worth manual review. |
| `no_diff` | Mutation didn't change observable behavior. Filtered out of reports. |
| `error` | Network / parse error during replay. |

The report sorts verdicts by priority and emits a HackerOne stub (title, severity hint, repro steps, evidence) for every `auth_bypassed` / `leak_detected` row.

## YAML suite reference

```yaml
name: "My suite"
description: "What this suite tests"

context:
  session_pool:
    user_b:
      identity_id: "42"            # sibling tenant's id for swap_user_id
      auth_header: "Bearer ..."    # optional
  extras:
    rs256_public_key_pem: |        # required for jwt_rs256_to_hs256_confusion
      -----BEGIN PUBLIC KEY-----
      ...
      -----END PUBLIC KEY-----

target:
  hosts: ["api.example.com"]       # optional; empty matches any host
  methods: ["GET", "POST"]         # optional
  path_glob: "/v1/*"                # optional fnmatch
  require_auth: true                # require at least one auth header
  status: [200, 201, 204]           # baseline status filter

mutations:
  - swap_user_id
  - strip_auth
  - jwt_alg_none

overrides:
  strip_auth:
    skip_if_path_matches: ["/healthz", "/version"]
```

## MCP usage

`iorpl-mcp` exposes everything the CLI does:

| Tool | Notes |
|---|---|
| `iorpl_record(target, output, ...)` | Run an engagement, save .iorpl. |
| `iorpl_import(run_dir, target, output, ...)` | Convert an openrecon run dir to .iorpl. |
| `iorpl_inspect(session_path)` | Summary of a session. |
| `iorpl_run(session_path, suite, output, http_timeout_seconds, verify_tls)` | Run suite, stream results to disk. |
| `iorpl_report(results_path, format)` | Render results to Markdown or HTML. |
| `iorpl_list_mutations()` | Catalog of mutations. |
| `iorpl_list_suites()` | Catalog of bundled suites. |

Register via `openrecon-install-mcp --agents <your-agent>` or paste into your agent's config:

```jsonc
{
  "mcpServers": {
    "iorpl": { "command": "iorpl-mcp", "args": [] }
  }
}
```

## What this isn't

- A web UI. Reports render to Markdown / HTML files; there's no live dashboard.
- A device manager. Use openrecon's runner / objection for that.
- A magic vulnerability scanner. Mutations are deterministic — false positives are possible. Use the verdict + evidence as a triage lead, not a guarantee.

## Roadmap (light)

- Recording **touches** (UIAutomation / XCTest synthesis) so the entire user journey replays, not just HTTP.
- Per-flow `expect:` blocks in the YAML suite for tighter pass/fail signals.
- A `diff` command to compare two `.iorpl` archives (regression-testing the same app across versions).
- Cloud / shared session library — push/pull `.iorpl` files via a small index server so teams share recordings.
