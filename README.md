# openrecon — Autonomous iOS Security Research Platform

A unified Claude Code-driven workflow that fuses **Frida**, **Objection**, and a forked **MITMProxy MCP** into one autonomous mobile security analyst.

The platform inspects an iOS app at runtime, captures and mutates its network traffic, correlates the two, and produces structured findings — IDOR, auth bypass, mass assignment, API tampering, GraphQL abuse, and token weaknesses.

> Use only against targets you own or are explicitly authorized to test. No safety gate is enforced; the operator is responsible for scope.

---

## What it does

1. **Runtime inspection** — Frida hooks (Objective-C / Swift) and Objection recon on a jailbroken iOS device.
2. **Traffic capture (two sources, transparent fallback)** —
   - **MITMProxy MCP** intercepts HTTPS, replays flows with TLS fingerprinting, fuzzes endpoints.
   - **NSURLSession / NSURLConnection body tracers** capture full request and response bodies at the Obj-C delegate layer — *no SSL pinning bypass required, no proxy required.* Synthetic flows are normalized to the same shape as mitm flows so correlator / finders / replay / modules consume both uniformly.
3. **Correlation** — A scoring engine links every captured flow to the runtime call that produced it (class, method, stack, args).
4. **Static analysis via radare2** — `r2-mcp` exposes 15 r2 tools (functions, xrefs, decompilation, entitlements, strings) over a separate MCP server. `r2frida-mcp` adds live-process equivalents (heap search, module enumeration, selector tracing).
5. **Bug-bounty modules** — IDOR, auth bypass, mass assignment, parameter tampering, GraphQL introspection, JWT analysis. Modules emit **open hypotheses** on ambiguous results that the planner re-tests in an exploit phase.
6. **Secret-store finders** — keychain, NSHTTPCookieStorage, and NSUserDefaults events feed pattern detectors for JWT / AWS / Stripe / GitHub PAT / Slack tokens and PII (email / phone / SSN).
7. **Autonomous planner** — A rule-based loop (LLM fallback) decides what to inspect next, generates findings, retests hypotheses, and writes reproducible Markdown + JSON reports.

---

## Layout

```
openrecon/
├── agent/             # planner, workflow engine, correlation, finder rules
│   ├── frida_flow_normalizer.py   # Frida HTTP events → MitmFlow records
│   └── finders_secrets.py         # keychain / cookie / userdefaults / static
├── api/               # bug-bounty modules (IDOR, auth, mass assignment, GraphQL, ...)
│   ├── binary.py      # decrypted Mach-O acquisition via Frida
│   └── static.py      # in-process r2 wrapper for the planner
├── frida_layer/       # JS hooks + Python orchestrator (jailbroken-first)
│   └── hooks/
│       ├── url_session_body_tracer.js     # full req/resp bodies, no SSL bypass
│       ├── ns_url_connection_tracer.js    # NSURLConnection equivalent
│       └── binary_dump.js                 # FairPlay-aware Mach-O dumper
├── objection_layer/   # scripted Objection command sequences
├── mitm/
│   ├── vendor/        # forked snapspecter/mitmproxy-mcp (git subtree)
│   ├── addons/        # custom mitmproxy addons (correlation emitter, iOS filter)
│   └── client.py      # adds replay_synthetic() for Frida-sourced flows
├── r2_mcp/            # radare2 static analysis MCP server (stdio)
├── r2frida_mcp/       # r2frida live-process MCP server (stdio)
├── skills/
│   ├── _upstream/                                 # vendored Anthropic skills
│   └── ios-security-research/                     # top-level orchestrator skill
├── templates/         # finding.md.j2, finding.schema.json, engagement.example.yaml
├── docs/              # architecture.md, roadmap.md, workflows.md, r2-integration.md
├── .claude/           # settings.json (MCP servers), commands/
└── tests/             # 161 passing
```

---

## Quick start

**Prerequisites:** Python 3.12–3.13 · jailbroken iOS device with `frida-server` · mitmproxy CA cert installed on device · USB connection. **Optional:** `radare2` for static analysis tools.

```bash
git clone https://github.com/xtofuub/openrecon-ios
cd openrecon-ios

# Core install (pulls every dep needed to run the vendored mitmproxy-mcp).
pip install -e .

# With radare2 static-analysis MCP servers (adds r2pipe).
pip install -e .[r2]
# Then install r2 itself:
#   macOS/Linux: build from source — https://github.com/radareorg/radare2
#   Windows:     scoop install radare2

# Optional: r2frida plugin for live-process introspection.
r2pm -ci r2frida
```

### One-command MCP install

Register the three openrecon MCP servers with every AI agent you use:

```bash
openrecon-install-mcp                         # interactive — pick agents from a checklist
openrecon-install-mcp --agents all            # write to every detected agent
openrecon-install-mcp --agents codex,opencode # comma-separated subset
openrecon-install-mcp --dry-run               # show what would change, write nothing
```

Supported agents: **Claude Code · Cursor · Windsurf · Cline · OpenCode · Codex CLI · Continue · Zed.** The installer is idempotent (re-run any time), backs up the original config to `<file>.openrecon.bak`, and never touches keys outside `mcpServers` / `mcp_servers` / `context_servers`.

### Run an engagement

```bash
openrecon doctor                                       # verify frida-tools, objection, mitmdump
openrecon run --target com.example.targetapp --device usb
```

#### Common recipes

```bash
# Minimal probe — no mitm, just SSL/jailbreak bypass. Use when the app
# crashes under heavy instrumentation. AI / MCP can install more hooks live.
openrecon run --target com.example.app --device usb --hooks essential --no-mitm

# Full autonomous run with everything (default).
openrecon run --target com.example.app --device usb --budget 1800

# Custom hook subset for a hardened app — keep the surface tiny.
openrecon run --target com.example.app \
  --hooks ssl_pinning_bypass.js,url_session_tracer.js

# Skip auto-install of hooks entirely. The MCP server is up, the planner
# walks the rest of the phases, and your AI / agent decides which hooks to
# load via mcp tools while the engagement is live.
openrecon run --target com.example.app --hooks none

# Skip mitmproxy entirely (e.g. you want only Frida-side observation).
openrecon run --target com.example.app --no-mitm

# Use a non-default proxy port (avoids collision with a separately-running
# mitmweb GUI on 8080).
openrecon run --target com.example.app --mitm-port 8081

# Inspect captured traffic with the mitm GUI:
# Open a second terminal and run mitmweb pointed at the same data dir,
# OR (recommended) just point your phone at the openrecon proxy and call
# the MCP tools below (replay_flow, search_traffic, etc.) from your AI agent.
mitmweb --listen-port 8090 -r runs/<run_id>/mitm_flows.jsonl
```

#### MCP-driven AI workflow

Once the engagement is running, your AI agent can interrogate live traffic and process state through MCP without any further CLI involvement:

| Goal | MCP call |
|---|---|
| List captured HTTP flows | `openrecon-mitm` → `get_traffic_summary` / `inspect_flows` |
| Inspect one request + response | `openrecon-mitm` → `inspect_flow(flow_id, full_body=true)` |
| Replay with mutations | `openrecon-mitm` → `replay_flow(flow_id, headers_json, body)` |
| Fuzz an endpoint | `openrecon-mitm` → `fuzz_endpoint` |
| Hunt for auth pattern | `openrecon-mitm` → `detect_auth_pattern` |
| Static analysis of dumped Mach-O | `openrecon-r2` → `r2_open(path)` then `r2_functions` / `r2_xrefs` / `r2_decompile` |
| Live process classes / heap | `openrecon-r2frida` → `r2f_attach(pid)` then `r2f_classes` / `r2f_search_heap` |

### MCP servers

| Server | Command | Notes |
|---|---|---|
| `openrecon-mitm` | `python -m mitmproxy_mcp.core.server` (with `PYTHONPATH` to `mitm/vendor/src`) | Always available after `pip install -e .`. |
| `openrecon-r2` | `r2-mcp` | Needs `pip install -e .[r2]` + `radare2` on PATH. |
| `openrecon-r2frida` | `r2frida-mcp` | Needs `r2pm -ci r2frida` + `frida-server` running on the device. |

### iOSReplay (`iorpl`) — Playwright for iOS pentest

Sister tool living in this repo. Record an iOS app session once, replay it against a library of bounty-shaped mutations (IDOR swap, JWT alg=none, strip auth, mass assignment, method/verb tampering, …), get a HackerOne-ready report.

```bash
# 1. Record a session (re-uses openrecon's engagement runner).
iorpl record --target com.example.app --device usb --budget 300 -o session.iorpl

# 2. Or import an existing openrecon run dir.
iorpl import runs/01ABC... --target com.example.app -o session.iorpl

# 3. Browse what's bundled.
iorpl mutations list
iorpl suites list

# 4. Run a suite (built-in name or path to your YAML).
iorpl run session.iorpl --suite full --output results.jsonl

# 5. Render the report.
iorpl report results.jsonl --format md --output report.md
```

MCP server: `iorpl-mcp`. Tools: `iorpl_record`, `iorpl_import`, `iorpl_inspect`, `iorpl_run`, `iorpl_report`, `iorpl_list_mutations`, `iorpl_list_suites`. Registered automatically by `openrecon-install-mcp`.

Full guide: [docs/iorpl.md](docs/iorpl.md).

### Tool reference

#### `openrecon-mitm` (vendored mitmproxy-mcp)

`start_proxy`, `stop_proxy`, `set_scope`, `set_global_header`, `remove_global_header`, `get_traffic_summary`, `inspect_flow`, `inspect_flows`, `get_flow_schema`, `load_traffic_file`, `extract_from_flow`, `search_traffic`, `set_session_variable`, `extract_session_variable`, `clear_traffic`, `fuzz_endpoint`, `replay_flow`, `add_interception_rule`, `list_rules`, `clear_rules`, `list_tools`, `export_openapi_spec`, `get_api_patterns`, `detect_auth_pattern`, `generate_scraper_code`.

#### `openrecon-r2` (radare2 static analysis)

`r2_open`, `r2_close`, `r2_info`, `r2_functions`, `r2_strings`, `r2_xrefs`, `r2_imports`, `r2_exports`, `r2_classes`, `r2_methods`, `r2_entitlements`, `r2_decompile`, `r2_disasm`, `r2_search_bytes`, `r2_search_string`, `r2_cmd`.

#### `openrecon-r2frida` (radare2 attached to a live process)

`r2f_attach`, `r2f_detach`, `r2f_sessions`, `r2f_modules`, `r2f_classes`, `r2f_methods`, `r2f_resolve`, `r2f_search_heap`, `r2f_search_string`, `r2f_memdump`, `r2f_trace`, `r2f_trace_stop`, `r2f_traces`, `r2f_disasm`, `r2f_eval`, `r2f_cmd`.

### NSURLSession capture without SSL pinning bypass

The body tracers (`url_session_body_tracer.js`, `ns_url_connection_tracer.js`) hook the Obj-C delegate / completion-handler layer **after** the OS TLS stack has decrypted the bytes. They emit a single `flow.complete` event with full request + response, which `agent.frida_flow_normalizer.FridaFlowNormalizer` turns into a `MitmFlow` record. Synthetic flow IDs are namespaced `frida-*`.

All consumers — correlator, endpoint_map, IDOR / auth / mass_assignment modules, finder rules, replay — accept the synthetic flows transparently. `MitmClient.replay_flow(flow_id)` dispatches `frida-*` IDs to `replay_synthetic`, which re-issues the request via `httpx` and appends the result back to `mitm_flows.jsonl` with `tags=["replayed", "synthetic-replay"]`.

### Static + live binary analysis with radare2

`AcquireBinary` is part of the bootstrap sequence. It loads `binary_dump.js`, which:

1. Locates the main module via `Process.enumerateModules()`.
2. Reads the on-disk Mach-O.
3. For every `LC_ENCRYPTION_INFO[_64]` with `cryptid != 0`, splices the **decrypted** bytes from memory over the encrypted bytes in the file buffer and zeros `cryptid`.
4. Streams the patched binary back in 1 MB chunks.

The result lands at `runs/<run_id>/artifacts/app.macho`. Operators can also pre-populate this path with `bagbak` or `frida-ios-dump` output. The `r2-mcp` tools then operate on the decrypted binary; `r2frida-mcp` attaches to the running process for live introspection.

---

## Status

Phases 1–8 implemented. 161 tests passing across unit / orchestration / module / integration layers. See [docs/roadmap.md](docs/roadmap.md) for milestones, [docs/architecture.md](docs/architecture.md) for the design, and [docs/r2-integration.md](docs/r2-integration.md) for the static-analysis MCP servers.

## License

MIT for original code in this repo. Vendored upstream projects retain their own licenses — see [`mitm/vendor/LICENSE`](mitm/vendor/LICENSE) and [`skills/_upstream/anthropic-cybersecurity-skills/LICENSE`](skills/_upstream/anthropic-cybersecurity-skills/LICENSE).
