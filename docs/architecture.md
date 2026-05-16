# Architecture

## What this is

A bug-bounty toolkit for iOS that turns one recorded session into hundreds of deterministic + AI-driven attack tests. The headline tool is **iorpl** (record → replay → mutate → report). Everything else — the engagement runner, the Frida hook library, the mitmproxy bridge, the radare2 servers — is supporting infrastructure that iorpl uses to do its job.

## North star

> Record one iOS session. Find bug-bounty-shaped vulnerabilities deterministically. File HackerOne reports faster than a human can copy-paste.

Everything in this repo exists to make that one sentence true.

## Layered model

```
┌─────────────────────────────────────────────────────────────────────────┐
│                          iorpl   (the product)                          │
│                                                                          │
│  iorpl record  → iorpl run --suite … → iorpl report                     │
│       │                  │                       │                       │
│       ▼                  ▼                       ▼                       │
│  .iorpl archive    mutated requests +     Markdown / HTML +              │
│  (portable)        verdicts (JSONL)       HackerOne stubs                │
└──────────┬──────────────────────────────────────────┬───────────────────┘
           │                                          │
           │  records via                              │  reads/writes
           ▼                                          ▼
┌────────────────────────────────────────────┐  ┌────────────────────────┐
│  openrecon engagement   (the recorder)     │  │  iorpl/mutations.py    │
│                                            │  │  iorpl/ai_mutations.py │
│  • frida_layer/  — JS hooks + Python pump  │  │                        │
│  • mitm/         — vendored mitmproxy-mcp  │  │  11 built-in mutations │
│  • api/          — IDOR / auth / JWT etc.  │  │  + LLM creative mut    │
│  • agent/        — planner + correlator    │  │                        │
└────────────────────────────────────────────┘  └────────────────────────┘
           │                                          │
           └──────────────┬───────────────────────────┘
                          │
                          ▼  exposed to AI agents via MCP
            ┌─────────────────────────────────┐
            │  iorpl-mcp  •  openrecon-mitm   │
            │  openrecon-r2  •  openrecon-r2frida │
            └─────────────────────────────────┘
                          │
                          ▼
                  ┌──────────────────┐
                  │  iOS device (JB) │
                  │  frida-server    │
                  └──────────────────┘
```

## Where the value lives

| Layer | Responsibility | Why it's separate |
|---|---|---|
| **iorpl** | record-once / replay-many / mutate / report | The headline. Everything else exists to feed this. |
| **openrecon engagement** | spawn app, attach Frida, capture flows, dump binary | Reuse for every iorpl recording. Standalone-runnable for autonomous engagements. |
| **frida_layer/** | JS hook library + Python message pump | Pure capture surface. No bug-finding logic here. |
| **mitm/** | vendored mitmproxy-mcp + iOS addons | We didn't reinvent HTTP capture — we vendored the proxy MCP. Local patches only. |
| **api/** | IDOR / auth / mass-assignment / tamper / graphql / token modules | Stand-alone modules with a clean `ModuleInput`/`ModuleResult` contract. Run by the planner OR by hand. |
| **agent/** | planner + correlator + finder rules + reporter | The autonomous loop for openrecon's *engagement* mode. iorpl drives this for recording but skips it for replay. |
| **r2_mcp / r2frida_mcp** | radare2 static + r2frida live | Optional. Bolted on for AI agents that want richer analysis context. |

## Two execution paths

**1. iorpl path (recommended for bug bounty):**
```
iorpl record → .iorpl → iorpl run --suite … → results.jsonl → iorpl report
```
Linear, deterministic, AI-friendly, scriptable.

**2. openrecon engagement path (deep autonomous):**
```
openrecon run → planner phases → finder rules → runs/<id>/findings/
```
The classic autonomous mode. Useful for exploratory recon when you don't know what shape the bug will be.

iorpl's `record` step is a thin wrapper around the engagement path 1.

## Repo invariants

1. **Reuse over rewrite.** Vendor (`mitm/vendor/`, `skills/_upstream/`) is read-only. Patches stay local.
2. **Everything is JSON / JSONL.** No SQL-only state. SQLite indexes are rebuildable from the JSONL source of truth.
3. **Per-run directories.** No cross-engagement global state. `runs/<run_id>/` holds everything.
4. **Modules run standalone.** `python -m api.idor --run-dir runs/<id>` works. The planner is a thin orchestrator over composable steps.
5. **MCP first.** Every product surface (iorpl, openrecon, r2, r2frida) ships an MCP server so AI agents can drive without a shell.
6. **Jailbroken iOS today.** Non-JB Gadget paths are stubs we'll grow if needed.
7. **No safety gate.** The operator owns scope. We don't enforce `engagement.yaml` checks.

## Data flow — a typical bug-bounty run

```
1.  iorpl record --target com.example.app --device usb -o session.iorpl
        │
        ├─ agent/runner.run_engagement
        │   ├─ frida_layer/runner.FridaRunner.spawn_and_attach
        │   │     • load ssl_pinning_bypass.js + jailbreak_bypass.js
        │   │     • optionally url_session_body_tracer.js (in-app HTTPS capture)
        │   │     • optionally keychain / cookies / NSUserDefaults tracers
        │   ├─ device.resume(pid)                 ← unblocks the launch
        │   ├─ binary_dump.js                     → runs/<id>/artifacts/app.macho
        │   └─ pump_frida + pump_mitm             → runs/<id>/{frida_events,mitm_flows}.jsonl
        └─ iorpl/format.SessionArchive.from_run_dir + save  → session.iorpl

2.  iorpl run session.iorpl --suite full -o results.jsonl
        │
        ├─ iorpl/suite.Suite — filter flows by host/method/path/auth/status
        ├─ for each (flow, mutation):
        │     ├─ mutation.apply(flow, ctx)  → list[MutatedRequest]
        │     ├─ httpx.AsyncClient.request(mutated)
        │     └─ mutation.verdict(baseline, mutated, req)  → verdict + evidence
        └─ stream MutationResult to results.jsonl

3.  iorpl report results.jsonl --format md -o report.md
        └─ render grouped by verdict + HackerOne stubs
```

## Mutations as plug-ins

`iorpl/mutations.py` exposes a tiny base class:

```python
class Mutation:
    name: str = ""
    description: str = ""

    def apply(self, flow, ctx) -> Iterable[MutatedRequest]: ...
    def verdict(self, baseline, mutated, req) -> tuple[verdict_str, evidence_list]: ...
```

11 built-in mutations cover the deterministic bounty classes. `iorpl/ai_mutations.LLMCreativeMutation` adds an AI-driven proposer for logic / business-rule bugs. New mutations register via `register()`; suites pick them by name.

## What's deliberately NOT here

- A web UI. Reports are Markdown / HTML files.
- Android support. Possible later via a parallel `android_layer/`.
- A persistent multi-engagement database. Today: per-run directories.
- Non-JB Gadget IPA repackaging as a first-class path (stub only).
- Anti-tamper bypass beyond SSL pinning + jailbreak detection. Hardened apps (Instagram, banking) may still self-terminate on attach.
