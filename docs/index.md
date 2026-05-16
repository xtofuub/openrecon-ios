# Docs

Start with the [README](../README.md) for the value prop and quickstart. The pages below go deeper.

| Doc | When to read |
|---|---|
| [iorpl.md](iorpl.md) | Full user guide for `iorpl record / run / report` — the headline tool. |
| [architecture.md](architecture.md) | How the pieces fit. iorpl on top, engagement runner + MCP servers underneath. |
| [mcp.md](mcp.md) | Setting up all four MCP servers in Claude Code / Cursor / Codex / etc. |

## File map

```
.
├── iorpl/                  the record/replay/mutate product
│   ├── format.py             .iorpl archive R/W
│   ├── record.py             wrap an openrecon engagement
│   ├── mutations.py          deterministic mutation library
│   ├── ai_mutations.py       LLM creative mutation
│   ├── suite.py              YAML suite loader
│   ├── replay.py             ReplayEngine
│   ├── report.py             render results to MD / HTML + H1 stubs
│   ├── cli.py                Click CLI (iorpl …)
│   ├── server.py             FastMCP server (iorpl-mcp)
│   └── suites/               bundled YAML suites (idor, auth, full, llm)
│
├── agent/                  openrecon engagement runner (recorder)
│   ├── runner.py             async engagement loop
│   ├── planner.py            phase machine
│   ├── steps.py              workflow primitives
│   ├── correlate.py          frida↔mitm correlation
│   ├── finder.py             pattern rules (autonomous mode)
│   ├── store.py              JSONL store + SQLite indexes
│   └── cli.py                openrecon …
│
├── frida_layer/            JS hooks + Python pump
│   ├── runner.py
│   └── hooks/*.js            ssl_pinning, jailbreak_bypass, body tracers, …
│
├── mitm/                   vendored mitmproxy-mcp + iOS addons
│   ├── client.py
│   ├── addons/
│   └── vendor/               git subtree, READ-ONLY
│
├── api/                    bug-bounty modules (IDOR / auth / mass / tamper / GraphQL / token)
│
├── r2_mcp/                 radare2 static-analysis MCP server
├── r2frida_mcp/            r2frida live-process MCP server
│
└── tests/                  185+ tests across unit / module / orchestration / integration
```

## When to use what

| Goal | Tool |
|---|---|
| One bug-bounty engagement on a target iOS app | `iorpl record` → `iorpl run` → `iorpl report` |
| Autonomous multi-phase exploration (no fixed playbook) | `openrecon run` |
| Static analysis on the dumped Mach-O | `r2-mcp` tools (`r2_functions`, `r2_xrefs`, `r2_entitlements`, …) |
| Live process introspection via Frida + r2 | `r2frida-mcp` tools (`r2f_attach`, `r2f_classes`, …) |
| Drop everything into Claude Code / Cursor | `openrecon-install-mcp` then talk to the agent |
