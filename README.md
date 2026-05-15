# openrecon — Autonomous iOS Security Research Platform

A unified Claude Code-driven workflow that fuses **Frida**, **Objection**, and a forked **MITMProxy MCP** into one autonomous mobile security analyst.

The platform inspects an iOS app at runtime, captures and mutates its network traffic, correlates the two, and produces structured findings — IDOR, auth bypass, mass assignment, API tampering, GraphQL abuse, and token weaknesses.

> Use only against targets you own or are explicitly authorized to test. No safety gate is enforced; the operator is responsible for scope.

---

## What it does

1. **Runtime inspection** — Frida hooks (Objective-C / Swift) and Objection recon on a jailbroken iOS device.
2. **Traffic capture** — MITMProxy MCP intercepts HTTPS, replays flows with TLS fingerprinting, fuzzes endpoints.
3. **Correlation** — A scoring engine links every captured flow to the runtime call that produced it (class, method, stack, args).
4. **Bug-bounty modules** — IDOR, auth bypass, mass assignment, parameter tampering, GraphQL introspection, JWT analysis.
5. **Autonomous planner** — A rule-based loop (LLM fallback) decides what to inspect next, generates findings, and writes reproducible Markdown + JSON reports.

---

## Layout

```
openrecon/
├── agent/         # planner, workflow engine, correlation, finding generator
├── api/           # bug-bounty modules (IDOR, auth, mass assignment, GraphQL, ...)
├── frida_layer/   # JS hooks + Python orchestrator (jailbroken-first)
├── objection_layer/   # scripted Objection command sequences
├── mitm/
│   ├── vendor/    # forked snapspecter/mitmproxy-mcp (git subtree)
│   └── addons/    # custom mitmproxy addons (correlation emitter, iOS filter)
├── skills/
│   ├── _upstream/                                 # vendored Anthropic skills
│   ├── reverse-engineering-ios-app-with-frida/    # wrapper -> _upstream
│   ├── analyzing-ios-app-security-with-objection/ # wrapper -> _upstream
│   └── ios-security-research/                     # top-level orchestrator skill
├── templates/     # finding.md.j2, finding.schema.json, engagement.example.yaml
├── reports/       # run outputs (gitignored)
├── docs/          # architecture.md, roadmap.md, workflows.md, ...
├── .claude/       # settings.json (MCP servers), commands/
└── tests/
```

---

## Quick start

**Prerequisites:** Python 3.12–3.13 · jailbroken iOS device with `frida-server` · mitmproxy CA cert installed on device · USB connection

```bash
git clone https://github.com/xtofuub/openrecon-ios
cd openrecon-ios
uv sync              # or: pip install -e .
openrecon doctor     # verify frida-tools, objection, mitmdump
openrecon run --target com.example.targetapp --device usb
```

Everything is already bundled — `mitm/vendor/` (mitmproxy-mcp) and `skills/_upstream/` (Anthropic iOS skills) ship in the repo. No extra setup commands.

**Claude Code:** open this folder. The `ios-security-research` skill auto-triggers on iOS engagement language. The MCP server (`openrecon-mitm`) starts automatically via `.claude/settings.json`.

**MCP only (no Claude Code):** point your MCP client at:
```json
{
  "command": "python",
  "args": ["-m", "mitmproxy_mcp.core.server"],
  "env": { "PYTHONPATH": "mitm/vendor/src:." }
}
```

---

## Status

Phase 1 scaffolding. See [docs/roadmap.md](docs/roadmap.md) for milestones and [docs/architecture.md](docs/architecture.md) for the design.

## License

MIT for original code in this repo. Vendored upstream projects retain their own licenses — see [`mitm/vendor/LICENSE`](mitm/vendor/LICENSE) and [`skills/_upstream/anthropic-cybersecurity-skills/LICENSE`](skills/_upstream/anthropic-cybersecurity-skills/LICENSE).
