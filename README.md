# lolmcp — Autonomous iOS Security Research Platform

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
lolmcp/
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

```bash
# Prerequisites: Python 3.12 or 3.13, a jailbroken iOS device with frida-server,
#                CA cert installed on the device, USB connection.

# 1. Install dependencies (uv recommended; pip also works)
uv sync

# 2. Vendor the upstream projects (one-time, see docs/roadmap.md)
git subtree add --prefix=mitm/vendor https://github.com/snapspecter/mitmproxy-mcp main --squash
git subtree add --prefix=skills/_upstream/anthropic-cybersecurity-skills \
    https://github.com/mukul975/Anthropic-Cybersecurity-Skills main --squash

# 3. Launch an engagement
lolmcp run --target com.example.targetapp --device usb
```

Claude Code session: open this repo, the top-level `ios-security-research` skill auto-triggers when you describe an iOS engagement.

---

## Status

Phase 1 scaffolding. See [docs/roadmap.md](docs/roadmap.md) for milestones and [docs/architecture.md](docs/architecture.md) for the design.

## License

MIT for original code in this repo. Vendored upstream projects retain their own licenses (see `mitm/vendor/LICENSE` and `skills/_upstream/*/LICENSE` after vendoring).
