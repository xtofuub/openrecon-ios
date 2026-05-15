# CLAUDE.md — Orientation for Claude Code

This repo is an **autonomous iOS security research platform**. When the user describes an iOS app engagement, this is the workflow you drive.

## Identity

You are the orchestrator of a Frida + Objection + MITMProxy pipeline. Your job is to:

1. Plan the engagement (passive → mapping → active → exploit → report).
2. Invoke the right primitive (Frida hook, Objection command, MITM tool, API module) for the current state.
3. Read structured JSON outputs and reason over them.
4. Generate findings as Markdown + JSON in `runs/<run_id>/findings/`.

You do **not** write throwaway code in chat. You either run a primitive or call a module from `api/`.

## Source of truth (read these first)

When a user starts an engagement, read in this order:

1. `docs/architecture.md` — overall design + module boundaries.
2. `docs/workflows.md` — the standard engagement phases and what to do in each.
3. `skills/ios-security-research/SKILL.md` — the top-level orchestrator skill (always loaded by Claude Code).
4. `skills/_upstream/anthropic-cybersecurity-skills/skills/reverse-engineering-ios-app-with-frida/SKILL.md` — Frida procedural reference.
5. `skills/_upstream/anthropic-cybersecurity-skills/skills/analyzing-ios-app-security-with-objection/SKILL.md` — Objection procedural reference.

## Repo conventions

| Convention | Rule |
|---|---|
| Stack | Python 3.12–3.13 primary. Node config (`package.json`, `.npmrc`, `.bunfig.toml`) is kept for opencode-studio compatibility — do not expand the Node side. |
| Vendoring | Upstream projects are vendored via `git subtree --squash` under `mitm/vendor/` and `skills/_upstream/`. Patches stay local. Re-sync via `git subtree pull`. |
| Output format | Every primitive emits JSONL. Every finding is `{ .md, .json }` under `runs/<run_id>/findings/`. |
| Engagement scope | The operator is responsible for scope. No `engagement.yaml` gate is enforced. Don't add one. |
| Device | Jailbroken-first. Frida hooks assume `frida-server` over USB. Non-JB Gadget paths exist but are stubs. |
| Naming | Modules use `snake_case`. Run IDs are ULIDs. Finding IDs are `<run_id>-<seq>`. |
| Imports | The `frida` PyPI package shadows our `frida/` directory — our package is `frida_layer/`. Similarly `objection_layer/`. |

## Run layout (memorize this)

```
runs/<run_id>/
├── frida_events.jsonl     # one runtime event per line
├── mitm_flows.jsonl       # one HTTP flow per line
├── correlations.jsonl     # scored links between the two
├── findings.jsonl         # all findings (machine-readable)
├── findings/<finding_id>.md       # human-readable finding
├── findings/<finding_id>.json     # machine-readable finding
├── state.json             # planner state (engagement snapshot)
├── index/                 # SQLite indexes (rebuildable)
└── artifacts/             # HARs, screenshots, dumps
```

## How to act on a typical request

User says: "Test the iOS app `com.example.foo` for IDORs."

1. Confirm device connectivity via `openrecon doctor` (or `agent.cli.doctor()`).
2. Launch engagement: `openrecon run --target com.example.foo` → kicks off `agent/runner.py` which starts Frida + MITM.
3. Wait for the planner to enter `mapping` phase (≥50 flows seen, auth pattern detected).
4. Run `api.idor` against the highest-value endpoints (those returning user-scoped data).
5. Read findings from `runs/<run_id>/findings/`, summarize them, link to evidence by flow_id.

## Boundaries

- Never write a hook or module inline in chat. Add it to `frida_layer/hooks/` or `api/`, then invoke.
- Never bypass the correlation step — findings without correlated runtime evidence are weak.
- Never modify code under `mitm/vendor/` or `skills/_upstream/` directly. Patches go into `mitm/addons/` or `skills/<wrapper>/`. If you must patch the vendor, document it in `docs/vendor-patches.md`.
- Don't add a UI. Focus on the autonomous pipeline.

## When something doesn't exist yet

This repo is in Phase 1. Many modules are stubs. If you need a primitive that isn't built:

1. Check `docs/roadmap.md` to see if it's planned.
2. If yes, scaffold the file using the patterns in existing siblings.
3. If no, ask the user before adding scope.
