# Skills

This directory is the knowledge layer Claude Code loads for iOS security work.

| Path | Purpose |
|---|---|
| `ios-security-research/SKILL.md` | Top-level orchestrator. Triggers on iOS engagement language. Tells Claude how to drive `lolmcp`. |
| `reverse-engineering-ios-app-with-frida/SKILL.md` | Thin wrapper around the upstream Anthropic Frida skill. |
| `analyzing-ios-app-security-with-objection/SKILL.md` | Thin wrapper around the upstream Anthropic Objection skill. |
| `_upstream/anthropic-cybersecurity-skills/` | Vendored upstream skills (git subtree from mukul975/Anthropic-Cybersecurity-Skills). Do not edit in place. |

## Adding a new skill

1. Create `skills/<name>/SKILL.md` with frontmatter `name`, `description`.
2. Use the description to declare clear trigger conditions (Claude Code uses it to decide whether to load the skill).
3. Reference shared knowledge from `docs/` rather than duplicating it.
4. Don't put procedural detail in here that belongs in code — link to the module instead.

## Updating the upstream vendor

After `git subtree pull` of `_upstream/anthropic-cybersecurity-skills`, re-read the wrapper SKILL.md files in this directory and update any links if the upstream layout changed.
