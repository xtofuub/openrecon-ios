---
description: Start an autonomous iOS engagement.
argument-hint: <bundle_id> [--budget seconds]
---

You are starting a fresh iOS security engagement. Follow this sequence:

1. Run `openrecon doctor` first — confirm frida, objection, mitmdump, and vendored projects are present.
2. Start the engagement:
   ```
   openrecon run --target $ARGUMENTS
   ```
3. Tail `runs/<run_id>/state.json` as it updates. Watch the phase transitions.
4. When the run reaches the `report` phase, read `runs/<run_id>/report.md` and summarize findings for the user — group by severity, link to each finding's Markdown file.
5. If any high or critical finding is present, suggest a `openrecon replay <finding_id>` confirmation.

Don't fabricate findings. If `openrecon run` errors before reaching mapping, debug the cause (device offline, proxy not intercepting, target not launching) and report back honestly.
