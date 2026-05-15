---
description: Re-render findings for an existing run.
argument-hint: <run_id>
---

Re-render the run report after a template tweak or finding edit:

```
lolmcp report $ARGUMENTS
```

Open `runs/$ARGUMENTS/report.md`, validate every `runs/$ARGUMENTS/findings/*.json` against `templates/finding.schema.json`, and surface any validation errors as fix-it suggestions.
