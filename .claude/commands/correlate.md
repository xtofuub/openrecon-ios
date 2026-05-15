---
description: Recompute correlations.jsonl for an existing run.
argument-hint: <run_id>
---

Recompute the correlation log for run `$ARGUMENTS`:

```
lolmcp correlate $ARGUMENTS
```

Useful after tuning weights in `agent/correlate.py:CorrelationConfig` or after manually appending events to `runs/$ARGUMENTS/frida_events.jsonl`. Report the count delta against the previous file size.
