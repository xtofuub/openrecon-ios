---
description: Run the IDOR module against a recorded run.
argument-hint: <run_id> <baseline_flow_id> [<baseline_flow_id> ...]
---

Run the IDOR module standalone against an existing run:

```
python -m api.idor --run-dir runs/$1 $(for f in ${@:2}; do echo "--baseline $f"; done)
```

After it completes, read the new entries in `runs/$1/findings.jsonl` (filter `category == "idor"`) and summarize each: severity, mutated position, mutated value, response status. Quote the diff for any high-severity finding.
