# radare2 + r2frida integration

openrecon ships two standalone MCP servers that expose radare2 to AI agents:

| Server | Module | Purpose |
|---|---|---|
| `r2-mcp` | `r2_mcp.server` | Static analysis on a decrypted Mach-O. One r2 session per binary, kept hot across tool calls. |
| `r2frida-mcp` | `r2frida_mcp.server` | r2 attached to a running process via the `frida://` IO plugin. Live memory, ObjC runtime, tracing. |

Both are FastMCP stdio servers. The Python package `openrecon` exposes them as console scripts (`r2-mcp` and `r2frida-mcp`) and `.claude/settings.json` registers them so Claude Code can call their tools directly.

## Install

1. **radare2** — install on the host. On macOS / Linux build from source ([radareorg/radare2](https://github.com/radareorg/radare2)). On Windows use `scoop install radare2`. Verify with `r2 -v`.
2. **r2pipe (Python)** — installed via the extras:
   ```bash
   pip install -e .[r2]
   ```
3. **r2frida plugin (optional, for live process)** — installed via radare2's package manager:
   ```bash
   r2pm -ci r2frida
   r2pm -l | grep r2frida   # verify
   ```
   r2frida talks to `frida-server` on the device. Make sure that is running and the device is enumerated by `frida-ls-devices`.

## Tool catalogue

### r2-mcp — static

| Tool | What it does |
|---|---|
| `r2_open(binary_path, analyze=true)` | Open a binary. Runs `aaa` once and caches the session. |
| `r2_info` | Bin info, sections, segments. |
| `r2_functions(limit=500)` | Function list (name, offset, size, complexity, callrefs). |
| `r2_strings(min_len=4, whole=false)` | Strings (`izj` / `izzj`). |
| `r2_xrefs(target, direction)` | `axtj` / `axfj` — who calls / where it points. |
| `r2_imports` / `r2_exports` | Symbol tables. |
| `r2_classes` / `r2_methods(class_name)` | ObjC layout from the Mach-O. |
| `r2_entitlements` | Parses `LC_CODE_SIGNATURE` blob for the entitlement plist. |
| `r2_decompile(target, engine=auto)` | Pseudocode via `pdc` (native), `pdd` (r2dec), or `pdg` (r2ghidra). Auto picks the best available. |
| `r2_disasm(target, count=64)` | Disassembly window. |
| `r2_search_bytes(pattern)` | Hex byte-pattern search. |
| `r2_search_string(needle)` | String search. |
| `r2_cmd(command, parse_json=false)` | Escape hatch — any r2 command. |
| `r2_close(binary_path)` | Drop a session from the registry. |

### r2frida-mcp — live process

| Tool | What it does |
|---|---|
| `r2f_attach(target, device=None)` | Attach via `frida://<device>/<pid_or_bundle>`. |
| `r2f_detach(target, device)` | Detach and clean up. |
| `r2f_sessions` | List active attachments. |
| `r2f_modules` | Loaded modules with base/size. |
| `r2f_classes(filter)` | Live ObjC classes. |
| `r2f_methods(class_name)` | Selectors for one class. |
| `r2f_resolve(symbol)` | Symbol → address. |
| `r2f_search_heap(pattern)` | Hex search on heap regions. |
| `r2f_search_string(needle)` | String search. |
| `r2f_memdump(address, size, encoding)` | Read process memory. |
| `r2f_trace(target_selector)` | Stalker-based trace. |
| `r2f_trace_stop(target_selector)` | Stop a trace. |
| `r2f_traces` | List active traces. |
| `r2f_disasm(address, count)` | Disassemble live code. |
| `r2f_eval(js)` | Inline Frida JS via `:eval`. |
| `r2f_cmd(command, parse_json)` | Escape hatch. |

## Binary acquisition

The planner's `AcquireBinary` step runs after `LaunchTarget` and writes the decrypted main binary to `runs/<run_id>/artifacts/app.macho`. The Frida hook `binary_dump.js` performs FairPlay decryption inline (see `README.md` for the algorithm). The step is idempotent — pre-populating the path with `bagbak` or `frida-ios-dump` output skips the live dump.

## In-process wrapper

For planner / finder rules that don't want to pay the MCP stdio round-trip, `api.static` re-uses the same `R2Session` registry:

```python
from api.static import open_binary, find_hardcoded_urls, find_high_entropy_secrets

session = open_binary(run_dir / "artifacts" / "app.macho")
urls = find_hardcoded_urls(session)
secrets = find_high_entropy_secrets(session)   # {"aws": [...], "stripe": [...], "jwt": [...]}
```

`StaticBinarySecretsRule` (in `agent/finders_secrets.py`) consumes these helpers automatically and emits findings for hard-coded URLs / AWS-style keys / Stripe keys / JWTs.

## Failure modes

| Symptom | Likely cause | Fix |
|---|---|---|
| `r2pipe not installed` | Skipped the `[r2]` extra. | `pip install -e .[r2]` |
| `r2 -v` not found | r2 binary not on PATH. | Install radare2; add its `bin/` to PATH. |
| `r2frida plugin not installed` | r2pm package missing. | `r2pm -ci r2frida` |
| `r2pipe failed to attach via frida://...` | `frida-server` not running or device not paired. | `frida-ls-devices` to verify; restart server on device. |
| Wrong slice on fat binary | r2 picks the wrong arch by default. | Use `R2Session.is_fat_binary()` to detect; open with `r2pipe.open(path, flags=["-a", "arm64"])`. (Hook into `R2Session._open` if you regularly hit this.) |
