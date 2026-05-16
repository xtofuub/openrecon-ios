# MCP servers

The project ships four [MCP](https://modelcontextprotocol.io/) stdio servers. They're independent — install the ones you want and ignore the rest. Each one is a console script created by `pip install -e .`.

| Server | Console script | What it does | Required |
|---|---|---|---|
| `iorpl` | `iorpl-mcp` | record/replay/mutate iOS sessions, render bounty reports | always |
| `openrecon-mitm` | `python -m mitmproxy_mcp.core.server` | mitmproxy proxy + flow inspection + replay | always |
| `openrecon-r2` | `r2-mcp` | radare2 static analysis on dumped Mach-O | optional |
| `openrecon-r2frida` | `r2frida-mcp` | radare2 attached to live process via frida:// | optional |

## One-command install

```bash
# Interactive picker — detects every supported agent on the host
openrecon-install-mcp

# Non-interactive
openrecon-install-mcp --agents claude,cursor,opencode,codex
openrecon-install-mcp --agents all
```

Supported agents: Claude Code · Cursor · Windsurf · Cline · OpenCode · Codex CLI · Continue · Zed. Installer is idempotent and writes a `.openrecon.bak` of each config file before editing.

## Manual install

```jsonc
// ~/.claude/settings.json (or your agent's equivalent)
{
  "mcpServers": {
    "iorpl":              { "command": "iorpl-mcp",      "args": [] },
    "openrecon-mitm":     { "command": "python",          "args": ["-m", "mitmproxy_mcp.core.server"],
                            "env": { "PYTHONPATH": "mitm/vendor/src:." } },
    "openrecon-r2":       { "command": "r2-mcp",          "args": [] },
    "openrecon-r2frida":  { "command": "r2frida-mcp",     "args": [] }
  }
}
```

## Tool catalogue

### iorpl — record/replay/mutate

`iorpl_record`, `iorpl_import`, `iorpl_inspect`, `iorpl_run`, `iorpl_report`, `iorpl_list_mutations`, `iorpl_list_suites`.

Full guide: [iorpl.md](iorpl.md).

### openrecon-mitm — mitmproxy

`start_proxy`, `stop_proxy`, `set_scope`, `set_global_header`, `remove_global_header`, `get_traffic_summary`, `inspect_flow`, `inspect_flows`, `get_flow_schema`, `load_traffic_file`, `extract_from_flow`, `search_traffic`, `set_session_variable`, `extract_session_variable`, `clear_traffic`, `fuzz_endpoint`, `replay_flow`, `add_interception_rule`, `list_rules`, `clear_rules`, `list_tools`, `export_openapi_spec`, `get_api_patterns`, `detect_auth_pattern`, `generate_scraper_code`.

### openrecon-r2 — radare2 static

`r2_open`, `r2_close`, `r2_info`, `r2_functions`, `r2_strings`, `r2_xrefs`, `r2_imports`, `r2_exports`, `r2_classes`, `r2_methods`, `r2_entitlements`, `r2_decompile`, `r2_disasm`, `r2_search_bytes`, `r2_search_string`, `r2_cmd`.

Install: `pip install -e .[r2]` + a working `r2` binary on PATH (macOS/Linux: build from source; Windows: `scoop install radare2`).

### openrecon-r2frida — live process

`r2f_attach`, `r2f_detach`, `r2f_sessions`, `r2f_modules`, `r2f_classes`, `r2f_methods`, `r2f_resolve`, `r2f_search_heap`, `r2f_search_string`, `r2f_memdump`, `r2f_trace`, `r2f_trace_stop`, `r2f_traces`, `r2f_disasm`, `r2f_eval`, `r2f_cmd`.

Install: `r2pm -ci r2frida` + a `frida-server` running on the device.

## Troubleshooting

| Symptom | Fix |
|---|---|
| `Cannot find radare2 in PATH` | Install r2 + verify `r2 -v`. On Windows the scoop shim is at `~/scoop/shims/r2.exe`. |
| `r2frida plugin not installed` | `r2pm -ci r2frida` then `r2pm -l | grep r2frida` |
| `r2pipe failed to attach via frida://...` | `frida-server` isn't running on the device, or no USB. `frida-ls-devices` to verify. |
| `r2frida: Frida host <=> server version mismatch` | Match the frida-server version on device to the frida-core embedded in your r2frida plugin (release notes list it). |
| Wrong slice on a fat binary | `R2Session.is_fat_binary()` detects it; pass `flags=["-a", "arm64"]` when opening. |
| Connection-closed on script load | A Frida hook is doing too much synchronous work. Defer via `setImmediate` or split into multiple smaller scripts. |
