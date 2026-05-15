# MCP Integration Plan

The proxy capability ships as an MCP server. We fork `snapspecter/mitmproxy-mcp` (MIT) and vendor it under `mitm/vendor/`. Claude Code talks to it over stdio. Our `agent/runner.py` and `api/` modules talk to it through a thin async client at `mitm/client.py`.

## Why we fork

- The project is solid (v0.6.0, May 2026, 20+ tools, active maintenance).
- We need a path-traversal patch on `load_traffic_file` (upstream issue #16).
- We need iOS-specific addons (`correlation_emitter`, `ios_filter`) that don't fit upstream's scope.
- We want freedom to add tools without an upstream PR cycle.

We avoid hard-forking publicly — instead vendor as `git subtree --squash` so the history stays in our repo and we can `subtree pull` for upstream updates.

## What the vendored server exposes

Tools we use as-is:

| Tool | Use |
|---|---|
| `start_proxy(port, scope)` | begin capture, scoped to target host |
| `stop_proxy()` | end |
| `set_scope(host_regex)` | narrow capture mid-engagement |
| `get_traffic_summary()` | quick listing for the planner |
| `inspect_flow(flow_id)` | full request + response |
| `search_traffic(query)` | regex/CSS search over captured flows |
| `replay_flow(flow_id, overrides)` | core mutation primitive (curl-cffi TLS fingerprinting) |
| `extract_from_flow(flow_id, jsonpath_or_css)` | structured extraction |
| `fuzz_endpoint(flow_id, mutator)` | upstream fuzzer (we extend in `api/tamper.py`) |
| `detect_auth_pattern()` | classify auth scheme across flows |
| `set_session_variable(name, value)` | persist token across replays |
| `extract_session_variable(name, from_flow, jsonpath)` | capture token |
| `export_openapi_spec(host)` | mapping artifact |
| `add_interception_rule(rule)` | live request mutation |
| `set_global_header(name, value)` | e.g. force auth header on every replay |
| `clear_traffic()`, `clear_rules()` | reset |

Tools we add (in `mitm/addons/` registered through the vendor's plugin loader):

| New tool | Purpose |
|---|---|
| `ios_install_ca(device_id)` | guide the operator (or run libimobiledevice) to install the mitmproxy CA on a paired iOS device |
| `ios_set_wifi_proxy(device_id, host, port)` | flip the WiFi proxy via libimobiledevice |
| `ios_dump_har(filter)` | filtered HAR export with iOS heuristics applied |
| `correlate_with_frida(flow_id)` | call back into `agent/query.py` to enrich a flow with the matched Frida event |

## Transport

stdio. The vendor server is started as a subprocess by Claude Code via `.claude/settings.json`. For programmatic access from the planner, `mitm/client.py` starts its own stdio subprocess and speaks MCP via the `mcp` Python SDK.

Why not SSE / Streamable HTTP? stdio is what Claude Code defaults to and what the planner needs anyway (single process tree, easy lifecycle). No reason to add network surface for an in-process tool.

## Registration

`.claude/settings.json`:

```json
{
  "mcpServers": {
    "openrecon-mitm": {
      "command": "python",
      "args": ["-m", "mitm.vendor.src.mitmproxy_mcp", "--addons", "mitm/addons/correlation_emitter.py", "mitm/addons/ios_filter.py"],
      "env": {
        "openrecon_RUN_DIR": "${openrecon_RUN_DIR:-runs/_default}"
      }
    }
  }
}
```

The `openrecon_RUN_DIR` env var tells our addons where to append JSONL. The runner sets it per engagement.

## Patches we carry

Tracked in `docs/vendor-patches.md`. After every `git subtree pull`, the operator must:

1. Re-run the patch script (`scripts/apply_vendor_patches.py`) if it exists.
2. Verify the path-traversal fix is still in place.
3. Run the vendor's tests under `mitm/vendor/tests/` (vendor-side) plus our integration tests (`tests/test_mitm_integration.py`).

### Patch 1 — `load_traffic_file` path traversal (upstream #16)

```python
# mitm/vendor/src/mitmproxy_mcp/core/server.py:324
def load_traffic_file(file_path: str) -> ...:
    p = pathlib.Path(file_path).resolve()
    allowed_root = pathlib.Path(os.environ.get("openrecon_RUN_DIR", ".")).resolve()
    if allowed_root not in p.parents and p != allowed_root:
        raise ValueError(f"path {p} outside allowed root {allowed_root}")
    ...
```

## Client architecture

`mitm/client.py`:

```python
class MitmClient:
    """Async client to the vendored mitmproxy-mcp server.

    Used by api/ modules to replay/mutate flows, by agent/steps.py to start
    and stop the proxy, by agent/runner.py to orchestrate. The class hides
    the stdio transport and MCP protocol; callers see typed async methods.
    """

    async def start_proxy(self, port: int = 8080, scope: list[str] | None = None) -> None: ...
    async def replay_flow(self, flow_id: str, *, overrides: ReplayOverrides | None = None) -> ReplayResult: ...
    async def extract(self, flow_id: str, *, jsonpath: str | None = None, css: str | None = None) -> Any: ...
    async def detect_auth(self) -> AuthPattern: ...
    async def fuzz(self, flow_id: str, mutator: str) -> list[ReplayResult]: ...
    async def list_flows(self, *, since: float | None = None) -> list[str]: ...
```

Two consumer patterns:

- **Long-lived client** for the planner — one `MitmClient` per engagement.
- **One-shot client** for `python -m api.idor` standalone runs — context-managed, spawns + tears down its own subprocess.

## Integration test plan

`tests/test_mitm_integration.py` runs the vendored server against a recorded HAR fixture in `tests/fixtures/`. Verifies:

- `start_proxy` returns within 3s.
- `replay_flow` with `{"headers": {"X-Test": "1"}}` produces a flow with that header.
- `correlate_with_flow` returns a matching Frida event when one exists in the fixture.
- `load_traffic_file("../../../etc/passwd")` returns `ValueError` (regression test for upstream #16).
