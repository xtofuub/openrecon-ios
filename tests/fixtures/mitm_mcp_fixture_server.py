"""Small MCP fixture server that mimics the vendored mitmproxy-mcp surface.

It lets the integration tests exercise stdio transport and client-side response
normalization without depending on a live mitmproxy process.
"""

from __future__ import annotations

import copy
import json
import re
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("Recorded MITM Fixture")
flows: dict[str, dict[str, Any]] = {}
session_variables: dict[str, str] = {}
allowed_domains: list[str] = []


def _headers(items: list[dict[str, str]]) -> dict[str, str]:
    return {item["name"]: item["value"] for item in items}


def _body_from_request(request: dict[str, Any]) -> str | None:
    post_data = request.get("postData") or {}
    return post_data.get("text")


def _body_from_response(response: dict[str, Any]) -> str | None:
    content = response.get("content") or {}
    return content.get("text")


def _read_har(file_path: str) -> dict[str, Any]:
    return json.loads(Path(file_path).read_text(encoding="utf-8"))


def _entry_to_flow(entry: dict[str, Any], index: int) -> dict[str, Any]:
    request = entry["request"]
    response = entry.get("response") or {}
    flow_id = entry.get("comment") or f"flow-{index}"
    return {
        "id": flow_id,
        "request": {
            "method": request["method"],
            "url": request["url"],
            "headers": _headers(request.get("headers", [])),
            "body_preview": _body_from_request(request),
        },
        "response": {
            "status_code": response.get("status"),
            "headers": _headers(response.get("headers", [])),
            "body_preview": _body_from_response(response),
        },
        "_timestamp": time.time() + index,
    }


def _in_scope(url: str, scope: list[str] | None) -> bool:
    if not scope:
        return True
    host = urlparse(url).hostname or ""
    return any(host == item or host.endswith(f".{item}") for item in scope)


def _public_flow(flow: dict[str, Any]) -> dict[str, Any]:
    return {key: copy.deepcopy(value) for key, value in flow.items() if not key.startswith("_")}


def _summary(limit: int) -> list[dict[str, Any]]:
    ordered = sorted(flows.values(), key=lambda flow: float(flow["_timestamp"]), reverse=True)
    out: list[dict[str, Any]] = []
    for flow in ordered[:limit]:
        response = flow.get("response") or {}
        body = response.get("body_preview") or ""
        out.append(
            {
                "id": flow["id"],
                "url": flow["request"]["url"],
                "method": flow["request"]["method"],
                "status_code": response.get("status_code"),
                "content_type": response.get("headers", {}).get("Content-Type", "unknown"),
                "size": len(body),
                "timestamp": flow["_timestamp"],
            }
        )
    return out


@mcp.tool()
async def start_proxy(port: int = 8080) -> str:
    return f"Started proxy on port {port}"


@mcp.tool()
async def stop_proxy() -> str:
    return "Stopped the proxy."


@mcp.tool()
async def set_scope(allowed_domains: list[str]) -> str:
    globals()["allowed_domains"] = list(allowed_domains)
    tracked = ", ".join(allowed_domains) if allowed_domains else "everything"
    return f"Updated. Now tracking: {tracked}"


@mcp.tool()
async def load_traffic_file(file_path: str, append: bool = False, scope: str | None = None) -> str:
    if not append:
        flows.clear()
    scope_list = [item.strip() for item in scope.split(",") if item.strip()] if scope else None
    data = _read_har(file_path)
    imported = 0
    skipped = 0
    for index, entry in enumerate(data["log"]["entries"], start=1):
        if not _in_scope(entry["request"]["url"], scope_list):
            skipped += 1
            continue
        flow = _entry_to_flow(entry, index)
        flows[flow["id"]] = flow
        imported += 1
    return json.dumps({"status": "ok", "imported": imported, "skipped": skipped, "errors": 0})


@mcp.tool()
async def get_traffic_summary(limit: int = 20) -> str:
    return json.dumps(_summary(limit), indent=2)


@mcp.tool()
async def inspect_flow(flow_id: str, full_body: bool = False) -> str:
    flow = flows.get(flow_id)
    if flow is None:
        return "Couldn't find that flow."
    public = _public_flow(flow)
    if full_body and public.get("request", {}).get("body_preview") is not None:
        public["request"]["body"] = public["request"].pop("body_preview")
    return json.dumps(public, indent=2)


@mcp.tool()
async def search_traffic(
    query: str | None = None,
    domain: str | None = None,
    method: str | None = None,
    limit: int = 50,
) -> str:
    matches: list[dict[str, Any]] = []
    for item in _summary(limit=500):
        if query and query not in item["url"]:
            continue
        if domain and domain not in item["url"]:
            continue
        if method and method.upper() != item["method"].upper():
            continue
        matches.append(item)
    return json.dumps(matches[:limit], indent=2)


@mcp.tool()
async def replay_flow(
    flow_id: str,
    method: str | None = None,
    headers_json: Any | None = None,
    body: Any | None = None,
    timeout: float = 30.0,  # noqa: ASYNC109 - mirrors vendored MCP tool schema.
) -> str:
    del timeout
    base = flows.get(flow_id)
    if base is None:
        return "Couldn't find that flow"
    new_flow = copy.deepcopy(base)
    new_flow["id"] = f"replay-{len(flows) + 1}"
    new_flow["_timestamp"] = time.time() + len(flows) + 1
    if method:
        new_flow["request"]["method"] = method
    if headers_json:
        header_updates = json.loads(headers_json) if isinstance(headers_json, str) else headers_json
        new_flow["request"]["headers"].update(header_updates)
    if body is not None and body != "__omit__":
        if isinstance(body, str):
            new_flow["request"]["body_preview"] = body
        else:
            new_flow["request"]["body_preview"] = json.dumps(body, separators=(",", ":"))
        new_flow["request"].pop("body", None)
    flows[new_flow["id"]] = new_flow
    return "Replayed successfully! (Status: 200). Check the traffic summary for the new flow."


@mcp.tool()
async def extract_from_flow(
    flow_id: str,
    json_path: str | None = None,
    css_selector: str | None = None,
) -> str:
    del css_selector
    flow = flows.get(flow_id)
    if flow is None:
        return "No matching flow."
    body = (flow.get("response") or {}).get("body_preview")
    if not body:
        return "Flow has no response body."
    if not json_path:
        return "You must provide a json_path or a css_selector."
    data: Any = json.loads(body)
    for part in [item for item in json_path.removeprefix("$.").split(".") if item]:
        data = data[part]
    return json.dumps([data], indent=2)


@mcp.tool()
async def detect_auth_pattern(flow_ids: str | None = None) -> str:
    del flow_ids
    details = {
        "jwt": {"detected": False, "signals": [], "flows": []},
        "bearer_token": {"detected": False, "signals": [], "flows": []},
    }
    for flow in flows.values():
        auth = flow["request"]["headers"].get("Authorization", "")
        if auth.startswith("Bearer "):
            details["bearer_token"]["detected"] = True
            details["bearer_token"]["flows"].append(flow["id"])
            if auth[7:].count(".") == 2:
                details["jwt"]["detected"] = True
                details["jwt"]["signals"].append("Bearer token appears to be JWT format")
                details["jwt"]["flows"].append(flow["id"])
    detected = [name for name, item in details.items() if item["detected"]]
    return json.dumps({"detected_auth_types": detected, "details": details}, indent=2)


@mcp.tool()
async def set_session_variable(name: str, value: str) -> str:
    session_variables[name] = value
    return f"Set session variable ${name} = {value}"


@mcp.tool()
async def extract_session_variable(
    name: str,
    flow_id: str,
    regex_pattern: str,
    group_index: int = 1,
) -> str:
    body = (flows.get(flow_id, {}).get("response") or {}).get("body_preview") or ""
    match = re.search(regex_pattern, body)
    if not match:
        return "Pattern not found in response body."
    session_variables[name] = match.group(group_index)
    return f"Extracted and set ${name} = {session_variables[name]}"


@mcp.tool()
async def fuzz_endpoint(
    flow_id: str,
    target_param: str,
    param_type: str,
    payload_category: str,
    timeout: float = 10.0,  # noqa: ASYNC109 - mirrors vendored MCP tool schema.
) -> str:
    del flow_id, target_param, param_type, payload_category, timeout
    return json.dumps({"baseline_status": 200, "baseline_len": 45, "anomalies": []}, indent=2)


@mcp.tool()
async def export_openapi_spec(domain: str | None = None, limit: int | None = None) -> str:
    del limit
    title = f"Reconstructed API - {domain if domain else 'All'}"
    return json.dumps({"openapi": "3.0.0", "info": {"title": title, "version": "0.1.0"}})


@mcp.tool()
async def clear_traffic() -> str:
    flows.clear()
    return "Cleared all traffic history."


@mcp.tool()
async def clear_rules() -> str:
    return "Cleared all interception rules."


@mcp.tool()
async def set_global_header(key: str, value: str) -> str:
    return f"Set global header: {key} = {value}"


@mcp.tool()
async def add_interception_rule(rule_id: str, action_type: str, **kwargs: Any) -> str:
    del action_type, kwargs
    return f"Added rule '{rule_id}'"


@mcp.tool()
async def list_tools() -> str:
    tools = await mcp.list_tools()
    return json.dumps(
        [
            {"name": tool.name, "description": tool.description, "input_schema": tool.inputSchema}
            for tool in tools
        ],
        indent=2,
    )


if __name__ == "__main__":
    mcp.run()
