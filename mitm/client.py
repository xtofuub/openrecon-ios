"""Async MCP stdio client to the vendored mitmproxy-mcp server.

Used by `agent/runner.py` for the engagement-long client and by every `api/`
module as a context manager for standalone invocation.
"""

from __future__ import annotations

import base64
import contextlib
import hashlib
import json
import os
import sys
from collections.abc import AsyncIterator, Mapping
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path
from typing import Any

import structlog
from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

from agent.schema import MitmFlow

log = structlog.get_logger(__name__)


class MitmClientError(RuntimeError):
    """Base error for MCP transport and tool-call failures."""


class MitmToolError(MitmClientError):
    """Raised when a vendored MCP tool returns an error result."""


@dataclass
class AuthPattern:
    scheme: str
    headers: list[str]
    rotation: str | None = None
    details: dict[str, Any] | None = None

    def model_dump(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "scheme": self.scheme,
            "headers": self.headers,
            "rotation": self.rotation,
        }
        if self.details is not None:
            data["details"] = self.details
        return data

    def model_dump_json(self, *, indent: int = 2) -> str:
        return json.dumps(self.model_dump(), indent=indent)


@dataclass
class ReplayResult:
    flow_id: str
    response: dict[str, Any] | None


class MitmClient:
    """Async client to the vendored mitmproxy-mcp stdio server.

    The default subprocess points at `mitm/vendor/src/mitmproxy_mcp` through
    `PYTHONPATH`, so callers do not need the vendored package installed into the
    active environment.
    """

    def __init__(
        self,
        *,
        port: int = 8080,
        run_dir: Path | str | None = None,
        server_command: str | None = None,
        server_args: list[str] | None = None,
        server_env: Mapping[str, str] | None = None,
        cwd: Path | str | None = None,
        tool_timeout_seconds: float = 30.0,
    ) -> None:
        self.port = port
        self.run_dir = Path(run_dir).resolve() if run_dir is not None else None
        self.server_command = server_command or sys.executable
        self.server_args = server_args or ["-m", "mitmproxy_mcp.core.server"]
        self.server_env = dict(server_env or {})
        self.cwd = Path(cwd).resolve() if cwd is not None else None
        self.tool_timeout = timedelta(seconds=tool_timeout_seconds)

        self._repo_root = Path(__file__).resolve().parents[1]
        self._vendor_src = self._repo_root / "mitm" / "vendor" / "src"
        self._session: ClientSession | None = None
        self._exit_stack: contextlib.AsyncExitStack | None = None

    @classmethod
    @contextlib.asynccontextmanager
    async def connect(
        cls,
        *,
        port: int = 8080,
        run_dir: Path | str | None = None,
        server_command: str | None = None,
        server_args: list[str] | None = None,
        server_env: Mapping[str, str] | None = None,
        cwd: Path | str | None = None,
        tool_timeout_seconds: float = 30.0,
    ) -> AsyncIterator[MitmClient]:
        client = cls(
            port=port,
            run_dir=run_dir,
            server_command=server_command,
            server_args=server_args,
            server_env=server_env,
            cwd=cwd,
            tool_timeout_seconds=tool_timeout_seconds,
        )
        await client._start()
        try:
            yield client
        finally:
            await client._stop()

    async def _start(self) -> None:
        if self._session is not None:
            return
        default_args = ["-m", "mitmproxy_mcp.core.server"]
        if not self._vendor_src.exists() and self.server_args == default_args:
            raise MitmClientError(
                "mitm/vendor/src is missing; add the vendored mitmproxy-mcp subtree first"
            )

        stack = contextlib.AsyncExitStack()
        params = StdioServerParameters(
            command=self.server_command,
            args=self.server_args,
            env=self._build_env(),
            cwd=self._server_cwd(),
        )

        try:
            read_stream, write_stream = await stack.enter_async_context(stdio_client(params))
            session = await stack.enter_async_context(
                ClientSession(
                    read_stream,
                    write_stream,
                    read_timeout_seconds=self.tool_timeout,
                )
            )
            await session.initialize()
        except Exception as exc:
            await stack.aclose()
            raise MitmClientError(f"failed to start mitmproxy-mcp over stdio: {exc}") from exc

        self._exit_stack = stack
        self._session = session
        log.info("mitm.mcp_connected", command=self.server_command, args=self.server_args)

    async def _stop(self) -> None:
        if self._session is not None:
            with contextlib.suppress(Exception):
                await self.stop_proxy()

        if self._exit_stack is not None:
            await self._exit_stack.aclose()

        self._session = None
        self._exit_stack = None

    def _build_env(self) -> dict[str, str]:
        env = {k: str(v) for k, v in self.server_env.items()}
        pythonpath_entries = [str(self._vendor_src), str(self._repo_root)]
        existing_pythonpath = env.get("PYTHONPATH") or os.environ.get("PYTHONPATH")
        if existing_pythonpath:
            pythonpath_entries.append(existing_pythonpath)
        env["PYTHONPATH"] = os.pathsep.join(pythonpath_entries)

        if self.run_dir is not None:
            self.run_dir.mkdir(parents=True, exist_ok=True)
            env.setdefault("openrecon_RUN_DIR", str(self.run_dir))
        else:
            env.setdefault("openrecon_RUN_DIR", str(self._repo_root / "runs" / "_default"))
        return env

    def _server_cwd(self) -> Path:
        if self.cwd is not None:
            self.cwd.mkdir(parents=True, exist_ok=True)
            return self.cwd
        if self.run_dir is not None:
            self.run_dir.mkdir(parents=True, exist_ok=True)
            return self.run_dir
        return self._repo_root

    def _require_session(self) -> ClientSession:
        if self._session is None:
            raise MitmClientError("MitmClient is not connected; use MitmClient.connect()")
        return self._session

    async def _call_tool(self, name: str, arguments: dict[str, Any] | None = None) -> str:
        session = self._require_session()
        try:
            result = await session.call_tool(
                name,
                arguments or {},
                read_timeout_seconds=self.tool_timeout,
            )
        except Exception as exc:
            raise MitmToolError(f"MCP tool {name!r} failed: {exc}") from exc

        text = _tool_result_text(result)
        if getattr(result, "isError", False):
            raise MitmToolError(f"MCP tool {name!r} returned an error: {text}")
        return text

    async def _call_json(self, name: str, arguments: dict[str, Any] | None = None) -> Any:
        text = await self._call_tool(name, arguments)
        try:
            return json.loads(text)
        except json.JSONDecodeError as exc:
            raise MitmToolError(f"MCP tool {name!r} did not return JSON: {text}") from exc

    # ----------------------------------------------------------------- methods

    async def start_proxy(self, *, scope: list[str] | None = None) -> None:
        if scope is not None:
            await self.set_scope(scope)
        await self._call_tool("start_proxy", {"port": self.port})
        log.info("mitm.start_proxy", port=self.port, scope=scope)

    async def stop_proxy(self) -> None:
        await self._call_tool("stop_proxy")
        log.info("mitm.stop_proxy")

    async def set_scope(self, allowed_domains: list[str]) -> str:
        return await self._call_tool("set_scope", {"allowed_domains": allowed_domains})

    async def get_traffic_summary(self, *, limit: int = 20) -> list[dict[str, Any]]:
        payload = await self._call_json("get_traffic_summary", {"limit": limit})
        if not isinstance(payload, list):
            raise MitmToolError("get_traffic_summary returned a non-list payload")
        return [dict(item) for item in payload if isinstance(item, dict)]

    async def list_flows(self, *, since: float | None = None, limit: int = 200) -> list[str]:
        summary = await self.get_traffic_summary(limit=limit)
        flow_ids: list[str] = []
        for item in summary:
            if since is not None and float(item.get("timestamp") or 0) < since:
                continue
            flow_id = item.get("id") or item.get("flow_id")
            if flow_id is not None:
                flow_ids.append(str(flow_id))
        return flow_ids

    async def inspect_flow(self, flow_id: str, *, full_body: bool = False) -> dict[str, Any]:
        raw = await self._inspect_flow_raw(flow_id, full_body=full_body)
        return _normalise_flow(raw)

    async def search_traffic(
        self,
        *,
        query: str | None = None,
        domain: str | None = None,
        method: str | None = None,
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        payload = await self._call_json(
            "search_traffic",
            {"query": query, "domain": domain, "method": method, "limit": limit},
        )
        if not isinstance(payload, list):
            raise MitmToolError("search_traffic returned a non-list payload")
        return [dict(item) for item in payload if isinstance(item, dict)]

    async def load_traffic_file(
        self,
        file_path: Path | str,
        *,
        append: bool = False,
        scope: list[str] | str | None = None,
    ) -> dict[str, Any]:
        path = _resolve_path(file_path)
        self._assert_path_in_run_dir(path)

        if isinstance(scope, list):
            scope_arg: str | None = ",".join(scope)
        else:
            scope_arg = scope

        payload = await self._call_json(
            "load_traffic_file",
            {"file_path": str(path), "append": append, "scope": scope_arg},
        )
        if not isinstance(payload, dict):
            raise MitmToolError("load_traffic_file returned a non-object payload")
        if payload.get("status") == "error":
            raise MitmToolError(str(payload.get("message") or "load_traffic_file failed"))
        return payload

    async def replay_flow(
        self,
        flow_id: str,
        *,
        overrides: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Replay a captured flow with optional method/header/body mutations.

        Synthetic ``frida-*`` flow_ids — created by ``FridaFlowNormalizer`` from
        NSURLSession / NSURLConnection hooks — never passed through mitmproxy's
        recorder. They are replayed via :meth:`replay_synthetic`, which reads
        the recorded request out of ``mitm_flows.jsonl`` and re-issues it with
        httpx. All other flow_ids dispatch to the vendored mitmproxy tool.
        """
        if flow_id.startswith("frida-"):
            return await self.replay_synthetic(flow_id, overrides=overrides or {})
        before_ids = set(await self.list_flows(limit=500))
        arguments = await self._replay_arguments(flow_id, overrides or {})
        message = await self._call_tool("replay_flow", arguments)
        replayed_flow_id = await self._newest_flow_id(before_ids)
        if replayed_flow_id:
            replayed = await self.inspect_flow(replayed_flow_id, full_body=True)
            replayed["message"] = message
            return replayed
        return {"flow_id": f"replay-{flow_id[:8]}", "response": None, "message": message}

    async def replay_synthetic(
        self,
        flow_id: str,
        *,
        overrides: dict[str, Any] | None = None,
        timeout_seconds: float = 30.0,
        verify_tls: bool = False,
    ) -> dict[str, Any]:
        """Replay a Frida-sourced synthetic flow using a direct httpx request.

        The recorded request lives in ``run_dir/mitm_flows.jsonl``. Overrides
        follow the same shape used by api modules: ``url``, ``method``,
        ``headers``, ``body_patch`` (JSON patch dict merged into a JSON body),
        and ``query`` (dict merged into the query string).

        The replay result is appended back to ``mitm_flows.jsonl`` with a new
        ``frida-replay-*`` flow_id and ``tags: ["replayed", "synthetic-replay"]``
        so downstream consumers (finder ClientSideValidationBypassRule, etc.)
        observe the new traffic on the next iteration.
        """
        import time as _time
        from urllib.parse import parse_qs, urlencode, urlsplit, urlunsplit

        import httpx
        from ulid import ULID

        flow = self._load_synthetic_flow(flow_id)
        if flow is None:
            raise MitmToolError(f"synthetic flow {flow_id!r} not found in run_dir")

        request = flow.get("request") or {}
        original_url = str(request.get("url") or "")
        method = str(request.get("method") or "GET").upper()
        headers = dict(request.get("headers") or {})
        body_b64 = request.get("body_b64")
        body_bytes: bytes | None = None
        if body_b64:
            try:
                body_bytes = base64.b64decode(body_b64)
            except Exception:
                body_bytes = None

        ov = overrides or {}
        url = str(ov.get("url") or original_url)
        method = str(ov.get("method") or method).upper()
        if ov.get("headers"):
            headers.update({str(k): str(v) for k, v in ov["headers"].items()})
        if ov.get("query"):
            split = urlsplit(url)
            qs = {k: v[0] if v else "" for k, v in parse_qs(split.query, keep_blank_values=True).items()}
            qs.update({str(k): str(v) for k, v in ov["query"].items()})
            url = urlunsplit(split._replace(query=urlencode(qs)))
        if ov.get("body_patch") and body_bytes is not None:
            try:
                body_obj = json.loads(body_bytes.decode("utf-8"))
                if isinstance(body_obj, dict):
                    body_obj.update(ov["body_patch"])
                    body_bytes = json.dumps(body_obj).encode("utf-8")
            except Exception:
                pass
        if ov.get("body_b64"):
            try:
                body_bytes = base64.b64decode(str(ov["body_b64"]))
            except Exception:
                pass

        ts_request = _time.time()
        async with httpx.AsyncClient(
            verify=verify_tls,
            timeout=timeout_seconds,
            follow_redirects=False,
        ) as client:
            try:
                response = await client.request(
                    method,
                    url,
                    headers=headers,
                    content=body_bytes,
                )
                resp_body = response.content
                resp_status = response.status_code
                resp_headers = {k: v for k, v in response.headers.items()}
                error: str | None = None
            except httpx.HTTPError as exc:
                resp_body = b""
                resp_status = 0
                resp_headers = {}
                error = f"{type(exc).__name__}: {exc}"
        ts_response = _time.time()

        replay_flow_id = f"frida-replay-{ULID()}"
        replay_record = MitmFlow(
            flow_id=replay_flow_id,
            ts_request=ts_request,
            ts_response=ts_response,
            request={
                "url": url,
                "method": method,
                "headers": headers,
                "body_b64": base64.b64encode(body_bytes).decode("ascii") if body_bytes else None,
                "body_sha256": hashlib.sha256(body_bytes).hexdigest() if body_bytes else None,
            },
            response={
                "status": resp_status,
                "headers": resp_headers,
                "body_b64": base64.b64encode(resp_body).decode("ascii") if resp_body else None,
                "body_sha256": hashlib.sha256(resp_body).hexdigest() if resp_body else None,
            },
            duration_ms=max(0.0, (ts_response - ts_request) * 1000.0),
            tags=["replayed", "synthetic-replay"],
        )
        self._append_synthetic_flow(replay_record)

        result: dict[str, Any] = replay_record.model_dump()
        result["message"] = "synthetic replay via httpx"
        if error:
            result["error"] = error
        return result

    def _load_synthetic_flow(self, flow_id: str) -> dict[str, Any] | None:
        if self.run_dir is None:
            return None
        path = self.run_dir / "mitm_flows.jsonl"
        if not path.exists():
            return None
        with path.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                except Exception:
                    continue
                if record.get("flow_id") == flow_id:
                    return record
        return None

    def _append_synthetic_flow(self, flow: MitmFlow) -> None:
        if self.run_dir is None:
            return
        path = self.run_dir / "mitm_flows.jsonl"
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as f:
            f.write(flow.model_dump_json() + "\n")

    async def detect_auth(self) -> AuthPattern:
        payload = await self._call_json("detect_auth_pattern")
        if not isinstance(payload, dict):
            raise MitmToolError("detect_auth_pattern returned a non-object payload")
        return _auth_pattern_from_payload(payload)

    async def extract(
        self,
        flow_id: str,
        *,
        jsonpath: str | None = None,
        css: str | None = None,
    ) -> Any:
        if bool(jsonpath) == bool(css):
            raise ValueError("provide exactly one of jsonpath or css")
        text = await self._call_tool(
            "extract_from_flow",
            {"flow_id": flow_id, "json_path": jsonpath, "css_selector": css},
        )
        return _json_or_text(text)

    async def fuzz(self, flow_id: str, mutator: str | dict[str, Any]) -> list[dict[str, Any]]:
        arguments = {"flow_id": flow_id, **_fuzz_arguments(mutator)}
        text = await self._call_tool("fuzz_endpoint", arguments)
        payload = _json_or_text(text)
        if isinstance(payload, dict) and isinstance(payload.get("anomalies"), list):
            return [dict(item) for item in payload["anomalies"] if isinstance(item, dict)]
        if isinstance(payload, list):
            return [dict(item) for item in payload if isinstance(item, dict)]
        if isinstance(payload, str) and "No significant anomalies" in payload:
            return []
        return [{"result": payload}]

    async def set_session_variable(self, name: str, value: str) -> str:
        return await self._call_tool("set_session_variable", {"name": name, "value": value})

    async def extract_session_variable(
        self,
        name: str,
        *,
        from_flow: str,
        regex_pattern: str,
        group_index: int = 1,
    ) -> str:
        return await self._call_tool(
            "extract_session_variable",
            {
                "name": name,
                "flow_id": from_flow,
                "regex_pattern": regex_pattern,
                "group_index": group_index,
            },
        )

    async def export_openapi_spec(
        self,
        host: str | None = None,
        *,
        limit: int | None = None,
    ) -> dict[str, Any]:
        payload = await self._call_json("export_openapi_spec", {"domain": host, "limit": limit})
        if not isinstance(payload, dict):
            raise MitmToolError("export_openapi_spec returned a non-object payload")
        return payload

    async def set_global_header(self, name: str, value: str) -> str:
        return await self._call_tool("set_global_header", {"key": name, "value": value})

    async def add_interception_rule(self, rule: dict[str, Any]) -> str:
        return await self._call_tool("add_interception_rule", rule)

    async def clear_traffic(self) -> str:
        return await self._call_tool("clear_traffic")

    async def clear_rules(self) -> str:
        return await self._call_tool("clear_rules")

    async def list_tools(self) -> list[dict[str, Any]]:
        payload = await self._call_json("list_tools")
        if not isinstance(payload, list):
            raise MitmToolError("list_tools returned a non-list payload")
        return [dict(item) for item in payload if isinstance(item, dict)]

    async def stream_flows(self) -> AsyncIterator[MitmFlow]:
        """Yield MitmFlow objects as the proxy captures them.

        The correlation emitter writes to `runs/<id>/mitm_flows.jsonl`; the
        planner currently reads that file through the store/query layer.
        """
        if False:
            yield  # type: ignore[unreachable]
        return

    async def _inspect_flow_raw(self, flow_id: str, *, full_body: bool = False) -> dict[str, Any]:
        payload = await self._call_json(
            "inspect_flow",
            {"flow_id": flow_id, "full_body": full_body},
        )
        if not isinstance(payload, dict):
            raise MitmToolError(f"inspect_flow returned a non-object payload for {flow_id}")
        return payload

    async def _replay_arguments(
        self,
        flow_id: str,
        overrides: dict[str, Any],
    ) -> dict[str, Any]:
        arguments: dict[str, Any] = {"flow_id": flow_id}
        if method := overrides.get("method"):
            arguments["method"] = str(method)

        header_updates: dict[str, str] = {}
        for key in ("headers", "set_headers"):
            value = overrides.get(key)
            if isinstance(value, Mapping):
                header_updates.update({str(k): str(v) for k, v in value.items()})
        for name in overrides.get("strip_headers") or []:
            header_updates[str(name)] = ""
        if header_updates:
            arguments["headers_json"] = json.dumps(header_updates)

        if "body_replace" in overrides:
            arguments["body"] = str(overrides["body_replace"])
        elif "body" in overrides:
            arguments["body"] = str(overrides["body"])
        elif "body_patch" in overrides:
            raw = await self._inspect_flow_raw(flow_id, full_body=True)
            arguments["body"] = _patched_body(raw, overrides["body_patch"])

        unsupported = sorted(
            set(overrides)
            - {
                "method",
                "headers",
                "set_headers",
                "strip_headers",
                "body",
                "body_replace",
                "body_patch",
            }
        )
        if unsupported:
            log.warning(
                "mitm.replay_unsupported_overrides",
                flow_id=flow_id,
                unsupported=unsupported,
            )
        return arguments

    async def _newest_flow_id(self, previous_ids: set[str]) -> str | None:
        try:
            summary = await self.get_traffic_summary(limit=10)
        except MitmClientError:
            return None
        for item in summary:
            flow_id = item.get("id") or item.get("flow_id")
            if flow_id is not None and str(flow_id) not in previous_ids:
                return str(flow_id)
        return None

    def _assert_path_in_run_dir(self, path: Path) -> None:
        if self.run_dir is None:
            return
        allowed_root = self.run_dir.resolve()
        if path != allowed_root and allowed_root not in path.parents:
            raise ValueError(f"path {path} outside allowed root {allowed_root}")


def _tool_result_text(result: Any) -> str:
    chunks: list[str] = []
    for content in getattr(result, "content", []):
        text = getattr(content, "text", None)
        if text is not None:
            chunks.append(str(text))
            continue
        if hasattr(content, "model_dump"):
            chunks.append(json.dumps(content.model_dump(mode="json"), default=str))
        else:
            chunks.append(str(content))
    return "\n".join(chunks)


def _resolve_path(file_path: Path | str) -> Path:
    return Path(file_path).resolve()


def _json_or_text(text: str) -> Any:
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return text


def _normalise_flow(raw: dict[str, Any]) -> dict[str, Any]:
    request = raw.get("request") or {}
    response = raw.get("response")
    flow_id = str(raw.get("flow_id") or raw.get("id"))
    req_body = request.get("body") if "body" in request else request.get("body_preview")

    normalised: dict[str, Any] = {
        "flow_id": flow_id,
        "request": {
            "method": str(request.get("method") or ""),
            "url": str(request.get("url") or ""),
            "headers": _headers_to_dict(request.get("headers")),
        },
    }
    body_b64, body_sha256 = _body_metadata(req_body)
    if body_b64 is not None:
        normalised["request"]["body_b64"] = body_b64
        normalised["request"]["body_sha256"] = body_sha256

    if isinstance(response, dict):
        resp_body = response.get("body") if "body" in response else response.get("body_preview")
        status = response.get("status")
        if status is None:
            status = response.get("status_code")
        normalised["response"] = {
            "status": int(status or 0),
            "headers": _headers_to_dict(response.get("headers")),
        }
        body_b64, body_sha256 = _body_metadata(resp_body)
        if body_b64 is not None:
            normalised["response"]["body_b64"] = body_b64
            normalised["response"]["body_sha256"] = body_sha256
    else:
        normalised["response"] = None

    if "message" in raw:
        normalised["message"] = raw["message"]
    return normalised


def _headers_to_dict(headers: Any) -> dict[str, str]:
    if not headers:
        return {}
    if isinstance(headers, Mapping):
        return {str(k): str(v) for k, v in headers.items()}
    if isinstance(headers, list):
        out: dict[str, str] = {}
        for item in headers:
            if isinstance(item, (list, tuple)) and len(item) == 2:
                out[str(item[0])] = str(item[1])
            elif isinstance(item, Mapping) and "name" in item and "value" in item:
                out[str(item["name"])] = str(item["value"])
        return out
    return {}


def _body_metadata(body: Any) -> tuple[str | None, str | None]:
    if body is None:
        return None, None
    if isinstance(body, bytes):
        data = body
    elif isinstance(body, str):
        data = body.encode("utf-8")
    else:
        data = json.dumps(body, sort_keys=True).encode("utf-8")
    return base64.b64encode(data).decode("ascii"), hashlib.sha256(data).hexdigest()


def _patched_body(raw_flow: dict[str, Any], patch: Any) -> str:
    if not isinstance(patch, Mapping):
        raise ValueError("body_patch must be a mapping")

    request = raw_flow.get("request") or {}
    body = request.get("body") if "body" in request else request.get("body_preview")
    if not body:
        data: Any = {}
    else:
        data = json.loads(str(body))

    if not isinstance(data, dict):
        raise ValueError("body_patch requires a JSON object request body")

    for path, value in patch.items():
        _set_json_path(data, str(path), value)
    return json.dumps(data, separators=(",", ":"))


def _set_json_path(data: dict[str, Any], path: str, value: Any) -> None:
    parts = [part for part in path.removeprefix("$.").split(".") if part]
    if not parts:
        raise ValueError("body_patch path cannot be empty")

    cursor: dict[str, Any] = data
    for part in parts[:-1]:
        next_value = cursor.setdefault(part, {})
        if not isinstance(next_value, dict):
            next_value = {}
            cursor[part] = next_value
        cursor = next_value
    cursor[parts[-1]] = value


def _auth_pattern_from_payload(payload: dict[str, Any]) -> AuthPattern:
    detected = [str(item) for item in payload.get("detected_auth_types") or []]
    preferred = [
        "oauth2",
        "jwt",
        "bearer_token",
        "basic_auth",
        "api_key",
        "session_cookie",
        "csrf",
    ]
    scheme_key = next((item for item in preferred if item in detected), "none")
    scheme_map = {
        "bearer_token": "bearer",
        "session_cookie": "cookie",
        "basic_auth": "basic",
    }
    header_map = {
        "jwt": ["authorization"],
        "bearer_token": ["authorization"],
        "basic_auth": ["authorization"],
        "api_key": ["x-api-key"],
        "session_cookie": ["cookie"],
        "csrf": ["x-csrf-token"],
        "oauth2": ["authorization"],
        "none": [],
    }
    return AuthPattern(
        scheme=scheme_map.get(scheme_key, scheme_key),
        headers=header_map.get(scheme_key, []),
        rotation=None,
        details=payload,
    )


def _fuzz_arguments(mutator: str | dict[str, Any]) -> dict[str, Any]:
    if isinstance(mutator, Mapping):
        return {
            "target_param": str(mutator.get("target_param", "id")),
            "param_type": str(mutator.get("param_type", "query")),
            "payload_category": str(mutator.get("payload_category", "sqli")),
            "timeout": float(mutator.get("timeout", 10.0)),
        }

    parsed = _json_or_text(mutator)
    if isinstance(parsed, dict):
        return _fuzz_arguments(parsed)

    parts = str(mutator).split(":")
    if len(parts) == 3:
        param_type, target_param, payload_category = parts
    else:
        param_type, target_param, payload_category = "query", "id", str(mutator)
    return {
        "target_param": target_param,
        "param_type": param_type,
        "payload_category": payload_category,
    }


__all__ = [
    "MitmClient",
    "MitmClientError",
    "MitmToolError",
    "AuthPattern",
    "ReplayResult",
]
