"""Shared contracts and helpers for bug-bounty modules.

Every module under `api/` consumes `ModuleInput` and produces `ModuleResult`.
The planner invokes them programmatically; the operator invokes them via
`python -m api.<name> ...` using `cli_entry`.
"""

from __future__ import annotations

import asyncio
import json
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import Any, ClassVar
from urllib.parse import urlparse

import click

from agent.schema import (
    Artifact,
    Finding,
    ModuleCoverage,
    ModuleResult,
    SessionCreds,
    Severity,
)


@dataclass
class ModuleInput:
    """Container the planner (or CLI) hands to a module.

    `mitm_mcp` is the typed async client to the vendored MITMProxy MCP server.
    Tests can substitute a fake client implementing the same protocol.
    """

    run_dir: Path
    baseline_flow_ids: list[str]
    session_pool: dict[str, SessionCreds]
    mitm_mcp: MitmClientLike
    config: dict[str, Any]


class MitmClientLike:  # protocol-light to keep the runtime dependency optional
    async def replay_flow(self, flow_id: str, *, overrides: dict[str, Any] | None = None) -> dict[str, Any]: ...
    async def detect_auth(self) -> dict[str, Any]: ...
    async def extract(self, flow_id: str, *, jsonpath: str | None = None, css: str | None = None) -> Any: ...
    async def fuzz(self, flow_id: str, mutator: str) -> list[dict[str, Any]]: ...
    async def list_flows(self) -> list[str]: ...


class ApiModule(ABC):
    name: ClassVar[str]
    severity_baseline: ClassVar[Severity] = Severity.MEDIUM

    @abstractmethod
    async def run(self, inp: ModuleInput) -> ModuleResult: ...

    # Helper used by subclasses
    @staticmethod
    def empty_result(name: str, *, error: str | None = None) -> ModuleResult:
        return ModuleResult(
            module=name,
            findings=[],
            artifacts=[],
            coverage=ModuleCoverage(),
            error=error,
        )


# ---------------------------------------------------------------------------
# Identifier heuristics — used by api/idor, api/mass_assignment, others.
# ---------------------------------------------------------------------------


_ID_KEY_RE = re.compile(r"(^|_)(id|uid|guid|owner|tenant|org|account)(_|$)", re.IGNORECASE)
_UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")


def identify_id_positions(flow: dict[str, Any]) -> list[dict[str, Any]]:
    """Return positions in the request that look ID-bearing.

    Output: list of {kind: "path"|"query"|"body", key, value, type: "numeric"|"uuid"|"opaque"}.
    """
    positions: list[dict[str, Any]] = []
    request = flow["request"]
    parsed = urlparse(request["url"])

    for i, seg in enumerate(parsed.path.split("/")):
        if not seg:
            continue
        if seg.isdigit():
            positions.append({"kind": "path", "index": i, "value": seg, "type": "numeric"})
        elif _UUID_RE.match(seg):
            positions.append({"kind": "path", "index": i, "value": seg, "type": "uuid"})
        elif len(seg) >= 12 and re.fullmatch(r"[A-Za-z0-9_-]+", seg):
            positions.append({"kind": "path", "index": i, "value": seg, "type": "opaque"})

    from urllib.parse import parse_qsl

    for k, v in parse_qsl(parsed.query, keep_blank_values=True):
        if _ID_KEY_RE.search(k) or v.isdigit() or _UUID_RE.match(v):
            t = "numeric" if v.isdigit() else "uuid" if _UUID_RE.match(v) else "opaque"
            positions.append({"kind": "query", "key": k, "value": v, "type": t})

    body_b64 = request.get("body_b64") or ""
    if body_b64:
        import base64

        try:
            body = base64.b64decode(body_b64).decode("utf-8", "ignore")
            data = json.loads(body)
            _walk_json_ids(data, positions, path="$")
        except Exception:
            pass

    return positions


def _walk_json_ids(node: Any, positions: list[dict[str, Any]], path: str) -> None:
    if isinstance(node, dict):
        for k, v in node.items():
            if _ID_KEY_RE.search(k):
                t = "numeric" if isinstance(v, int) else (
                    "uuid" if isinstance(v, str) and _UUID_RE.match(v) else "opaque"
                )
                positions.append({"kind": "body", "key": f"{path}.{k}", "value": v, "type": t})
            _walk_json_ids(v, positions, f"{path}.{k}")
    elif isinstance(node, list):
        for i, item in enumerate(node):
            _walk_json_ids(item, positions, f"{path}[{i}]")


# ---------------------------------------------------------------------------
# Diff helper — used by every module that mutates and compares.
# ---------------------------------------------------------------------------


def response_diff(orig: dict[str, Any], mutated: dict[str, Any]) -> dict[str, Any]:
    """Cheap structural diff. Not exhaustive; good enough for triage."""
    orig_r = orig.get("response") or {}
    mut_r = mutated.get("response") or {}
    return {
        "status_changed": orig_r.get("status") != mut_r.get("status"),
        "status_orig": orig_r.get("status"),
        "status_mutated": mut_r.get("status"),
        "body_size_orig": len(orig_r.get("body_b64") or ""),
        "body_size_mutated": len(mut_r.get("body_b64") or ""),
        "body_hash_changed": orig_r.get("body_sha256") != mut_r.get("body_sha256"),
        "new_headers": sorted(
            set(mut_r.get("headers") or {}) - set(orig_r.get("headers") or {})
        ),
    }


# ---------------------------------------------------------------------------
# CLI plumbing for standalone module invocation.
# ---------------------------------------------------------------------------


def cli_entry(module_cls: type[ApiModule]) -> None:
    """Build a click command for the module and run it.

    Usage: `python -m api.idor --run-dir runs/<id> --baseline <flow_ids...>`
    """

    @click.command(name=module_cls.name)
    @click.option("--run-dir", required=True, type=click.Path(exists=True, file_okay=False))
    @click.option(
        "--baseline",
        "baseline",
        multiple=True,
        required=True,
        help="Baseline flow ids to mutate (repeatable).",
    )
    @click.option(
        "--session",
        "sessions",
        multiple=True,
        help="label=path/to/cred.json (repeatable).",
    )
    @click.option("--mitm-port", default=8080, type=int)
    @click.option("--config", "config_path", default=None, type=click.Path())
    def _cmd(run_dir: str, baseline: tuple[str, ...], sessions: tuple[str, ...], mitm_port: int, config_path: str | None) -> None:
        async def _go() -> None:
            from mitm.client import MitmClient

            session_pool: dict[str, SessionCreds] = {}
            for spec in sessions:
                label, path = spec.split("=", 1)
                session_pool[label] = SessionCreds.model_validate_json(Path(path).read_text(encoding="utf-8"))

            config: dict[str, Any] = {}
            if config_path:
                config = json.loads(Path(config_path).read_text(encoding="utf-8"))

            async with MitmClient.connect(port=mitm_port) as client:
                inp = ModuleInput(
                    run_dir=Path(run_dir),
                    baseline_flow_ids=list(baseline),
                    session_pool=session_pool,
                    mitm_mcp=client,
                    config=config,
                )
                result = await module_cls().run(inp)

            findings_jsonl = Path(run_dir) / "findings.jsonl"
            with findings_jsonl.open("a", encoding="utf-8") as f:
                for finding in result.findings:
                    f.write(finding.model_dump_json() + "\n")
            click.echo(json.dumps(result.model_dump(), indent=2, default=str))

        asyncio.run(_go())

    _cmd.main(standalone_mode=True)


__all__ = [
    "ModuleInput",
    "ModuleResult",
    "ApiModule",
    "MitmClientLike",
    "identify_id_positions",
    "response_diff",
    "cli_entry",
    "Finding",
    "Severity",
    "Artifact",
]
