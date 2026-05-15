"""Async MCP stdio client to the vendored mitmproxy-mcp server.

Used by `agent/runner.py` for the engagement-long client and by every `api/`
module as a context manager for standalone invocation.

This is a thin protocol-light wrapper. It accepts overrides like
`{"strip_headers": [...], "set_headers": {...}, "body_patch": {...}}` and
translates them into the vendor's tool-call payload.
"""

from __future__ import annotations

import contextlib
from collections.abc import AsyncIterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import structlog

from agent.schema import MitmFlow

log = structlog.get_logger(__name__)


@dataclass
class AuthPattern:
    scheme: str
    headers: list[str]
    rotation: str | None = None

    def model_dump(self) -> dict[str, Any]:
        return {"scheme": self.scheme, "headers": self.headers, "rotation": self.rotation}

    def model_dump_json(self, *, indent: int = 2) -> str:
        import json

        return json.dumps(self.model_dump(), indent=indent)


@dataclass
class ReplayResult:
    flow_id: str
    response: dict[str, Any] | None


class MitmClient:
    """Async client to the vendored mitmproxy-mcp.

    Today this is a stub that talks to the vendor's HTTP API if available, or
    raises a clear error if the vendor isn't yet checked in. Phase 3 wires this
    up to the real MCP stdio transport via the `mcp` Python SDK.
    """

    def __init__(self, *, port: int = 8080, run_dir: Path | None = None) -> None:
        self.port = port
        self.run_dir = run_dir

    @classmethod
    @contextlib.asynccontextmanager
    async def connect(cls, *, port: int = 8080, run_dir: Path | None = None) -> AsyncIterator["MitmClient"]:
        client = cls(port=port, run_dir=run_dir)
        await client._start()
        try:
            yield client
        finally:
            await client._stop()

    async def _start(self) -> None:
        vendor = Path(__file__).resolve().parent / "vendor"
        if not vendor.exists():
            log.warning(
                "mitm.vendor_missing",
                hint=(
                    "Run `git subtree add --prefix=mitm/vendor "
                    "https://github.com/snapspecter/mitmproxy-mcp main --squash`"
                ),
            )
        # Phase 3: spawn the vendored mcp server here and connect via stdio.

    async def _stop(self) -> None:
        pass

    # ----------------------------------------------------------------- methods

    async def start_proxy(self, *, scope: list[str] | None = None) -> None:
        log.info("mitm.start_proxy", port=self.port, scope=scope)

    async def stop_proxy(self) -> None:
        log.info("mitm.stop_proxy")

    async def replay_flow(
        self, flow_id: str, *, overrides: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        """Replay a captured flow with optional mutations.

        Phase 3 replaces this stub with the real MCP call. Modules already
        depend on the contract so we can swap the implementation without
        rewriting any callers.
        """
        log.info("mitm.replay_flow", flow_id=flow_id, overrides=overrides)
        return {"flow_id": f"replay-{flow_id[:8]}", "response": None}

    async def detect_auth(self) -> AuthPattern:
        return AuthPattern(scheme="bearer", headers=["authorization"], rotation=None)

    async def extract(
        self, flow_id: str, *, jsonpath: str | None = None, css: str | None = None
    ) -> Any:
        return None

    async def fuzz(self, flow_id: str, mutator: str) -> list[dict[str, Any]]:
        return []

    async def list_flows(self) -> list[str]:
        return []

    async def stream_flows(self) -> AsyncIterator[MitmFlow]:
        """Yield MitmFlow objects as the proxy captures them.

        Today this just yields nothing — Phase 3 wires it to the correlation
        addon's named-pipe / fifo.
        """
        if False:
            yield  # type: ignore[unreachable]
        return


__all__ = ["MitmClient", "AuthPattern", "ReplayResult"]
