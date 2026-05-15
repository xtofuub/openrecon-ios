"""Shared pytest fixtures for openrecon's test suite.

Provides:
- `frida_event_factory` / `mitm_flow_factory` — synthetic events for correlator + store tests.
- `fake_mitm_client` — drop-in `MitmClientLike` that records calls + returns scripted responses.
- `run_dir` / `event_store` — tmp run directory with an `EventStore` pre-initialized.
- `seed_flow` — append a flow to the run directory and return its record.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import sys
import time
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest

# Make the repo root importable so `from agent.* import ...` works in tests
# regardless of where pytest is launched from.
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from agent.schema import (  # noqa: E402  (import after sys.path tweak)
    ArgValue,
    FridaEvent,
    HttpRequest,
    HttpResponse,
    MitmFlow,
)
from agent.store import EventStore  # noqa: E402


# ---------------------------------------------------------------------------
# Synthetic event factories
# ---------------------------------------------------------------------------


@pytest.fixture
def frida_event_factory() -> Callable[..., FridaEvent]:
    def make(
        *,
        cls: str = "NSURLSession",
        method: str = "dataTaskWithRequest:",
        ts: float | None = None,
        thread_id: int = 1,
        args_preview: list[str] | None = None,
        ret_preview: str | None = None,
        stack: list[str] | None = None,
        arg_types: list[str] | None = None,
    ) -> FridaEvent:
        previews = args_preview or ["https://api.example.com/v1/users/42"]
        types = arg_types or ["NSURLRequest"] * len(previews)
        return FridaEvent(
            ts=ts if ts is not None else time.time(),
            pid=1234,
            cls=cls,
            method=method,
            args=[
                ArgValue(type=t, repr=f"<{t}>", preview=p)
                for t, p in zip(types, previews, strict=False)
            ],
            ret=ArgValue(type="NSData", repr="<data>", preview=ret_preview) if ret_preview else None,
            thread_id=thread_id,
            stack=stack or [],
        )

    return make


@pytest.fixture
def mitm_flow_factory() -> Callable[..., MitmFlow]:
    def make(
        *,
        flow_id: str | None = None,
        url: str = "https://api.example.com/v1/users/42",
        method: str = "GET",
        ts: float | None = None,
        request_headers: dict[str, str] | None = None,
        request_body: bytes | None = None,
        response_status: int | None = 200,
        response_headers: dict[str, str] | None = None,
        response_body: bytes | None = None,
    ) -> MitmFlow:
        flow_id = flow_id or f"flow-{int((ts or time.time()) * 1000)}"
        request = HttpRequest(
            url=url,
            method=method,
            headers=request_headers if request_headers is not None else {"Authorization": "Bearer eyJtest"},
            body_b64=base64.b64encode(request_body).decode("ascii") if request_body else None,
            body_sha256=hashlib.sha256(request_body).hexdigest() if request_body else None,
        )
        response = None
        if response_status is not None:
            body = response_body if response_body is not None else b'{"id": 42, "email": "user@example.com"}'
            response = HttpResponse(
                status=response_status,
                headers=response_headers if response_headers is not None else {"Content-Type": "application/json"},
                body_b64=base64.b64encode(body).decode("ascii"),
                body_sha256=hashlib.sha256(body).hexdigest(),
            )
        ts_req = ts if ts is not None else time.time()
        return MitmFlow(
            flow_id=flow_id,
            ts_request=ts_req,
            ts_response=ts_req + 0.05 if response else None,
            request=request,
            response=response,
            duration_ms=50.0 if response else None,
        )

    return make


# ---------------------------------------------------------------------------
# Run dir + store
# ---------------------------------------------------------------------------


@pytest.fixture
def run_dir(tmp_path: Path) -> Path:
    d = tmp_path / "run-test"
    d.mkdir()
    return d


@pytest.fixture
def event_store(run_dir: Path) -> Iterator[EventStore]:
    store = EventStore(run_dir)
    yield store
    store.close()


@pytest.fixture
def seed_flow(event_store: EventStore, mitm_flow_factory: Callable[..., MitmFlow]) -> Callable[..., dict[str, Any]]:
    def _seed(**kwargs: Any) -> dict[str, Any]:
        flow = mitm_flow_factory(**kwargs)
        event_store.append("mitm_flows", flow)
        return flow.model_dump()

    return _seed


# ---------------------------------------------------------------------------
# Fake MitmClient
# ---------------------------------------------------------------------------


class FakeMitmClient:
    """Records every call and returns scripted responses.

    Tests configure responses via `scripts` (a dict of method-name -> response or
    callable). Unset methods return safe defaults so module code can run without
    boilerplate setup.
    """

    def __init__(self, scripts: dict[str, Any] | None = None, flows: dict[str, dict[str, Any]] | None = None) -> None:
        self.scripts = scripts or {}
        self.flows = flows or {}
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self._replay_counter = 0

    async def replay_flow(self, flow_id: str, *, overrides: dict[str, Any] | None = None) -> dict[str, Any]:
        self.calls.append(("replay_flow", {"flow_id": flow_id, "overrides": overrides}))
        script = self.scripts.get("replay_flow")
        if callable(script):
            return script(flow_id=flow_id, overrides=overrides, fake=self)
        if script is not None:
            return script

        # Default: mirror the baseline with a synthetic replay id.
        self._replay_counter += 1
        baseline = copy.deepcopy(self.flows.get(flow_id, {}))
        baseline["flow_id"] = f"replay-{self._replay_counter}"
        # Apply trivial header / method overrides for realism.
        overrides = overrides or {}
        if "set_headers" in overrides and "request" in baseline:
            baseline["request"].setdefault("headers", {}).update(overrides["set_headers"])
        if "strip_headers" in overrides and "request" in baseline:
            for h in overrides["strip_headers"]:
                baseline["request"].get("headers", {}).pop(h, None)
                baseline["request"].get("headers", {}).pop(h.lower(), None)
                baseline["request"].get("headers", {}).pop(h.title(), None)
        if "method" in overrides and "request" in baseline:
            baseline["request"]["method"] = overrides["method"]
        return baseline or {"flow_id": f"replay-{self._replay_counter}", "response": {"status": 200}}

    async def detect_auth(self) -> dict[str, Any]:
        self.calls.append(("detect_auth", {}))
        return self.scripts.get("detect_auth", {"scheme": "bearer", "headers": ["authorization"]})

    async def extract(self, flow_id: str, *, jsonpath: str | None = None, css: str | None = None) -> Any:
        self.calls.append(("extract", {"flow_id": flow_id, "jsonpath": jsonpath, "css": css}))
        return self.scripts.get("extract")

    async def fuzz(self, flow_id: str, mutator: str) -> list[dict[str, Any]]:
        self.calls.append(("fuzz", {"flow_id": flow_id, "mutator": mutator}))
        return self.scripts.get("fuzz", [])

    async def list_flows(self) -> list[str]:
        self.calls.append(("list_flows", {}))
        return list(self.flows.keys())


@pytest.fixture
def fake_mitm_client() -> Callable[..., FakeMitmClient]:
    def factory(scripts: dict[str, Any] | None = None, flows: dict[str, dict[str, Any]] | None = None) -> FakeMitmClient:
        return FakeMitmClient(scripts=scripts, flows=flows)

    return factory


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


@pytest.fixture
def write_flow_to_run() -> Callable[[Path, dict[str, Any]], None]:
    """Append a raw flow dict to a run_dir's mitm_flows.jsonl (no EventStore needed)."""

    def _write(run_dir: Path, flow: dict[str, Any]) -> None:
        path = run_dir / "mitm_flows.jsonl"
        with path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(flow) + "\n")

    return _write
