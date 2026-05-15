"""Spawn, attach, and pump Frida messages into the EventStore.

Phase 1 ships a skeleton with stubs that fail gracefully when no device is
attached. Phase 2 fills in the real message pump.
"""

from __future__ import annotations

import asyncio
import json
import time
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import structlog

from agent.schema import ArgValue, EngagementState, FridaEvent

log = structlog.get_logger(__name__)

HOOKS_DIR = Path(__file__).resolve().parent / "hooks"


class FridaRunner:
    """Owns one frida.Session against one target."""

    def __init__(self, *, bundle_id: str, device_id: str | None = None) -> None:
        self.bundle_id = bundle_id
        self.device_id = device_id
        self.pid: int | None = None
        self._session: Any | None = None
        self._scripts: list[Any] = []
        self._queue: asyncio.Queue[FridaEvent] = asyncio.Queue()

    @classmethod
    def from_state(cls, state: EngagementState) -> FridaRunner:
        return cls(bundle_id=state.target.bundle_id, device_id=state.target.device_id)

    async def spawn_and_attach(self) -> None:
        try:
            import frida
        except ImportError:  # pragma: no cover
            raise RuntimeError("`frida` python package not installed") from None

        device = self._get_device(frida)
        log.info("frida.spawn", bundle=self.bundle_id, device=device.id)
        self.pid = device.spawn([self.bundle_id])
        self._session = device.attach(self.pid)
        self._session.on("detached", lambda reason: log.warning("frida.detached", reason=reason))

    def load_hook(self, hook_name: str, *, replacements: dict[str, Any] | None = None) -> None:
        if self._session is None:
            raise RuntimeError("call spawn_and_attach first")
        path = hook_name if Path(hook_name).is_absolute() else HOOKS_DIR / hook_name
        source = Path(path).read_text(encoding="utf-8")
        if replacements:
            for k, v in replacements.items():
                source = source.replace("{{" + k + "}}", json.dumps(v))
        script = self._session.create_script(source)
        script.on("message", self._on_message)
        script.load()
        self._scripts.append(script)
        log.info("frida.hook_loaded", hook=str(path))

    def _on_message(self, message: dict[str, Any], data: bytes | None) -> None:
        if message.get("type") != "send":
            if message.get("type") == "error":
                log.warning("frida.script_error", description=message.get("description"))
            return
        payload = message.get("payload") or {}
        if payload.get("kind") != "frida.event":
            return
        ev = FridaEvent(
            ts=float(payload.get("ts") or time.time()),
            pid=int(payload.get("pid") or (self.pid or 0)),
            cls=str(payload.get("cls", "?")),
            method=str(payload.get("method", "?")),
            args=[ArgValue.model_validate(a) for a in payload.get("args") or []],
            ret=ArgValue.model_validate(payload["ret"]) if payload.get("ret") else None,
            thread_id=int(payload.get("thread_id") or 0),
            stack=list(payload.get("stack") or []),
            hook_source=payload.get("hook_source"),
            extra=payload.get("extra") or {},
        )
        try:
            self._queue.put_nowait(ev)
        except asyncio.QueueFull:  # pragma: no cover
            log.warning("frida.queue_full_dropping_event")

    async def stream_events(self) -> AsyncIterator[FridaEvent]:
        while True:
            try:
                ev = await asyncio.wait_for(self._queue.get(), timeout=0.5)
            except TimeoutError:
                if self._session is None:
                    return
                continue
            yield ev

    async def stop(self) -> None:
        for script in self._scripts:
            try:
                script.unload()
            except Exception:  # pragma: no cover
                pass
        if self._session is not None:
            try:
                self._session.detach()
            except Exception:  # pragma: no cover
                pass
            self._session = None

    def _get_device(self, frida: Any) -> Any:
        if self.device_id:
            return frida.get_device(self.device_id)
        return frida.get_usb_device(timeout=5)


def probe_device(device_id: str | None = None) -> bool:
    """Used by `openrecon doctor` to verify connectivity."""
    try:
        import frida

        dev = frida.get_device(device_id) if device_id else frida.get_usb_device(timeout=3)
        _ = dev.enumerate_processes()
        return True
    except Exception as exc:
        log.warning("frida.probe_failed", error=str(exc))
        return False


__all__ = ["FridaRunner", "probe_device"]
