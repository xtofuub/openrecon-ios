"""R2FridaSession — radare2 attached to a live process via r2frida.

r2frida is an r2 IO backend (``r2 frida://<target>``) that proxies r2 commands
into a frida-server agent running on the device or host. With r2frida loaded,
commands prefixed with ``:`` (e.g. ``:dm``, ``:ic``, ``:dt``) are interpreted
by the r2frida agent against the live process.

This wrapper:
    - Holds one r2pipe handle per (target, device) pair.
    - Supplies a small API of common r2frida operations alongside an escape
      hatch for arbitrary ``:`` commands.
    - Performs a doctor check at first use (``r2pm -l | grep r2frida``)
      and surfaces clear remediation if r2frida isn't installed.

Why a separate session class from R2Session?
    The lifecycle differs: r2frida sessions are *attachments* (need detach on
    exit) and can be invalidated by the target process dying. R2Session
    targets static files which can't disappear underneath us.
"""

from __future__ import annotations

import shutil
import subprocess
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any


class R2FridaSessionError(RuntimeError):
    """Raised on r2frida attach failure, missing plugin, or dead session."""


def _doctor_r2frida_installed() -> bool:
    """Check whether the r2frida plugin is installed via r2pm."""
    r2pm = shutil.which("r2pm")
    if r2pm is None:
        return False
    try:
        out = subprocess.run(
            [r2pm, "-l"], capture_output=True, text=True, timeout=10, check=False
        )
    except (subprocess.SubprocessError, OSError):
        return False
    return "r2frida" in (out.stdout or "")


class R2FridaSession:
    """A single r2 + r2frida attachment to a live process."""

    _registry: dict[str, R2FridaSession] = {}
    _registry_lock = threading.Lock()

    def __init__(self, target: str, device: str | None = None) -> None:
        try:
            import r2pipe  # noqa: F401
        except ImportError as exc:  # pragma: no cover
            raise R2FridaSessionError(
                "r2pipe not installed. `pip install r2pipe` and ensure r2 is on PATH."
            ) from exc
        self.target = target
        self.device = device
        self._lock = threading.Lock()
        self._pipe: Any | None = None
        if not _doctor_r2frida_installed():
            raise R2FridaSessionError(
                "r2frida plugin not installed. Install with: `r2pm -ci r2frida`. "
                "After installing, run `r2pm -l | grep r2frida` to verify."
            )

    # ------------------------------------------------------------------ registry

    @staticmethod
    def _key(target: str, device: str | None) -> str:
        return f"{target}@{device or 'usb'}"

    @classmethod
    def get_or_attach(cls, target: str, device: str | None = None) -> R2FridaSession:
        key = cls._key(target, device)
        with cls._registry_lock:
            existing = cls._registry.get(key)
            if existing is not None:
                return existing
            session = cls(target, device)
            session._attach()
            cls._registry[key] = session
            return session

    @classmethod
    def detach_all(cls) -> None:
        with cls._registry_lock:
            for sess in cls._registry.values():
                sess.detach()
            cls._registry.clear()

    # --------------------------------------------------------------- lifecycle

    def _frida_url(self) -> str:
        if self.device:
            return f"frida://{self.device}/{self.target}"
        return f"frida://{self.target}"

    def _attach(self) -> None:
        import r2pipe

        url = self._frida_url()
        try:
            self._pipe = r2pipe.open(url, flags=["-2"])
        except Exception as exc:  # pragma: no cover
            raise R2FridaSessionError(
                f"r2pipe failed to attach via {url}: {exc}. "
                "Verify frida-server is running on the device (`frida-ls-devices`)."
            ) from exc

    def detach(self) -> None:
        with self._lock:
            if self._pipe is not None:
                try:
                    # `:die` cleanly unloads the r2frida agent; quit closes r2.
                    self._pipe.cmd(":die")
                except Exception:
                    pass
                try:
                    self._pipe.quit()
                except Exception:
                    pass
                self._pipe = None

    @contextmanager
    def _acquired(self) -> Iterator[Any]:
        with self._lock:
            if self._pipe is None:
                self._attach()
            yield self._pipe

    # ---------------------------------------------------------------- commands

    def cmd(self, command: str) -> str:
        with self._acquired() as pipe:
            try:
                result = pipe.cmd(command)
            except Exception as exc:
                raise R2FridaSessionError(f"r2frida cmd {command!r} failed: {exc}") from exc
        return result or ""

    def cmdj(self, command: str) -> Any:
        import json

        raw = self.cmd(command)
        if not raw.strip():
            return None
        try:
            return json.loads(raw)
        except json.JSONDecodeError as exc:
            raise R2FridaSessionError(
                f"r2frida cmd {command!r} did not return JSON: {raw[:200]!r}"
            ) from exc


__all__ = ["R2FridaSession", "R2FridaSessionError"]
