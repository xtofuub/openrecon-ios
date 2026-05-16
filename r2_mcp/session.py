"""R2Session — a thin, well-behaved wrapper around r2pipe.

One session per binary path. Sessions are reused across tool calls so we pay
the cost of `aaa` (analyze all) only once per binary. The registry is process-
local; concurrent MCP tool calls share a single underlying r2pipe instance per
binary via a threading lock.

Why a session abstraction at all?
    r2pipe is stateful (`open` returns a cursor into the binary). Running every
    tool call as a one-shot `r2 -qc "...; q" <bin>` would re-analyze the binary
    on every call (slow on large iOS apps). A long-lived session amortizes the
    analysis cost.

Design choices:
    - Lazy import of `r2pipe` so the rest of the codebase can import this
      module in environments where r2 isn't installed (CI without radare2).
    - JSON-first: prefer `cmdj()` over `cmd()` so callers don't parse free-form
      output. The `cmd()` escape hatch remains for r2 commands that don't
      have a `j` variant.
    - Idempotent open: re-opening the same path returns the existing handle.
    - Thread-safe: r2pipe itself is not concurrent-safe; we guard each call.
"""

from __future__ import annotations

import json
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any


class R2SessionError(RuntimeError):
    """Raised when r2pipe can't open a binary or returns an unusable result."""


class R2Session:
    """A single r2pipe session against one binary."""

    _registry: dict[str, R2Session] = {}
    _registry_lock = threading.Lock()

    def __init__(self, binary_path: Path) -> None:
        try:
            import r2pipe  # noqa: F401 — imported lazily so module import succeeds
        except ImportError as exc:  # pragma: no cover — environment-dependent
            raise R2SessionError(
                "r2pipe is not installed. Install with `pip install r2pipe` "
                "and ensure radare2 is on PATH (`r2 -v`)."
            ) from exc
        self.binary_path = binary_path.resolve()
        if not self.binary_path.exists():
            raise R2SessionError(f"binary not found: {self.binary_path}")
        self._lock = threading.Lock()
        self._pipe: Any | None = None
        self._analyzed = False

    # ------------------------------------------------------------------ registry

    @classmethod
    def get_or_open(cls, binary_path: str | Path) -> R2Session:
        """Return a session for ``binary_path``, opening it once if new."""
        key = str(Path(binary_path).resolve())
        with cls._registry_lock:
            existing = cls._registry.get(key)
            if existing is not None:
                return existing
            session = cls(Path(key))
            session._open()
            cls._registry[key] = session
            return session

    @classmethod
    def close_all(cls) -> None:
        with cls._registry_lock:
            for sess in cls._registry.values():
                sess.close()
            cls._registry.clear()

    # --------------------------------------------------------------- lifecycle

    def _open(self) -> None:
        import r2pipe

        try:
            self._pipe = r2pipe.open(str(self.binary_path), flags=["-2"])  # -2 suppresses stderr
        except Exception as exc:  # pragma: no cover — r2 invocation error
            raise R2SessionError(f"r2pipe failed to open {self.binary_path}: {exc}") from exc

    def close(self) -> None:
        with self._lock:
            if self._pipe is not None:
                try:
                    self._pipe.quit()
                except Exception:
                    pass
                self._pipe = None

    @contextmanager
    def _acquired(self) -> Iterator[Any]:
        with self._lock:
            if self._pipe is None:
                self._open()
            yield self._pipe

    # ----------------------------------------------------------------- analysis

    def ensure_analyzed(self) -> None:
        """Run `aaa` once. Idempotent — subsequent calls are no-ops."""
        if self._analyzed:
            return
        self.cmd("aaa")
        self._analyzed = True

    # ---------------------------------------------------------------- commands

    def cmd(self, command: str) -> str:
        with self._acquired() as pipe:
            try:
                result = pipe.cmd(command)
            except Exception as exc:
                raise R2SessionError(f"r2 cmd {command!r} failed: {exc}") from exc
        return result or ""

    def cmdj(self, command: str) -> Any:
        raw = self.cmd(command)
        if not raw.strip():
            return None
        try:
            return json.loads(raw)
        except json.JSONDecodeError as exc:
            raise R2SessionError(
                f"r2 cmd {command!r} did not return JSON: {raw[:200]!r}"
            ) from exc

    # ----------------------------------------------------------------- helpers

    def info(self) -> dict[str, Any]:
        data = self.cmdj("ij")
        return data if isinstance(data, dict) else {}

    def arch(self) -> str:
        return str(self.info().get("bin", {}).get("arch") or "")

    def is_fat_binary(self) -> bool:
        """Detect a Mach-O fat binary by reading the magic. Useful for selecting
        a slice before analysis (``-a arm64`` flag on open)."""
        try:
            with self.binary_path.open("rb") as f:
                magic = f.read(4)
        except OSError:
            return False
        # FAT_MAGIC / FAT_CIGAM / FAT_MAGIC_64 / FAT_CIGAM_64
        return magic in (b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca", b"\xca\xfe\xba\xbf", b"\xbf\xba\xfe\xca")


__all__ = ["R2Session", "R2SessionError"]
