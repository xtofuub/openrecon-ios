"""Binary acquisition — pull a decrypted Mach-O off the device.

Uses the ``binary_dump.js`` Frida hook (FairPlay-aware) to stream the
decrypted main binary back over the Frida session in chunks, then reassembles
to ``runs/<run_id>/artifacts/app.macho``. The patched binary has cryptid
zeroed in the LC_ENCRYPTION_INFO load command(s), so radare2 / otool / IDA
will treat it as a plain Mach-O.

The function is idempotent: if ``artifacts/app.macho`` already exists for
the run, it's returned unchanged. Operators can also pre-populate this path
manually (e.g. via ``bagbak`` or another dumper) and the rest of the pipeline
will use it without re-running the live dump.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

import structlog

log = structlog.get_logger(__name__)


class BinaryAcquisitionError(RuntimeError):
    """Raised when the dump can't be obtained for any reason."""


async def acquire_binary(
    *,
    frida_session: Any,
    run_dir: Path,
    hook_path: Path | None = None,
    chunk_size: int = 1024 * 1024,
    timeout_seconds: float = 120.0,
) -> Path:
    """Pull a decrypted Mach-O via Frida and write it under ``artifacts/``.

    ``frida_session`` is a live ``frida.core.Session``. Get one from
    ``FridaRunner._session`` after ``spawn_and_attach``. The caller is
    responsible for keeping the session alive until this call returns.
    """
    artifact_dir = run_dir / "artifacts"
    artifact_dir.mkdir(parents=True, exist_ok=True)
    out_path = artifact_dir / "app.macho"
    if out_path.exists() and out_path.stat().st_size > 0:
        log.info("binary_acquire.reuse", path=str(out_path), size=out_path.stat().st_size)
        return out_path

    hook_file = hook_path or (Path(__file__).resolve().parents[1] / "frida_layer" / "hooks" / "binary_dump.js")
    if not hook_file.exists():
        raise BinaryAcquisitionError(f"hook script missing: {hook_file}")
    source = hook_file.read_text(encoding="utf-8").replace("{{chunk_size}}", str(int(chunk_size)))

    loop = asyncio.get_running_loop()
    chunks: dict[int, bytes] = {}
    done_event = asyncio.Event()
    state: dict[str, Any] = {"meta": None, "error": None, "expected_total": None}

    def on_message(message: dict[str, Any], data: bytes | None) -> None:
        if message.get("type") == "error":
            state["error"] = message.get("description") or "frida script error"
            loop.call_soon_threadsafe(done_event.set)
            return
        if message.get("type") != "send":
            return
        payload = message.get("payload") or {}
        if payload.get("kind") != "frida.event":
            return
        extra = payload.get("extra") or {}
        kind = payload.get("method") or extra.get("kind")
        if kind == "binary_dump.chunk" and data is not None:
            seq = int(extra.get("seq", -1))
            if seq >= 0:
                chunks[seq] = data
            state["expected_total"] = extra.get("total")
        elif kind == "binary_dump.done":
            state["meta"] = extra
            loop.call_soon_threadsafe(done_event.set)
        elif kind == "binary_dump.error":
            state["error"] = extra.get("error")
            loop.call_soon_threadsafe(done_event.set)
        elif kind == "binary_dump.start":
            log.info("binary_acquire.start", **{k: extra.get(k) for k in ("name", "path", "size")})

    try:
        script = frida_session.create_script(source)
    except Exception as exc:
        raise BinaryAcquisitionError(f"failed to create script: {exc}") from exc
    script.on("message", on_message)
    try:
        script.load()
    except Exception as exc:
        raise BinaryAcquisitionError(f"failed to load dump script: {exc}") from exc

    try:
        await asyncio.wait_for(done_event.wait(), timeout=timeout_seconds)
    except TimeoutError as exc:  # noqa: BLE001 - explicit re-raise
        raise BinaryAcquisitionError(
            f"binary dump timed out after {timeout_seconds}s "
            f"({len(chunks)} chunks received)"
        ) from exc
    finally:
        try:
            script.unload()
        except Exception:
            pass

    if state["error"]:
        raise BinaryAcquisitionError(str(state["error"]))
    if not chunks:
        raise BinaryAcquisitionError("no chunks received from dump hook")

    expected_total = int(state.get("expected_total") or 0)
    total_assembled = sum(len(b) for b in chunks.values())
    if expected_total and total_assembled != expected_total:
        log.warning(
            "binary_acquire.size_mismatch",
            assembled=total_assembled,
            expected=expected_total,
        )

    tmp = out_path.with_suffix(".macho.partial")
    with tmp.open("wb") as f:
        for seq in sorted(chunks):
            f.write(chunks[seq])
    tmp.replace(out_path)

    meta = state.get("meta") or {}
    meta_path = artifact_dir / "binary_dump.json"
    meta_path.write_text(
        json.dumps(
            {
                "path": str(out_path),
                "size": out_path.stat().st_size,
                "source_path_on_device": meta.get("path"),
                "name": meta.get("name"),
                "patched_encryption_segments": meta.get("patched_encryption_segments"),
                "chunks": meta.get("chunks"),
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    log.info(
        "binary_acquire.done",
        path=str(out_path),
        size=out_path.stat().st_size,
        patched=meta.get("patched_encryption_segments"),
    )
    return out_path


__all__ = ["acquire_binary", "BinaryAcquisitionError"]
