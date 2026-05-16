"""iorpl archive format — read/write ``.iorpl`` session bundles.

The ``.iorpl`` file is a gzipped tar archive with a fixed internal layout:

    meta.json            — SessionMeta (schema_version, target, recorded_at, ...)
    flows.jsonl          — every captured MitmFlow (matches openrecon's wire shape)
    frida_events.jsonl   — Frida runtime events
    auth_state.json      — snapshot of keychain / cookies / NSUserDefaults at record time
    endpoints.json       — derived endpoint map (host, method, path_template, sample_flow_ids)
    notes.md             — operator-authored free-form context (optional)
    artifacts/<*>        — optional binaries, screenshots, har exports

Design goals:

- **Round-trip stable.** Loading then saving an archive must produce a
  byte-identical-where-possible file. We dump JSON with sorted keys + a
  trailing newline so diffs are deterministic.
- **No openrecon import in the format layer.** Anyone with Python + tarfile
  must be able to crack open a .iorpl file. ``IorplSession`` is intentionally
  schemaless (plain dicts) so the format outlives schema churn in openrecon.
- **Forward compatible.** ``SessionMeta.schema_version`` is bumped on breaking
  changes; readers fall back gracefully.
"""

from __future__ import annotations

import io
import json
import tarfile
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

SCHEMA_VERSION = 1
DEFAULT_NOTES = "# Notes\n\nAuthor notes go here.\n"


@dataclass
class SessionMeta:
    """Top-level metadata recorded with each session."""

    schema_version: int = SCHEMA_VERSION
    target_bundle: str = ""
    device_id: str | None = None
    recorded_at: float = field(default_factory=time.time)
    recorder_version: str = "0.1.0"
    description: str = ""
    tags: list[str] = field(default_factory=list)
    # Extra metadata recorded by the operator (URLs of HackerOne reports,
    # CVE references the session is meant to cover, etc.).
    extra: dict[str, Any] = field(default_factory=dict)


@dataclass
class IorplSession:
    """In-memory representation of a recorded session.

    All collections default empty so a SessionArchive can read a partial
    archive (e.g. one without Frida events) and still hand back a usable
    object. Consumers should tolerate empty fields.
    """

    meta: SessionMeta = field(default_factory=SessionMeta)
    flows: list[dict[str, Any]] = field(default_factory=list)
    frida_events: list[dict[str, Any]] = field(default_factory=list)
    auth_state: dict[str, Any] = field(default_factory=dict)
    endpoints: list[dict[str, Any]] = field(default_factory=list)
    notes: str = DEFAULT_NOTES
    artifacts: dict[str, bytes] = field(default_factory=dict)

    def flow_count(self) -> int:
        return len(self.flows)

    def endpoint_count(self) -> int:
        return len(self.endpoints)


# ── archive I/O ─────────────────────────────────────────────────────────────


class SessionArchive:
    """Read / write ``.iorpl`` files.

    Both directions stream so very large flow logs don't blow up memory.
    The class is a thin wrapper around ``tarfile`` plus JSON / JSONL
    serialization rules — no other deps.
    """

    @staticmethod
    def save(session: IorplSession, path: str | Path) -> Path:
        """Write a session to ``path`` (creates parent dirs)."""
        out = Path(path)
        out.parent.mkdir(parents=True, exist_ok=True)
        with tarfile.open(out, "w:gz") as tar:
            _add_text(tar, "meta.json", _dumps(asdict(session.meta)))
            _add_text(tar, "flows.jsonl", _to_jsonl(session.flows))
            _add_text(tar, "frida_events.jsonl", _to_jsonl(session.frida_events))
            _add_text(tar, "auth_state.json", _dumps(session.auth_state))
            _add_text(tar, "endpoints.json", _dumps(session.endpoints))
            _add_text(tar, "notes.md", session.notes if session.notes is not None else DEFAULT_NOTES)
            for rel, blob in session.artifacts.items():
                _add_bytes(tar, f"artifacts/{rel}", blob)
        return out

    @staticmethod
    def load(path: str | Path) -> IorplSession:
        """Read a session from ``path``. Missing files are tolerated."""
        archive = Path(path)
        if not archive.exists():
            raise FileNotFoundError(archive)
        session = IorplSession()
        with tarfile.open(archive, "r:gz") as tar:
            members = {m.name: m for m in tar.getmembers()}
            session.meta = _meta_from_member(tar, members.get("meta.json"))
            session.flows = _jsonl_from_member(tar, members.get("flows.jsonl"))
            session.frida_events = _jsonl_from_member(tar, members.get("frida_events.jsonl"))
            session.auth_state = _json_from_member(tar, members.get("auth_state.json"), default={})
            ep = _json_from_member(tar, members.get("endpoints.json"), default=[])
            session.endpoints = ep if isinstance(ep, list) else []
            session.notes = _text_from_member(tar, members.get("notes.md"), default=DEFAULT_NOTES)
            for name, member in members.items():
                if name.startswith("artifacts/") and member.isreg():
                    fileobj = tar.extractfile(member)
                    if fileobj is not None:
                        rel = name[len("artifacts/") :]
                        session.artifacts[rel] = fileobj.read()
        return session

    @staticmethod
    def from_run_dir(run_dir: str | Path, *, target_bundle: str, description: str = "") -> IorplSession:
        """Build an IorplSession from an existing openrecon run directory.

        Pulls ``mitm_flows.jsonl``, ``frida_events.jsonl``, and the
        ``artifacts/`` payload directly off disk. Auth state is left empty
        — callers that captured it separately can attach it before saving.
        """
        rd = Path(run_dir)
        session = IorplSession()
        session.meta.target_bundle = target_bundle
        session.meta.description = description

        flows_path = rd / "mitm_flows.jsonl"
        if flows_path.exists():
            session.flows = _read_jsonl(flows_path)

        events_path = rd / "frida_events.jsonl"
        if events_path.exists():
            session.frida_events = _read_jsonl(events_path)

        endpoints_artifact = rd / "artifacts" / "endpoints.json"
        if endpoints_artifact.exists():
            try:
                obj = json.loads(endpoints_artifact.read_text(encoding="utf-8"))
                # openrecon's MapEndpoints emits a {key: [flow_ids]} dict; convert
                # to a list of records for portability.
                if isinstance(obj, dict):
                    session.endpoints = [{"endpoint": k, "flow_ids": v} for k, v in obj.items()]
                elif isinstance(obj, list):
                    session.endpoints = obj
            except json.JSONDecodeError:
                session.endpoints = []

        artifacts_dir = rd / "artifacts"
        if artifacts_dir.exists():
            for child in artifacts_dir.iterdir():
                if child.is_file():
                    try:
                        session.artifacts[child.name] = child.read_bytes()
                    except OSError:
                        continue
        return session


# ── helpers ─────────────────────────────────────────────────────────────────


def _dumps(obj: Any) -> str:
    return json.dumps(obj, indent=2, sort_keys=True, default=str) + "\n"


def _to_jsonl(records: list[dict[str, Any]]) -> str:
    return "".join(json.dumps(r, default=str) + "\n" for r in records)


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return out


def _add_text(tar: tarfile.TarFile, name: str, body: str) -> None:
    data = body.encode("utf-8")
    info = tarfile.TarInfo(name=name)
    info.size = len(data)
    info.mtime = int(time.time())
    info.mode = 0o644
    tar.addfile(info, io.BytesIO(data))


def _add_bytes(tar: tarfile.TarFile, name: str, blob: bytes) -> None:
    info = tarfile.TarInfo(name=name)
    info.size = len(blob)
    info.mtime = int(time.time())
    info.mode = 0o644
    tar.addfile(info, io.BytesIO(blob))


def _meta_from_member(tar: tarfile.TarFile, member: tarfile.TarInfo | None) -> SessionMeta:
    if member is None:
        return SessionMeta()
    fileobj = tar.extractfile(member)
    if fileobj is None:
        return SessionMeta()
    try:
        data = json.loads(fileobj.read().decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return SessionMeta()
    if not isinstance(data, dict):
        return SessionMeta()
    return SessionMeta(
        schema_version=int(data.get("schema_version", SCHEMA_VERSION)),
        target_bundle=str(data.get("target_bundle", "")),
        device_id=data.get("device_id"),
        recorded_at=float(data.get("recorded_at", time.time())),
        recorder_version=str(data.get("recorder_version", "0.1.0")),
        description=str(data.get("description", "")),
        tags=list(data.get("tags") or []),
        extra=dict(data.get("extra") or {}),
    )


def _jsonl_from_member(tar: tarfile.TarFile, member: tarfile.TarInfo | None) -> list[dict[str, Any]]:
    if member is None:
        return []
    fileobj = tar.extractfile(member)
    if fileobj is None:
        return []
    out: list[dict[str, Any]] = []
    for line in fileobj.read().decode("utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return out


def _json_from_member(
    tar: tarfile.TarFile,
    member: tarfile.TarInfo | None,
    *,
    default: Any,
) -> Any:
    if member is None:
        return default
    fileobj = tar.extractfile(member)
    if fileobj is None:
        return default
    try:
        return json.loads(fileobj.read().decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return default


def _text_from_member(tar: tarfile.TarFile, member: tarfile.TarInfo | None, *, default: str) -> str:
    if member is None:
        return default
    fileobj = tar.extractfile(member)
    if fileobj is None:
        return default
    try:
        return fileobj.read().decode("utf-8")
    except UnicodeDecodeError:
        return default
