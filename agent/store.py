"""Append-only JSONL event store with SQLite indexes.

Every event the platform produces is written here. The store is the source of
truth — indexes are rebuildable from the JSONL files at any time. Crash-safe by
construction: no partial writes that can't be replayed.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from collections.abc import Iterable, Iterator
from pathlib import Path
from typing import Any, TypeVar

from pydantic import BaseModel

from .schema import Correlation, FridaEvent, MitmFlow

T = TypeVar("T", bound=BaseModel)


class EventStore:
    """File-backed append-only event store.

    Layout under `run_dir/`:
        frida_events.jsonl
        mitm_flows.jsonl
        correlations.jsonl
        findings.jsonl
        index/by_flow.sqlite
        index/fts.sqlite
        state.json
        artifacts/
    """

    JSONL_FILES = {
        "frida_events": "frida_events.jsonl",
        "mitm_flows": "mitm_flows.jsonl",
        "correlations": "correlations.jsonl",
        "findings": "findings.jsonl",
        "errors": "errors.jsonl",
    }

    def __init__(self, run_dir: Path) -> None:
        self.run_dir = Path(run_dir)
        self.run_dir.mkdir(parents=True, exist_ok=True)
        (self.run_dir / "artifacts").mkdir(exist_ok=True)
        (self.run_dir / "findings").mkdir(exist_ok=True)
        (self.run_dir / "index").mkdir(exist_ok=True)
        self._locks: dict[str, threading.Lock] = {
            name: threading.Lock() for name in self.JSONL_FILES
        }
        self._index_db: sqlite3.Connection | None = None

    # ------------------------------------------------------------------ writes

    def append(self, stream: str, record: BaseModel | dict[str, Any]) -> None:
        if stream not in self.JSONL_FILES:
            raise KeyError(f"unknown stream {stream!r}")
        path = self.run_dir / self.JSONL_FILES[stream]
        line = record.model_dump_json() if isinstance(record, BaseModel) else json.dumps(record)
        with self._locks[stream]:
            with path.open("a", encoding="utf-8") as f:
                f.write(line + "\n")
        self._index_record(stream, record)

    def append_many(self, stream: str, records: Iterable[BaseModel | dict[str, Any]]) -> None:
        for r in records:
            self.append(stream, r)

    # ------------------------------------------------------------------- reads

    def read(self, stream: str) -> Iterator[dict[str, Any]]:
        path = self.run_dir / self.JSONL_FILES[stream]
        if not path.exists():
            return iter(())
        with path.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                yield json.loads(line)

    def read_typed(self, stream: str, model: type[T]) -> Iterator[T]:
        for record in self.read(stream):
            yield model.model_validate(record)

    # ------------------------------------------------------------ artifact API

    def write_artifact(self, relative_path: str, content: bytes | str) -> Path:
        target = self.run_dir / "artifacts" / relative_path
        target.parent.mkdir(parents=True, exist_ok=True)
        mode = "wb" if isinstance(content, bytes) else "w"
        with target.open(mode) as f:
            f.write(content)
        return target.relative_to(self.run_dir)

    # ---------------------------------------------------------- index plumbing

    def _index_db_conn(self) -> sqlite3.Connection:
        if self._index_db is None:
            db_path = self.run_dir / "index" / "events.sqlite"
            self._index_db = sqlite3.connect(db_path, check_same_thread=False)
            self._index_db.executescript(
                """
                PRAGMA journal_mode = WAL;
                CREATE TABLE IF NOT EXISTS by_flow (
                    flow_id TEXT PRIMARY KEY,
                    event_id TEXT NOT NULL,
                    ts REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS by_method (
                    cls TEXT,
                    method TEXT,
                    event_id TEXT,
                    ts REAL
                );
                CREATE INDEX IF NOT EXISTS by_method_idx ON by_method(cls, method);
                CREATE VIRTUAL TABLE IF NOT EXISTS fts USING fts5(
                    event_id UNINDEXED,
                    stream UNINDEXED,
                    content
                );
                CREATE TABLE IF NOT EXISTS correlations (
                    correlation_id TEXT PRIMARY KEY,
                    flow_event_id TEXT NOT NULL,
                    score REAL NOT NULL,
                    frida_event_ids TEXT NOT NULL
                );
                """
            )
        return self._index_db

    def _index_record(self, stream: str, record: BaseModel | dict[str, Any]) -> None:
        data = record.model_dump() if isinstance(record, BaseModel) else record
        conn = self._index_db_conn()
        cur = conn.cursor()
        if stream == "mitm_flows":
            cur.execute(
                "INSERT OR REPLACE INTO by_flow(flow_id, event_id, ts) VALUES (?, ?, ?)",
                (data["flow_id"], data["event_id"], data["ts_request"]),
            )
            content = " ".join(
                [
                    data["request"]["url"],
                    data["request"]["method"],
                    *data["request"]["headers"].keys(),
                ]
            )
            cur.execute(
                "INSERT INTO fts(event_id, stream, content) VALUES (?, ?, ?)",
                (data["event_id"], stream, content),
            )
        elif stream == "frida_events":
            cur.execute(
                "INSERT INTO by_method(cls, method, event_id, ts) VALUES (?, ?, ?, ?)",
                (data["cls"], data["method"], data["event_id"], data["ts"]),
            )
            previews = " ".join(
                [a.get("preview") or "" for a in data.get("args", [])]
                + [(data.get("ret") or {}).get("preview") or ""]
            )
            cur.execute(
                "INSERT INTO fts(event_id, stream, content) VALUES (?, ?, ?)",
                (data["event_id"], stream, f"{data['cls']} {data['method']} {previews}"),
            )
        elif stream == "correlations":
            cur.execute(
                "INSERT OR REPLACE INTO correlations VALUES (?, ?, ?, ?)",
                (
                    data["correlation_id"],
                    data["flow_event_id"],
                    data["score"],
                    json.dumps(data["frida_event_ids"]),
                ),
            )
        conn.commit()

    # ------------------------------------------------------ rebuild from disk

    def rebuild_indexes(self) -> None:
        """Drop and rebuild SQLite indexes from JSONL files. Idempotent."""
        if self._index_db is not None:
            self._index_db.close()
            self._index_db = None
        (self.run_dir / "index" / "events.sqlite").unlink(missing_ok=True)
        for stream in ("frida_events", "mitm_flows", "correlations"):
            for record in self.read(stream):
                self._index_record(stream, record)

    def close(self) -> None:
        if self._index_db is not None:
            self._index_db.close()
            self._index_db = None


__all__ = ["EventStore", "Correlation", "FridaEvent", "MitmFlow"]
