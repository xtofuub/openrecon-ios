"""Bundle a run directory into a shareable tar.gz archive.

Backs `openrecon export <run_id>`. The bundle includes:
- frida_events.jsonl, mitm_flows.jsonl, correlations.jsonl, findings.jsonl
- findings/*.{md,json}
- report.md, report.json
- artifacts/ (recon, openapi drafts, schemas)
- state.json
- A top-level MANIFEST.json with run summary + file inventory.

SQLite indexes are excluded — rebuildable from JSONL.
"""

from __future__ import annotations

import hashlib
import json
import tarfile
from dataclasses import asdict
from pathlib import Path

from .runs import summarize_run


_EXCLUDE_PATTERNS = ("index", "__pycache__")
_EXCLUDE_SUFFIXES = (".sqlite", ".sqlite-wal", ".sqlite-shm", ".pyc")


def export_run(run_dir: Path, out_path: Path | None = None) -> Path:
    """Create a tar.gz at `out_path` (default: alongside run_dir) and return its path."""
    run_dir = Path(run_dir)
    if not run_dir.is_dir():
        raise FileNotFoundError(f"no run at {run_dir}")
    if out_path is None:
        out_path = run_dir.parent / f"{run_dir.name}.tar.gz"
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    summary = summarize_run(run_dir)

    files: list[Path] = []
    for path in run_dir.rglob("*"):
        if path.is_dir():
            continue
        if _excluded(path):
            continue
        files.append(path)

    manifest = {
        "run": asdict(summary) | {"path": str(summary.path)},
        "exported_from": str(run_dir),
        "files": [
            {
                "path": str(p.relative_to(run_dir)),
                "size_bytes": p.stat().st_size,
                "sha256": _sha256(p),
            }
            for p in sorted(files)
        ],
    }
    manifest_path = run_dir / "MANIFEST.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, default=str), encoding="utf-8")

    try:
        with tarfile.open(out_path, "w:gz") as tar:
            tar.add(manifest_path, arcname=f"{run_dir.name}/MANIFEST.json")
            for path in files:
                arcname = f"{run_dir.name}/{path.relative_to(run_dir)}"
                tar.add(path, arcname=arcname)
    finally:
        # Manifest is regenerated on each export — drop the on-disk copy.
        manifest_path.unlink(missing_ok=True)
    return out_path


def _excluded(path: Path) -> bool:
    for part in path.parts:
        if part in _EXCLUDE_PATTERNS:
            return True
    return path.suffix in _EXCLUDE_SUFFIXES


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


__all__ = ["export_run"]
