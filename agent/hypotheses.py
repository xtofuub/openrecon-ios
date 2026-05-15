"""Hypothesis store — persistent open investigations.

A `Hypothesis` is a claim the platform is investigating but has not yet
confirmed. Finder rules can emit hypotheses when confidence is below the
threshold for a Finding; the planner sees the list of open hypotheses and
emits `TestHypothesis` steps that confirm or refute them.

Storage: `runs/<run_id>/hypotheses.jsonl` — append-only, one JSON object per
line. Status transitions (open → confirmed/refuted/stale) rewrite the file.
"""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path

from .schema import Hypothesis

HYPOTHESES_FILE = "hypotheses.jsonl"


def read_all(run_dir: Path) -> list[Hypothesis]:
    path = run_dir / HYPOTHESES_FILE
    out: list[Hypothesis] = []
    if not path.exists():
        return out
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        out.append(Hypothesis.model_validate_json(line))
    return out


def open_hypotheses(run_dir: Path) -> list[Hypothesis]:
    return [h for h in read_all(run_dir) if h.status == "open"]


def append(run_dir: Path, hypothesis: Hypothesis) -> None:
    """Add a new hypothesis. Deduplicates on claim string."""
    existing = read_all(run_dir)
    if any(h.claim == hypothesis.claim for h in existing):
        return
    path = run_dir / HYPOTHESES_FILE
    with path.open("a", encoding="utf-8") as fh:
        fh.write(hypothesis.model_dump_json() + "\n")


def write_all(run_dir: Path, hypotheses: Iterable[Hypothesis]) -> None:
    """Rewrite the file. Used for status transitions."""
    path = run_dir / HYPOTHESES_FILE
    with path.open("w", encoding="utf-8") as fh:
        for h in hypotheses:
            fh.write(h.model_dump_json() + "\n")


def set_status(
    run_dir: Path,
    hypothesis_id: str,
    status: str,
    *,
    evidence_refs: list[str] | None = None,
) -> bool:
    """Mark a hypothesis confirmed/refuted/stale. Returns True if updated."""
    if status not in {"open", "confirmed", "refuted", "stale"}:
        raise ValueError(f"invalid status {status!r}")
    items = read_all(run_dir)
    updated = False
    for h in items:
        if h.hypothesis_id == hypothesis_id:
            h.status = status  # type: ignore[assignment]
            if evidence_refs:
                from .schema import Evidence

                for ref in evidence_refs:
                    h.evidence.append(Evidence(kind="flow", ref=ref))
            updated = True
            break
    if updated:
        write_all(run_dir, items)
    return updated


def counts(run_dir: Path) -> dict[str, int]:
    out = {"open": 0, "confirmed": 0, "refuted": 0, "stale": 0}
    for h in read_all(run_dir):
        out[h.status] = out.get(h.status, 0) + 1
    return out


__all__ = [
    "HYPOTHESES_FILE",
    "append",
    "counts",
    "open_hypotheses",
    "read_all",
    "set_status",
    "write_all",
]
