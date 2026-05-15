"""Run scripted Objection commands and normalize the output."""

from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import structlog

from agent.schema import EngagementState

log = structlog.get_logger(__name__)

SCRIPTS_DIR = Path(__file__).resolve().parent / "scripts"


@dataclass
class ObjectionResult:
    script: str
    returncode: int
    stdout: str
    stderr: str
    parsed: dict[str, Any] = field(default_factory=dict)
    summary_count: int = 0

    @property
    def payload(self) -> dict[str, Any]:
        return {
            "script": self.script,
            "returncode": self.returncode,
            "summary_count": self.summary_count,
            "parsed": self.parsed,
        }

    @property
    def parsed_json(self) -> str:
        return json.dumps(self.parsed, indent=2, default=str)


class ObjectionRunner:
    def __init__(self, bundle_id: str, *, device_id: str | None = None) -> None:
        self.bundle_id = bundle_id
        self.device_id = device_id

    @classmethod
    def from_state(cls, state: EngagementState) -> "ObjectionRunner":
        return cls(bundle_id=state.target.bundle_id, device_id=state.target.device_id)

    def run_script(self, script: str) -> ObjectionResult:
        path = script if Path(script).is_absolute() else SCRIPTS_DIR / f"{script}.objection"
        path = Path(path)
        if not path.exists():
            return ObjectionResult(
                script=str(path),
                returncode=2,
                stdout="",
                stderr=f"script not found: {path}",
            )
        commands = path.read_text(encoding="utf-8")
        proc = subprocess.run(
            [
                "objection",
                "--gadget",
                self.bundle_id,
                "explore",
                "--no-resume",
                "--quiet",
                "--commands",
                commands,
            ],
            capture_output=True,
            text=True,
            timeout=120,
        )
        result = ObjectionResult(
            script=path.stem,
            returncode=proc.returncode,
            stdout=proc.stdout,
            stderr=proc.stderr,
        )
        parser = _PARSERS.get(path.stem, _parse_default)
        result.parsed = parser(proc.stdout)
        result.summary_count = _summary_count(result.parsed)
        return result


def probe_objection() -> bool:
    return shutil.which("objection") is not None


# ---------------------------------------------------------------------------
# Per-script parsers — each turns Objection's text stdout into structured data.
# ---------------------------------------------------------------------------


def _parse_default(stdout: str) -> dict[str, Any]:
    return {"raw_lines": stdout.splitlines()}


def _parse_recon(stdout: str) -> dict[str, Any]:
    out: dict[str, Any] = {"env": {}, "info": [], "classes": [], "frameworks": []}
    current = None
    for line in stdout.splitlines():
        line = line.rstrip()
        if "Environment" in line:
            current = "env"
            continue
        if "Bundles" in line or "Frameworks" in line:
            current = "frameworks"
            continue
        if "Classes" in line:
            current = "classes"
            continue
        if current == "env" and ":" in line:
            k, _, v = line.partition(":")
            out["env"][k.strip()] = v.strip()
        elif current == "frameworks" and line.strip():
            out["frameworks"].append(line.strip())
        elif current == "classes" and line.strip().startswith("-"):
            out["classes"].append(line.strip().lstrip("- ").strip())
    return out


def _parse_keychain(stdout: str) -> dict[str, Any]:
    entries: list[dict[str, str]] = []
    for line in stdout.splitlines():
        if "|" not in line:
            continue
        cols = [c.strip() for c in line.split("|")]
        if len(cols) >= 3 and cols[0] and not cols[0].startswith("---"):
            entries.append({"account": cols[0], "service": cols[1], "data": cols[2]})
    return {"entries": entries}


_PARSERS: dict[str, Any] = {
    "recon": _parse_recon,
    "keychain_dump": _parse_keychain,
}


def _summary_count(parsed: dict[str, Any]) -> int:
    for key in ("entries", "classes", "frameworks"):
        if isinstance(parsed.get(key), list):
            return len(parsed[key])
    return 0


__all__ = ["ObjectionRunner", "ObjectionResult", "probe_objection"]
