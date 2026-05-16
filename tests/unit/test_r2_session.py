"""r2_mcp.session — registry, lazy open, JSON parsing, fat-binary detection."""

from __future__ import annotations

import sys
import types
from pathlib import Path

import pytest

from r2_mcp.session import R2Session, R2SessionError


class _FakePipe:
    def __init__(self, responses: dict[str, str] | None = None) -> None:
        self.calls: list[str] = []
        self.responses = responses or {}

    def cmd(self, command: str) -> str:
        self.calls.append(command)
        return self.responses.get(command, "")

    def quit(self) -> None:
        self.calls.append("__quit__")


@pytest.fixture(autouse=True)
def _stub_r2pipe(monkeypatch):
    fake_module = types.ModuleType("r2pipe")
    holder: dict[str, _FakePipe] = {}

    def fake_open(path: str, **_):
        pipe = _FakePipe(
            responses={
                "ij": '{"bin": {"arch": "arm64"}}',
                "aaa": "",
                "aflj": '[{"name": "_main", "offset": 4096, "size": 128}]',
                "izj": '[{"vaddr": 1, "string": "hello"}]',
            }
        )
        holder[path] = pipe
        return pipe

    fake_module.open = fake_open  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "r2pipe", fake_module)
    R2Session._registry.clear()  # noqa: SLF001
    yield holder
    R2Session._registry.clear()  # noqa: SLF001


def test_get_or_open_reuses_session(tmp_path):
    bin_path = tmp_path / "fake.macho"
    bin_path.write_bytes(b"\xca\xfe\xba\xbe" + b"\x00" * 8)  # fat magic
    a = R2Session.get_or_open(bin_path)
    b = R2Session.get_or_open(bin_path)
    assert a is b
    assert a.is_fat_binary() is True


def test_ensure_analyzed_runs_once(tmp_path, _stub_r2pipe):
    bin_path = tmp_path / "fake.macho"
    bin_path.write_bytes(b"\xcf\xfa\xed\xfe" + b"\x00" * 32)
    sess = R2Session.get_or_open(bin_path)
    sess.ensure_analyzed()
    sess.ensure_analyzed()
    fake = _stub_r2pipe[str(bin_path.resolve())]
    assert fake.calls.count("aaa") == 1


def test_cmdj_parses_json(tmp_path):
    bin_path = tmp_path / "fake.macho"
    bin_path.write_bytes(b"\xcf\xfa\xed\xfe")
    sess = R2Session.get_or_open(bin_path)
    fns = sess.cmdj("aflj")
    assert isinstance(fns, list)
    assert fns[0]["name"] == "_main"


def test_missing_binary_raises():
    with pytest.raises(R2SessionError):
        R2Session(Path("/does/not/exist/binary"))
