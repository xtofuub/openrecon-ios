"""IorplSession archive — save/load round trip + from_run_dir converter."""

from __future__ import annotations

import json

from iorpl.format import IorplSession, SessionArchive, SessionMeta


def test_round_trip_preserves_meta_and_flows(tmp_path):
    session = IorplSession()
    session.meta = SessionMeta(target_bundle="com.example.app", description="test", tags=["smoke"])
    session.flows = [
        {"flow_id": "f1", "request": {"url": "https://api.example.com/u/1", "method": "GET", "headers": {}}},
        {"flow_id": "f2", "request": {"url": "https://api.example.com/u/2", "method": "POST", "headers": {}}},
    ]
    session.frida_events = [{"event_id": "e1", "cls": "X", "method": "y", "hook_source": "ssl_pinning_bypass.js"}]
    session.endpoints = [{"endpoint": "api.example.com GET /u/{id}", "flow_ids": ["f1"]}]
    session.notes = "# Test\n\nHello.\n"
    session.artifacts["thumb.png"] = b"\x89PNG\r\n\x1a\n" + b"\x00" * 8

    out = SessionArchive.save(session, tmp_path / "test.iorpl")
    assert out.exists()
    assert out.stat().st_size > 0

    reloaded = SessionArchive.load(out)
    assert reloaded.meta.target_bundle == "com.example.app"
    assert reloaded.meta.tags == ["smoke"]
    assert reloaded.meta.description == "test"
    assert len(reloaded.flows) == 2
    assert reloaded.flows[0]["flow_id"] == "f1"
    assert len(reloaded.frida_events) == 1
    assert reloaded.endpoints[0]["endpoint"] == "api.example.com GET /u/{id}"
    assert "thumb.png" in reloaded.artifacts
    assert reloaded.artifacts["thumb.png"].startswith(b"\x89PNG")


def test_load_missing_file_raises(tmp_path):
    import pytest

    with pytest.raises(FileNotFoundError):
        SessionArchive.load(tmp_path / "does_not_exist.iorpl")


def test_from_run_dir_pulls_flows_and_endpoints(tmp_path):
    run_dir = tmp_path / "run-test"
    run_dir.mkdir()
    (run_dir / "mitm_flows.jsonl").write_text(
        json.dumps({"flow_id": "f1", "request": {"url": "https://x/a", "method": "GET", "headers": {}}}) + "\n",
        encoding="utf-8",
    )
    (run_dir / "frida_events.jsonl").write_text(
        json.dumps({"event_id": "e1", "cls": "Foo", "method": "bar", "hook_source": "x.js"}) + "\n",
        encoding="utf-8",
    )
    (run_dir / "artifacts").mkdir()
    (run_dir / "artifacts" / "endpoints.json").write_text(
        json.dumps({"x GET /a": ["f1"]}), encoding="utf-8"
    )

    session = SessionArchive.from_run_dir(run_dir, target_bundle="com.example.app")
    assert session.meta.target_bundle == "com.example.app"
    assert len(session.flows) == 1
    assert len(session.frida_events) == 1
    assert any(ep.get("flow_ids") == ["f1"] for ep in session.endpoints)
