"""Run bundle export — tar.gz contents and manifest."""

from __future__ import annotations

import json
import tarfile

from agent.export import export_run


def test_export_run_creates_tar_gz_with_expected_layout(event_store, mitm_flow_factory):
    event_store.append("mitm_flows", mitm_flow_factory(flow_id="f1"))
    (event_store.run_dir / "findings.jsonl").write_text(
        '{"finding_id":"x","run_id":"r","severity":"low","category":"idor","title":"t","summary":"s"}\n',
        encoding="utf-8",
    )

    out = export_run(event_store.run_dir)
    assert out.exists()
    assert out.suffix == ".gz"

    with tarfile.open(out, "r:gz") as tar:
        names = tar.getnames()
        run_name = event_store.run_dir.name
        assert f"{run_name}/MANIFEST.json" in names
        assert f"{run_name}/mitm_flows.jsonl" in names
        assert f"{run_name}/findings.jsonl" in names
        # SQLite indexes excluded.
        assert not any(n.endswith(".sqlite") for n in names)
        assert not any("/index/" in n for n in names)


def test_export_manifest_contains_sha256_for_each_file(event_store, mitm_flow_factory):
    event_store.append("mitm_flows", mitm_flow_factory(flow_id="f1"))
    out = export_run(event_store.run_dir)
    run_name = event_store.run_dir.name
    with tarfile.open(out, "r:gz") as tar:
        manifest_member = tar.getmember(f"{run_name}/MANIFEST.json")
        fobj = tar.extractfile(manifest_member)
        assert fobj is not None
        manifest = json.loads(fobj.read())
    assert manifest["run"]["run_id"] == run_name
    assert any(entry["path"] == "mitm_flows.jsonl" for entry in manifest["files"])
    for entry in manifest["files"]:
        assert len(entry["sha256"]) == 64


def test_export_run_missing_dir_raises(tmp_path):
    import pytest

    with pytest.raises(FileNotFoundError):
        export_run(tmp_path / "nope")


def test_export_explicit_out_path(event_store, tmp_path, mitm_flow_factory):
    event_store.append("mitm_flows", mitm_flow_factory(flow_id="f1"))
    out = tmp_path / "bundles" / "myrun.tar.gz"
    result = export_run(event_store.run_dir, out)
    assert result == out
    assert out.exists()
