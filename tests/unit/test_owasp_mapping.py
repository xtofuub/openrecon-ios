"""OWASP Mobile Top 10 mapping helpers."""

from __future__ import annotations

from agent.owasp_mapping import (
    CATEGORY_TO_OWASP,
    annotate_finding,
    owasp_for_category,
)


def test_idor_maps_to_m3():
    out = owasp_for_category("idor")
    codes = [c for c, _ in out]
    assert "M3" in codes


def test_token_weakness_maps_to_m1_and_m10():
    out = owasp_for_category("token-weakness")
    codes = {c for c, _ in out}
    assert codes == {"M1", "M10"}


def test_unknown_category_returns_empty():
    assert owasp_for_category("not-a-real-category") == []


def test_annotate_finding_adds_owasp_field():
    f = {"finding_id": "x", "category": "idor", "severity": "high", "title": "t", "summary": "s"}
    enriched = annotate_finding(f)
    assert "owasp" in enriched
    assert {item["id"] for item in enriched["owasp"]} == {"M3"}


def test_annotate_finding_no_op_when_unknown_category():
    f = {"finding_id": "x", "category": "rce", "severity": "high", "title": "t", "summary": "s"}
    enriched = annotate_finding(f)
    assert "owasp" not in enriched


def test_every_mapped_category_has_at_least_one_owasp_entry():
    for category, mappings in CATEGORY_TO_OWASP.items():
        assert mappings, f"category {category!r} has empty mapping"
