"""iorpl report rendering."""

from __future__ import annotations

from iorpl.report import render_html, render_markdown


def _result(verdict: str = "auth_bypassed") -> dict:
    return {
        "mutation_name": "strip_auth",
        "flow_id": "f1",
        "mutated_request": {
            "url": "https://api.example.com/protected",
            "method": "GET",
            "headers": {},
            "note": "stripped Authorization",
        },
        "baseline_response": {"status": 200, "headers": {}, "body_b64": None},
        "mutated_response": {"status": 200, "headers": {}, "body_b64": None},
        "verdict": verdict,
        "evidence": ["server returned 200 with no auth"],
    }


def test_markdown_includes_summary_and_finding():
    out = render_markdown([_result(), _result(verdict="no_diff")])
    assert "iorpl replay report" in out
    assert "auth_bypassed" in out
    assert "strip_auth" in out


def test_markdown_emits_hackerone_stub_for_confirmed_findings():
    out = render_markdown([_result()])
    assert "HackerOne report stubs" in out
    assert "Severity" in out
    assert "Steps to reproduce" in out


def test_markdown_skips_hackerone_section_when_no_findings():
    out = render_markdown([_result(verdict="no_diff")])
    assert "HackerOne report stubs" not in out


def test_html_wraps_markdown_in_html_doc():
    out = render_html([_result()], suite_name="my suite")
    assert out.startswith("<!doctype html>")
    assert "auth_bypassed" in out
    assert "my suite" in out
