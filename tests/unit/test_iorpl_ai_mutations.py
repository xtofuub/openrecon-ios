"""LLM creative mutation — graceful fallbacks + candidate parsing."""

from __future__ import annotations

from iorpl.ai_mutations import LLMCreativeMutation, _candidate_to_request, _parse_candidates
from iorpl.mutations import BUILTIN_MUTATIONS, MutationContext


def test_registered_in_builtins():
    assert "llm_creative" in BUILTIN_MUTATIONS


def test_returns_empty_without_api_key(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    mut = LLMCreativeMutation()
    flow = {
        "request": {"url": "https://api.example.com/v1/things", "method": "GET", "headers": {}},
        "response": {"status": 200},
    }
    out = list(mut.apply(flow, MutationContext()))
    assert out == []


def test_returns_empty_when_url_missing(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "fake")
    mut = LLMCreativeMutation()
    out = list(mut.apply({"request": {"method": "GET", "headers": {}}}, MutationContext()))
    assert out == []


def test_parse_candidates_extracts_array_from_prose():
    text = """
    Here are some ideas:
    [
      {"url": "https://x/a", "method": "POST", "headers": {}, "body": null, "rationale": "test"}
    ]
    Thanks!
    """
    out = _parse_candidates(text)
    assert len(out) == 1
    assert out[0]["url"] == "https://x/a"


def test_parse_candidates_returns_empty_on_garbage():
    assert _parse_candidates("not json") == []
    assert _parse_candidates("") == []
    assert _parse_candidates("{not an array}") == []


def test_candidate_to_request_falls_back_to_baseline():
    fallback = {"url": "https://x/a", "method": "GET", "headers": {"Authorization": "Bearer x"}}
    req = _candidate_to_request({"method": "POST", "body": '{"x":1}'}, fallback=fallback)
    assert req.url == "https://x/a"
    assert req.method == "POST"
    assert req.body == b'{"x":1}'
    assert req.headers.get("Authorization") == "Bearer x"


def test_candidate_to_request_dict_body_serialized():
    fallback = {"url": "https://x/a", "method": "POST", "headers": {}}
    req = _candidate_to_request({"body": {"role": "admin"}, "rationale": "priv esc"}, fallback=fallback)
    assert req.body == b'{"role": "admin"}'
    assert "priv esc" in req.note
