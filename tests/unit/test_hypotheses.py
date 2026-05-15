"""Hypothesis store — append, dedupe, status transitions."""

from __future__ import annotations

import pytest

from agent import hypotheses as h_store
from agent.schema import Hypothesis


def test_read_all_empty(run_dir):
    assert h_store.read_all(run_dir) == []


def test_append_and_read_round_trip(run_dir):
    h = Hypothesis(claim="header X-Sig is HMAC of body")
    h_store.append(run_dir, h)
    items = h_store.read_all(run_dir)
    assert len(items) == 1
    assert items[0].claim == h.claim


def test_append_dedupes_on_claim(run_dir):
    h_store.append(run_dir, Hypothesis(claim="same claim"))
    h_store.append(run_dir, Hypothesis(claim="same claim"))
    assert len(h_store.read_all(run_dir)) == 1


def test_open_hypotheses_filters(run_dir):
    h1 = Hypothesis(claim="open one")
    h2 = Hypothesis(claim="confirmed one", status="confirmed")
    h_store.append(run_dir, h1)
    h_store.append(run_dir, h2)
    open_only = h_store.open_hypotheses(run_dir)
    assert len(open_only) == 1
    assert open_only[0].claim == "open one"


def test_set_status_updates_record(run_dir):
    h = Hypothesis(claim="testable claim")
    h_store.append(run_dir, h)
    items = h_store.read_all(run_dir)
    updated = h_store.set_status(run_dir, items[0].hypothesis_id, "confirmed", evidence_refs=["flow-abc"])
    assert updated is True
    again = h_store.read_all(run_dir)
    assert again[0].status == "confirmed"
    assert any(e.ref == "flow-abc" for e in again[0].evidence)


def test_set_status_returns_false_when_unknown_id(run_dir):
    assert h_store.set_status(run_dir, "no-such-id", "stale") is False


def test_set_status_rejects_invalid_status(run_dir):
    h = Hypothesis(claim="x")
    h_store.append(run_dir, h)
    with pytest.raises(ValueError):
        h_store.set_status(run_dir, h.hypothesis_id, "wat")


def test_counts_reflects_distribution(run_dir):
    h_store.append(run_dir, Hypothesis(claim="one"))
    h_store.append(run_dir, Hypothesis(claim="two", status="confirmed"))
    h_store.append(run_dir, Hypothesis(claim="three", status="refuted"))
    c = h_store.counts(run_dir)
    assert c["open"] == 1
    assert c["confirmed"] == 1
    assert c["refuted"] == 1
    assert c["stale"] == 0
