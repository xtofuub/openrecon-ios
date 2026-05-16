"""iorpl YAML suite loader + flow filter."""

from __future__ import annotations

import pytest

from iorpl.suite import FlowFilter, load_suite

YAML = """
name: "Test suite"
description: "Round trip"
context:
  session_pool:
    user_b:
      identity_id: "99"
target:
  hosts: ["api.example.com"]
  methods: ["GET", "POST"]
  path_glob: "/v1/*"
  require_auth: true
  status: [200, 201]
mutations:
  - swap_user_id
  - strip_auth
overrides:
  strip_auth:
    skip_if_path_matches: ["/healthz"]
"""


def test_load_suite_round_trip(tmp_path):
    p = tmp_path / "suite.yaml"
    p.write_text(YAML, encoding="utf-8")
    suite = load_suite(p)
    assert suite.name == "Test suite"
    assert suite.target.hosts == ["api.example.com"]
    assert suite.target.methods == ["GET", "POST"]
    assert suite.target.path_glob == "/v1/*"
    assert suite.target.require_auth is True
    assert suite.target.status == [200, 201]
    assert suite.mutation_names == ["swap_user_id", "strip_auth"]
    assert suite.context.session_pool["user_b"]["identity_id"] == "99"


def test_load_suite_unknown_mutation_raises(tmp_path):
    p = tmp_path / "bad.yaml"
    p.write_text("name: x\nmutations: [does_not_exist]\n", encoding="utf-8")
    with pytest.raises(ValueError, match="unknown mutation"):
        load_suite(p)


def test_flow_filter_host_method_path():
    f = FlowFilter(hosts=["api.example.com"], methods=["GET"], path_glob="/v1/*", require_auth=True, status=[200])
    flow_ok = {
        "request": {
            "url": "https://api.example.com/v1/users",
            "method": "GET",
            "headers": {"Authorization": "Bearer x"},
        },
        "response": {"status": 200},
    }
    flow_no_auth = {
        "request": {"url": "https://api.example.com/v1/users", "method": "GET", "headers": {}},
        "response": {"status": 200},
    }
    flow_other_host = {
        "request": {
            "url": "https://other.example.com/v1/users",
            "method": "GET",
            "headers": {"Authorization": "Bearer x"},
        },
        "response": {"status": 200},
    }
    assert f.matches(flow_ok) is True
    assert f.matches(flow_no_auth) is False
    assert f.matches(flow_other_host) is False


def test_applies_to_skip_path_overrides(tmp_path):
    p = tmp_path / "s.yaml"
    p.write_text(YAML, encoding="utf-8")
    suite = load_suite(p)
    skipped = {
        "request": {"url": "https://api.example.com/healthz", "method": "GET", "headers": {"Authorization": "x"}},
        "response": {"status": 200},
    }
    matched = {
        "request": {"url": "https://api.example.com/v1/users", "method": "GET", "headers": {"Authorization": "x"}},
        "response": {"status": 200},
    }
    assert suite.applies_to("strip_auth", skipped) is False
    assert suite.applies_to("strip_auth", matched) is True
