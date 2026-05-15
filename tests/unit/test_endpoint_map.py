"""Endpoint templating and grouping."""

from __future__ import annotations

from agent.endpoint_map import group_flows, template_path


def test_template_path_replaces_numeric_id():
    assert template_path("/v1/users/42/orders") == "/v1/users/{id}/orders"


def test_template_path_replaces_uuid():
    assert (
        template_path("/v1/orgs/550e8400-e29b-41d4-a716-446655440000/members")
        == "/v1/orgs/{uuid}/members"
    )


def test_template_path_replaces_opaque_token():
    assert template_path("/v1/sessions/abc123_DEF456-XYZ") == "/v1/sessions/{token}"


def test_template_path_keeps_known_words():
    assert template_path("/v1/users/me/profile") == "/v1/users/me/profile"


def test_group_flows_dedupes_same_endpoint(mitm_flow_factory):
    flows = [
        mitm_flow_factory(flow_id="a", url="https://api.example.com/v1/users/42").model_dump(),
        mitm_flow_factory(flow_id="b", url="https://api.example.com/v1/users/43").model_dump(),
        mitm_flow_factory(flow_id="c", url="https://api.example.com/v1/users/44").model_dump(),
    ]
    groups = group_flows(flows)
    assert len(groups) == 1
    assert groups[0].path_template == "/v1/users/{id}"
    assert groups[0].flow_ids == ["a", "b", "c"]


def test_group_flows_separates_methods(mitm_flow_factory):
    flows = [
        mitm_flow_factory(flow_id="a", method="GET", url="https://api/x").model_dump(),
        mitm_flow_factory(flow_id="b", method="POST", url="https://api/x").model_dump(),
    ]
    groups = group_flows(flows)
    assert len(groups) == 2


def test_group_flows_records_auth_headers(mitm_flow_factory):
    flows = [
        mitm_flow_factory(
            flow_id="a",
            url="https://api/x",
            request_headers={"Authorization": "Bearer abc"},
        ).model_dump(),
    ]
    groups = group_flows(flows)
    assert groups[0].auth_headers_seen == {"authorization"}


def test_group_flows_tracks_status_counts(mitm_flow_factory):
    flows = [
        mitm_flow_factory(flow_id=f"f{i}", response_status=200, url="https://api/x").model_dump()
        for i in range(3)
    ]
    flows.append(
        mitm_flow_factory(flow_id="err", response_status=401, url="https://api/x").model_dump()
    )
    groups = group_flows(flows)
    assert len(groups) == 1
    assert groups[0].status_counts == {200: 3, 401: 1}
