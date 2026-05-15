"""Endpoint deduplication and templating.

Used by the planner's `MapEndpoints` step, the finder rules, and the bug-bounty
modules whenever they want to group flows by canonical endpoint. The same path
appearing with different IDs (e.g. `/v1/users/42` and `/v1/users/43`) becomes
one templated endpoint `/v1/users/{id}`.
"""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

_UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_OPAQUE_TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{16,}$")


def template_path(path: str) -> str:
    """Replace ID-shaped segments with `{id}` / `{uuid}` / `{token}`."""
    out: list[str] = []
    for seg in path.split("/"):
        if not seg:
            out.append(seg)
            continue
        if seg.isdigit():
            out.append("{id}")
        elif _UUID_RE.match(seg):
            out.append("{uuid}")
        elif _OPAQUE_TOKEN_RE.match(seg):
            out.append("{token}")
        else:
            out.append(seg)
    return "/".join(out)


@dataclass
class EndpointGroup:
    host: str
    method: str
    path_template: str
    flow_ids: list[str] = field(default_factory=list)
    status_counts: dict[int, int] = field(default_factory=dict)
    auth_headers_seen: set[str] = field(default_factory=set)

    def as_dict(self) -> dict[str, Any]:
        return {
            "host": self.host,
            "method": self.method,
            "path_template": self.path_template,
            "flow_count": len(self.flow_ids),
            "sample_flow_ids": self.flow_ids[:5],
            "status_counts": dict(self.status_counts),
            "auth_headers_seen": sorted(self.auth_headers_seen),
        }


def group_flows(flows: list[dict[str, Any]]) -> list[EndpointGroup]:
    """Group a list of MITM flow dicts into deduplicated endpoint records."""
    groups: dict[tuple[str, str, str], EndpointGroup] = defaultdict(
        lambda: EndpointGroup(host="", method="", path_template="")
    )
    auth_header_names = {"authorization", "cookie", "x-api-key", "x-auth-token", "x-session-token"}

    for flow in flows:
        req = flow.get("request") or {}
        url = urlparse(req.get("url", ""))
        host = url.hostname or ""
        method = (req.get("method") or "").upper()
        template = template_path(url.path or "/")
        key = (host, method, template)

        group = groups[key]
        if not group.host:
            group.host = host
            group.method = method
            group.path_template = template
        group.flow_ids.append(flow.get("flow_id", "?"))
        status = (flow.get("response") or {}).get("status")
        if isinstance(status, int):
            group.status_counts[status] = group.status_counts.get(status, 0) + 1
        for k in req.get("headers", {}):
            if k.lower() in auth_header_names:
                group.auth_headers_seen.add(k.lower())

    # Stable ordering: by host then path then method.
    return sorted(groups.values(), key=lambda g: (g.host, g.path_template, g.method))


__all__ = ["template_path", "EndpointGroup", "group_flows"]
