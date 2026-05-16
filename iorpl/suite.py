"""YAML test-suite loader for iorpl.

A *suite* defines what subset of the recorded flows to attack and which
mutations to run against each. Suites live as YAML so they can be hand-
authored, version-controlled, and shared across teams.

Minimal schema::

    name: "Auth + IDOR sweep"
    description: "Bounty-shaped checks for any authenticated 2xx flow"

    context:
      session_pool:
        user_b:
          identity_id: "42"
          auth_header: "Bearer user_b_token_here"
      extras:
        rs256_public_key_pem: |
          -----BEGIN PUBLIC KEY-----
          ...
          -----END PUBLIC KEY-----

    target:
      hosts: ["api.example.com"]
      methods: ["GET", "POST", "PUT", "PATCH"]
      path_glob: "/v1/**"
      require_auth: true
      status: [200, 201, 204]

    mutations:
      - swap_user_id
      - integer_overflow_id
      - strip_auth
      - jwt_alg_none
      - mass_assignment_inject_privileged_fields
      - method_swap
      - path_extra_admin_segment

    # Optional per-mutation skip/include rules.
    overrides:
      strip_auth:
        skip_if_path_matches: ["/healthz", "/version"]

The two ``flow_matches()`` and ``mutations_for()`` helpers are pure (no
side-effects) so they're trivially testable.
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from .mutations import BUILTIN_MUTATIONS, Mutation, MutationContext

_AUTH_HEADERS = ("authorization", "cookie", "x-api-key", "x-auth-token", "x-session-token")


@dataclass
class FlowFilter:
    hosts: list[str] = field(default_factory=list)        # empty → any host
    methods: list[str] = field(default_factory=list)
    path_glob: str | None = None
    require_auth: bool = False
    status: list[int] = field(default_factory=list)        # empty → any 2xx

    def matches(self, flow: dict[str, Any]) -> bool:
        request = flow.get("request") or {}
        response = flow.get("response") or {}
        url = str(request.get("url") or "")
        method = str(request.get("method") or "").upper()
        try:
            parsed = urlparse(url)
        except ValueError:
            return False
        host = parsed.hostname or ""
        path = parsed.path or "/"

        if self.hosts and host not in self.hosts:
            return False
        if self.methods and method not in {m.upper() for m in self.methods}:
            return False
        if self.path_glob and not fnmatch.fnmatch(path, self.path_glob):
            return False
        if self.require_auth:
            headers_lower = {str(k).lower() for k in (request.get("headers") or {})}
            if not any(h in headers_lower for h in _AUTH_HEADERS):
                return False
        if self.status:
            if int(response.get("status") or 0) not in self.status:
                return False
        return True


@dataclass
class Suite:
    name: str = "unnamed"
    description: str = ""
    target: FlowFilter = field(default_factory=FlowFilter)
    mutation_names: list[str] = field(default_factory=list)
    context: MutationContext = field(default_factory=MutationContext)
    overrides: dict[str, dict[str, Any]] = field(default_factory=dict)

    def mutations(self) -> list[Mutation]:
        out: list[Mutation] = []
        for name in self.mutation_names:
            m = BUILTIN_MUTATIONS.get(name)
            if m is not None:
                out.append(m)
        return out

    def applies_to(self, mutation_name: str, flow: dict[str, Any]) -> bool:
        """Per-mutation overrides — currently only ``skip_if_path_matches``."""
        rules = self.overrides.get(mutation_name) or {}
        skip_paths = rules.get("skip_if_path_matches") or []
        if not skip_paths:
            return True
        request = flow.get("request") or {}
        try:
            path = urlparse(str(request.get("url") or "")).path or "/"
        except ValueError:
            return True
        return not any(fnmatch.fnmatch(path, p) for p in skip_paths)


def load_suite(path: str | Path) -> Suite:
    """Parse a YAML suite from disk."""
    import yaml

    text = Path(path).read_text(encoding="utf-8")
    data = yaml.safe_load(text) or {}
    if not isinstance(data, dict):
        raise ValueError(f"suite root must be a mapping; got {type(data).__name__}")

    target_raw = data.get("target") or {}
    target = FlowFilter(
        hosts=list(target_raw.get("hosts") or []),
        methods=list(target_raw.get("methods") or []),
        path_glob=target_raw.get("path_glob"),
        require_auth=bool(target_raw.get("require_auth", False)),
        status=[int(s) for s in (target_raw.get("status") or []) if isinstance(s, (int, str)) and str(s).isdigit()],
    )

    context_raw = data.get("context") or {}
    context = MutationContext(
        session_pool=dict(context_raw.get("session_pool") or {}),
        extras=dict(context_raw.get("extras") or {}),
    )

    mutation_names = [str(n) for n in (data.get("mutations") or [])]
    unknown = [n for n in mutation_names if n not in BUILTIN_MUTATIONS]
    if unknown:
        known = ", ".join(sorted(BUILTIN_MUTATIONS))
        raise ValueError(f"unknown mutation(s): {unknown}. Known: {known}")

    return Suite(
        name=str(data.get("name") or Path(path).stem),
        description=str(data.get("description") or ""),
        target=target,
        mutation_names=mutation_names,
        context=context,
        overrides=dict(data.get("overrides") or {}),
    )


__all__ = ["FlowFilter", "Suite", "load_suite"]
