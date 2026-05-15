"""GraphQL module — introspection, depth, alias bypass, batch smuggling."""

from __future__ import annotations

import base64
import json
from typing import Any

from agent.schema import (
    Evidence,
    Finding,
    ModuleCoverage,
    ModuleResult,
    ReproStep,
    Severity,
)

from .base import ApiModule, ModuleInput, cli_entry


_INTROSPECTION_QUERY = """
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    types { name kind fields { name type { name kind } } }
  }
}
""".strip()


class GraphqlModule(ApiModule):
    name = "graphql"
    severity_baseline = Severity.MEDIUM

    async def run(self, inp: ModuleInput) -> ModuleResult:
        findings: list[Finding] = []
        coverage = ModuleCoverage(totals={"endpoints": 0, "probes": 0})

        gql_flows = await self._discover_endpoints(inp)
        for flow in gql_flows:
            coverage.totals["endpoints"] += 1
            findings += await self._introspect(inp, flow, coverage)
            findings += await self._depth_abuse(inp, flow, coverage)
            findings += await self._alias_bypass(inp, flow, coverage)
            findings += await self._batch_smuggle(inp, flow, coverage)
            coverage.tested.append(flow["flow_id"])

        if not gql_flows:
            coverage.skipped.append(("*", "no graphql endpoint detected"))

        return ModuleResult(module=self.name, findings=findings, coverage=coverage)

    async def _discover_endpoints(self, inp: ModuleInput) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        path = inp.run_dir / "mitm_flows.jsonl"
        if not path.exists():
            return out
        with path.open(encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                r = json.loads(line)
                if _looks_graphql(r):
                    out.append(r)
        return out

    async def _introspect(self, inp: ModuleInput, flow: dict[str, Any], coverage: ModuleCoverage) -> list[Finding]:
        coverage.totals["probes"] += 1
        replay = await inp.mitm_mcp.replay_flow(
            flow["flow_id"],
            overrides={"body_replace": json.dumps({"query": _INTROSPECTION_QUERY})},
        )
        status = (replay.get("response") or {}).get("status", 0)
        if not (200 <= status < 300):
            return []
        body = _decode_body(replay) or ""
        if "__schema" in body:
            artifact_path = inp.run_dir / "artifacts" / "graphql_schema.json"
            artifact_path.parent.mkdir(parents=True, exist_ok=True)
            artifact_path.write_text(body, encoding="utf-8")
            return [
                _finding(
                    inp,
                    flow,
                    replay,
                    title="GraphQL introspection enabled",
                    severity=Severity.MEDIUM,
                    detail="full __schema returned",
                    repro_query=_INTROSPECTION_QUERY,
                )
            ]
        return []

    async def _depth_abuse(self, inp: ModuleInput, flow: dict[str, Any], coverage: ModuleCoverage) -> list[Finding]:
        coverage.totals["probes"] += 1
        nested = "{ a " * 18 + "}" * 18  # depth=18
        query = "query D " + nested
        replay = await inp.mitm_mcp.replay_flow(
            flow["flow_id"], overrides={"body_replace": json.dumps({"query": query})}
        )
        status = (replay.get("response") or {}).get("status", 0)
        if status in (500, 502, 503, 504) or (replay.get("response", {}).get("duration_ms") or 0) > 5000:
            return [
                _finding(
                    inp,
                    flow,
                    replay,
                    title="GraphQL depth-abuse causes server error or timeout",
                    severity=Severity.LOW,
                    detail=f"depth=18 → status {status}",
                    repro_query=query,
                )
            ]
        return []

    async def _alias_bypass(self, inp: ModuleInput, flow: dict[str, Any], coverage: ModuleCoverage) -> list[Finding]:
        coverage.totals["probes"] += 1
        body = _decode_body(flow)
        if not body:
            return []
        try:
            data = json.loads(body)
            base = data.get("query")
        except Exception:
            return []
        if not base or "query" not in base:
            return []
        # naive: aliases of the same field; works on simple queries
        aliased = "query Q { " + " ".join(f"a{i}:{base.strip().lstrip('query').strip(' {}')}" for i in range(5)) + " }"
        replay = await inp.mitm_mcp.replay_flow(
            flow["flow_id"], overrides={"body_replace": json.dumps({"query": aliased})}
        )
        status = (replay.get("response") or {}).get("status", 0)
        if 200 <= status < 300:
            return [
                _finding(
                    inp,
                    flow,
                    replay,
                    title="GraphQL aliasing accepted — potential rate-limit bypass",
                    severity=Severity.LOW,
                    detail="5 aliases in one query",
                    repro_query=aliased,
                )
            ]
        return []

    async def _batch_smuggle(self, inp: ModuleInput, flow: dict[str, Any], coverage: ModuleCoverage) -> list[Finding]:
        coverage.totals["probes"] += 1
        body = _decode_body(flow)
        if not body:
            return []
        try:
            data = json.loads(body)
        except Exception:
            return []
        if isinstance(data, list):
            return []  # already a batch — skip
        batch = [data, {"query": "{ __typename }"}]
        replay = await inp.mitm_mcp.replay_flow(
            flow["flow_id"], overrides={"body_replace": json.dumps(batch)}
        )
        status = (replay.get("response") or {}).get("status", 0)
        if 200 <= status < 300:
            body_resp = _decode_body(replay) or ""
            if body_resp.lstrip().startswith("["):
                return [
                    _finding(
                        inp,
                        flow,
                        replay,
                        title="GraphQL batched queries accepted",
                        severity=Severity.LOW,
                        detail="batch smuggling possible",
                        repro_query=json.dumps(batch),
                    )
                ]
        return []


def _looks_graphql(flow: dict[str, Any]) -> bool:
    url = flow["request"]["url"].lower()
    if url.endswith("/graphql") or "/graphql?" in url:
        return True
    for k, v in flow["request"]["headers"].items():
        if k.lower() == "content-type" and "graphql" in v.lower():
            return True
    body = _decode_body(flow)
    if body and ('"query"' in body or '"mutation"' in body):
        return True
    return False


def _decode_body(record: dict[str, Any]) -> str | None:
    body = record.get("request", {}).get("body_b64") or record.get("response", {}).get("body_b64")
    if not body:
        return None
    try:
        return base64.b64decode(body).decode("utf-8", "ignore")
    except Exception:
        return None


def _finding(
    inp: ModuleInput,
    flow: dict[str, Any],
    replay: dict[str, Any],
    *,
    title: str,
    severity: Severity,
    detail: str,
    repro_query: str,
) -> Finding:
    return Finding(
        run_id=str(inp.run_dir.name),
        severity=severity,
        category="graphql",
        title=title,
        summary=detail,
        evidence=[
            Evidence(kind="flow", ref=flow["flow_id"], note="baseline"),
            Evidence(kind="flow", ref=replay.get("flow_id", "?"), note="probe"),
        ],
        correlated_flows=[flow["flow_id"], replay.get("flow_id", "?")],
        reproduction=[
            ReproStep(
                description=detail,
                primitive="replay_flow",
                args={"flow_id": flow["flow_id"], "body": repro_query[:2000]},
            )
        ],
        tags=["graphql"],
        confidence=0.6,
    )


if __name__ == "__main__":  # pragma: no cover
    cli_entry(GraphqlModule)
