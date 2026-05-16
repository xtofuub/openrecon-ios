"""ReplayEngine — apply a Suite to an IorplSession and write results.

Algorithm:
    for each flow in session.flows matching suite.target:
        for each mutation in suite.mutations():
            if not suite.applies_to(mutation.name, flow): continue
            for each mutated_request in mutation.apply(flow, ctx):
                send mutated_request via httpx
                verdict = mutation.verdict(flow, mutated_response, mutated_request)
                yield MutationResult(...)

The engine writes one JSONL line per result so consumers can stream-render a
report while a long replay is still running.

httpx is used directly (not openrecon's MitmClient) because iorpl is meant to
be a standalone, repo-agnostic tool — drop a ``.iorpl`` archive on any
machine with Python and the suite still runs.
"""

from __future__ import annotations

import asyncio
import base64
import json
import logging
from dataclasses import asdict
from pathlib import Path
from typing import Any

import httpx

from .format import IorplSession
from .mutations import (
    VERDICT_ERROR,
    MutatedRequest,
    Mutation,
    MutationResult,
)
from .suite import Suite

log = logging.getLogger(__name__)


class ReplayEngine:
    """Drive a session + suite through every mutation, collect verdicts.

    Parameters
    ----------
    session : IorplSession
        Loaded from a ``.iorpl`` archive.
    suite : Suite
        Loaded from YAML via :func:`iorpl.suite.load_suite`.
    output_path : Path
        ``results.jsonl`` destination. Created if missing; appended to (so
        you can resume a partial run by passing the same path).
    timeout : float
        Per-request httpx timeout. Defaults to 30 s.
    verify_tls : bool
        Whether to verify TLS certs. Most engagements set this to False
        because the target backend is being tested with self-issued certs
        or mitm CAs.
    """

    def __init__(
        self,
        session: IorplSession,
        suite: Suite,
        output_path: str | Path,
        *,
        timeout: float = 30.0,
        verify_tls: bool = False,
    ) -> None:
        self.session = session
        self.suite = suite
        self.output_path = Path(output_path)
        self.output_path.parent.mkdir(parents=True, exist_ok=True)
        self.timeout = timeout
        self.verify_tls = verify_tls

    # ---------------------------------------------------------------- run API

    async def run(self) -> list[MutationResult]:
        """Run the suite against the session and return all results.

        Also streams each result to ``output_path`` so partial progress
        survives a crash.
        """
        results: list[MutationResult] = []
        mutations = self.suite.mutations()
        if not mutations:
            log.warning("suite.no_mutations", suite=self.suite.name)
            return results

        async with httpx.AsyncClient(
            verify=self.verify_tls,
            timeout=self.timeout,
            follow_redirects=False,
        ) as client:
            with self.output_path.open("a", encoding="utf-8") as fh:
                for flow in self.session.flows:
                    if not self.suite.target.matches(flow):
                        continue
                    for mutation in mutations:
                        if not self.suite.applies_to(mutation.name, flow):
                            continue
                        for result in await self._run_one(client, mutation, flow):
                            results.append(result)
                            fh.write(json.dumps(asdict(result), default=str) + "\n")
                            fh.flush()
        return results

    def run_sync(self) -> list[MutationResult]:
        return asyncio.run(self.run())

    # ----------------------------------------------------------- single flow

    async def _run_one(
        self,
        client: httpx.AsyncClient,
        mutation: Mutation,
        flow: dict[str, Any],
    ) -> list[MutationResult]:
        results: list[MutationResult] = []
        baseline = flow
        flow_id = str(flow.get("flow_id") or "?")
        try:
            requests = list(mutation.apply(flow, self.suite.context))
        except Exception as exc:
            log.warning("mutation.apply_failed", mutation=mutation.name, error=str(exc))
            return results

        for req in requests:
            mutated_resp = await self._send(client, req)
            try:
                verdict, evidence = mutation.verdict(baseline, mutated_resp, req)
            except Exception as exc:
                verdict, evidence = VERDICT_ERROR, [f"verdict raised {type(exc).__name__}: {exc}"]
            results.append(
                MutationResult(
                    mutation_name=mutation.name,
                    flow_id=flow_id,
                    mutated_request={
                        "url": req.url,
                        "method": req.method,
                        "headers": req.headers,
                        "body_b64": _b64(req.body),
                        "note": req.note,
                    },
                    baseline_response=baseline.get("response") or {},
                    mutated_response=mutated_resp,
                    verdict=verdict,
                    evidence=evidence,
                )
            )
        return results

    # ---------------------------------------------------------- httpx wrapper

    async def _send(self, client: httpx.AsyncClient, req: MutatedRequest) -> dict[str, Any]:
        try:
            response = await client.request(
                req.method,
                req.url,
                headers=req.headers or None,
                content=req.body,
            )
        except httpx.HTTPError as exc:
            return {
                "status": 0,
                "headers": {},
                "body_b64": None,
                "error": f"{type(exc).__name__}: {exc}",
            }
        return {
            "status": response.status_code,
            "headers": dict(response.headers),
            "body_b64": _b64(response.content),
        }


def _b64(data: bytes | None) -> str | None:
    if data is None:
        return None
    if not isinstance(data, (bytes, bytearray)):
        return None
    return base64.b64encode(bytes(data)).decode("ascii")


__all__ = ["ReplayEngine"]
