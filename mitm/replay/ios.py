"""iOS-aware request replay defaults.

Wraps `MitmClient.replay_flow` with the right User-Agent, language, and other
device-shaped headers so a replay looks like it came from the original app.
"""

from __future__ import annotations

from typing import Any

from mitm.client import MitmClient


IOS_USER_AGENT_TEMPLATE = "MyApp/1.0 (iPhone; iOS 17.5; Scale/3.00)"


async def replay_as_ios(
    client: MitmClient,
    flow_id: str,
    *,
    overrides: dict[str, Any] | None = None,
    user_agent: str | None = None,
    locale: str = "en-US",
) -> dict[str, Any]:
    overrides = dict(overrides or {})
    set_headers = dict(overrides.get("set_headers") or {})
    set_headers.setdefault("User-Agent", user_agent or IOS_USER_AGENT_TEMPLATE)
    set_headers.setdefault("Accept-Language", locale)
    overrides["set_headers"] = set_headers
    return await client.replay_flow(flow_id, overrides=overrides)


__all__ = ["replay_as_ios", "IOS_USER_AGENT_TEMPLATE"]
