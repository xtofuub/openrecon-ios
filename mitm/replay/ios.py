"""iOS-aware request replay defaults.

Wraps `MitmClient.replay_flow` with the right User-Agent, language, and other
device-shaped headers so a replay looks like it came from the original app.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from mitm.client import MitmClient

IOS_USER_AGENT_TEMPLATE = "MyApp/1.0 (iPhone; iOS 17.5; Scale/3.00)"


@dataclass(frozen=True)
class IosReplayProfile:
    """Headers that make active replays look like the assessed iOS app."""

    user_agent: str = IOS_USER_AGENT_TEMPLATE
    locale: str = "en-US"
    device_model: str | None = None
    ios_version: str | None = None
    app_version: str | None = None
    timezone: str | None = None
    extra_headers: dict[str, str] = field(default_factory=dict)

    def headers(self) -> dict[str, str]:
        headers = {
            "User-Agent": self.user_agent,
            "Accept-Language": self.locale,
        }
        if self.device_model:
            headers["X-Device-Model"] = self.device_model
        if self.ios_version:
            headers["X-IOS-Version"] = self.ios_version
        if self.app_version:
            headers["X-App-Version"] = self.app_version
        if self.timezone:
            headers["X-Timezone"] = self.timezone
        headers.update(self.extra_headers)
        return headers


DEFAULT_IOS_REPLAY_PROFILE = IosReplayProfile()


async def replay_as_ios(
    client: MitmClient,
    flow_id: str,
    *,
    overrides: dict[str, Any] | None = None,
    profile: IosReplayProfile | None = None,
    user_agent: str | None = None,
    locale: str = "en-US",
    device_headers: dict[str, str] | None = None,
) -> dict[str, Any]:
    overrides = dict(overrides or {})
    set_headers = (profile or DEFAULT_IOS_REPLAY_PROFILE).headers()
    set_headers["User-Agent"] = user_agent or set_headers["User-Agent"]
    set_headers["Accept-Language"] = locale or set_headers["Accept-Language"]
    set_headers.update(device_headers or {})
    set_headers.update(overrides.get("set_headers") or {})
    overrides["set_headers"] = set_headers
    return await client.replay_flow(flow_id, overrides=overrides)


__all__ = [
    "DEFAULT_IOS_REPLAY_PROFILE",
    "IOS_USER_AGENT_TEMPLATE",
    "IosReplayProfile",
    "replay_as_ios",
]
