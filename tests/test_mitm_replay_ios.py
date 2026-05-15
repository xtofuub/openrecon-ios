from __future__ import annotations

from typing import Any

import pytest

from mitm.replay.ios import IosReplayProfile, replay_as_ios


class FakeMitmClient:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, Any] | None]] = []

    async def replay_flow(
        self,
        flow_id: str,
        *,
        overrides: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        self.calls.append((flow_id, overrides))
        return {"flow_id": "replay-1", "response": {"status": 200}}


@pytest.mark.asyncio
async def test_replay_as_ios_adds_profile_headers() -> None:
    client = FakeMitmClient()
    profile = IosReplayProfile(
        user_agent="ExampleApp/7.1 (iPhone; iOS 18.0; Scale/3.00)",
        locale="uk-UA",
        device_model="iPhone16,2",
        ios_version="18.0",
        app_version="7.1",
        timezone="Europe/Kiev",
    )

    result = await replay_as_ios(client, "flow-1", profile=profile, locale="uk-UA")

    assert result["flow_id"] == "replay-1"
    assert client.calls[0][0] == "flow-1"
    headers = client.calls[0][1]["set_headers"]  # type: ignore[index]
    assert headers["User-Agent"] == "ExampleApp/7.1 (iPhone; iOS 18.0; Scale/3.00)"
    assert headers["Accept-Language"] == "uk-UA"
    assert headers["X-Device-Model"] == "iPhone16,2"
    assert headers["X-IOS-Version"] == "18.0"
    assert headers["X-App-Version"] == "7.1"
    assert headers["X-Timezone"] == "Europe/Kiev"


@pytest.mark.asyncio
async def test_replay_as_ios_preserves_explicit_header_overrides() -> None:
    client = FakeMitmClient()

    await replay_as_ios(
        client,
        "flow-2",
        overrides={
            "method": "POST",
            "set_headers": {
                "User-Agent": "PinnedUA/1.0",
                "X-App-Version": "9.9",
            },
        },
        device_headers={"X-Device-ID": "test-device"},
    )

    overrides = client.calls[0][1]
    assert overrides is not None
    assert overrides["method"] == "POST"
    assert overrides["set_headers"]["User-Agent"] == "PinnedUA/1.0"
    assert overrides["set_headers"]["X-App-Version"] == "9.9"
    assert overrides["set_headers"]["X-Device-ID"] == "test-device"
