"""mitmproxy addon — drop common iOS telemetry hosts.

Pass `--set openrecon_ios_strict=1` to disable filtering.
"""

from __future__ import annotations

import os

from mitmproxy import ctx, http  # type: ignore[import-not-found]


_TELEMETRY_HOST_SUFFIXES = (
    "crashlytics.com",
    "firebaselogging-pa.googleapis.com",
    "firebase-settings.crashlytics.com",
    "app-measurement.com",
    "sentry.io",
    "ingest.sentry.io",
    "amplitude.com",
    "mixpanel.com",
    "branch.io",
    "apple.com",  # broad — narrowed below
)

_APPLE_TELEMETRY_PATHS = (
    "/itunes_apple_com/",
    "/v1/applepay",  # keep apple pay traffic? actually drop telemetry only
    "/iadsdk/",
)


class IosFilter:
    def request(self, flow: http.HTTPFlow) -> None:
        if os.environ.get("openrecon_IOS_STRICT") == "1":
            return
        host = flow.request.pretty_host
        for suffix in _TELEMETRY_HOST_SUFFIXES:
            if host.endswith(suffix):
                if host.endswith("apple.com"):
                    if not any(p in flow.request.path for p in _APPLE_TELEMETRY_PATHS):
                        continue
                ctx.log.info(f"ios_filter: dropping {host}{flow.request.path}")
                flow.kill()
                return


addons = [IosFilter()]
