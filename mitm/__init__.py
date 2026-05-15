"""MITMProxy layer.

`mitm/vendor/` will hold the forked `snapspecter/mitmproxy-mcp` (added via
git subtree). `mitm/addons/` holds our custom mitmproxy addons. `mitm/client.py`
is the thin async MCP client other modules use.
"""

__all__ = ["client"]
