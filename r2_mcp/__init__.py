"""r2_mcp — radare2 MCP server for static iOS binary analysis.

Pairs with the autonomous engagement pipeline. Holds one radare2 session per
binary path so repeated queries (functions, xrefs, decompilation) reuse a
single analysis pass.

Public API:
    R2Session  — r2pipe wrapper with idempotent ``aaa`` analysis
    main       — entrypoint for ``r2-mcp`` stdio server
"""

from .session import R2Session, R2SessionError

__all__ = ["R2Session", "R2SessionError", "main"]


def main() -> None:
    """Console entry-point for ``r2-mcp``. Delegates to FastMCP stdio run."""
    from .server import run_stdio

    run_stdio()
