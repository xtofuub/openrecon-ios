"""r2frida_mcp — r2frida MCP server for live iOS process inspection.

Bridges radare2's ``frida://`` IO plugin (r2frida) so AI agents can introspect
a running iOS app's memory, ObjC runtime, modules, and trace selectors —
all with radare2's analysis primitives on top of Frida's dynamic instrumentation.

Public API:
    R2FridaSession  — r2pipe + frida:// wrapper
    main            — entrypoint for ``r2frida-mcp`` stdio server
"""

from .session import R2FridaSession, R2FridaSessionError

__all__ = ["R2FridaSession", "R2FridaSessionError", "main"]


def main() -> None:
    """Console entry-point for ``r2frida-mcp``. Delegates to FastMCP stdio run."""
    from .server import run_stdio

    run_stdio()
