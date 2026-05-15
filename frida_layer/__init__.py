"""Frida orchestration layer.

This package is named `frida_layer` (not `frida`) because the PyPI `frida`
package owns the `frida` import name. We use it via `import frida`.
"""

__all__ = ["runner", "auto_hook"]
