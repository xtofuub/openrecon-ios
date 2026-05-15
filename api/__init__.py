"""Bug-bounty modules.

Each submodule implements `ApiModule` (see `api.base`) and exposes a CLI via
`api.base.cli_entry`. The planner discovers modules by importing them under
`api.<name>` and picking the first class ending with `Module`.
"""

__all__ = [
    "base",
    "idor",
    "auth",
    "mass_assignment",
    "tamper",
    "graphql",
    "token_analysis",
]
