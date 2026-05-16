"""iOSReplay (``iorpl``) — record/replay/mutate iOS app sessions for bug-bounty work.

Think of this as **Playwright for iOS security**:

1. **Record** an interaction with a real iOS app once (touches, API flows,
   auth state) into a portable ``.iorpl`` archive.
2. **Replay** that session against the live backend, with **mutations** applied
   to test for bounty-shaped vulnerabilities — IDOR swap, JWT alg=none, auth
   strip, mass-assignment injection, integer-overflow IDs, etc.
3. **Diff** mutated responses against the baseline and emit verdicts:
   ``no-diff`` / ``status-change`` / ``leak-detected`` / ``auth-bypassed``.
4. **Report** the surviving findings as HackerOne-shaped stubs ready to file.

The Big Idea: most disclosed iOS bounties follow shapes you can fuzz
deterministically once you have a baseline session. ``iorpl`` codifies those
shapes as named mutations + YAML suites, then turns one human-recorded
walkthrough into hundreds of bounty-classifier test cases.

Public API:

    IorplSession        — in-memory session model
    SessionArchive      — read/write ``.iorpl`` tar.gz archives
    Mutation            — abstract mutation interface
    BUILTIN_MUTATIONS   — registry of named mutations
    Suite               — YAML suite definition
    ReplayEngine        — orchestrates session + suite → results
    render_report       — results → markdown / HTML
    main                — CLI entry-point (Click)
"""

# Side-effect import — registers ``llm_creative`` into BUILTIN_MUTATIONS.
# Kept lazy-friendly: the mutation itself only imports anthropic when its
# ``apply()`` runs, so this module-level import doesn't pull the SDK at startup.
from . import ai_mutations  # noqa: F401
from .format import IorplSession, SessionArchive, SessionMeta
from .mutations import BUILTIN_MUTATIONS, Mutation, MutationResult

__all__ = [
    "BUILTIN_MUTATIONS",
    "IorplSession",
    "Mutation",
    "MutationResult",
    "SessionArchive",
    "SessionMeta",
    "main",
]


def main() -> None:
    """Console entry-point for the ``iorpl`` CLI."""
    from .cli import cli

    cli()
