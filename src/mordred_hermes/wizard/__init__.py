"""mordred_wizard — `hermes mordred …` CLI surface.

Phase 0 scaffold: register() is a no-op stub. Phase 1.3 will wire:
- ctx.register_cli_command("mordred", ...) with subparser tree
  (configure / upgrade / install / network / policy / audit / keyvault)
"""

from typing import Any


def register(ctx: Any) -> None:
    """Hermes plugin entry point. Phase 0 stub — no CLI commands registered yet."""
    return None
