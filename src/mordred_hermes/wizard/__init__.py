"""mordred_wizard — ``hermes-mordred …`` CLI surface.

Phase 1.3 wires :func:`register` to Hermes's ``register_cli_command``.
The full subcommand tree lives in :mod:`.cli`; each handler is filled in
phase-by-phase (Phases B-F). ``register()`` itself is cheap and
side-effect-free at plugin discovery time.
"""

from ._typing import PluginContext
from .cli import _setup_subparser


def register(ctx: PluginContext) -> None:
    """Hermes plugin entry point — wires the ``hermes mordred`` subcommand."""
    ctx.register_cli_command(
        "mordred",
        help="Mordred privacy layer — configure, upgrade, install, audit",
        setup_fn=_setup_subparser,
        description=(
            "Mordred wraps the Hermes agent with privacy-preserving "
            "policy enforcement (skill metadata gating, network-path "
            "control, local-LLM redirection, keyvault). Run "
            "`hermes-mordred configure` to start."
        ),
    )
