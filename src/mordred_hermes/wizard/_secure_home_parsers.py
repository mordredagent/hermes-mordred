"""``secure-home {status,adopt,run}`` argparse wiring.

Lives outside :mod:`._cli_parsers` — mirroring :mod:`.keyvault_eth_cli`'s
role for ``keyvault eth`` — so the main parser module stays under its size
convention. :func:`add_secure_home` is hooked into
``_cli_parsers._setup_subparser`` the same lazy-import way
``keyvault_eth_cli.add_eth_subparsers`` is hooked into ``_add_keyvault``.
"""

from __future__ import annotations

import argparse

__all__ = ["add_secure_home"]


def add_secure_home(sub: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    """Register ``secure-home {status,adopt,run}`` under the top-level subparsers."""
    p = sub.add_parser(
        "secure-home",
        help="Run Hermes from a user-mounted encrypted APFS volume (opt-in, macOS-only)",
    )
    ssub = p.add_subparsers(dest="secure_home_command", required=True, metavar="COMMAND")

    p_status = ssub.add_parser("status", help="Show secure-home configuration, mount, and identity-verification state")
    p_status.add_argument("--json", action="store_true", help="Machine-readable JSON output")
    p_status.set_defaults(func=_handle_secure_home_status)

    p_adopt = ssub.add_parser(
        "adopt",
        help="Record an already-mounted, user-created encrypted APFS volume as the secure home "
        "(never mounts or creates the volume itself)",
    )
    p_adopt.add_argument("mountpoint", help="Path where the encrypted APFS volume is already mounted")
    p_adopt.add_argument("--force", action="store_true", help="Replace an existing secure-home config")
    p_adopt.set_defaults(func=_handle_secure_home_adopt)

    p_run = ssub.add_parser(
        "run",
        help="Verify the secure home, then exec a command with HERMES_HOME pointed at it "
        "(use: secure-home run -- <command...>)",
    )
    p_run.add_argument(
        "command",
        nargs=argparse.REMAINDER,
        help="Command (and its arguments) to exec, conventionally after a literal `--` "
        "(e.g. `secure-home run -- hermes`)",
    )
    p_run.set_defaults(func=_handle_secure_home_run)


# -----------------------------------------------------------------------------
# Handlers — thin, lazy-imported (mirrors _cli_parsers._handle_* style).
# -----------------------------------------------------------------------------
def _handle_secure_home_status(args: argparse.Namespace) -> int:
    from . import secure_home_cli

    return secure_home_cli.cli_status(args)


def _handle_secure_home_adopt(args: argparse.Namespace) -> int:
    from . import secure_home_cli

    return secure_home_cli.cli_adopt(args)


def _handle_secure_home_run(args: argparse.Namespace) -> int:
    from . import secure_home_cli

    return secure_home_cli.cli_run(args)
