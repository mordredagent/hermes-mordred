"""``secure-home {status,adopt,run,init,mount,unmount}`` argparse wiring.

Lives outside :mod:`._cli_parsers` — mirroring :mod:`.keyvault_eth_cli`'s
role for ``keyvault eth`` — so the main parser module stays under its size
convention. :func:`add_secure_home` is hooked into
``_cli_parsers._setup_subparser`` the same lazy-import way
``keyvault_eth_cli.add_eth_subparsers`` is hooked into ``_add_keyvault``.

Note what is deliberately *absent*: no verb takes a passphrase. The volume
passphrase is only ever collected from an interactive prompt (see
:mod:`.secure_home_lifecycle_cli`), because a flag would put it in ``ps``
output and shell history.

``--size`` / ``--volname`` repeat their defaults as literals rather than
importing ``secure_home_lifecycle_cli.DEFAULT_*``: this module is imported
whenever the CLI parser is built, and that module pulls in the whole
``configure`` prompt stack. ``tests/test_wizard_secure_home_lifecycle_cli.py``
pins the literals to the constants so they cannot drift.
"""

from __future__ import annotations

import argparse

from ._secure_home_paths import MODES

__all__ = ["add_secure_home"]

_MODE_HELP = "Record the intended unlock cadence (informational in Phase 2; drives the post-init guidance)"


def add_secure_home(sub: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    """Register ``secure-home {status,adopt,run,init,mount,unmount}`` under the top-level subparsers."""
    p = sub.add_parser(
        "secure-home",
        help="Run Hermes from an encrypted APFS volume (opt-in, macOS-only)",
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
    p_adopt.add_argument("--mode", choices=list(MODES), default=None, help=_MODE_HELP)
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

    _add_lifecycle(ssub)


def _add_lifecycle(ssub: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    """The Phase 2 volume ceremonies — the only verbs that change a volume's state."""
    p_init = ssub.add_parser(
        "init",
        help="Create an encrypted disk image, attach it, and record it as the secure home "
        "(prompts for the passphrase; there is deliberately no passphrase flag)",
    )
    p_init.add_argument(
        "--image",
        default=None,
        help="Disk image to create (default: ~/Library/Application Support/hermes-mordred/secure-home.sparseimage)",
    )
    p_init.add_argument(
        "--mount-point",
        default=None,
        help="Where to mount it (default: ~/Library/Application Support/hermes-mordred/secure-home)",
    )
    p_init.add_argument("--size", default="4g", help="Maximum image size; sparse, so it grows on demand (default: 4g)")
    p_init.add_argument("--volname", default="HermesSecure", help="APFS volume name (default: HermesSecure)")
    p_init.add_argument("--mode", choices=list(MODES), default=None, help=_MODE_HELP)
    p_init.add_argument(
        "--force",
        action="store_true",
        help="Replace an existing secure-home CONFIG; never overwrites an existing image",
    )
    p_init.set_defaults(func=_handle_secure_home_init)

    p_mount = ssub.add_parser(
        "mount",
        help="Unlock and mount the configured secure home, then re-verify it (idempotent)",
    )
    p_mount.set_defaults(func=_handle_secure_home_mount)

    p_unmount = ssub.add_parser(
        "unmount",
        help="Verify the mounted volume's identity, then lock the secure home again",
    )
    p_unmount.add_argument(
        "--force",
        action="store_true",
        help="Unmount even when the volume is busy (stops nothing; the OS force-ejects it)",
    )
    p_unmount.set_defaults(func=_handle_secure_home_unmount)


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


def _handle_secure_home_init(args: argparse.Namespace) -> int:
    from . import secure_home_lifecycle_cli

    return secure_home_lifecycle_cli.cli_init(args)


def _handle_secure_home_mount(args: argparse.Namespace) -> int:
    from . import secure_home_lifecycle_cli

    return secure_home_lifecycle_cli.cli_mount(args)


def _handle_secure_home_unmount(args: argparse.Namespace) -> int:
    from . import secure_home_lifecycle_cli

    return secure_home_lifecycle_cli.cli_unmount(args)
