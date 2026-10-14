"""Recognize offline database maintenance before Hermes imports its CLI."""

from __future__ import annotations

import sys
from pathlib import Path

# Match the root options from hermes_cli._parser without importing Hermes
# during site initialization. Consume values rather than searching argv:
# a model name or a one-shot prompt may itself contain "mordred".
_VALUES = {"--model", "-m", "--provider", "--toolsets", "-t", "--resume", "-r", "--skills", "-s", "--usage-file"}
_FLAGS = {
    "--no-restore-cwd",
    "--worktree",
    "-w",
    "--accept-hooks",
    "--yolo",
    "--pass-session-id",
    "--ignore-user-config",
    "--ignore-rules",
    "--safe-mode",
    "--tui",
    "--cli",
    "--dev",
    "--version",
    "-V",
}
_OPTIONS = _VALUES | _FLAGS | {"--continue", "-c", "--oneshot", "-z"}


def _root_option(token: str) -> tuple[str, bool] | None:
    option, separator, _ = token.partition("=")
    attached = bool(separator)
    if option in _OPTIONS:
        return option, attached
    if option.startswith("--") and len(option) > 2:
        matches = [known for known in _OPTIONS if known.startswith(option)]
        return (matches[0], attached) if len(matches) == 1 else None
    if len(option) > 2 and option[:2] in _VALUES | {"-c", "-z"}:
        return option[:2], True
    return None


def _skip_root_option(args: list[str]) -> list[str]:
    parsed = _root_option(args[0])
    if parsed is None:
        return []
    option, attached = parsed
    if option in {"--oneshot", "-z"}:
        return []  # one-shot execution takes precedence over subcommands
    if option in _FLAGS:
        return [] if attached else args[1:]
    if attached:
        return args[1:]
    if option in _VALUES:
        return args[2:]
    # --continue/-c takes an optional session name.
    return args[2:] if len(args) > 1 and not args[1].startswith("-") else args[1:]


def maintenance_process() -> bool:
    """The standalone DB/uninstall CLI must be able to take exclusive custody."""
    if not sys.argv:
        return False
    name = Path(sys.argv[0].replace("\\", "/")).stem.casefold()
    args = sys.argv[1:]
    if name == "hermes-mordred":
        # The standalone parser accepts this global flag (including argparse's
        # unambiguous abbreviations) before the subcommand.
        while args and len(args[0]) > 2 and args[0].startswith("--") and "--no-color".startswith(args[0]):
            args = args[1:]
        return bool(args and args[0] in {"databases", "uninstall"})
    plugin = False
    while args:
        # Hermes consumes profiles anywhere, including between the plugin name
        # and its command. Options belonging to a root flag's value are skipped
        # below, just as in Hermes's early profile selection.
        if args[0] in {"--profile", "-p"}:
            args = args[2:]
            continue
        elif args[0].startswith("--profile="):
            args = args[1:]
            continue
        if plugin:
            return args[0] in {"databases", "uninstall"}
        if args[0] in {"mordred", "mordred-wizard"}:
            plugin = True
            args = args[1:]
            continue
        args = _skip_root_option(args)
    return False
