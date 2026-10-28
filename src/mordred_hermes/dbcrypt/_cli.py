"""Recognize offline database maintenance before Hermes imports its CLI."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import NoReturn

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
        return args[2:] if len(args) > 1 and args[1] and not args[1].startswith("-") else []
    # --continue/-c takes an optional session name.
    return args[2:] if len(args) > 1 and not args[1].startswith("-") else args[1:]


class _ObservationParser(argparse.ArgumentParser):
    def error(self, message: str) -> NoReturn:
        raise ValueError("not a recognized offline command")


def _setup_options(setup: _ObservationParser) -> None:
    # Keep this finite startup grammar aligned with wizard._cli_parsers._add_setup.
    # Setup owns database mutation; it must not first acquire a runtime lease.
    setup.add_argument("--non-interactive", action="store_true")
    hermes_setup = setup.add_mutually_exclusive_group()
    hermes_setup.add_argument("--with-hermes-setup", action="store_true")
    hermes_setup.add_argument("--skip-hermes-setup", action="store_true")
    attended = setup.add_mutually_exclusive_group()
    attended.add_argument("--unattended-keys", action="store_true")
    attended.add_argument("--attended-keys", action="store_true")
    seed = setup.add_mutually_exclusive_group()
    seed.add_argument("--store-seed-for-hd", action="store_true")
    seed.add_argument("--paper-only", action="store_true")


def _passive_or_maintenance(args: list[str], *, profiles: bool = False) -> bool:  # noqa: C901 - finite CLI grammar
    """Parse only reviewed metadata/ceremony commands, without importing Hermes.

    Values are consumed by argparse: command words inside prompts, roots or
    option values cannot grant an exemption. Unknown/malformed commands retain
    ordinary runtime protection. Profiles are Hermes-only, accepted at each
    command boundary just as Hermes's early profile selection permits.
    """

    def parser() -> _ObservationParser:
        result = _ObservationParser(add_help=False, exit_on_error=False)
        result.add_argument("--help", "-h", action="store_true")
        if profiles:
            result.add_argument("--profile", "-p")
        return result

    root = parser()
    sub = root.add_subparsers(required=True)

    def child(owner: argparse._SubParsersAction[_ObservationParser], name: str) -> _ObservationParser:
        return owner.add_parser(name, parents=[parser()], add_help=False, exit_on_error=False)

    _setup_options(child(sub, "setup"))
    database = child(sub, "databases").add_subparsers(required=True)
    for verb in ("status", "diagnose", "encrypt", "decrypt"):
        item = child(database, verb)
        if verb in {"encrypt", "decrypt"}:
            item.add_argument("--dry-run", action="store_true")
    # Offline restore owns the exclusive lease; a runtime shared lease would refuse it.
    # Keep aligned with wizard.activity_store_cli.add_parsers("restore").
    restore = child(child(sub, "activity").add_subparsers(required=True), "restore")
    restore.add_argument("--input", required=True)
    restore.add_argument("--yes", action="store_true")
    uninstall = child(sub, "uninstall")
    for flag in ("--dry-run", "--yes", "--purge-data", "--remove-helper", "--erase-encrypted"):
        uninstall.add_argument(flag, action="store_true")
    status = child(sub, "status")
    status.add_argument("--json", action="store_true")
    for family in ("encryption", "mail"):
        commands = child(sub, family).add_subparsers(required=True)
        child(commands, "status").add_argument("--json", action="store_true")
        if family == "encryption":
            for verb in ("enable", "disable", "purge"):
                item = child(commands, verb)
                item.add_argument("target", choices=("memory", "all"))
                if verb != "purge":
                    item.add_argument("--non-interactive", action="store_true")
                else:
                    item.add_argument("--yes", "-y", action="store_true")
                if verb == "enable":
                    item.add_argument("--force-runtime-unverified", action="store_true")
    vault = child(sub, "vault").add_subparsers(required=True)
    for verb in ("init", "recover", "set-memory-key"):
        item = child(vault, verb)
        item.add_argument("--root")
        if verb == "set-memory-key":
            item.add_argument("--rotate", action="store_true")
    keyvault = child(sub, "keyvault").add_subparsers(required=True)
    init = child(keyvault, "init").add_mutually_exclusive_group()
    init.add_argument("--paper-only", action="store_true")
    init.add_argument("--store-seed-for-hd", action="store_true")
    child(keyvault, "recover").add_argument("--blob", required=True)
    child(keyvault, "reset").add_argument("--yes", "-y", action="store_true")
    native = child(keyvault, "native").add_subparsers(required=True)
    child(native, "init").add_argument("--role", action="append", choices=("memory", "audit", "telegram"))
    try:
        root.parse_args(args)
    except (argparse.ArgumentError, ValueError):
        return False
    return True


def maintenance_process(argv: Sequence[str] | None = None) -> bool:  # noqa: C901, PLR0912 - ordered root argument consumption
    """Recognize reviewed passive commands and explicit native source ceremonies."""
    argv = list(sys.argv if argv is None else argv)
    if not argv:
        return False
    name = Path(argv[0].replace("\\", "/")).stem.casefold()
    args = list(argv[1:])
    if name == "-m":
        original = list(getattr(sys, "orig_argv", ()))
        if "-m" not in original[:-1] or original[original.index("-m") + 1].split(".")[0] != "hermes_cli":
            return False
        name = "hermes"
    if name == "hermes-mordred":
        # The standalone parser accepts this global flag (including argparse's
        # unambiguous abbreviations) before the subcommand.
        while args and len(args[0]) > 2 and args[0].startswith("--") and "--no-color".startswith(args[0]):
            args = args[1:]
        return _passive_or_maintenance(args)
    if (
        name not in {"hermes", "hermes-agent", "hermes-acp", "hermes_cli"}
        and "/hermes_cli/" not in argv[0].replace("\\", "/")
        and "hermes_bootstrap" not in sys.modules
    ):
        return False
    plugin = False
    while args:
        # Hermes consumes profiles anywhere, including between the plugin name
        # and its command. Options belonging to a root flag's value are skipped
        # below, just as in Hermes's early profile selection.
        if args[0] in {"--profile", "-p"}:
            if len(args) < 2 or not args[1] or args[1].startswith("-"):
                return False
            args = args[2:]
            continue
        elif args[0].startswith("--profile="):
            if not args[0].partition("=")[2]:
                return False
            args = args[1:]
            continue
        if plugin:
            return _passive_or_maintenance(args, profiles=True)
        if args[0] in {"mordred", "mordred-wizard"}:
            plugin = True
            args = args[1:]
            continue
        args = _skip_root_option(args)
    return False
