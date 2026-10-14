"""``hermes-mordred update`` -- move the installed package to a newer release.

Not to be confused with ``hermes-mordred upgrade``, which migrates an existing
Hermes / OpenClaw *configuration* and never touches the package. This command
is the terminal face of :mod:`.._self_update`: it asks PyPI once, shows what
would change, asks for confirmation (``--yes`` skips it; a non-interactive
run without ``--yes`` refuses instead of guessing), installs with the same
feature extras and Hermes-pin constraints as the installer, and ends with the
one thing the user must still do: restart the gateway or Hermes Desktop.

Exit codes: ``0`` done or already current, ``1`` failed, ``2`` refused here
(Windows, source checkout, missing uv, non-interactive without ``--yes``),
``10`` only with ``--check`` when a newer release exists.
"""

from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass, field
from pathlib import Path

from .. import _self_update as core
from . import _term

EXIT_OK = 0
EXIT_FAILED = 1
EXIT_REFUSED = 2
EXIT_UPDATE_AVAILABLE = 10

RESTART_HINT = "Restart the Hermes gateway (or quit and reopen Hermes Desktop) so it starts on the new version."


@dataclass
class UpdateOptions:
    check_only: bool = False
    version: str | None = None
    yes: bool = False
    interactive: bool = field(default_factory=lambda: sys.stdin.isatty())


def _print(message: str) -> None:
    print(message)


def _confirm(previous: str, target: str, opts: UpdateOptions) -> bool:
    if opts.yes:
        return True
    if not opts.interactive:
        _term.emit_error(f"not a terminal; pass --yes to update hermes-mordred {previous} -> {target}")
        return False
    try:
        answer = input(f"Update hermes-mordred {previous} -> {target}? [y/N] ")
    except EOFError:
        return False
    return answer.strip().lower() in {"y", "yes"}


def _resolve_target(opts: UpdateOptions) -> tuple[str | None, int]:
    """The release to install, or ``None`` with the exit code to return instead."""
    if opts.version is not None:
        if opts.check_only:
            _term.emit_error("--check and --version cannot be combined")
            return None, EXIT_REFUSED
        return opts.version, EXIT_OK
    try:
        result = core.check()
    except core.UpdateCheckFailed as exc:
        _term.emit_error(f"could not ask PyPI for releases: {exc}")
        return None, EXIT_FAILED
    if result.latest is None:
        _print(f"hermes-mordred {result.installed} is installed; no newer release qualifies ({result.reason}).")
        return None, EXIT_OK
    if result.available is not True:
        _print(f"hermes-mordred {result.installed} is up to date (latest on PyPI: {result.latest}).")
        return None, EXIT_OK
    _print(f"hermes-mordred {result.installed} is installed; {result.latest} is available.")
    if opts.check_only:
        _print("Run `hermes-mordred update` to install it.")
        return None, EXIT_UPDATE_AVAILABLE
    return result.latest, EXIT_OK


def _apply(current: core.Installed, target: str, uv: Path | None) -> int:
    extras = ", ".join(current.extras) or "none"
    _print(f"Installing hermes-mordred {target} (extras: {extras}) into {sys.prefix} ...")
    try:
        report = core.apply(target, current=current, uv=uv)
    except core.UpdateRefused as exc:
        _term.emit_error(exc.message)
        return EXIT_REFUSED
    except core.UpdateFailed as exc:
        _term.emit_error(f"update step '{exc.step}' failed:\n{exc.output}")
        _term.emit_note("the previous install may still be intact; rerun after fixing the cause, or use the installer")
        return EXIT_FAILED
    for warning in report.warnings:
        _term.emit_warn(warning)
    _print(f"Updated hermes-mordred {report.previous} -> {report.target}.")
    _print(RESTART_HINT)
    return EXIT_OK


def run(opts: UpdateOptions) -> int:
    """Check, confirm, apply; see the module docstring for the exit codes."""
    try:
        current = core.installed()
    except Exception as exc:  # metadata missing / broken environment
        _term.emit_error(f"cannot read the installed hermes-mordred: {type(exc).__name__}: {exc}")
        return EXIT_FAILED
    target, code = _resolve_target(opts)
    if target is None:
        return code
    uv = core.find_uv()
    try:
        core.refuse_if_unsupported(current, uv=uv)
    except core.UpdateRefused as exc:
        _term.emit_error(exc.message)
        return EXIT_REFUSED
    if not _confirm(current.version, target, opts):
        return EXIT_REFUSED
    return _apply(current, target, uv)


def cli_update(args: argparse.Namespace) -> int:
    """argparse handler for ``update [--check] [--version V] [--yes]``."""
    opts = UpdateOptions(
        check_only=bool(getattr(args, "check", False)),
        version=getattr(args, "version", None),
        yes=bool(getattr(args, "yes", False)),
    )
    return run(opts)


__all__ = [
    "EXIT_FAILED",
    "EXIT_OK",
    "EXIT_REFUSED",
    "EXIT_UPDATE_AVAILABLE",
    "RESTART_HINT",
    "UpdateOptions",
    "cli_update",
    "run",
]
