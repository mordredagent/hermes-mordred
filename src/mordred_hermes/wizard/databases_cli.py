"""Explicit offline database maintenance and passive authority observation."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import TYPE_CHECKING

from . import _term

if TYPE_CHECKING:
    from ..dbcrypt._backup import BackupAbandonment, BackupRecovery

_RECOVER_COMMAND = "hermes-mordred databases backup recover"


def _printable(value: object) -> str:
    """Journal paths are same-user-writable state; escape them, never truncate them."""
    text = str(value)
    if not text.isprintable():
        text = text.encode("unicode_escape").decode("ascii")
    # A legacy stream encoding must not turn a finished operation into a traceback.
    encoding = getattr(sys.stdout, "encoding", None) or "utf-8"
    return text.encode(encoding, "backslashreplace").decode(encoding)


def _home() -> Path:
    from ..dbcrypt._runtime import _home as database_home

    return database_home()


def _render_status(home: Path, *, diagnose: bool) -> int:
    from ..dbcrypt import database_status, diagnose_database
    from ..dbcrypt._capability import backup_recovery_required

    status = diagnose_database(home) if diagnose else database_status(home)
    recovery = backup_recovery_required(home)
    print("Database encryption:")
    print(f"  configured: {'yes' if status.configured else 'no'}")
    print(f"  capability: {status.capability}")
    authenticated = ("yes (this diagnostic)" if status.authenticated else "no") if diagnose else "not checked"
    print(f"  authenticated: {authenticated}")
    print(f"  dependencies: {status.dependencies if status.dependencies is not None else 'unknown'}")
    if recovery:
        print(f"  backup recovery: required unless a backup is running (stop Hermes, then run `{_RECOVER_COMMAND}`)")
    elif recovery is None:
        print("  backup recovery: unknown (journal metadata is unavailable)")
    if status.reason:
        print(f"  reason: {status.reason}")
    if not diagnose:
        print("  Authenticate explicitly with `hermes-mordred databases diagnose`.")
    return int(diagnose and not (status.authenticated and status.capability == "available"))


def databases_status(home: Path | None = None) -> int:
    return _render_status(home or _home(), diagnose=False)


def databases_diagnose(home: Path | None = None) -> int:
    return _render_status(home or _home(), diagnose=True)


def _convert(*, decrypting: bool, dry_run: bool, home: Path | None) -> int:
    from .._core._database_lifecycle import acquire_exclusive
    from ..dbcrypt import _migrate, arm, database_status
    from ..dbcrypt._marker import LegacyMarker, Marker, read_marker
    from ..keyvault._database_authority import (
        enroll_database_source,
        require_database_memory_enabled,
        resolve_database_domain,
    )

    try:
        base = resolve_database_domain(home or _home()).root
        status = database_status(base)
        if status.capability == "unavailable":
            raise _migrate.MigrationError(status.reason or "database capability unavailable")
        if dry_run:
            # Observation is deliberately metadata-only: no enrollment, native
            # authentication, SQL classification, marker, journal or schedule.
            print(f"Dependencies: {status.dependencies if status.dependencies is not None else 'unknown'}")
            print("Dry run: metadata only; no authentication or changes.")
            return 0
        with acquire_exclusive(base) as lease:
            if not decrypting:
                require_database_memory_enabled(root=base)
            marker = read_marker(base)
            if isinstance(marker, LegacyMarker):
                _migrate.adopt_legacy(base, lease=lease)
            elif not isinstance(marker, Marker) and not decrypting:
                enroll_database_source(root=base, lease=lease)
            # The conversion owner authenticates exactly under actual EX. A
            # runtime SH provider cannot authorize this offline operation.
            report = _migrate.decrypt_all(base, None) if decrypting else _migrate.migrate(base, None, arm=arm)
    except (OSError, RuntimeError, ValueError) as exc:
        _term.emit_error(f"database maintenance stopped: {exc}. Stop Hermes and resolve the refusal before retrying.")
        return 1
    print(f"{'Decrypted' if decrypting else 'Encrypted'} {len(report.converted)} database(s).")
    if decrypting:
        print("Native key and retained backup evidence remain; decryption does not authorize key removal.")
    else:
        print(
            "Replaced plaintext blocks and external backups may still contain plaintext; "
            "review your disk encryption and backups."
        )
    return 0


def databases_encrypt(*, dry_run: bool = False, home: Path | None = None) -> int:
    return _convert(decrypting=False, dry_run=dry_run, home=home)


def databases_decrypt(*, dry_run: bool = False, home: Path | None = None) -> int:
    return _convert(decrypting=True, dry_run=dry_run, home=home)


def _report_abandonment(plan: BackupAbandonment, *, requested: bool) -> int:
    print(f"Interrupted backup publication (phase: {_printable(plan.phase)}):")
    registered = ", already registered" if plan.registered else ""
    print(f"  destination: {_printable(plan.destination)} ({plan.destination_state}{registered})")
    print(f"  staging:     {_printable(plan.staging)} ({plan.staging_state})")
    print("--abandon never deletes files.")
    if plan.registered:
        print("The registered destination stays protected: key teardown still detects it.")
    if "absent" in (plan.destination_state, plan.staging_state):
        print("An absent path on an unmounted volume may still exist: mount it before abandoning.")
    if plan.removed:
        print("Abandoned: the backup journal was removed. Nothing else was deleted.")
        if plan.copy_may_remain:
            print("Any copy listed above as present or unknown is now an unmanaged encrypted copy of your database:")
            print("key teardown will not detect it, `recover` can no longer finish it, and its retention and key are")
            print("your responsibility.")
        return 0
    if plan.copy_may_remain:
        print("A copy listed above as present or unknown would become an unmanaged encrypted copy of your database:")
        print("key teardown would not detect it, and its retention and key would be your responsibility.")
    if plan.phase == "verified":
        print(f"`{_RECOVER_COMMAND}` publishes and registers the verified copy only if its checks pass.")
    else:
        print(f"`{_RECOVER_COMMAND}` rebuilds the staged copy from the source and registers it if its checks pass.")
    flags = "--abandon --yes --accept-unmanaged-copy" if plan.copy_may_remain else "--abandon --yes"
    if requested:
        print(f"Not abandoned; the journal was retained. To accept the copy above, re-run with {flags}.")
    else:
        print(f"Preview only; the journal was retained. To abandon it, re-run with {flags}.")
    return 1


def _report_recovery(result: BackupRecovery) -> int:
    if result.outcome == "none":
        print("No interrupted backup operation; nothing to recover.")
    elif result.outcome == "published":
        print(f"Interrupted backup finished and registered: {_printable(result.path)}")
    else:
        print(f"Interrupted backup deletion finished; {_printable(result.path)} is no longer registered.")
    return 0


def databases_backup_recover(
    *, abandon: bool = False, yes: bool = False, accept_unmanaged_copy: bool = False, home: Path | None = None
) -> int:
    from .._core._database_lifecycle import acquire_exclusive
    from ..dbcrypt._backup import abandon_backup_journal, recover_backups
    from ..keyvault._database_authority import resolve_database_domain

    if yes and not abandon:
        _term.emit_error("--yes applies only to --abandon")
        return 1
    if accept_unmanaged_copy and not (abandon and yes):
        _term.emit_error("--accept-unmanaged-copy applies only to --abandon --yes")
        return 1
    try:
        root = resolve_database_domain(home or _home()).root
        with acquire_exclusive(root) as lease:
            recovery = None if abandon else recover_backups(root, lease=lease)
            plan = (
                abandon_backup_journal(root, lease=lease, commit=yes, accept_unmanaged_copy=accept_unmanaged_copy)
                if abandon
                else None
            )
    except Exception as exc:  # SQLCipher errors are neither OSError nor RuntimeError; report, never a traceback
        if abandon:
            _term.emit_error(f"database backup abandonment stopped: {_printable(exc)}; the journal may remain")
        else:
            _term.emit_error(
                f"database backup recovery stopped: {_printable(exc)}; the journal may remain. Stop Hermes and "
                f"retry. If it cannot be finished, `{_RECOVER_COMMAND} --abandon` previews whether it can be abandoned."
            )
        return 1
    # Outcomes print outside the handler: a display failure must not misreport finished work.
    if recovery is not None:
        return _report_recovery(recovery)
    if plan is None:
        print("No interrupted backup publication; nothing to abandon.")
        return 0
    return _report_abandonment(plan, requested=yes)


def cli_databases(args: argparse.Namespace) -> int:
    command = getattr(args, "databases_command", None)
    if command == "backup":
        if getattr(args, "backup_command", None) == "recover":
            return databases_backup_recover(
                abandon=bool(getattr(args, "abandon", False)),
                yes=bool(getattr(args, "yes", False)),
                accept_unmanaged_copy=bool(getattr(args, "accept_unmanaged_copy", False)),
            )
        from .._core._database_lifecycle import acquire_exclusive
        from ..dbcrypt._backup import export_database
        from ..keyvault._database_authority import resolve_database_domain

        try:
            root = resolve_database_domain(_home()).root
            with acquire_exclusive(root) as lease:
                output = export_database(
                    root, Path(args.source), Path(args.output), lease=lease, member=getattr(args, "member", None)
                )
        except (OSError, RuntimeError, ValueError) as exc:
            _term.emit_error(f"database backup export stopped: {exc}; original backup retained")
            return 1
        print(f"Verified plaintext database exported to {output}. Original backup and native key retained.")
        return 0
    if command == "encrypt":
        return databases_encrypt(dry_run=bool(getattr(args, "dry_run", False)))
    if command == "decrypt":
        return databases_decrypt(dry_run=bool(getattr(args, "dry_run", False)))
    if command == "diagnose":
        return databases_diagnose()
    return databases_status()


__all__ = [
    "cli_databases",
    "databases_backup_recover",
    "databases_decrypt",
    "databases_diagnose",
    "databases_encrypt",
    "databases_status",
]
