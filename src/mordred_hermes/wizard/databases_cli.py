"""Explicit offline database maintenance and passive authority observation."""

from __future__ import annotations

import argparse
from pathlib import Path

from . import _term


def _home() -> Path:
    from ..dbcrypt import _home as database_home

    return database_home()


def _render_status(home: Path, *, diagnose: bool) -> int:
    from ..dbcrypt import database_status, diagnose_database

    status = diagnose_database(home) if diagnose else database_status(home)
    print("Database encryption:")
    print(f"  configured: {'yes' if status.configured else 'no'}")
    print(f"  capability: {status.capability}")
    authenticated = ("yes (this diagnostic)" if status.authenticated else "no") if diagnose else "not checked"
    print(f"  authenticated: {authenticated}")
    print(f"  dependencies: {status.dependencies if status.dependencies is not None else 'unknown'}")
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
    from .._database_lifecycle import acquire_exclusive
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


def cli_databases(args: argparse.Namespace) -> int:
    command = getattr(args, "databases_command", None)
    if command == "encrypt":
        return databases_encrypt(dry_run=bool(getattr(args, "dry_run", False)))
    if command == "decrypt":
        return databases_decrypt(dry_run=bool(getattr(args, "dry_run", False)))
    if command == "diagnose":
        return databases_diagnose()
    return databases_status()


__all__ = ["cli_databases", "databases_decrypt", "databases_diagnose", "databases_encrypt", "databases_status"]
