"""``hermes-mordred databases status|encrypt`` — SQLCipher for Hermes's databases.

``encrypt`` converts every plaintext database Hermes owns (state.db and its
siblings, per profile too) and arms the SQLCipher shim. If Hermes has them
open, the conversion is scheduled and runs when Hermes next starts. Needs
agent-memory encryption (the database key is derived from its key).
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from . import _term

_RESIDUE_NOTE = (
    "The old plaintext files were replaced, not overwritten: on an SSD their blocks can survive in free "
    "space or APFS local snapshots until reused. FileVault keeps them unreadable to anyone without your "
    "login; `tmutil listlocalsnapshots /` lists local snapshots."
)


def _home() -> Path:
    from ..dbcrypt import _home as database_home

    return database_home()


def _key_from_environment() -> object | None:
    """The key if ``HERMES_MEMORY_KEY`` is already in the environment (status never unlocks the vault)."""
    from ..dbcrypt import _key
    from ..keyvault._memory_hook import _decode_env_key

    memory_key = _decode_env_key(os.environ)
    return _key.derive(memory_key) if memory_key is not None else None


def databases_status(home: Path | None = None) -> int:
    if sys.platform == "win32":
        from .._home import hermes_home
        from ._windows_databases import refusal

        print("Database encryption: unsupported on Windows (macOS only).")
        detail = refusal(home or hermes_home())
        if detail is not None:
            _term.emit_error(detail)
            return 1
        print("  Hermes databases are not protected by Mordred database encryption on Windows.")
        return 0
    from ..dbcrypt import _migrate, armed, protected_state_present

    base = home or _home()
    if sys.platform != "darwin":
        print("Database encryption: unsupported on this platform (macOS only).")
        if protected_state_present(base):
            _term.emit_error("This home contains database encryption state; decrypt it on macOS before migration.")
            return 1
        print("  Hermes databases are not protected by Mordred database encryption on this platform.")
    print(f"Database encryption: {'on' if armed(base) else 'off'}")
    if _migrate.pending_path(base).is_file():
        print("  A conversion is scheduled; it runs the next time Hermes starts.")
    if _migrate.journal_path(base).is_file():
        print("  An interrupted conversion will be completed the next time Hermes starts.")
    try:
        key = _key_from_environment() if sys.platform == "darwin" else None
        databases = _migrate.discover(base, key)  # type: ignore[arg-type]
    except ImportError:
        _term.emit_warn("SQLCipher is not installed (pip install 'hermes-mordred[macos]').")
        return 1
    for database in databases:
        state = database.state
        if state == "unreadable" and key is None:
            state = "encrypted or unreadable"
        print(f"  {state:<24} {database.relative}")
    return 0


def _preflight() -> str | None:
    if sys.platform != "darwin":
        return "database encryption is macOS-only (its key lives in the Secure Enclave vault)."
    try:
        import sqlcipher3  # noqa: F401
    except ImportError:
        return "SQLCipher is not installed: pip install 'hermes-mordred[macos]'."
    return None


def databases_encrypt(*, dry_run: bool = False, home: Path | None = None) -> int:
    from ..dbcrypt import _migrate, arm
    from ..dbcrypt._key import KeyProvider

    refusal = _preflight()
    if refusal:
        _term.emit_error(refusal)
        return 1
    base = home or _home()
    key = KeyProvider()()
    if key is None:
        _term.emit_error(
            "the database key comes from the agent-memory key, which is not set up: run "
            "`hermes-mordred encryption enable memory` (or the Mordred page in Hermes Desktop) first."
        )
        return 1
    databases = _migrate.discover(base, key)
    todo = [d for d in databases if d.state == "plaintext"]
    for database in databases:
        print(f"  {'will encrypt' if database.state == 'plaintext' else database.state:<14} {database.relative}")
    for archive in _migrate.plaintext_backups(base):
        _term.emit_warn(f"{archive} may contain plaintext copies of the databases; delete it if you do not need it.")
    if dry_run:
        print("Dry run: nothing was changed.")
        return 0
    busy = _migrate.holders([d.path for d in todo])
    if busy is None or busy:
        _migrate.schedule(base)
        print(
            "Hermes has its databases open, so the conversion is scheduled. Quit Hermes (in Hermes Desktop: ⌘Q) "
            "and start it again — the databases are encrypted before Hermes opens them."
        )
        return 0
    try:
        report = _migrate.migrate(base, key, arm=arm)
    except _migrate.MigrationBusy:
        _migrate.schedule(base)
        print("A Hermes process is running; database encryption is scheduled for the next start after quitting Hermes.")
        return 0
    except _migrate.MigrationError as exc:
        _term.emit_error(f"nothing was changed: {exc}")
        return 1
    print(f"Encrypted {len(report.converted)} database(s); database encryption is on.")
    if report.unreadable:
        _term.emit_warn(
            "the database key does not open: "
            + ", ".join(report.unreadable)
            + " (encrypted with another key, or damaged); Hermes cannot read them with this key."
        )
    print(_RESIDUE_NOTE)
    return 0


def databases_decrypt(*, dry_run: bool = False, home: Path | None = None) -> int:
    """Turn every encrypted Hermes database back into plain SQLite and switch encryption off."""
    from ..dbcrypt import _migrate, armed
    from ..dbcrypt._key import KeyProvider

    refusal = _preflight()
    if refusal:
        _term.emit_error(refusal)
        return 1
    base = home or _home()
    key = KeyProvider()()
    if key is None:
        _term.emit_error("the database key is not available (the vault could not be opened); nothing was changed.")
        return 1
    databases = _migrate.discover(base, key)
    todo = [d for d in databases if d.state == "encrypted"]
    for database in databases:
        print(f"  {'will decrypt' if database.state == 'encrypted' else database.state:<14} {database.relative}")
    if dry_run:
        print("Dry run: nothing was changed.")
        return 0
    if not todo and not armed(base):
        print("Database encryption is already off.")
        return 0
    busy = _migrate.holders([d.path for d in todo])
    if busy is None or busy:
        _migrate.schedule_decrypt(base)
        print(
            "Hermes has its databases open, so decryption is scheduled. Quit Hermes (in Hermes Desktop: ⌘Q) and "
            "start it again — the databases are turned back into plain SQLite before Hermes opens them."
        )
        return 0
    try:
        report = _migrate.decrypt_all(base, key)
    except _migrate.MigrationBusy:
        _migrate.schedule_decrypt(base)
        print("A Hermes process is running; database decryption is scheduled for the next start after quitting Hermes.")
        return 0
    except _migrate.MigrationError as exc:
        _term.emit_error(f"nothing was changed: {exc}")
        return 1
    print(f"Decrypted {len(report.converted)} database(s); database encryption is off.")
    return 0


def cli_databases(args: argparse.Namespace) -> int:
    command = getattr(args, "databases_command", None)
    if command == "encrypt":
        return databases_encrypt(dry_run=bool(getattr(args, "dry_run", False)))
    if command == "decrypt":
        return databases_decrypt(dry_run=bool(getattr(args, "dry_run", False)))
    return databases_status()


__all__ = ["cli_databases", "databases_decrypt", "databases_encrypt", "databases_status"]
