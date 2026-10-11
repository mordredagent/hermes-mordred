"""At-rest encryption of Hermes's SQLite databases with SQLCipher.

Armed by ``<home>/mordred/db-encryption.marker`` (written once every database
has been converted). When armed, :func:`install` — called from Mordred's
interpreter-startup bootstrap, before Hermes imports ``sqlite3`` — swaps the
``sqlite3`` module for SQLCipher and keys Hermes's own databases with a key
derived from the existing agent-memory key. When not armed nothing changes.

macOS only, like the vault that holds the key. See
``docs/dev/STATE_DB_ENCRYPTION.md``.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Final

from ._key import KeyProvider

MARKER_SUBPATH: Final = ("mordred", "db-encryption.marker")
_PROVIDER: KeyProvider | None = None


def marker_path(home: Path) -> Path:
    return home.joinpath(*MARKER_SUBPATH)


def root_home(home: Path) -> Path:
    """The Hermes home that owns the marker: the root for a profile home (``<root>/profiles/<name>``).

    Hermes starts profile processes (gateways, Desktop chats, kanban workers)
    with ``HERMES_HOME`` set to the profile home; their databases, and the
    root's shared ones they open, are covered by the root's marker.
    """
    resolved = Path(os.path.realpath(home))
    return resolved.parent.parent if resolved.parent.name == "profiles" else home


def _home() -> Path:
    from .._home import hermes_home

    return root_home(hermes_home())


def armed(home: Path | None = None) -> bool:
    """Persisted encryption intent, including on an unsupported destination OS."""
    return marker_path(home or _home()).is_file()


def protected_state_present(home: Path) -> bool:
    """A marker or interrupted transaction that requires SQLCipher-aware handling."""
    directory = home / "mordred"
    return armed(home) or any(
        (directory / name).is_file() for name in ("db-encryption.journal.json", "db-decryption.pending")
    )


def _maintenance_process() -> bool:
    """The standalone DB/uninstall CLI must be able to take exclusive custody."""
    if not sys.argv:
        return False
    name = Path(sys.argv[0].replace("\\", "/")).stem.casefold()
    args = sys.argv[1:]
    if name == "hermes-mordred":
        return bool(args and args[0] in {"databases", "uninstall"})
    return len(args) >= 2 and args[0] in {"mordred", "mordred-wizard"} and args[1] in {"databases", "uninstall"}


def arm(home: Path) -> None:
    path = marker_path(home)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("1\n", encoding="utf-8")


def _run_pending_conversion(base: Path, key_provider: KeyProvider) -> None:
    """Convert the databases at startup if a conversion was scheduled (best effort).

    Runs before this process opens any database. Other Hermes processes that
    start meanwhile wait on the conversion lock. On any refusal the databases
    stay as they are (plaintext, unarmed) and the conversion stays scheduled.
    """
    from . import _migrate

    if armed(base) or not _migrate.pending_path(base).is_file():
        return
    try:
        key = key_provider()
        if key is None:
            raise _migrate.MigrationError("the database key is not available (memory encryption is not set up)")
        report = _migrate.migrate(base, key, arm=arm)
        sys.stderr.write(f"mordred: encrypted {len(report.converted)} Hermes database(s) with SQLCipher\n")
    except Exception as exc:
        sys.stderr.write(f"mordred: database encryption postponed — {exc}\n")


def _run_pending_decryption(base: Path, key_provider: KeyProvider) -> None:
    """Turn the databases back into plain SQLite at startup if that was scheduled (best effort)."""
    from . import _migrate

    if not armed(base) or not _migrate.decrypt_pending_path(base).is_file():
        return
    try:
        key = key_provider()
        if key is None:
            raise _migrate.MigrationError("the database key is not available")
        report = _migrate.decrypt_all(base, key)
        sys.stderr.write(f"mordred: decrypted {len(report.converted)} Hermes database(s) back to plain SQLite\n")
    except Exception as exc:
        sys.stderr.write(f"mordred: database decryption postponed — {exc}\n")


def register(ctx: object) -> None:
    """Hermes plugin component: the protection monitor and the status prompt line."""
    from ._hooks import register as register_hooks

    register_hooks(ctx)


def install(*, home: Path | None = None, provider: KeyProvider | None = None) -> bool:
    """Swap ``sqlite3`` for SQLCipher if database encryption is armed. Returns whether it did.

    Runs a scheduled conversion first, and completes an interrupted one.
    Raises when armed but SQLCipher cannot be loaded: Hermes's databases are
    encrypted then, and the stdlib module cannot open them.
    """
    # Maintenance commands explicitly open databases through _migrate. Running
    # queued work here would mutate a home before status/--dry-run/confirmation,
    # and a lifetime reader lease would prevent their own offline conversion.
    if _maintenance_process():
        return False
    base = home or _home()
    if sys.platform != "darwin":
        if protected_state_present(base):
            raise RuntimeError(
                "Hermes database encryption is supported only on macOS; decrypt this home on macOS "
                "before moving it to this platform. The databases were not opened."
            )
        return False
    from . import _migrate, _shim
    from ._locking import runtime_lease

    if _shim.is_installed():
        return True
    global _PROVIDER
    _PROVIDER = provider or KeyProvider()
    key_provider = _PROVIDER
    if _migrate.journal_path(base).is_file():  # an interrupted conversion (either way); needs no key
        with _migrate.migration_lock(base, timeout=120.0):
            _migrate.resume(base)
    _run_pending_conversion(base, key_provider)
    _run_pending_decryption(base, key_provider)
    with runtime_lease(base):
        # A converter may have started before we took our shared lease. Read
        # the format only after it finishes; never admit a half-swapped home.
        if _migrate.journal_path(base).is_file():
            raise _migrate.MigrationError("an interrupted database conversion must be completed before startup")
        if not armed(base):
            return False

        def has_key() -> bool:
            return bool(os.environ.get("HERMES_MEMORY_KEY"))

        module = _shim.build_module(key=key_provider, home=lambda: base, has_key=has_key)
        _shim.install_module(module)
        return True


def is_installed() -> bool:
    from . import _shim

    return _shim.is_installed()


__all__ = ["arm", "armed", "install", "is_installed", "marker_path", "register", "root_home"]
