"""At-rest encryption of Hermes's SQLite databases with SQLCipher.

Armed by ``<home>/mordred/db-encryption.marker`` (written once every database
has been converted). When armed, :func:`install` — called from Mordred's
interpreter-startup bootstrap, before Hermes imports ``sqlite3`` — swaps the
``sqlite3`` module for SQLCipher and keys Hermes's own databases with a key
derived from the existing agent-memory key. When not armed nothing changes.

Native activation is independently gated on each platform. See
``docs/dev/STATE_DB_ENCRYPTION.md``.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Final

from ._capability import DatabaseStatus, database_status, diagnose_database
from ._cli import maintenance_process as _maintenance_process
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


def _check_legacy_marker_posix(path: Path) -> None:
    """Read an unchanged private legacy leaf under the preceding root EX lease."""
    from contextlib import ExitStack

    from .._database_contracts import DatabaseRefused
    from .._private_fs._posix import _ancestor, _private

    with ExitStack() as resources:
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        resources.callback(os.close, directory)
        _ancestor(directory)  # Owned 0755 is allowed, unsafe permissions/ACLs are not.
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=directory)
        resources.callback(os.close, fd)
        before = _private(fd)
        if before.st_size != 2 or os.read(fd, 3) != b"1\n":
            raise DatabaseRefused("legacy publication cannot replace native or unknown database intent")
        expected = (
            before.st_dev,
            before.st_ino,
            before.st_mode,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        )
        for observed in (_private(fd), os.stat(path.name, dir_fd=directory, follow_symlinks=False)):
            current = (
                observed.st_dev,
                observed.st_ino,
                observed.st_mode,
                observed.st_size,
                observed.st_mtime_ns,
                observed.st_ctime_ns,
            )
            if current != expected:
                raise DatabaseRefused("legacy database marker changed during observation")


def arm(home: Path) -> None:
    """Legacy publication seam: never overwrite native or unknown marker bytes."""
    from .._database_contracts import DatabaseRefused
    from .._database_lifecycle import acquire_exclusive
    from .._private_fs import open_private_directory

    with acquire_exclusive(home) as lease:
        # Preserve the explicit legacy seam for older 0755 Mordred directories.
        # Exclusive creation cannot replace a concurrently published v2 marker.
        try:
            with marker_path(home).open("xb") as stream:
                stream.write(b"1\n")
            marker_path(home).chmod(0o600)
            return
        except FileExistsError:
            pass
        try:
            lease.assert_held(home)
            if os.name == "posix":
                # The legacy lease admits an owned 0755 directory; the leaf
                # still needs the exact private-file policy and pinned identity.
                _check_legacy_marker_posix(marker_path(home))
            else:
                with open_private_directory(home / "mordred") as directory, directory.transaction() as tx:
                    if tx.read_bytes(MARKER_SUBPATH[-1], max_bytes=4096) != b"1\n":
                        raise DatabaseRefused("legacy publication cannot replace native or unknown database intent")
            lease.assert_held(home)
        except OSError:
            raise DatabaseRefused("legacy database marker cannot be published safely") from None


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


def _native_home(home: Path | None) -> tuple[Path, Path]:
    from .._home import hermes_home
    from ..keyvault._database_authority import resolve_database_domain

    requested = home or hermes_home()
    if requested.exists():
        domain = resolve_database_domain(requested)
        return domain.home, domain.root
    return requested, root_home(requested)


def _refuse_deferred_native_state(base: Path) -> None:
    """Native recovery/adoption remain closed until the offline transaction layer."""
    from .._database_contracts import DatabaseRefused

    for name in (
        "db-encryption.journal.json",
        "db-encryption.pending",
        "db-decryption.pending",
    ):
        try:
            (base / "mordred" / name).lstat()
        except FileNotFoundError:
            continue
        raise DatabaseRefused("native database recovery is unavailable; database files were not opened")


def _install_native(home: Path | None, provider: KeyProvider | None) -> bool:
    from .._database_contracts import DatabaseRefused
    from . import _shim
    from ._locking import runtime_lease

    global _PROVIDER
    requested_home, base = _native_home(home)
    _refuse_deferred_native_state(base)
    if _PROVIDER is not None and _PROVIDER.runtime_native and _PROVIDER.current_authority is not None:
        existing = _PROVIDER.current_authority
        existing.check()
        if existing.home != requested_home or (provider is not None and provider is not _PROVIDER):
            raise DatabaseRefused("installed database authority cannot be rebound")
        return True
    candidate = provider or KeyProvider(home=requested_home)
    # Offline adoption, recovery and pending conversion stay closed.
    try:
        marker_path(base).lstat()
    except FileNotFoundError:
        # Preserve plain-runtime exclusion and first-time home initialization.
        # This lease uses no native custody and never enters offline recovery.
        with runtime_lease(base):
            _refuse_deferred_native_state(base)
            try:
                marker_path(base).lstat()
            except FileNotFoundError:
                return False
            raise DatabaseRefused("database publication changed during startup; restart required") from None
    try:
        authority = candidate.authority
        if authority.home != requested_home or authority.root != base:
            raise DatabaseRefused("database provider does not match the requested home")
        authority.check()
        _refuse_deferred_native_state(base)
        module = _shim.build_module(authority=authority)
        _shim.install_module(module)
    except BaseException:
        candidate.close()
        raise
    _PROVIDER = candidate
    return True


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
    base = root_home(home or _home())
    if sys.platform != "darwin":
        if protected_state_present(base):
            raise RuntimeError(
                "Hermes database encryption is supported only on macOS; decrypt this home on macOS "
                "before moving it to this platform. The databases were not opened."
            )
        return False
    from . import _migrate, _shim
    from ._locking import runtime_lease

    global _PROVIDER
    if provider is None or provider.runtime_native:
        return _install_native(home, provider)
    if _shim.is_installed():
        return True
    _PROVIDER = provider
    key_provider = provider
    _migrate.resume_at_startup(base)
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


__all__ = [
    "DatabaseStatus",
    "arm",
    "armed",
    "database_status",
    "diagnose_database",
    "install",
    "is_installed",
    "marker_path",
    "register",
    "root_home",
]
