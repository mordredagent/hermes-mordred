"""Database restoration/erasure before uninstall can remove the shared key.

The root home's marker covers every profile. Keep the migration lease for the
whole uninstall so a Hermes runtime cannot reopen an encrypted database while
its key and bootstrap are being removed.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import TYPE_CHECKING

from ..dbcrypt import root_home
from ..dbcrypt._policy import DENY_DIRS, in_scope, looks_like_database_name

if TYPE_CHECKING:
    from ._flow_session import FlowSession
    from .uninstall_cli import UninstallContext

_STATE_NAMES = (
    "db-encryption.marker",
    "db-encryption.pending",
    "db-decryption.pending",
    "db-encryption.journal.json",
)
_PREPARED_SUFFIX = ".mordred-enc"
_SIDECARS = ("-wal", "-shm", "-journal")
_SQLITE_MAGIC = b"SQLite format 3\x00"


def state_paths(home: Path) -> list[Path]:
    base = root_home(home)
    return [base / "mordred" / name for name in _STATE_NAMES]


def needed(home: Path) -> bool:
    return any(path.exists() or path.is_symlink() for path in state_paths(home)) or any(
        _PREPARED_SUFFIX in path.name for path in _files(root_home(home), strict=False)
    )


def _files(home: Path, *, strict: bool = True) -> Iterator[Path]:
    def fail(exc: OSError) -> None:
        raise exc

    for directory, dirs, files in os.walk(home, onerror=fail if strict else None):
        relative = Path(directory).relative_to(home).parts
        local = relative[2:] if len(relative) >= 2 and relative[0] == "profiles" else relative
        if not local:
            dirs[:] = sorted(d for d in dirs if d not in DENY_DIRS)
        for name in sorted(files):
            path = Path(directory, name)
            candidate = str(path)
            for suffix in _SIDECARS:
                if candidate.endswith(suffix):
                    candidate = candidate[: -len(suffix)]
                    break
            if in_scope(candidate, home):
                yield path


def database_files(home: Path) -> list[Path]:
    """Database candidates and their artifacts, without SQLCipher or a key.

    Recognize Hermes's copied/renamed databases by the retained SQLite header;
    similarly named JSON repair metadata is not database content. Primary DB
    names and orphaned sidecars remain erasable even if their header is damaged.
    """
    files = list(_files(home))
    bases: set[Path] = set()
    for path in files:
        name = str(path)
        for suffix in _SIDECARS:
            if name.endswith(suffix):
                name = name[: -len(suffix)]
                break
        if name.endswith(_PREPARED_SUFFIX):
            name = name[: -len(_PREPARED_SUFFIX)]
        base = Path(name)
        if not looks_like_database_name(base.name):
            continue
        if base.suffix.casefold() in (".db", ".sqlite", ".sqlite3") or name != str(path):
            bases.add(base)
        elif path == base or path == Path(f"{base}{_PREPARED_SUFFIX}"):
            with path.open("rb") as handle:
                if handle.read(len(_SQLITE_MAGIC)) == _SQLITE_MAGIC:
                    bases.add(base)
    targets = {
        Path(f"{base}{prepared}{sidecar}")
        for base in bases
        for prepared in ("", _PREPARED_SUFFIX)
        for sidecar in ("", *_SIDECARS)
    }
    # Enumerate sidecars only for validated database base names.
    return sorted(path for path in targets if path.exists() or path.is_symlink())


def detail(home: Path, *, erase: bool = False) -> str:
    base = root_home(home)
    names = ", ".join(str(path.relative_to(base)) for path in database_files(base)) or "no database files found"
    if erase:
        return (
            f"delete all Hermes databases under {base}, including profiles, backups, sidecars and prepared copies "
            f"({names}); cancel pending conversions"
        )
    return (
        f"restore all Hermes databases under {base}, including profiles and backups ({names}); "
        "cancel pending conversions"
    )


def needs_vault(ctx: UninstallContext) -> bool:
    from ._vault_open import _vault_present

    return _vault_present(ctx.vault_root) and any(
        path.name != "db-encryption.pending" and path.exists() for path in state_paths(ctx.home)
    )


@contextmanager
def guard(ctx: UninstallContext) -> Iterator[None]:
    """Refuse unsupported/profile operations before any restore or teardown."""
    base = root_home(ctx.home)
    if ctx.platform != "darwin":
        raise RuntimeError(
            "database encryption can only be restored or erased on macOS; Mordred and its keys were kept"
        )
    from ..dbcrypt._migrate import migration_lock

    with migration_lock(base, timeout=0):
        if base.resolve() != ctx.home.resolve() and needed(base):
            raise RuntimeError(
                f"database encryption is shared with the root home {base}; run uninstall with HERMES_HOME={base} "
                "to restore or erase every profile before removing the shared key"
            )
        yield


def restore(ctx: UninstallContext, flow: FlowSession) -> None:
    """Synchronously finish conversion and restore plaintext; never schedule it."""
    from ..dbcrypt import _migrate
    from ..dbcrypt._key import derive
    from ..keyvault._memory_hook import _decode_env_key
    from . import memory_cli
    from ._vault_open import _vault_present

    base = root_home(ctx.home)
    prepared = [path for path in database_files(base) if _PREPARED_SUFFIX in path.name]
    if prepared and not _migrate.journal_path(base).exists():
        raise _migrate.MigrationError(
            "prepared database copies remain; resolve the interrupted conversion before uninstalling: "
            + ", ".join(str(path) for path in prepared)
        )
    # Only a scheduled, unstarted encryption can be cancelled without the key.
    if not any(path.exists() for path in state_paths(base) if path.name != "db-encryption.pending"):
        _migrate.pending_path(base).unlink(missing_ok=True)
        return
    if _vault_present(ctx.vault_root):
        memory_key = memory_cli._memory_key_from_vault(
            root=ctx.vault_root, backend=ctx.backend, store=ctx.store, flow_session=flow
        )
    else:
        memory_key = _decode_env_key(os.environ)
    if memory_key is None:
        raise _migrate.MigrationError("the database key is unavailable; restore vault access before uninstalling")
    key = derive(memory_key)
    unreadable = [database.relative for database in _migrate.discover(base, key) if database.state == "unreadable"]
    if unreadable:
        raise _migrate.MigrationError("database key cannot open: " + ", ".join(unreadable))
    report = _migrate.decrypt_all(base, key)
    if report.scheduled or report.unreadable or any(path.exists() for path in state_paths(base)):
        raise _migrate.MigrationError("database restoration did not finish; Mordred and its keys must be kept")
    # Interrupted preparation can leave unjournaled encrypted copies. They are
    # still database content, so do not orphan them when removing the key.
    prepared = [path for path in database_files(base) if _PREPARED_SUFFIX in path.name]
    if prepared:
        raise _migrate.MigrationError(
            "prepared database copies remain; resolve the interrupted conversion before uninstalling: "
            + ", ".join(str(path) for path in prepared)
        )
    print(f"Restored {len(report.converted)} Hermes database(s) to plaintext.")


def erase(ctx: UninstallContext) -> None:
    """Remove scoped DBs and all conversion artifacts before any key deletion."""
    from ..dbcrypt import _migrate

    base = root_home(ctx.home)
    paths = database_files(base)
    busy = _migrate.holders(paths)
    if busy is None:
        raise _migrate.MigrationError("could not check whether Hermes has the databases open (lsof failed)")
    if busy:
        raise _migrate.MigrationError(f"the databases are open (pids {busy}); stop Hermes first")
    for path in paths:
        path.unlink(missing_ok=True)
        print(f"Erased database file {path}.")
    if database_files(base):
        raise _migrate.MigrationError("database files remain after erasure; Mordred and its keys were kept")
    for path in state_paths(base):
        path.unlink(missing_ok=True)
    _migrate.journal_path(base).with_suffix(".json.tmp").unlink(missing_ok=True)
