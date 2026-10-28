"""Root-bound offline conversion/adoption with durable authenticated recovery.

A genuine exclusive lifecycle lease precedes native source custody and SQL.
Journal v2 binds the complete inventory, source/staging identities, directory
parents and schema/count proof. Scoped runtime acquisition refuses pending work.
Sources are checkpointed before their revision is recorded. Each POSIX replace
swap re-proves that no process holds the files and, for a converted source, that
no WAL commit arrived after its export.
Windows uses the owning checked VFS and retained-original publication. Windows
admission is source-controlled; workstation editions are refused; see
docs/dev/CI.md for native acceptance. Only explicit tests replace the native
authentication seam for historical raw-key compatibility. Unknown legacy
journals and uncertain survivors remain untouched.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import secrets
import shutil
import stat
import subprocess
import sys
import time
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Final
from urllib.parse import quote

from .._database_contracts import NativeSnapshot
from .._database_inventory import scan_dependencies
from .._database_lifecycle import ExclusiveLease
from .._private_fs import PrivateFSError, open_private_directory
from ..keyvault import _database_authority as custody
from . import _shim
from ._key import DatabaseKey, derive
from ._locking import LOCK_SUBPATH as LOCK_SUBPATH
from ._locking import MigrationBusy as MigrationBusy
from ._locking import MigrationError as MigrationError
from ._locking import migration_lock as migration_lock
from ._marker import LegacyMarker, Marker, read_marker, write_marker
from ._policy import DENY_DIRS, in_scope, looks_like_database_name
from ._shim import PLAINTEXT_HEADER_BYTES, apply_key, wrong_key_errors

PENDING_SUBPATH: Final = ("mordred", "db-encryption.pending")
DECRYPT_PENDING_SUBPATH: Final = ("mordred", "db-decryption.pending")
JOURNAL_SUBPATH: Final = ("mordred", "db-encryption.journal.json")
PREPARED_SUFFIX: Final = ".mordred-enc"
RETAINED_SUFFIX: Final = ".mordred-original-"


@dataclass(frozen=True)
class Database:
    path: Path
    relative: str
    state: str  # "plaintext" | "encrypted" | "unreadable" (empty files and repair metadata are omitted)


@dataclass
class Report:
    converted: list[str] = field(default_factory=list)
    already_encrypted: list[str] = field(default_factory=list)
    unreadable: list[str] = field(default_factory=list)
    scheduled: bool = False


def _path(home: Path, subpath: tuple[str, ...]) -> Path:
    return home.joinpath(*subpath)


def pending_path(home: Path) -> Path:
    return _path(home, PENDING_SUBPATH)


def decrypt_pending_path(home: Path) -> Path:
    return _path(home, DECRYPT_PENDING_SUBPATH)


def journal_path(home: Path) -> Path:
    return _path(home, JOURNAL_SUBPATH)


# -- discovery -------------------------------------------------------------------------


def _pruned(relative_dir: tuple[str, ...]) -> bool:
    """Whether a directory holds other programs' files (never walked)."""
    if relative_dir and relative_dir[0] == "profiles":
        relative_dir = relative_dir[2:] if len(relative_dir) >= 2 else ()
    return bool(relative_dir) and relative_dir[0] in DENY_DIRS


def _sqlcipher() -> Any:
    import sqlcipher3.dbapi2 as sc

    return sc


@contextlib.contextmanager
def _offline_connection(
    path: Path,
    *,
    readonly: bool = False,
    target: Path | None = None,
    alias: str | None = None,
    root: Path | None = None,
) -> Any:
    if os.name == "nt":
        from ._maintenance_windows import connection

        with connection(path, readonly=readonly, target=target, alias=alias, root=root) as raw:
            yield raw
    else:
        from ._connection import _MaintenanceConnection

        uri = f"file:{quote(path.as_posix(), safe='/:')}?mode={'ro' if readonly else 'rw'}"
        with contextlib.closing(_MaintenanceConnection(_sqlcipher().connect(uri, uri=True))) as raw:
            yield raw


def _wrong_key_errors(sc: Any) -> tuple[type[BaseException], ...]:
    """What reading a file with the wrong (or no) key raises (see :func:`._shim.wrong_key_errors`)."""
    return wrong_key_errors(sc)


def _refuse_inside_a_runtime() -> None:
    """Offline classification/maintenance cannot share a protected runtime.

    SQL probes use the owning SQLCipher library; maintenance additionally pins
    filesystem identities and may fsync or rename closed files under actual EX.
    """
    if _shim.is_installed():
        raise MigrationError(
            "classifying the databases opens the files directly, which cannot run inside a Hermes process "
            "(it would drop Hermes's own SQLite locks); use `hermes-mordred databases` instead"
        )


def _classify(path: Path, key: DatabaseKey | None) -> str:
    """``plaintext`` / ``encrypted`` / ``unreadable``, or ``other`` (empty file, JSON metadata).

    Offline only (see :func:`_refuse_inside_a_runtime`): nothing in this process
    may have ``path`` open.
    """
    _refuse_inside_a_runtime()
    if path.suffix.casefold() == ".json":
        return "other"
    _file_identity(path)
    if _revision(path)[0] == 0:
        return "other"
    sc = _sqlcipher()
    # The owning SQLCipher library handles both classifications. Test the
    # authenticated format first, including its valid empty-schema case.
    for candidate in [key, None] if key is not None else [None]:
        try:
            with _offline_connection(path, readonly=True) as connection:
                if candidate is not None:
                    apply_key(connection, candidate)
                connection.execute("SELECT count(*) FROM sqlite_master").fetchone()
                return "encrypted" if candidate is not None else "plaintext"
        except _wrong_key_errors(sc):
            continue
    return "unreadable"


def database_paths(home: Path) -> list[Path]:
    """Every file under ``home`` (and its profile homes) that may be one of Hermes's databases.

    Only lists directories: no file is opened, so this is safe inside Hermes.
    """
    found: list[Path] = []

    def failed(error: OSError) -> None:
        raise MigrationError("database directory inventory is incomplete") from error

    for root, dirs, files in os.walk(home, onerror=failed):
        relative_root = Path(root).relative_to(home).parts
        dirs[:] = sorted(d for d in dirs if not _pruned((*relative_root, d)))
        for name in sorted(files):
            path = Path(root, name)
            if (
                name.endswith(PREPARED_SUFFIX)
                or RETAINED_SUFFIX in name
                or not looks_like_database_name(name)
                or not in_scope(path, home)
            ):
                continue
            found.append(path)
    return found


def discover(home: Path, key: DatabaseKey | None) -> list[Database]:
    """Every database file Hermes owns under ``home`` (and its profile homes), classified. Offline only."""
    found: list[Database] = []
    for path in database_paths(home):
        state = _classify(path, key)
        if state != "other":
            found.append(Database(path, str(path.relative_to(home)), state))
    return found


# -- other processes ---------------------------------------------------------------------


def holders(paths: list[Path], *, runner: Callable[..., Any] = subprocess.run) -> list[int] | None:
    """PIDs with any of ``paths`` (or their sidecars) open; ``None`` if unknown.

    Our own open connection is unsafe too: a Desktop callback must not replace
    the database underneath its running server.
    """
    targets = [
        str(p)
        for base in paths
        for p in (base, Path(f"{base}-wal"), Path(f"{base}-shm"), Path(f"{base}-journal"))
        if p.exists()
    ]
    if not targets:
        return []
    if os.name == "nt":
        from ._maintenance_windows import holders as windows_holders

        return windows_holders([Path(p) for p in targets])
    if sys.platform == "linux":
        from .._database_locking_posix import linux_holders_of

        return linux_holders_of([Path(p) for p in targets])
    try:
        executable = shutil.which("lsof")
        if executable is None or sys.platform == "win32":
            return None
        proc = runner([executable, "-t", "--", *targets], capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if proc.returncode not in (0, 1) or proc.stderr:  # 1 = no process has them open
        return None
    tokens = proc.stdout.split()
    if any(not pid.isdigit() for pid in tokens) or (proc.returncode == 0 and not tokens):
        return None
    return sorted({int(pid) for pid in tokens})


# -- one database ----------------------------------------------------------------------------


def _counts(conn: Any) -> dict[str, int]:
    names = [
        row[0]
        for row in conn.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
        )
    ]
    return {
        name: conn.execute(f'SELECT count(*) FROM "{name.replace(chr(34), chr(34) * 2)}"').fetchone()[0]
        for name in names
    }


def _ids(conn: Any, schema: str = "main") -> tuple[int, int]:
    app = conn.execute(f"PRAGMA {schema}.application_id").fetchone()[0]
    version = conn.execute(f"PRAGMA {schema}.user_version").fetchone()[0]
    return int(app), int(version)


def wal_reset_vulnerable(version_info: tuple[int, ...]) -> bool:
    """Whether this SQLite has the WAL-reset corruption bug (https://sqlite.org/wal.html#walresetbug).

    Same ranges as Hermes's own gate (``hermes_cli.sqlite_runtime``), which
    creates new databases in rollback-journal mode on such a library.
    """
    info = (*tuple(version_info), 0, 0, 0)[:3]
    return not (
        info < (3, 7, 0) or info >= (3, 51, 3) or (3, 50, 7) <= info < (3, 51, 0) or (3, 44, 6) <= info < (3, 45, 0)
    )


def prepare(database: Database, key: DatabaseKey, *, _reserved_identity: list[int] | None = None) -> Path:
    """Export ``database`` to an encrypted sibling and verify it; return the sibling."""
    sc = _sqlcipher()
    target = Path(f"{database.path}{PREPARED_SUFFIX}")
    if _reserved_identity is None:
        _reserve(target)
    elif _file_identity(target) != _reserved_identity or target.stat().st_size != 0:
        raise MigrationError("reserved export staging identity changed")
    with _offline_connection(database.path, target=target, alias="enc") as source:
        source.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchall()
        if source.execute("PRAGMA quick_check").fetchone()[0] != "ok":
            raise MigrationError(f"{database.relative} fails SQLite's quick_check; not converted")
        expected_counts, (app, version) = _counts(source), _ids(source)
        journal_mode = source.execute("PRAGMA journal_mode").fetchone()[0]
        source.execute(
            f"ATTACH DATABASE '{str(target).replace(chr(39), chr(39) * 2)}' AS enc KEY \"x'{key.key.hex()}'\""
        )
        source.execute(f"PRAGMA enc.cipher_plaintext_header_size = {PLAINTEXT_HEADER_BYTES}")
        source.execute(f"PRAGMA enc.cipher_salt = \"x'{key.salt.hex()}'\"")
        source.execute("SELECT sqlcipher_export('enc')").fetchall()
        source.execute(f"PRAGMA enc.application_id = {app}")
        source.execute(f"PRAGMA enc.user_version = {version}")
        # Keep WAL only where Hermes itself would: SQLCipher may link an older
        # SQLite than the interpreter's, and on one with the WAL-reset bug
        # Hermes uses rollback-journal mode (it never downgrades an open WAL DB,
        # so the offline conversion is the moment to do it).
        if (
            database.path.name != "mordred.db"
            and str(journal_mode).lower() == "wal"
            and not wal_reset_vulnerable(sc.sqlite_version_info)
        ):
            source.execute("PRAGMA enc.journal_mode = WAL").fetchall()
        source.execute("DETACH DATABASE enc")
    with _offline_connection(target) as check:
        apply_key(check, key)
        if check.execute("PRAGMA quick_check").fetchone()[0] != "ok":
            raise MigrationError(f"the encrypted copy of {database.relative} fails quick_check")
        if _counts(check) != expected_counts or _ids(check) != (app, version):
            raise MigrationError(f"the encrypted copy of {database.relative} does not match the original")
        check.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchall()
    _cleanup_sidecars(target)
    if os.name != "nt":
        os.chmod(target, stat.S_IMODE(database.path.stat().st_mode))  # e.g. state.db is owner-only
    return target


def prepare_plain(database: Database, key: DatabaseKey, *, _reserved_identity: list[int] | None = None) -> Path:
    """Export an encrypted ``database`` to a plaintext sibling and verify it; return the sibling."""
    sc = _sqlcipher()
    target = Path(f"{database.path}{PREPARED_SUFFIX}")
    if _reserved_identity is None:
        _reserve(target)
    elif _file_identity(target) != _reserved_identity or target.stat().st_size != 0:
        raise MigrationError("reserved export staging identity changed")
    with _offline_connection(database.path, target=target, alias="plain") as source:
        apply_key(source, key)
        source.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchall()
        if source.execute("PRAGMA quick_check").fetchone()[0] != "ok":
            raise MigrationError(f"{database.relative} fails SQLite's quick_check; not decrypted")
        expected_counts, (app, version) = _counts(source), _ids(source)
        journal_mode = source.execute("PRAGMA journal_mode").fetchone()[0]
        source.execute(f"ATTACH DATABASE '{str(target).replace(chr(39), chr(39) * 2)}' AS plain KEY ''")
        source.execute("SELECT sqlcipher_export('plain')").fetchall()
        source.execute(f"PRAGMA plain.application_id = {app}")
        source.execute(f"PRAGMA plain.user_version = {version}")
        if (
            database.path.name != "mordred.db"
            and str(journal_mode).lower() == "wal"
            and not wal_reset_vulnerable(sc.sqlite_version_info)
        ):
            source.execute("PRAGMA plain.journal_mode = WAL").fetchall()
        source.execute("DETACH DATABASE plain")
    with _offline_connection(target) as check:
        if check.execute("PRAGMA quick_check").fetchone()[0] != "ok":
            raise MigrationError(f"the decrypted copy of {database.relative} fails quick_check")
        if _counts(check) != expected_counts or _ids(check) != (app, version):
            raise MigrationError(f"the decrypted copy of {database.relative} does not match the original")
        check.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchall()
    _cleanup_sidecars(target)
    if os.name != "nt":
        os.chmod(target, stat.S_IMODE(database.path.stat().st_mode))  # e.g. state.db is owner-only
    return target


def _cleanup_sidecars(path: Path) -> None:
    """Delete only private, regular sidecars through their checked identity."""
    if os.name != "nt":
        # Historical POSIX DB directories may be 0755 and DBs 0644. Preserve
        # that accepted owner-only-write policy rather than requiring 0700.
        for suffix in ("-wal", "-shm"):
            sidecar = Path(f"{path}{suffix}")
            try:
                _file_identity(sidecar)
            except FileNotFoundError:
                continue
            sidecar.unlink()
        _sync_directory(path.parent)
        return
    with open_private_directory(path.parent) as directory, directory.transaction() as tx:
        for suffix in ("-wal", "-shm"):
            try:
                metadata = tx.stat(path.name + suffix)
            except PrivateFSError as exc:
                if exc.reason != "missing":
                    raise
            else:
                tx.delete_file(path.name + suffix, expected_identity=metadata.identity)


def _swap(path: Path, prepared: Path) -> None:
    if prepared.exists():
        os.replace(prepared, path)
    _cleanup_sidecars(path)


def _refuse_committed_wal(path: Path, relative: str) -> None:
    """Refuse while ``path``'s WAL holds frames that are not in its main file.

    Only an empty (or absent) WAL lets the main file's revision stand for the
    whole database, and lets a swap discard the sidecars without losing commits.
    """
    try:
        size = Path(f"{path}-wal").lstat().st_size
    except FileNotFoundError:
        return
    if size:
        raise MigrationError(
            f"{relative} has WAL commits that are not in its main file (another process wrote without "
            "the database lease); originals retained"
        )


def _checkpoint_source(database: Database, key: DatabaseKey | None) -> None:
    """Fold committed WAL frames into ``database``'s main file before its revision is recorded.

    ``prepare``/``prepare_plain`` checkpoint (TRUNCATE) again. After this
    their checkpoint copies nothing, so the main file's size/mtime/ctime stay
    as the journal records them and a failed export remains resumable. Closing
    the read-write connection also removes the emptied ``-wal``/``-shm``.
    """
    with _offline_connection(database.path) as conn:
        if key is not None:
            apply_key(conn, key)
        row = conn.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
    if row is None or row[0] != 0:  # busy: another connection still uses the WAL
        raise MigrationError(f"{database.relative} could not be checkpointed; stop every process using it first")
    _refuse_committed_wal(database.path, database.relative)


# -- the whole home ---------------------------------------------------------------------


def resume_at_startup(home: Path, *, timeout: float = 120.0) -> None:
    """Recover a journal, or join the runtime that finished recovery first.

    Re-check between nonblocking lock attempts: another startup can finish
    recovery and retain its shared lease for hours, so waiting unconditionally
    for exclusive custody would prevent this runtime from starting.
    """
    deadline = time.monotonic() + timeout
    while journal_path(home).is_file():
        try:
            with migration_lock(home):
                resume(home)
            return
        except MigrationBusy:
            if not journal_path(home).is_file():
                return
            if time.monotonic() >= deadline:
                raise
            time.sleep(min(0.05, max(0, deadline - time.monotonic())))


def _transition(phase: str) -> None:
    """Durable crash-injection boundary; production intentionally does nothing."""


def _sync_directory(path: Path) -> None:
    if os.name == "nt":
        # Full checked NTFS directory barrier under the accepted local-flush
        # mapping. Windows admission is source-controlled; workstation editions
        # are refused; see docs/dev/CI.md for native acceptance.
        from ._maintenance_windows import require_qualified

        require_qualified()
        with open_private_directory(path) as directory, directory.transaction() as tx:
            tx.flush_directory()
        return
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _file_identity(path: Path) -> list[int]:
    if os.name == "nt":
        with open_private_directory(path.parent) as directory:
            identity = directory.stat(path.name).identity
        return [identity.volume, int.from_bytes(identity.file_id, "big"), 0, 0]
    info = path.lstat()
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_nlink != 1
        or info.st_mode & 0o022
        or (os.name == "posix" and info.st_uid != os.getuid())
    ):
        raise MigrationError("database must be a checked regular owned file")
    if path != path.resolve(strict=True):
        raise MigrationError("database aliases are not maintenance destinations")
    return [info.st_dev, info.st_ino, info.st_mode, info.st_uid]


def _revision(path: Path) -> list[int]:
    if os.name == "nt":
        with open_private_directory(path.parent) as directory:
            metadata = directory.stat(path.name)
        return [metadata.size, metadata.mtime_ns, 0]
    info = path.lstat()
    return [info.st_size, info.st_mtime_ns, info.st_ctime_ns]


def _parents(root: Path, path: Path) -> list[dict[str, Any]]:
    parts = path.relative_to(root).parts
    if len(parts) >= 3 and parts[0] == "profiles":
        custody.resolve_database_domain(root / "profiles" / parts[1])
    result = []
    for parent in path.parents:
        if not parent.is_relative_to(root):
            break
        if os.name == "nt":
            with open_private_directory(parent) as directory:
                identity = directory.directory_identity()
            result.append(
                {
                    "relative": str(parent.relative_to(root)),
                    "identity": [identity.volume, int.from_bytes(identity.file_id, "big"), 0, 0],
                }
            )
            continue
        info = parent.lstat()
        if (
            not stat.S_ISDIR(info.st_mode)
            or info.st_mode & 0o022
            or (os.name == "posix" and info.st_uid != os.getuid())
            or parent != parent.resolve(strict=True)
        ):
            raise MigrationError("database parent is not a checked physical directory")
        result.append(
            {
                "relative": str(parent.relative_to(root)),
                "identity": [info.st_dev, info.st_ino, info.st_mode, info.st_uid],
            }
        )
    return result


def _inventory_binding(root: Path) -> dict[str, Any]:
    return {
        str(path.relative_to(root)): {"identity": _file_identity(path), "parents": _parents(root, path)}
        for path in database_paths(root)
    }


def _check_inventory_binding(root: Path, data: dict[str, Any]) -> None:
    expected = data["inventory"]
    actual = _inventory_binding(root)
    if data["publication"] == "retained":
        for entry in data["files"]:
            relative = entry["relative"]
            if relative not in actual:
                retained = root / entry["retained"]
                if _file_identity(retained) != entry["source_identity"]:
                    raise MigrationError("retained original identity changed")
                actual[relative] = {"identity": entry["source_identity"], "parents": _parents(root, root / relative)}
    if not isinstance(expected, dict) or set(actual) != set(expected):
        raise MigrationError("database inventory changed since journal preparation")
    replacements = {entry["relative"]: entry["prepared_identity"] for entry in data["files"]}
    for relative, observed in actual.items():
        previous = expected[relative]
        if observed["parents"] != previous["parents"] or observed["identity"] not in (
            previous["identity"],
            replacements.get(relative),
        ):
            raise MigrationError("database file or parent identity changed since preparation")


def _reserve(path: Path) -> None:
    # Never erase an orphan: it may be the only verified copy after a crash.
    if os.name == "nt":
        with open_private_directory(path.parent) as directory, directory.transaction() as tx:
            tx.create_bytes(path.name, b"")
        return
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    _sync_directory(path.parent)


def _fsync_file(path: Path) -> None:
    if os.name == "nt":
        with open_private_directory(path.parent) as directory, directory.transaction() as tx:
            tx.flush_file(path.name, expected_identity=tx.stat(path.name).identity)
        return
    before = _file_identity(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        if [info.st_dev, info.st_ino, info.st_mode, info.st_uid] != before:
            raise MigrationError("staged database identity changed")
        os.fsync(fd)
    finally:
        os.close(fd)
    if _file_identity(path) != before:
        raise MigrationError("staged database identity changed")
    _sync_directory(path.parent)


def _put_json(root: Path, name: str, value: Any) -> None:
    data = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode() + b"\n"
    with open_private_directory(root / "mordred") as directory, directory.transaction() as tx:
        try:
            tx.stat(name)
        except PrivateFSError as exc:
            if exc.reason != "missing":
                raise
            tx.create_bytes(name, data)
        else:
            tx.replace_bytes(name, data)


def _read_json(root: Path, name: str) -> Any:
    def pairs(values: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in values:
            if key in result:
                raise MigrationError("duplicate journal field")
            result[key] = value
        return result

    with open_private_directory(root / "mordred") as directory:
        raw = directory.read_bytes(name, max_bytes=8 * 1024 * 1024)
    try:
        return json.loads(raw, object_pairs_hook=pairs)
    except (ValueError, UnicodeError, RecursionError):
        raise MigrationError("invalid database journal") from None


def _remove_record(root: Path, name: str) -> None:
    with open_private_directory(root / "mordred") as directory, directory.transaction() as tx:
        try:
            metadata = tx.stat(name)
        except PrivateFSError as exc:
            if exc.reason != "missing":
                raise
        else:
            tx.delete_file(name, expected_identity=metadata.identity)


def _authenticate(
    root: Path, supplied: DatabaseKey | None, lease: ExclusiveLease
) -> tuple[NativeSnapshot | None, DatabaseKey]:
    """Source proof under preceding EX. Tests may inject this seam explicitly."""
    ExclusiveLease.assert_held(lease, root)
    if os.name == "nt":
        from ._maintenance_windows import require_qualified

        require_qualified()
    snapshot = custody.observe_database_source(root=root)
    key = derive(custody.load_database_source(root=root, expected=snapshot))
    if supplied is not None and key != supplied:
        raise MigrationError("supplied database key does not belong to the native source")
    marker = read_marker(root)
    if isinstance(marker, Marker) and marker.snapshot != snapshot:
        raise MigrationError("database marker and native source disagree")
    ExclusiveLease.assert_held(lease, root)
    return snapshot, key


def _schema_hash(rows: Any) -> str:
    payload = json.dumps([list(row) for row in rows], separators=(",", ":"), allow_nan=False).encode()
    return hashlib.sha256(payload).hexdigest()


def _schema(path: Path, key: DatabaseKey | None, *, root: Path | None = None) -> dict[str, Any]:
    before = _file_identity(path)
    with _offline_connection(path, readonly=True, root=root) as conn:
        if key is not None:
            apply_key(conn, key)
            if conn.execute("PRAGMA cipher_integrity_check").fetchall():
                raise MigrationError("database cipher integrity verification failed")
        if conn.execute("PRAGMA quick_check").fetchone() != ("ok",):
            raise MigrationError("database integrity verification failed")
        result = {
            "counts": _counts(conn),
            "ids": list(_ids(conn)),
            "schema_sha256": _schema_hash(
                conn.execute("SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY type,name")
            ),
        }
    if _file_identity(path) != before:
        raise MigrationError("database changed during schema verification")
    return result


def _inventory(root: Path, *, recovery: bool = False) -> None:
    inventory = scan_dependencies(root)
    if not inventory.complete:
        raise MigrationError("database dependency inventory is incomplete")
    for entry in inventory.entries:
        name = entry.path.name
        if entry.kind == "pending" and (name.endswith(PREPARED_SUFFIX) or RETAINED_SUFFIX in name) and not recovery:
            raise MigrationError("orphan prepared database requires explicit recovery")
        if name.endswith(("-wal", "-shm", "-journal")):
            base = Path(str(entry.path).rsplit("-", 1)[0])
            if not base.is_file():
                raise MigrationError("unknown database sidecar")
            _file_identity(entry.path)


def _refuse_if_open(todo: list[Database], holders_of: Callable[[list[Path]], list[int] | None] | None) -> None:
    if not todo:
        return
    busy = (holders_of or holders)([d.path for d in todo])
    if busy is None:
        raise MigrationError("could not check database holders (lsof or platform inspection failed)")
    if busy:
        raise MigrationError(f"the databases are open in other processes (pids {busy}); stop Hermes first")


def _bound_path(root: Path, relative: Any) -> Path:
    if not isinstance(relative, str) or not relative or Path(relative).is_absolute() or ".." in Path(relative).parts:
        raise MigrationError("journal database path is not root-relative")
    result = root / relative
    if str(result.relative_to(root)) != relative or not in_scope(result, root):
        raise MigrationError("journal database path is outside scope")
    return result


def _arm(home: Path) -> None:
    # Only the explicit raw-key test seam uses legacy intent. Native callers
    # always publish the authenticated v2 snapshot through write_marker.
    _put_legacy_marker(home)


def _put_legacy_marker(home: Path) -> None:
    path = home / "mordred/db-encryption.marker"
    path.write_bytes(b"1\n")
    path.chmod(0o600)
    _fsync_file(path)


def _disarm(home: Path) -> None:
    _remove_record(home, "db-encryption.marker")


def _publish_marker(
    root: Path, snapshot: NativeSnapshot | None, lease: ExclusiveLease, arm: Callable[[Path], None] | None
) -> None:
    if snapshot is None:
        (arm or _arm)(root)
    else:
        write_marker(root, snapshot, lease=lease)


def _save_journal(root: Path, data: dict[str, Any], phase: str) -> None:
    _put_json(root, JOURNAL_SUBPATH[-1], data)
    _transition(phase)


def _validate_journal(root: Path, data: Any, snapshot: NativeSnapshot | None, lease: ExclusiveLease) -> None:
    if not isinstance(data, dict) or type(data.get("version")) is not int or data.get("version") != 2:
        # Old path-only journals contain neither physical identities nor source
        # proof. Even apparently empty records cannot authorize marker removal.
        raise MigrationError("legacy journal has no unambiguous identity and key proof")
    if (
        set(data) != {"version", "root", "snapshot", "direction", "transaction", "files", "inventory", "publication"}
        or data.get("root") != asdict(lease.root)
        or data.get("snapshot") != (asdict(snapshot) if snapshot else None)
        or data.get("direction") not in {"encrypt", "decrypt", "adopt"}
        or data.get("publication") not in {"replace", "retained"}
        or not isinstance(data.get("transaction"), str)
        or len(data["transaction"]) != 32
        or not isinstance(data.get("files"), list)
    ):
        raise MigrationError("journal belongs to another root or native generation")
    seen: set[str] = set()
    for entry in data["files"]:
        if not isinstance(entry, dict) or entry.get("phase") not in {
            "prepared",
            "verified",
            "armed",
            "swapped",
            "complete",
        }:
            raise MigrationError("invalid journal file phase")
        if type(entry.get("wal_checkpointed", False)) is not bool:
            raise MigrationError("invalid journal WAL proof")
        path = _bound_path(root, entry.get("relative"))
        if str(path) in seen:
            raise MigrationError("duplicate journal database")
        seen.add(str(path))
        if (
            entry.get("prepared") != entry["relative"] + PREPARED_SUFFIX
            or entry.get("retained") != entry["relative"] + RETAINED_SUFFIX + data["transaction"]
        ):
            raise MigrationError("invalid journal prepared path")


def _reserve_journal_staging(root: Path, data: dict[str, Any], entry: dict[str, Any]) -> None:
    path, staged = root / entry["relative"], root / entry["prepared"]
    try:
        identity = _file_identity(staged)
    except FileNotFoundError:
        pass
    except PrivateFSError as exc:
        if exc.reason != "missing" or exc.commit_state != "not_committed":
            raise
    else:
        if entry["prepared_identity"] is None or identity != entry["prepared_identity"]:
            raise MigrationError("unrecorded staging survivor cannot authorize export")
        # A crash during export may leave arbitrary partial bytes. Rebuild
        # only the recorded inode from the unchanged authenticated source.
        _cleanup_sidecars(staged)
        if os.name == "nt":
            with open_private_directory(staged.parent) as directory, directory.transaction() as tx:
                tx.delete_file(staged.name, expected_identity=tx.stat(staged.name).identity)
        else:
            if _file_identity(staged) != identity:
                raise MigrationError("reserved staging changed before removal")
            staged.unlink()
            _sync_directory(staged.parent)
    _reserve(staged)
    if os.name != "nt":
        os.chmod(staged, stat.S_IMODE(path.stat().st_mode))
    entry["prepared_identity"] = _file_identity(staged)
    _fsync_file(staged)
    # Reserve ownership must reach the journal BEFORE any export writes.
    # A crash before this save leaves an unrecorded inode and refuses.
    _save_journal(root, data, "reserved")


def _complete_preparation(root: Path, data: dict[str, Any], key: DatabaseKey, decrypting: bool) -> None:
    target_key = None if decrypting else key
    # A durable prepare record lists the WHOLE conversion, including files not
    # yet exported. Recovery must never arm only the prefix prepared so far.
    for entry in data["files"]:
        if entry["phase"] == "prepared":
            path = _bound_path(root, entry["relative"])
            staged = root / entry["prepared"]
            if _file_identity(path) != entry["source_identity"] or _revision(path) != entry["source_revision"]:
                raise MigrationError("unprepared source identity or contents changed")
            if _schema(path, key if decrypting else None) != entry["verification"]:
                raise MigrationError("unprepared source schema changed")
            _reserve_journal_staging(root, data, entry)
            database = Database(path, entry["relative"], "encrypted" if decrypting else "plaintext")
            (prepare_plain if decrypting else prepare)(database, key, _reserved_identity=entry["prepared_identity"])
            if (
                _file_identity(staged) != entry["prepared_identity"]
                or _schema(staged, target_key) != entry["verification"]
            ):
                raise MigrationError("reserved staged file is not a verified target")
            _fsync_file(staged)
            entry["source_revision"] = _revision(path)
            # prepare() truncated the source's WAL. From here on WAL content is a
            # commit the staged copy lacks, which the swap must not discard.
            # Restore entries (_backup) never pass here: they replace by design.
            entry["wal_checkpointed"] = True
            entry["phase"] = "verified"
            _save_journal(root, data, "verified")


def _verify_survivors(root: Path, data: dict[str, Any], target_key: DatabaseKey | None) -> None:
    # Verify every survivor before any marker or swap mutation.
    for entry in data["files"]:
        path = _bound_path(root, entry["relative"])
        staged = root / entry["prepared"]
        if staged.exists():
            original = path if path.exists() else root / entry["retained"]
            revision = _revision(original)
            expected_revision = entry["source_revision"]
            if original != path:
                revision, expected_revision = revision[:2], expected_revision[:2]
            if (
                _file_identity(original) != entry["source_identity"]
                or revision != expected_revision
                or _file_identity(staged) != entry["prepared_identity"]
            ):
                raise MigrationError("migration source changed after preparation")
            candidate = staged
        else:
            if _file_identity(path) != entry["prepared_identity"]:
                raise MigrationError("migration lost its verified prepared database")
            candidate = path
        if _schema(candidate, target_key) != entry["verification"]:
            raise MigrationError("migration schema/count proof changed")


def _two_step_publication() -> bool:
    return os.name == "nt"


def _retained_swap(root: Path, data: dict[str, Any], entry: dict[str, Any]) -> None:
    path, staged, retained = (root / entry[name] for name in ("relative", "prepared", "retained"))
    with open_private_directory(path.parent) as directory, directory.transaction() as tx:
        if path.exists() and _file_identity(path) == entry["prepared_identity"]:
            if staged.exists():
                raise MigrationError("two prepared survivors are ambiguous")
            return
        if path.exists():
            if (
                _file_identity(path) != entry["source_identity"]
                or _revision(path) != entry["source_revision"]
                or retained.exists()
            ):
                raise MigrationError("original destination changed before retained publication")
            tx.rename_file(path.name, retained.name, expected_identity=tx.stat(path.name).identity)
            _save_journal(root, data, "retained")
        if _file_identity(retained) != entry["source_identity"] or _file_identity(staged) != entry["prepared_identity"]:
            raise MigrationError("retained publication identities changed")
        tx.rename_file(staged.name, path.name, expected_identity=tx.stat(staged.name).identity)
        _transition("published")
        for suffix in ("-wal", "-shm"):
            try:
                sidecar = tx.stat(path.name + suffix)
            except PrivateFSError as exc:
                if exc.reason != "missing":
                    raise
            else:
                tx.delete_file(path.name + suffix, expected_identity=sidecar.identity)


def _retire_originals(root: Path, data: dict[str, Any], target_key: DatabaseKey | None) -> None:
    for entry in data["files"]:
        path, retained = root / entry["relative"], root / entry["retained"]
        if _file_identity(path) != entry["prepared_identity"] or _schema(path, target_key) != entry["verification"]:
            raise MigrationError("target must be verified before retiring the original")
        if retained.exists():
            with open_private_directory(retained.parent) as directory, directory.transaction() as tx:
                if (
                    _file_identity(retained) != entry["source_identity"]
                    or _revision(retained)[:2] != entry["source_revision"][:2]
                ):
                    raise MigrationError("retained original identity or contents changed")
                tx.delete_file(retained.name, expected_identity=tx.stat(retained.name).identity)
    _transition("retired")


def _replace_swap(
    root: Path, entry: dict[str, Any], holders_of: Callable[[list[Path]], list[int] | None] | None
) -> None:
    path, staged = _bound_path(root, entry["relative"]), root / entry["prepared"]
    if staged.exists():
        # _swap unlinks the original's -wal/-shm. The earlier holder checks do
        # not cover a writer that started without the lease, so re-prove both
        # here, slowest first: a holder scan, then the stat-only WAL and
        # revision proofs, which also catch a commit that landed during the scan.
        _refuse_if_open([Database(path, entry["relative"], ""), Database(staged, entry["prepared"], "")], holders_of)
        if entry.get("wal_checkpointed") is True:
            _refuse_committed_wal(path, entry["relative"])
        if (
            _file_identity(path) != entry["source_identity"]
            or _revision(path) != entry["source_revision"]
            or _file_identity(staged) != entry["prepared_identity"]
        ):
            raise MigrationError("migration file identity changed before swap")
        _swap(path, staged)
        _sync_directory(path.parent)


def _finish(
    root: Path,
    data: dict[str, Any],
    key: DatabaseKey,
    snapshot: NativeSnapshot | None,
    lease: ExclusiveLease,
    arm: Callable[[Path], None] | None,
    disarm: Callable[[Path], None] | None,
    *,
    holders_of: Callable[[list[Path]], list[int] | None] | None = None,
) -> None:
    _check_inventory_binding(root, data)
    decrypting = data["direction"] == "decrypt"
    target_key = None if decrypting else key
    files = data["files"]
    _complete_preparation(root, data, key, decrypting)
    _verify_survivors(root, data, target_key)
    converted = {entry["relative"] for entry in files}
    for relative in set(data["inventory"]) - converted:
        # Public metadata cannot assert that an untouched file is ciphertext.
        _schema(_bound_path(root, relative), target_key)
    if decrypting:
        # Journal blocks all scoped admission. Disarm before publishing any
        # plaintext, so protection can never be armed over a plaintext swap.
        (disarm or _disarm)(root)
    else:
        _publish_marker(root, snapshot, lease, arm)
    for entry in files:
        entry["phase"] = "armed"
    _save_journal(root, data, "armed")
    for entry in files:
        ExclusiveLease.assert_held(lease, root)
        if data["publication"] == "retained":
            _retained_swap(root, data, entry)
        else:
            _replace_swap(root, entry, holders_of)
        entry["phase"] = "swapped"
        _save_journal(root, data, "swapped")
    for entry in files:
        entry["phase"] = "complete"
    _save_journal(root, data, "complete")
    if data["publication"] == "retained":
        _retire_originals(root, data, target_key)
    for name in (PENDING_SUBPATH[-1], DECRYPT_PENDING_SUBPATH[-1], JOURNAL_SUBPATH[-1]):
        _remove_record(root, name)
    _transition("removed")


def resume(
    home: Path,
    *,
    disarm: Callable[[Path], None] | None = None,
    arm: Callable[[Path], None] | None = None,
    holders_of: Callable[[list[Path]], list[int] | None] | None = None,
) -> bool:
    """Recover only authenticated root/identity-bound journals under EX."""
    if not journal_path(home).exists():
        return False
    _refuse_inside_a_runtime()
    with migration_lock(home) as lease:
        snapshot, key = _authenticate(home, None, lease)
        data = _read_json(home, JOURNAL_SUBPATH[-1])
        _validate_journal(home, data, snapshot, lease)
        _inventory(home, recovery=True)
        allowed = {home / entry[name] for entry in data["files"] for name in ("prepared", "retained")}
        for dependency in scan_dependencies(home).entries:
            if (
                dependency.kind == "pending"
                and (dependency.path.name.endswith(PREPARED_SUFFIX) or RETAINED_SUFFIX in dependency.path.name)
                and dependency.path not in allowed
            ):
                raise MigrationError("unowned prepared or retained file requires explicit inspection")
        paths = [
            Database(home / entry[name], entry[name], "")
            for entry in data["files"]
            for name in ("relative", "prepared", "retained")
            if (home / entry[name]).exists()
        ]
        _refuse_if_open(paths, holders_of)
        if data["direction"] == "adopt":
            _finish_adoption(home, data, snapshot, key, lease)
        else:
            _finish(home, data, key, snapshot, lease, arm, disarm, holders_of=holders_of)
    return True


def _convert(
    home: Path,
    key: DatabaseKey | None,
    *,
    decrypting: bool,
    arm: Callable[[Path], None] | None = None,
    disarm: Callable[[Path], None] | None = None,
    holders_of: Callable[[list[Path]], list[int] | None] | None = None,
) -> Report:
    _refuse_inside_a_runtime()
    report = Report()
    with migration_lock(home) as lease:
        snapshot, authenticated = _authenticate(home, key, lease)
        if journal_path(home).exists():
            resume(home, arm=arm, disarm=disarm, holders_of=holders_of)
        if snapshot is not None and isinstance(read_marker(home), LegacyMarker):
            raise MigrationError("legacy encryption must be adopted before conversion")
        _inventory(home)
        candidates = [Database(p, str(p.relative_to(home)), "") for p in database_paths(home)]
        _refuse_if_open(candidates, holders_of)
        databases = discover(home, authenticated)
        report.already_encrypted = [d.relative for d in databases if d.state == "encrypted"]
        report.unreadable = [d.relative for d in databases if d.state == "unreadable"]
        if report.unreadable:
            raise MigrationError("unreadable database(s); originals retained: " + ", ".join(report.unreadable))
        _refuse_if_open(databases, holders_of)
        todo = [d for d in databases if d.state == ("encrypted" if decrypting else "plaintext")]
        # prepare() checkpoints its source, which rewrites the main file. Do it
        # now, before any journal exists, so the recorded revision is the one a
        # failed export leaves behind and resume() can still match it. A crash
        # here leaves only SQLite's own recoverable WAL state and no journal.
        for database in todo:
            _checkpoint_source(database, authenticated if decrypting else None)
        data: dict[str, Any] = {
            "version": 2,
            "root": asdict(lease.root),
            "snapshot": asdict(snapshot) if snapshot else None,
            "inventory": _inventory_binding(home),
            "publication": "retained" if _two_step_publication() else "replace",
            "direction": "decrypt" if decrypting else "encrypt",
            "transaction": secrets.token_hex(16),
            "files": [],
        }
        for database in todo:
            data["files"].append(
                {
                    "relative": database.relative,
                    "prepared": database.relative + PREPARED_SUFFIX,
                    "retained": database.relative + RETAINED_SUFFIX + data["transaction"],
                    "source_identity": _file_identity(database.path),
                    "source_revision": _revision(database.path),
                    "prepared_identity": None,
                    "verification": _schema(database.path, authenticated if decrypting else None),
                    "phase": "prepared",
                }
            )
        _save_journal(home, data, "prepared")
        _finish(home, data, authenticated, snapshot, lease, arm, disarm, holders_of=holders_of)
        report.converted = [d.relative for d in todo]
    return report


def migrate(
    home: Path,
    key: DatabaseKey | None,
    *,
    arm: Callable[[Path], None],
    holders_of: Callable[[list[Path]], list[int] | None] | None = None,
) -> Report:
    return _convert(home, key, decrypting=False, arm=arm, holders_of=holders_of)


def decrypt_all(
    home: Path,
    key: DatabaseKey | None,
    *,
    disarm: Callable[[Path], None] = _disarm,
    holders_of: Callable[[list[Path]], list[int] | None] | None = None,
) -> Report:
    return _convert(home, key, decrypting=True, disarm=disarm, holders_of=holders_of)


def _finish_adoption(
    root: Path, data: dict[str, Any], snapshot: NativeSnapshot | None, key: DatabaseKey, lease: ExclusiveLease
) -> None:
    if snapshot is None:
        raise MigrationError("adoption requires native source proof")
    _check_inventory_binding(root, data)
    if not data["files"] or {entry["relative"] for entry in data["files"]} != set(data["inventory"]):
        raise MigrationError("adoption must prove every nonempty legacy database")
    for entry in data["files"]:
        path = _bound_path(root, entry["relative"])
        if (
            _file_identity(path) != entry["source_identity"]
            or _revision(path) != entry["source_revision"]
            or _schema(path, key) != entry["verification"]
        ):
            raise MigrationError("legacy database changed during adoption")
    from ._marker import _adopt_marker

    _adopt_marker(root, snapshot, lease=lease)
    _transition("armed")
    _remove_record(root, JOURNAL_SUBPATH[-1])
    _transition("complete")


def adopt_legacy(root: Path, *, lease: ExclusiveLease) -> NativeSnapshot:
    """Authenticate the complete legacy root before publishing any new binding."""
    if type(lease) is not ExclusiveLease:
        raise MigrationError("a preceding exclusive database lease is required")
    ExclusiveLease.assert_held(lease, root)
    _refuse_inside_a_runtime()
    if not isinstance(read_marker(root), LegacyMarker):
        raise MigrationError("legacy adoption requires exact historical intent")
    if journal_path(root).exists():
        raise MigrationError("recover the existing adoption journal first")
    _inventory(root)
    candidates = [Database(p, str(p.relative_to(root)), "") for p in database_paths(root)]
    _refuse_if_open(candidates, None)
    # Absence is the only historical route. Invalid existing binding is never
    # retried as an unbound source, and custody itself has no ambient fallback.
    binding = root / "mordred/db-key-source.json"
    try:
        binding.lstat()
    except FileNotFoundError:
        digest, material = custody._load_historical_database_source(root=root, lease=lease)
        snapshot, key = None, derive(material)
    else:
        snapshot, key = _authenticate(root, None, lease)
        digest = snapshot.record_sha256 if snapshot else ""
    databases = discover(root, key)
    if not databases or len(databases) != len(candidates) or any(d.state != "encrypted" for d in databases):
        raise MigrationError("legacy root has empty, mixed, or unreadable database authority")
    _refuse_if_open(databases, None)
    transaction = secrets.token_hex(16)
    entries = [
        {
            "relative": d.relative,
            "prepared": d.relative + PREPARED_SUFFIX,
            "retained": d.relative + RETAINED_SUFFIX + transaction,
            "source_identity": _file_identity(d.path),
            "source_revision": _revision(d.path),
            "prepared_identity": None,
            "verification": _schema(d.path, key),
            "phase": "verified",
        }
        for d in databases
    ]
    if snapshot is None:
        snapshot = custody.enroll_database_source(root=root, lease=lease)
        if snapshot.record_sha256 != digest:
            raise MigrationError("historical source changed before enrollment")
    data = {
        "version": 2,
        "root": asdict(lease.root),
        "snapshot": asdict(snapshot),
        "inventory": _inventory_binding(root),
        "publication": "retained" if _two_step_publication() else "replace",
        "direction": "adopt",
        "transaction": transaction,
        "files": entries,
    }
    _save_journal(root, data, "verified")
    _finish_adoption(root, data, snapshot, key, lease)
    return snapshot


def _schedule_intent(home: Path, name: str) -> None:
    with open_private_directory(home / "mordred", create=True) as directory, directory.transaction() as tx:
        try:
            tx.stat(name)
        except PrivateFSError as exc:
            if exc.reason != "missing":
                raise
            tx.create_bytes(name, b"1\n")
        else:
            if tx.read_bytes(name, max_bytes=16) != b"1\n":
                raise MigrationError("pending database intent is invalid")


def schedule_decrypt(home: Path) -> None:
    """Persist private decryption intent without upgrading an active SH lease."""
    _schedule_intent(home, DECRYPT_PENDING_SUBPATH[-1])
    _remove_record(home, PENDING_SUBPATH[-1])


def schedule(home: Path) -> None:
    """Persist private conversion intent without upgrading an active SH lease."""
    _schedule_intent(home, PENDING_SUBPATH[-1])


def plaintext_backups(home: Path) -> list[Path]:
    """Hermes backup archives that may hold plaintext copies of the databases."""
    backups = home / "backups"
    if not backups.is_dir():
        return []
    return sorted(p for p in backups.rglob("*") if p.is_file() and p.suffix in (".zip", ".tar", ".gz", ".tgz"))
