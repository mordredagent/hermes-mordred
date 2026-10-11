"""Convert Hermes's existing plaintext databases to SQLCipher (phase 3).

Works on a Hermes home that has been in use for a while (Mordred installed
later). All-or-nothing, in three steps:

1. **Prepare** — every plaintext database is checkpointed and exported to an
   encrypted sibling (``<db>.mordred-enc``), which is then verified (opens
   with the key, ``quick_check`` ok, same tables with the same row counts,
   same ``application_id`` / ``user_version``). Any failure deletes the
   prepared copies and changes nothing.
2. **Commit** — a journal listing the swaps is written, then the
   ``db-encryption.marker`` that arms the SQLCipher shim.
3. **Swap** — each prepared copy replaces its database (``os.replace``) and
   the old ``-wal`` / ``-shm`` go. The journal is removed last. A crash in
   between is completed by :func:`resume` on the next start.

Databases must not be open in another process while this runs (checked with
``lsof``). When they are — Hermes is running — the conversion is scheduled
instead (``db-encryption.pending``) and runs from the interpreter-startup
bootstrap of the next Hermes process, before anything opens a database.

Old plaintext blocks are freed by the swap, not overwritten: on an SSD/APFS
volume they can survive in free space or local snapshots until reused.
"""

from __future__ import annotations

import contextlib
import json
import os
import stat
import subprocess
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final

from ._key import DatabaseKey
from ._locking import LOCK_SUBPATH as LOCK_SUBPATH
from ._locking import MigrationBusy as MigrationBusy
from ._locking import MigrationError as MigrationError
from ._locking import migration_lock as migration_lock
from ._policy import DENY_DIRS, in_scope, looks_like_database_name
from ._shim import PLAINTEXT_HEADER_BYTES, SQLITE_MAGIC, apply_key, stdlib_sqlite3, wrong_key_errors

PENDING_SUBPATH: Final = ("mordred", "db-encryption.pending")
DECRYPT_PENDING_SUBPATH: Final = ("mordred", "db-decryption.pending")
JOURNAL_SUBPATH: Final = ("mordred", "db-encryption.journal.json")
PREPARED_SUFFIX: Final = ".mordred-enc"


@dataclass(frozen=True)
class Database:
    path: Path
    relative: str
    state: str  # "plaintext" | "encrypted" | "unreadable" (files that are not SQLite are not listed)


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


def _wrong_key_errors(sc: Any) -> tuple[type[BaseException], ...]:
    """What reading a file with the wrong (or no) key raises (see :func:`._shim.wrong_key_errors`)."""
    return wrong_key_errors(sc)


def _classify(path: Path, key: DatabaseKey | None) -> str:
    plain_sqlite = stdlib_sqlite3()
    try:
        with path.open("rb") as handle:
            if handle.read(len(SQLITE_MAGIC)) != SQLITE_MAGIC:
                return "other"  # not SQLite (``state.db.repair-attempts.json``) or empty
    except OSError:
        return "unreadable"
    uri = f"file:{path.as_posix()}?mode=ro"
    with contextlib.closing(plain_sqlite.connect(uri, uri=True)) as plain:
        try:
            plain.execute("SELECT count(*) FROM sqlite_master").fetchone()
            return "plaintext"
        except _wrong_key_errors(plain_sqlite):
            pass
    if key is not None:
        sc = _sqlcipher()
        with contextlib.closing(sc.connect(uri, uri=True)) as keyed:
            try:
                apply_key(keyed, key)
                keyed.execute("SELECT count(*) FROM sqlite_master").fetchone()
                return "encrypted"
            except _wrong_key_errors(sc):
                pass
    return "unreadable"


def discover(home: Path, key: DatabaseKey | None) -> list[Database]:
    """Every database file Hermes owns under ``home`` (and its profile homes)."""
    found: list[Database] = []
    for root, dirs, files in os.walk(home):
        relative_root = Path(root).relative_to(home).parts
        dirs[:] = sorted(d for d in dirs if not _pruned((*relative_root, d)))
        for name in sorted(files):
            path = Path(root, name)
            if name.endswith(PREPARED_SUFFIX) or not looks_like_database_name(name) or not in_scope(path, home):
                continue
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
    targets = [str(p) for base in paths for p in (base, Path(f"{base}-wal"), Path(f"{base}-shm")) if p.exists()]
    if not targets:
        return []
    try:
        proc = runner(["/usr/sbin/lsof", "-t", "--", *targets], capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if proc.returncode not in (0, 1):  # 1 = no process has them open
        return None
    return sorted({int(pid) for pid in proc.stdout.split() if pid.isdigit()})


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


def prepare(database: Database, key: DatabaseKey) -> Path:
    """Export ``database`` to an encrypted sibling and verify it; return the sibling."""
    sc = _sqlcipher()
    target = Path(f"{database.path}{PREPARED_SUFFIX}")
    target.unlink(missing_ok=True)
    with contextlib.closing(sc.connect(str(database.path))) as source:
        source.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        if source.execute("PRAGMA quick_check").fetchone()[0] != "ok":
            raise MigrationError(f"{database.relative} fails SQLite's quick_check; not converted")
        expected_counts, (app, version) = _counts(source), _ids(source)
        journal_mode = source.execute("PRAGMA journal_mode").fetchone()[0]
        source.execute(f"ATTACH DATABASE ? AS enc KEY \"x'{key.key.hex()}'\"", (str(target),))
        source.execute(f"PRAGMA enc.cipher_plaintext_header_size = {PLAINTEXT_HEADER_BYTES}")
        source.execute(f"PRAGMA enc.cipher_salt = \"x'{key.salt.hex()}'\"")
        source.execute("SELECT sqlcipher_export('enc')")
        source.execute(f"PRAGMA enc.application_id = {app}")
        source.execute(f"PRAGMA enc.user_version = {version}")
        # Keep WAL only where Hermes itself would: SQLCipher may link an older
        # SQLite than the interpreter's, and on one with the WAL-reset bug
        # Hermes uses rollback-journal mode (it never downgrades an open WAL DB,
        # so the offline conversion is the moment to do it).
        if str(journal_mode).lower() == "wal" and not wal_reset_vulnerable(sc.sqlite_version_info):
            source.execute("PRAGMA enc.journal_mode = WAL")
        source.execute("DETACH DATABASE enc")
    with contextlib.closing(sc.connect(str(target))) as check:
        apply_key(check, key)
        if check.execute("PRAGMA quick_check").fetchone()[0] != "ok":
            raise MigrationError(f"the encrypted copy of {database.relative} fails quick_check")
        if _counts(check) != expected_counts or _ids(check) != (app, version):
            raise MigrationError(f"the encrypted copy of {database.relative} does not match the original")
        check.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    for suffix in ("-wal", "-shm"):
        Path(f"{target}{suffix}").unlink(missing_ok=True)
    os.chmod(target, stat.S_IMODE(database.path.stat().st_mode))  # e.g. state.db is owner-only
    return target


def prepare_plain(database: Database, key: DatabaseKey) -> Path:
    """Export an encrypted ``database`` to a plaintext sibling and verify it; return the sibling."""
    sc = _sqlcipher()
    target = Path(f"{database.path}{PREPARED_SUFFIX}")
    target.unlink(missing_ok=True)
    with contextlib.closing(sc.connect(str(database.path))) as source:
        apply_key(source, key)
        source.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        if source.execute("PRAGMA quick_check").fetchone()[0] != "ok":
            raise MigrationError(f"{database.relative} fails SQLite's quick_check; not decrypted")
        expected_counts, (app, version) = _counts(source), _ids(source)
        journal_mode = source.execute("PRAGMA journal_mode").fetchone()[0]
        source.execute("ATTACH DATABASE ? AS plain KEY ''", (str(target),))
        source.execute("SELECT sqlcipher_export('plain')")
        source.execute(f"PRAGMA plain.application_id = {app}")
        source.execute(f"PRAGMA plain.user_version = {version}")
        if str(journal_mode).lower() == "wal":
            source.execute("PRAGMA plain.journal_mode = WAL")
        source.execute("DETACH DATABASE plain")
    with contextlib.closing(sc.connect(str(target))) as check:
        if check.execute("PRAGMA quick_check").fetchone()[0] != "ok":
            raise MigrationError(f"the decrypted copy of {database.relative} fails quick_check")
        if _counts(check) != expected_counts or _ids(check) != (app, version):
            raise MigrationError(f"the decrypted copy of {database.relative} does not match the original")
        check.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    for suffix in ("-wal", "-shm"):
        Path(f"{target}{suffix}").unlink(missing_ok=True)
    os.chmod(target, stat.S_IMODE(database.path.stat().st_mode))  # e.g. state.db is owner-only
    return target


def _swap(path: Path, prepared: Path) -> None:
    if prepared.exists():
        os.replace(prepared, path)
    for suffix in ("-wal", "-shm"):
        Path(f"{path}{suffix}").unlink(missing_ok=True)


# -- the whole home ---------------------------------------------------------------------


def resume(
    home: Path, *, disarm: Callable[[Path], None] | None = None, arm: Callable[[Path], None] | None = None
) -> bool:
    """Finish an interrupted conversion from its journal (no key needed). Returns whether one was found.

    An encryption journal also re-arms the home: the run may have stopped
    between writing the journal and writing the marker, and encrypted
    databases in an unarmed home are unreadable to Hermes.
    """
    journal = journal_path(home)
    if not journal.is_file():
        return False
    data = json.loads(journal.read_text(encoding="utf-8"))
    decrypting = data.get("direction") == "decrypt"
    if not decrypting:
        (arm or _arm)(home)
    for entry in data["swaps"]:
        _swap(Path(entry["path"]), Path(entry["prepared"]))
    if decrypting:
        (disarm or _disarm)(home)
        decrypt_pending_path(home).unlink(missing_ok=True)
    else:
        pending_path(home).unlink(missing_ok=True)
    journal.unlink()
    return True


def _marker(home: Path) -> Path:
    return home.joinpath("mordred", "db-encryption.marker")


def _arm(home: Path) -> None:
    _marker(home).parent.mkdir(parents=True, exist_ok=True)
    _marker(home).write_text("1\n", encoding="utf-8")


def _disarm(home: Path) -> None:
    _marker(home).unlink(missing_ok=True)


def _prepare_all(
    todo: list[Database], prepare_one: Callable[[Database, DatabaseKey], Path], key: DatabaseKey
) -> list[tuple[Database, Path]]:
    prepared: list[tuple[Database, Path]] = []
    try:
        for database in todo:
            prepared.append((database, prepare_one(database, key)))
    except Exception:
        for database in todo:
            Path(f"{database.path}{PREPARED_SUFFIX}").unlink(missing_ok=True)
        raise
    return prepared


def _refuse_if_open(todo: list[Database], holders_of: Callable[[list[Path]], list[int] | None] | None) -> None:
    if not todo:
        return
    busy = (holders_of or holders)([d.path for d in todo])
    if busy is None:
        raise MigrationError("could not check whether Hermes has the databases open (lsof failed)")
    if busy:
        raise MigrationError(f"the databases are open in other processes (pids {busy}); stop Hermes first")


def _write_journal(home: Path, prepared: list[tuple[Database, Path]], direction: str) -> None:
    journal = journal_path(home)
    journal.parent.mkdir(parents=True, exist_ok=True)
    swaps = [{"path": str(d.path), "prepared": str(copy)} for d, copy in prepared]
    staged = journal.with_name(f"{journal.name}.tmp")  # never a torn journal: startup would refuse to parse it
    with staged.open("w", encoding="utf-8") as handle:
        handle.write(json.dumps({"direction": direction, "swaps": swaps}))
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(staged, journal)


def migrate(
    home: Path,
    key: DatabaseKey,
    *,
    arm: Callable[[Path], None],
    holders_of: Callable[[list[Path]], list[int] | None] | None = None,
) -> Report:
    """Convert every plaintext database under ``home``; raise :class:`MigrationError` on refusal."""
    report = Report()
    with migration_lock(home):
        resume(home, arm=arm)
        databases = discover(home, key)
        report.already_encrypted = [d.relative for d in databases if d.state == "encrypted"]
        report.unreadable = [d.relative for d in databases if d.state == "unreadable"]
        todo = [d for d in databases if d.state == "plaintext"]
        _refuse_if_open(todo, holders_of)
        prepared = _prepare_all(todo, prepare, key)
        _write_journal(home, prepared, "encrypt")
        arm(home)
        for database, copy in prepared:
            _swap(database.path, copy)
            report.converted.append(database.relative)
        journal_path(home).unlink()
        pending_path(home).unlink(missing_ok=True)
    return report


def decrypt_all(
    home: Path,
    key: DatabaseKey,
    *,
    disarm: Callable[[Path], None] = _disarm,
    holders_of: Callable[[list[Path]], list[int] | None] | None = None,
) -> Report:
    """Turn every encrypted Hermes database back into plain SQLite, then disarm.

    Same all-or-nothing shape as :func:`migrate`; the swap happens before the
    marker goes, so an interruption leaves an armed home whose journal
    :func:`resume` completes (still without a key) on the next start.
    """
    report = Report()
    with migration_lock(home):
        resume(home, disarm=disarm)
        databases = discover(home, key)
        report.unreadable = [d.relative for d in databases if d.state == "unreadable"]
        if report.unreadable:
            raise MigrationError("unreadable database(s); encryption remains enabled: " + ", ".join(report.unreadable))
        todo = [d for d in databases if d.state == "encrypted"]
        _refuse_if_open(todo, holders_of)
        prepared = _prepare_all(todo, prepare_plain, key)
        _write_journal(home, prepared, "decrypt")
        for database, copy in prepared:
            _swap(database.path, copy)
            report.converted.append(database.relative)
        disarm(home)
        journal_path(home).unlink()
        decrypt_pending_path(home).unlink(missing_ok=True)
        pending_path(home).unlink(missing_ok=True)
    return report


def schedule_decrypt(home: Path) -> None:
    """Decrypt on the next Hermes start (the databases are in use now)."""
    path = decrypt_pending_path(home)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("1\n", encoding="utf-8")
    pending_path(home).unlink(missing_ok=True)


def schedule(home: Path) -> None:
    """Convert on the next Hermes start (the databases are in use now)."""
    path = pending_path(home)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("1\n", encoding="utf-8")


def plaintext_backups(home: Path) -> list[Path]:
    """Hermes backup archives that may hold plaintext copies of the databases."""
    backups = home / "backups"
    if not backups.is_dir():
        return []
    return sorted(p for p in backups.rglob("*") if p.is_file() and p.suffix in (".zip", ".tar", ".gz", ".tgz"))
