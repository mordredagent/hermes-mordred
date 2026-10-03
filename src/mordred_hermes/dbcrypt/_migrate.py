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
import fcntl
import json
import os
import subprocess
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final

from ._key import DatabaseKey
from ._policy import DENY_DIRS, in_scope, looks_like_database_name
from ._shim import PLAINTEXT_HEADER_BYTES, SQLITE_MAGIC, apply_key

PENDING_SUBPATH: Final = ("mordred", "db-encryption.pending")
JOURNAL_SUBPATH: Final = ("mordred", "db-encryption.journal.json")
LOCK_SUBPATH: Final = ("mordred", "db-encryption.lock")
PREPARED_SUFFIX: Final = ".mordred-enc"


class MigrationError(RuntimeError):
    """A conversion that was refused or rolled back; the message says why."""


@dataclass(frozen=True)
class Database:
    path: Path
    relative: str
    state: str  # "plaintext" | "encrypted" | "unreadable"


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


def _classify(path: Path, key: DatabaseKey | None) -> str:
    sc = _sqlcipher()
    try:
        with path.open("rb") as handle:
            if handle.read(len(SQLITE_MAGIC)) != SQLITE_MAGIC:
                return "unreadable"
    except OSError:
        return "unreadable"
    uri = f"file:{path.as_posix()}?mode=ro"
    with contextlib.closing(sc.connect(uri, uri=True)) as plain:
        try:
            plain.execute("SELECT count(*) FROM sqlite_master").fetchone()
            return "plaintext"
        except sc.DatabaseError:
            pass
    if key is not None:
        with contextlib.closing(sc.connect(uri, uri=True)) as keyed:
            try:
                apply_key(keyed, key)
                keyed.execute("SELECT count(*) FROM sqlite_master").fetchone()
                return "encrypted"
            except sc.DatabaseError:
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
            found.append(Database(path, str(path.relative_to(home)), _classify(path, key)))
    return found


# -- other processes ---------------------------------------------------------------------


def holders(paths: list[Path], *, runner: Callable[..., Any] = subprocess.run) -> list[int] | None:
    """PIDs (other than ours) with any of ``paths`` (or their sidecars) open; ``None`` if unknown."""
    targets = [str(p) for base in paths for p in (base, Path(f"{base}-wal"), Path(f"{base}-shm")) if p.exists()]
    if not targets:
        return []
    try:
        proc = runner(["/usr/sbin/lsof", "-t", "--", *targets], capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if proc.returncode not in (0, 1):  # 1 = no process has them open
        return None
    return sorted({int(pid) for pid in proc.stdout.split() if pid.isdigit() and int(pid) != os.getpid()})


@contextlib.contextmanager
def migration_lock(home: Path, *, timeout: float = 120.0) -> Iterator[None]:
    """Serialize conversions (and the processes that wait for one) on this home."""
    path = _path(home, LOCK_SUBPATH)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        deadline = time.monotonic() + timeout
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() > deadline:
                    raise MigrationError("another process is converting the databases") from None
                time.sleep(0.2)
        yield
    finally:
        os.close(fd)


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
        if str(journal_mode).lower() == "wal":
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
    return target


def _swap(path: Path, prepared: Path) -> None:
    if prepared.exists():
        os.replace(prepared, path)
    for suffix in ("-wal", "-shm"):
        Path(f"{path}{suffix}").unlink(missing_ok=True)


# -- the whole home ---------------------------------------------------------------------


def resume(home: Path) -> bool:
    """Finish an interrupted swap from its journal. Returns whether one was found."""
    journal = journal_path(home)
    if not journal.is_file():
        return False
    entries = json.loads(journal.read_text(encoding="utf-8"))["swaps"]
    for entry in entries:
        _swap(Path(entry["path"]), Path(entry["prepared"]))
    journal.unlink()
    pending_path(home).unlink(missing_ok=True)
    return True


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
        resume(home)
        databases = discover(home, key)
        report.already_encrypted = [d.relative for d in databases if d.state == "encrypted"]
        report.unreadable = [d.relative for d in databases if d.state == "unreadable"]
        todo = [d for d in databases if d.state == "plaintext"]
        if todo:
            busy = (holders_of or holders)([d.path for d in todo])
            if busy is None:
                raise MigrationError("could not check whether Hermes has the databases open (lsof failed)")
            if busy:
                raise MigrationError(f"the databases are open in other processes (pids {busy}); stop Hermes first")
        prepared: list[tuple[Database, Path]] = []
        try:
            for database in todo:
                prepared.append((database, prepare(database, key)))
        except Exception:
            for _database, copy in prepared:
                copy.unlink(missing_ok=True)
            for database in todo:
                Path(f"{database.path}{PREPARED_SUFFIX}").unlink(missing_ok=True)
            raise
        journal = journal_path(home)
        journal.parent.mkdir(parents=True, exist_ok=True)
        swaps = [{"path": str(d.path), "prepared": str(copy)} for d, copy in prepared]
        journal.write_text(json.dumps({"swaps": swaps}), encoding="utf-8")
        arm(home)
        for database, copy in prepared:
            _swap(database.path, copy)
            report.converted.append(database.relative)
        journal.unlink()
        pending_path(home).unlink(missing_ok=True)
    return report


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
