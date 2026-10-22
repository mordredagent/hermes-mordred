"""Phase 4: notice when Hermes's databases are not protected as they should be.

Run at session start and at the start of every turn (``pre_llm_call``). When
database encryption is armed it checks:

- ``unprotected_process`` — this process has the stdlib ``sqlite3``, not the
  SQLCipher replacement (it started some way the bootstrap did not cover);
- ``no_key`` — the database key cannot be resolved;
- ``interrupted`` — a conversion journal is left over;
- ``plaintext`` — a Hermes database that SQLite reads without the key and the
  key does not open, i.e. a plaintext file where only encrypted ones should be
  (Hermes recreated or restored one, or another environment without Mordred
  wrote it).

The full set of database paths is cached for a few minutes; the homes' top
levels (where ``state.db`` lives) are re-listed on every check so a new
plaintext ``state.db`` is seen on the next turn. When encryption is not armed
the only finding is ``pending`` (a conversion is scheduled).

This runs inside Hermes, next to its open connections, so every probe goes
through the SQLite library those connections use (:func:`_own_sqlite`) and
never through a plain ``open()``: POSIX record locks belong to the process,
and closing any other descriptor of a database file drops all of them.
"""

from __future__ import annotations

import os
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final
from urllib.parse import quote

from . import _migrate, _shim, armed, protected_state_present
from ._policy import in_scope, looks_like_database_name

#: Findings that mean the databases are not protected.
VIOLATIONS: Final = frozenset(
    {"unprotected_process", "no_key", "wrong_key", "interrupted", "plaintext", "unsupported_platform"}
)
_DEEP_SCAN_SECONDS: Final = 300.0
_LOCK: Final = threading.Lock()
_DEEP_CACHE: dict[str, Any] = {}


@dataclass(frozen=True)
class Finding:
    code: str
    detail: str

    @property
    def violation(self) -> bool:
        return self.code in VIOLATIONS


def _homes(home: Path) -> list[Path]:
    homes = [home]
    profiles = home / "profiles"
    if profiles.is_dir():
        homes += sorted(p for p in profiles.iterdir() if p.is_dir())
    return homes


def _top_level(home: Path) -> list[Path]:
    paths: list[Path] = []
    for base in _homes(home):
        for sub in (base, base / "cron"):
            try:
                entries = list(os.scandir(sub))
            except OSError:
                continue
            paths += [Path(e.path) for e in entries if e.is_file() and looks_like_database_name(e.name)]
    return [p for p in paths if in_scope(p, home)]


def _deep(home: Path) -> list[Path]:
    with _LOCK:
        cached = _DEEP_CACHE.get(str(home))
        if cached and time.monotonic() - cached[0] < _DEEP_SCAN_SECONDS:
            return list(cached[1])
    found = _migrate.database_paths(home)  # names only: classifying is the probes' job
    with _LOCK:
        _DEEP_CACHE[str(home)] = (time.monotonic(), found)
    return found


def _own_sqlite() -> tuple[Any, bool]:
    """The SQLite library this process's own connections use, and whether it is SQLCipher.

    The only library a probe may open their files with. POSIX record locks
    belong to the process, and closing any descriptor of a file drops every
    lock the process holds on it. SQLite defers closing its descriptors while
    another connection *of the same library* holds a lock (its per-inode
    table), so a probe through Hermes's library is safe. A plain ``open()`` or
    a second SQLite library (the stdlib's, while Hermes uses SQLCipher's)
    closes at once and silently unlocks Hermes's live database; another
    process can then reset the WAL index under it (SIGBUS) or checkpoint and
    delete the WAL.
    """
    if _shim.is_installed():
        return _migrate._sqlcipher(), True
    return _shim.stdlib_sqlite3(), False


def _readonly_uri(path: Path) -> str:
    """Read-only, no locks, no sidecars: only the main file is read."""
    return f"file:{quote(path.as_posix())}?mode=ro&immutable=1"


def _reads(lib: Any, path: Path, *, key: Any = None, query: str = "SELECT count(*) FROM sqlite_master") -> bool:
    """Whether ``lib`` (keyed with ``key``, if given) can run ``query`` on ``path``."""
    try:
        conn = lib.connect(_readonly_uri(path), uri=True)
    except (OSError, lib.Error, UnicodeDecodeError):
        return False
    try:
        if key is not None:
            _shim.apply_key(conn, key)
        conn.execute(query).fetchone()
        return True
    except _shim.wrong_key_errors(lib):
        return False
    finally:
        conn.close()


def _empty_or_missing(path: Path) -> bool:
    try:
        return path.stat().st_size == 0
    except OSError:
        return True


def is_plaintext(path: Path, key: Any = None) -> bool:
    """Whether ``path`` is a plaintext SQLite database (probed with :func:`_own_sqlite`).

    ``key`` settles the one ambiguous case. Page 1's b-tree header lies inside
    the plaintext header, so an encrypted database whose main file still has
    an empty schema (a new one before its first checkpoint: its rows are only
    in the WAL) reads like an empty plaintext one. The key opens it, and never
    opens a plaintext file. Without SQLCipher in this process, or without the
    key, such a file is reported.
    """
    if _empty_or_missing(path):
        return False
    lib, sqlcipher = _own_sqlite()
    if not _reads(lib, path):
        return False
    return not (sqlcipher and key is not None and _reads(lib, path, key=key))


def key_opens(path: Path, key: Any) -> bool:
    """Whether ``key`` opens the encrypted ``path`` (read-only, no locks, no sidecars).

    Files that are not SQLite at all (``state.db.repair-attempts.json``) are not
    reported. Probes with SQLCipher: call it only where this process's
    connections are SQLCipher's (the shim is installed) or none are open.
    """
    if _empty_or_missing(path):
        return True
    sc = _migrate._sqlcipher()
    return _reads(sc, path, key=key) or not _reads(sc, path, query="PRAGMA user_version")


def _unsupported(home: Path) -> list[Finding]:
    if protected_state_present(home):
        return [Finding("unsupported_platform", "this encrypted Hermes home requires macOS; decrypt it there first")]
    return []


def check(home: Path, *, key_available: Any = None, key: Any = None) -> list[Finding]:
    """Everything wrong with the databases' protection right now (empty = fine).

    ``key`` (a callable returning the database key) also checks that the key
    opens the top-level databases: with another key Hermes can read none of
    its history and saves no new turns.
    """
    if sys.platform != "darwin":
        return _unsupported(home)
    if not armed(home):
        if _migrate.pending_path(home).is_file():
            return [Finding("pending", "database encryption is scheduled for the next Hermes start")]
        return []
    findings: list[Finding] = []
    if not _shim.is_installed():
        findings.append(Finding("unprotected_process", "this Hermes process opened its databases without SQLCipher"))
    elif key_available is not None and not key_available():
        findings.append(Finding("no_key", "the database key is not available (the vault could not be opened)"))
    if _migrate.journal_path(home).is_file():
        findings.append(Finding("interrupted", "an interrupted database conversion has not been completed"))
    resolved = key() if key is not None and _shim.is_installed() else None
    top_level = _top_level(home)
    candidates = {*top_level, *_deep(home)}
    plaintext = sorted(str(p.relative_to(home)) for p in candidates if p.is_file() and is_plaintext(p, resolved))
    if plaintext:
        findings.append(Finding("plaintext", "unencrypted database(s): " + ", ".join(plaintext)))
    if resolved is not None:
        locked = sorted(
            str(p.relative_to(home))
            for p in top_level
            if str(p.relative_to(home)) not in plaintext and p.is_file() and not key_opens(p, resolved)
        )
        if locked:
            findings.append(
                Finding(
                    "wrong_key",
                    "the database key does not open " + ", ".join(locked) + " (encrypted with another key?); "
                    "Hermes cannot read this history and does not save new turns",
                )
            )
    return findings


def reset_cache() -> None:
    with _LOCK:
        _DEEP_CACHE.clear()
