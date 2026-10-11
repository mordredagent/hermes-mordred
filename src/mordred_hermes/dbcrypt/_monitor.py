"""Phase 4: notice when Hermes's databases are not protected as they should be.

Run at session start and at the start of every turn (``pre_llm_call``). When
database encryption is armed it checks:

- ``unprotected_process`` — this process has the stdlib ``sqlite3``, not the
  SQLCipher replacement (it started some way the bootstrap did not cover);
- ``no_key`` — the database key cannot be resolved;
- ``interrupted`` — a conversion journal is left over;
- ``plaintext`` — a Hermes database that the *stdlib* ``sqlite3`` can read,
  i.e. a plaintext file where only encrypted ones should be (Hermes recreated
  or restored one, or another environment without Mordred wrote it).

The full set of database paths is cached for a few minutes; the homes' top
levels (where ``state.db`` lives) are re-listed on every check so a new
plaintext ``state.db`` is seen on the next turn. When encryption is not armed
the only finding is ``pending`` (a conversion is scheduled).
"""

from __future__ import annotations

import os
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

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
    found = [d.path for d in _migrate.discover(home, None)]
    with _LOCK:
        _DEEP_CACHE[str(home)] = (time.monotonic(), found)
    return found


def is_plaintext(path: Path) -> bool:
    """Whether the stdlib ``sqlite3`` can read ``path`` (read-only, no locks, no sidecars)."""
    stdlib = _shim.stdlib_sqlite3()
    try:
        if path.stat().st_size == 0:
            return False
        conn = stdlib.connect(f"file:{path.as_posix()}?mode=ro&immutable=1", uri=True)
    except (OSError, stdlib.Error, UnicodeDecodeError):
        return False
    try:
        conn.execute("SELECT count(*) FROM sqlite_master").fetchone()
        return True
    except _shim.wrong_key_errors(stdlib):
        return False
    finally:
        conn.close()


def key_opens(path: Path, key: Any) -> bool:
    """Whether ``key`` opens the encrypted ``path`` (read-only, no locks, no sidecars).

    Files that are not SQLite at all (``state.db.repair-attempts.json``) are not reported.
    """
    try:
        with path.open("rb") as handle:
            if handle.read(len(_shim.SQLITE_MAGIC)) != _shim.SQLITE_MAGIC:
                return True
    except OSError:
        return True
    sc = _migrate._sqlcipher()
    try:
        conn = sc.connect(f"file:{path.as_posix()}?mode=ro&immutable=1", uri=True)
    except (OSError, sc.Error):
        return True  # cannot tell; not reported
    try:
        _shim.apply_key(conn, key)
        conn.execute("SELECT count(*) FROM sqlite_master").fetchone()
        return True
    except _shim.wrong_key_errors(sc):
        return False
    finally:
        conn.close()


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
    top_level = _top_level(home)
    candidates = {*top_level, *_deep(home)}
    plaintext = sorted(str(p.relative_to(home)) for p in candidates if p.is_file() and is_plaintext(p))
    if plaintext:
        findings.append(Finding("plaintext", "unencrypted database(s): " + ", ".join(plaintext)))
    resolved = key() if key is not None and _shim.is_installed() else None
    if resolved is not None:
        locked = sorted(
            str(p.relative_to(home))
            for p in top_level
            if str(p.relative_to(home)) not in plaintext
            and p.is_file()
            and p.stat().st_size > 0
            and not key_opens(p, resolved)
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
