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
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

from . import _migrate, _shim, armed
from ._policy import in_scope, looks_like_database_name

#: Findings that mean the databases are not protected.
VIOLATIONS: Final = frozenset({"unprotected_process", "no_key", "interrupted", "plaintext"})
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
    except (stdlib.DatabaseError, UnicodeDecodeError):  # see _migrate._wrong_key_errors
        return False
    finally:
        conn.close()


def check(home: Path, *, key_available: Any = None) -> list[Finding]:
    """Everything wrong with the databases' protection right now (empty = fine)."""
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
    candidates = {*_top_level(home), *_deep(home)}
    plaintext = sorted(str(p.relative_to(home)) for p in candidates if p.is_file() and is_plaintext(p))
    if plaintext:
        findings.append(Finding("plaintext", "unencrypted database(s): " + ", ".join(plaintext)))
    return findings


def reset_cache() -> None:
    with _LOCK:
        _DEEP_CACHE.clear()
