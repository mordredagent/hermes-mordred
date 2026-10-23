"""Phase 4/5: noticing unprotected databases, and telling the model the real status."""

from __future__ import annotations

import shutil
import sqlite3 as stdlib_sqlite3
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("sqlcipher3")

from mordred_hermes import dbcrypt
from mordred_hermes.dbcrypt import _hooks, _key, _migrate, _monitor, _shim

KEY = _key.derive(bytes(range(32)))


@pytest.fixture
def home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    base = tmp_path / "hermes"
    conn = stdlib_sqlite3.connect(base.mkdir() or base / "state.db")
    conn.execute("CREATE TABLE t (a)")
    conn.commit()
    conn.close()
    _migrate.migrate(base, KEY, arm=dbcrypt.arm, holders_of=lambda _p: [])
    _monitor.reset_cache()
    monkeypatch.setattr(sys, "platform", "darwin")
    monkeypatch.setattr(_hooks, "_home", lambda: base)
    monkeypatch.setattr(_hooks, "_reported", set())
    monkeypatch.setattr(_hooks, "_audit", lambda *a, **k: None)
    monkeypatch.setattr(_hooks, "_notify", lambda *a, **k: None)
    return base


def _protected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(_shim, "is_installed", lambda: True)
    monkeypatch.setattr(_hooks, "_key_available", lambda: True)


def test_clean_state_has_no_findings(home: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _protected(monkeypatch)
    assert _monitor.check(home, key_available=lambda: True) == []
    assert _hooks.pre_llm_call() is None
    assert "encrypted at rest" in _hooks.status_line()


def test_a_plaintext_state_db_is_noticed_on_the_next_turn(home: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _protected(monkeypatch)
    (home / "state.db").unlink()
    plain = stdlib_sqlite3.connect(home / "state.db")  # Hermes recreated it without SQLCipher
    plain.execute("CREATE TABLE t (a)")
    plain.commit()
    plain.close()
    monkeypatch.setattr(_hooks, "_policy_mode", lambda: "lenient")

    findings = _monitor.check(home, key_available=lambda: True)
    assert [f.code for f in findings] == ["plaintext"] and "state.db" in findings[0].detail
    warning = _hooks.pre_llm_call()
    assert warning and "NOT protected" in warning["context"]
    assert "WARNING" in _hooks.status_line()


def test_strict_policy_stops_the_turn(home: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(_shim, "is_installed", lambda: False)  # this process has the stdlib module
    monkeypatch.setattr(_hooks, "_policy_mode", lambda: "strict")
    with pytest.raises(_hooks.DatabaseEncryptionRefused, match="not protected"):
        _hooks.pre_llm_call()
    assert issubclass(_hooks.DatabaseEncryptionRefused, BaseException)
    assert not issubclass(_hooks.DatabaseEncryptionRefused, Exception)  # escapes Hermes's hook guard


def test_missing_key_and_interrupted_conversion_are_findings(home: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(_shim, "is_installed", lambda: True)
    _migrate.journal_path(home).write_text('{"swaps": []}', encoding="utf-8")
    codes = {f.code for f in _monitor.check(home, key_available=lambda: False)}
    assert codes == {"no_key", "interrupted"}


def test_unarmed_homes_report_only_a_scheduled_conversion(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "platform", "darwin")
    monkeypatch.setattr(_hooks, "_home", lambda: tmp_path)
    assert _monitor.check(tmp_path) == [] and _hooks.status_line() == ""
    _migrate.schedule(tmp_path)
    assert [f.code for f in _monitor.check(tmp_path)] == ["pending"]
    assert "not active yet" in _hooks.status_line()
    assert _hooks.pre_llm_call() is None  # scheduled is not a violation


def test_the_plaintext_probe_never_touches_the_file(home: Path) -> None:
    before = sorted(p.name for p in home.iterdir())
    assert _monitor.is_plaintext(home / "state.db") is False
    assert sorted(p.name for p in home.iterdir()) == before  # no -wal/-shm created


def test_component_registers_its_hooks_and_prompt_section() -> None:
    calls: list[tuple[str, object]] = []

    class Ctx:
        def register_hook(self, name: str, fn: object) -> None:
            calls.append((name, fn))

        def register_system_prompt_section(self, name: str, fn: object, max_chars: int) -> None:
            calls.append((name, fn))

    dbcrypt.register(Ctx())
    assert [name for name, _fn in calls] == ["on_session_start", "pre_llm_call", "mordred.databases"]


def test_status_line_accepts_hermes_session_info(home: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Hermes renders a prompt section by calling it with a read-only session-info mapping."""
    from types import MappingProxyType

    _protected(monkeypatch)
    assert "encrypted at rest" in _hooks.status_line(MappingProxyType({"platform": "cli"}))


def test_a_key_that_does_not_open_the_databases_is_a_violation(home: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Wrong key: Hermes reads no history and saves no turns; never report "encrypted, all fine"."""
    _protected(monkeypatch)
    wrong = _key.derive(bytes(32))
    (home / "state.db.repair-attempts.json").write_text("{}", encoding="utf-8")  # Hermes's, not SQLite
    findings = _monitor.check(home, key_available=lambda: True, key=lambda: wrong)
    assert [f.code for f in findings] == ["wrong_key"] and "state.db" in findings[0].detail
    assert "repair-attempts" not in findings[0].detail
    assert _monitor.check(home, key_available=lambda: True, key=lambda: KEY) == []


def test_a_wal_file_read_with_the_wrong_key_is_unreadable_not_a_crash(tmp_path: Path) -> None:
    """With the wrong key a WAL-mode file can raise MemoryError (SQLITE_NOMEM)."""
    base = tmp_path / "h"
    conn = stdlib_sqlite3.connect(base.mkdir() or base / "state.db")
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("CREATE TABLE t (a)")
    conn.commit()
    conn.close()
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(_migrate, "wal_reset_vulnerable", lambda _v: False)  # keep WAL
        _migrate.migrate(base, KEY, arm=dbcrypt.arm, holders_of=lambda _p: [])
    wrong = _key.derive(bytes(32))
    for _ in range(3):
        assert [d.state for d in _migrate.discover(base, wrong)] == ["unreadable"]
        assert _monitor.key_opens(base / "state.db", wrong) is False


def test_a_long_violation_still_fits_the_prompt_section(home: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Hermes drops a section longer than its max_chars, exactly when the warning matters."""
    monkeypatch.setattr(
        _monitor,
        "check",
        lambda *_a, **_k: [_monitor.Finding("plaintext", "unencrypted database(s): " + "x.db, " * 200)],
    )
    text = _hooks.status_line()
    assert "NOT protected" in text and len(text) <= _hooks._SECTION_MAX_CHARS


# -- in-process probes keep this process's SQLite locks ------------------------------------
#
# POSIX record locks belong to the process: closing ANY descriptor of a file
# drops every lock the process holds on it. SQLite defers closing its own
# descriptors while another connection of the same library holds a lock, but
# a plain open() or another SQLite library (the stdlib's, while Hermes uses
# SQLCipher's) closes immediately. Hermes then still believes it holds its
# locks; another process can reset the -shm under its mapping (SIGBUS) or
# checkpoint and delete the WAL.

_posix_locks = pytest.mark.skipif(sys.platform == "win32", reason="POSIX record-lock semantics")

#: Run in another process: can it take what this process should still hold?
#: SQLite's unix VFS keeps a shared lock on the -shm "dead man switch" byte
#: (offset 128) while the wal-index is mapped, and a SHARED lock on the main
#: file (bytes 0x40000002..+510) for as long as a WAL connection is open.
_LOCK_PROBE = """
import fcntl, os, sys

def held(path, start, length):
    fd = os.open(path, os.O_RDWR)
    try:
        fcntl.lockf(fd, fcntl.LOCK_EX | fcntl.LOCK_NB, length, start, os.SEEK_SET)
    except OSError:
        return 1
    finally:
        os.close(fd)
    return 0

db = sys.argv[1]
print(held(db + "-shm", 128, 1), held(db, 0x40000002, 510))
"""

#: Run in another process: a plaintext WAL database whose rows are only in the WAL, held open.
_PLAINTEXT_WRITER = """
import sqlite3, sys

conn = sqlite3.connect(sys.argv[1])
conn.execute("PRAGMA journal_mode = WAL")
conn.execute("PRAGMA wal_autocheckpoint = 0")
conn.execute("CREATE TABLE tasks (title TEXT)")
conn.execute("INSERT INTO tasks VALUES ('plaintext row')")
conn.commit()
print("ready", flush=True)
sys.stdin.read()
conn.close()
"""


def _locks_held(path: Path) -> tuple[bool, bool]:
    """(-shm dead-man-switch lock, main-file SHARED lock) still held by this process, as another one sees it."""
    out = subprocess.run(
        [sys.executable, "-c", _LOCK_PROBE, str(path)], capture_output=True, text=True, check=True, timeout=60
    )
    shm, shared = out.stdout.split()
    return shm == "1", shared == "1"


def _hermes_sqlite3(home: Path) -> Any:
    """The ``sqlite3`` module Hermes gets in an armed home (the shim, backed by sqlcipher3)."""
    return _shim.build_module(key=lambda: KEY, home=lambda: home, has_key=lambda: True)


def _live(module: Any, path: Path, *, tables: bool = True) -> Any:
    """A connection held open like Hermes's SessionDB: WAL mode, rows only in the WAL (no checkpoint)."""
    conn = module.connect(str(path), check_same_thread=False)
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA wal_autocheckpoint = 0")
    if tables:
        conn.execute("CREATE TABLE IF NOT EXISTS live (a)")
        conn.execute("INSERT INTO live VALUES ('row')")
        conn.commit()
    return conn


def _protected_with_key(monkeypatch: pytest.MonkeyPatch) -> None:
    _protected(monkeypatch)
    monkeypatch.setattr(_hooks, "_key", lambda: KEY)


@_posix_locks
def test_the_lock_probe_sees_a_dropped_lock(tmp_path: Path) -> None:
    """Without this the tests below could pass vacuously: one plain open() and close unlocks the file."""
    home = tmp_path / "home"
    home.mkdir()
    live = _live(_hermes_sqlite3(home), home / "state.db")
    try:
        assert _locks_held(home / "state.db") == (True, True)
        with (home / "state.db").open("rb") as handle:
            handle.read(16)
        assert _locks_held(home / "state.db") == (True, False)
    finally:
        live.close()


@_posix_locks
def test_the_per_turn_check_keeps_hermess_locks_on_its_live_database(
    home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """D1: the check runs inside Hermes while state.db is open; it must never unlock it."""
    _protected_with_key(monkeypatch)
    live = _live(_hermes_sqlite3(home), home / "state.db")
    try:
        assert _locks_held(home / "state.db") == (True, True)
        for _ in range(2):  # the second turn uses the cached deep scan
            assert _monitor.check(home, key_available=lambda: True, key=lambda: KEY) == []
            assert _hooks.pre_llm_call() is None
            assert "encrypted at rest" in _hooks.status_line()
        assert _locks_held(home / "state.db") == (True, True)
        live.execute("INSERT INTO live VALUES ('after the check')")
        live.commit()
    finally:
        live.close()


@_posix_locks
def test_an_unprotected_process_is_probed_through_its_own_sqlite(home: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Hermes started without the SQLCipher module: its connections are the stdlib's, and so are the probes."""
    monkeypatch.setattr(_shim, "is_installed", lambda: False)
    (home / "state.db").unlink()
    live = _live(stdlib_sqlite3, home / "state.db")  # a plaintext state.db, rows only in the WAL
    try:
        assert _locks_held(home / "state.db") == (True, True)
        findings = _monitor.check(home, key_available=lambda: True, key=lambda: KEY)
        assert [f.code for f in findings] == ["unprotected_process", "plaintext"]
        assert "state.db" in findings[1].detail
        assert _locks_held(home / "state.db") == (True, True)
    finally:
        live.close()


@_posix_locks
def test_reopening_an_encrypted_copy_keeps_the_locks_of_its_open_connection(tmp_path: Path) -> None:
    """The shim probes a file outside the home on every connect(); Hermes may already have it open."""
    home = tmp_path / "home"
    home.mkdir()
    sq = _hermes_sqlite3(home)
    _live(sq, home / "kanban.db").close()
    staged = tmp_path / "export" / "kanban.db"  # keyed only because it is one of our encrypted databases
    staged.parent.mkdir()
    shutil.copy(home / "kanban.db", staged)
    first = _live(sq, staged)
    try:
        assert _locks_held(staged) == (True, True)
        second = sq.connect(str(staged))
        assert second.execute("SELECT count(*) FROM live").fetchone() == (2,)
        second.close()
        assert _locks_held(staged) == (True, True)
    finally:
        first.close()


@pytest.mark.parametrize("tables", [True, False], ids=["rows-only-in-the-wal", "no-tables-yet"])
def test_a_fresh_encrypted_database_is_not_reported_as_plaintext(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, tables: bool
) -> None:
    """L1: before its first checkpoint a new state.db's main file is page 1 with an empty schema.

    Page 1's b-tree header lies inside the 112-byte plaintext header, so the
    stdlib reads that file as an empty plaintext database.
    """
    base = tmp_path / "fresh"
    base.mkdir()
    dbcrypt.arm(base)
    monkeypatch.setattr(sys, "platform", "darwin")
    monkeypatch.setattr(_hooks, "_home", lambda: base)
    _protected_with_key(monkeypatch)
    live = _live(_hermes_sqlite3(base), base / "state.db", tables=tables)
    try:
        seen = subprocess.run(
            [
                sys.executable,
                "-c",
                "import sqlite3, sys; c = sqlite3.connect(sys.argv[1], uri=True); "
                "print(c.execute('SELECT count(*) FROM sqlite_master').fetchone()[0])",
                f"file:{(base / 'state.db').as_posix()}?mode=ro&immutable=1",
            ],
            capture_output=True,
            text=True,
            check=True,
            timeout=60,
        )
        assert seen.stdout.strip() == "0"  # what the stdlib makes of the main file alone
        assert _monitor.check(base, key_available=lambda: True, key=lambda: KEY) == []
        assert "encrypted at rest" in _hooks.status_line()
    finally:
        live.close()


def test_a_plaintext_database_with_rows_only_in_its_wal_is_still_reported(
    home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Never claim protection that is not there: an empty-looking plaintext main file is not 'encrypted'."""
    _protected_with_key(monkeypatch)
    writer = subprocess.Popen(
        [sys.executable, "-c", _PLAINTEXT_WRITER, str(home / "kanban.db")],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        text=True,
    )
    try:
        assert writer.stdout is not None and writer.stdout.readline().strip() == "ready"
        findings = _monitor.check(home, key_available=lambda: True, key=lambda: KEY)
        assert [f.code for f in findings] == ["plaintext"] and "kanban.db" in findings[0].detail
    finally:
        writer.communicate("", timeout=60)


def test_offline_classification_refuses_to_run_inside_a_protected_runtime(
    home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``discover`` opens files with plain open() and the stdlib: only where nothing holds a connection."""
    monkeypatch.setattr(_shim, "is_installed", lambda: True)
    with pytest.raises(_migrate.MigrationError, match="inside a Hermes process"):
        _migrate.discover(home, KEY)
    assert [p.name for p in _migrate.database_paths(home)] == ["state.db"]  # listing never opens a file
