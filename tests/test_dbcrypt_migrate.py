"""Converting an existing Hermes home's databases to SQLCipher (dbcrypt._migrate)."""

from __future__ import annotations

import json
import sqlite3 as stdlib_sqlite3
import subprocess
import sys
from contextlib import closing
from pathlib import Path

import pytest

pytest.importorskip("sqlcipher3")

from mordred_hermes import dbcrypt
from mordred_hermes.dbcrypt import _key, _migrate, _shim
from tests._dbcrypt_platform_support import policy_sys

KEY = _key.derive(bytes(range(32)))
APP_ID = 682968903


@pytest.fixture(autouse=True)
def explicit_raw_key_seam(monkeypatch):
    """Legacy portable SQL tests explicitly replace custody, never production policy."""
    from mordred_hermes.dbcrypt import _locking

    previous = set(_locking._LEASES)
    monkeypatch.setattr(
        _migrate, "_authenticate", lambda root, supplied, lease: (None, supplied or _key.derive(bytes(range(32))))
    )
    yield
    # Fixtures own synthetic lifetimes; installed production shims have no reset.
    for root in set(_locking._LEASES) - previous:
        context, _lease = _locking._LEASES.pop(root)
        context.__exit__(None, None, None)


def _plain_db(path: Path, rows: int = 3, *, fts: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = stdlib_sqlite3.connect(path)
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute(f"PRAGMA application_id = {APP_ID}")
    conn.execute("PRAGMA user_version = 7")
    conn.execute("CREATE TABLE messages (id INTEGER PRIMARY KEY, content TEXT)")
    if fts:
        conn.execute("CREATE VIRTUAL TABLE messages_fts USING fts5(content, tokenize='trigram')")
    for i in range(rows):
        conn.execute("INSERT INTO messages (content) VALUES (?)", (f"secret りんご {i}",))
        if fts:
            conn.execute("INSERT INTO messages_fts VALUES (?)", (f"secret りんご {i}",))
    conn.commit()
    conn.close()


@pytest.fixture
def home(tmp_path: Path) -> Path:
    base = tmp_path / "hermes"
    _plain_db(base / "state.db", fts=True)
    _plain_db(base / "shared-state.db")
    _plain_db(base / "cron" / "executions.db")
    _plain_db(base / "profiles" / "work" / "state.db")
    _plain_db(base / "installs" / "env" / "build.db")  # another program's file
    return base


def _keyed(path: Path) -> stdlib_sqlite3.Connection:
    import sqlcipher3.dbapi2 as sc

    conn = sc.connect(str(path))
    _shim.apply_key(conn, KEY)
    return conn  # type: ignore[no-any-return]


def _is_plaintext(path: Path) -> bool:
    try:
        stdlib_sqlite3.connect(path).execute("SELECT count(*) FROM sqlite_master").fetchone()
        return True
    except (stdlib_sqlite3.DatabaseError, UnicodeDecodeError):  # a wrong key can surface as either
        return False


def _no_holders(_paths: list[Path]) -> list[int]:
    return []


def test_discovery_finds_hermes_databases_only(home: Path) -> None:
    found = {d.relative: d.state for d in _migrate.discover(home, KEY)}
    assert found == {
        "cron/executions.db": "plaintext",
        "profiles/work/state.db": "plaintext",
        "shared-state.db": "plaintext",
        "state.db": "plaintext",
    }


def _expected_journal_mode() -> str:
    import sqlcipher3.dbapi2 as sc

    return "delete" if _migrate.wal_reset_vulnerable(sc.sqlite_version_info) else "wal"


def test_migrate_encrypts_everything_and_keeps_the_data(home: Path) -> None:
    report = _migrate.migrate(home, KEY, arm=dbcrypt.arm, holders_of=_no_holders)

    assert sorted(report.converted) == ["cron/executions.db", "profiles/work/state.db", "shared-state.db", "state.db"]
    for relative in report.converted:
        path = home / relative
        assert not _is_plaintext(path)
        assert b"secret" not in path.read_bytes()
        conn = _keyed(path)
        assert conn.execute("SELECT count(*) FROM messages").fetchone() == (3,)
        assert conn.execute("PRAGMA application_id").fetchone() == (APP_ID,)
        assert conn.execute("PRAGMA user_version").fetchone() == (7,)
        assert conn.execute("PRAGMA journal_mode").fetchone() == (_expected_journal_mode(),)
    fts = _keyed(home / "state.db").execute("SELECT count(*) FROM messages_fts WHERE messages_fts MATCH 'りんご'")
    assert fts.fetchone() == (3,)
    assert _is_plaintext(home / "installs" / "env" / "build.db")  # left alone
    assert dbcrypt.marker_path(home).is_file()
    assert not _migrate.journal_path(home).exists() and not list(home.rglob(f"*{_migrate.PREPARED_SUFFIX}"))


def test_second_run_finds_nothing_to_do(home: Path) -> None:
    _migrate.migrate(home, KEY, arm=dbcrypt.arm, holders_of=_no_holders)
    report = _migrate.migrate(home, KEY, arm=dbcrypt.arm, holders_of=_no_holders)
    assert report.converted == [] and len(report.already_encrypted) == 4


def test_refuses_while_another_process_has_them_open(home: Path) -> None:
    with pytest.raises(_migrate.MigrationError, match="open in other processes"):
        _migrate.migrate(home, KEY, arm=dbcrypt.arm, holders_of=lambda _p: [4242])
    assert _is_plaintext(home / "state.db") and not dbcrypt.marker_path(home).exists()


def test_refuses_when_holders_cannot_be_checked(home: Path) -> None:
    with pytest.raises(_migrate.MigrationError, match="lsof"):
        _migrate.migrate(home, KEY, arm=dbcrypt.arm, holders_of=lambda _p: None)


def test_a_failure_while_preparing_retains_originals_and_recovery(home: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    real = _migrate.prepare
    calls: list[str] = []

    def flaky(database: _migrate.Database, key: _key.DatabaseKey, **kwargs) -> Path:
        calls.append(database.relative)
        if len(calls) == 2:
            raise _migrate.MigrationError("boom")
        return real(database, key, **kwargs)

    monkeypatch.setattr(_migrate, "prepare", flaky)
    with pytest.raises(_migrate.MigrationError, match="boom"):
        _migrate.migrate(home, KEY, arm=dbcrypt.arm, holders_of=_no_holders)
    assert all(_is_plaintext(home / r) for r in ("state.db", "shared-state.db", "cron/executions.db"))
    assert not dbcrypt.marker_path(home).exists()
    assert list(home.rglob(f"*{_migrate.PREPARED_SUFFIX}"))
    assert _migrate.journal_path(home).exists()


def test_a_run_stopped_before_arming_is_completed_and_armed(home: Path, monkeypatch) -> None:
    monkeypatch.setattr(_migrate, "holders", _no_holders)
    """Crash point: the journal is written, the marker not yet; nothing swapped."""

    class Crash(Exception):
        pass

    def crash(_home: Path) -> None:
        raise Crash

    with pytest.raises(Crash):
        _migrate.migrate(home, KEY, arm=crash, holders_of=_no_holders)
    assert _migrate.journal_path(home).is_file() and not dbcrypt.marker_path(home).exists()

    assert _migrate.resume(home) is True
    assert dbcrypt.marker_path(home).is_file()  # encrypted databases in an unarmed home would be unreadable
    assert not _is_plaintext(home / "state.db")
    assert _keyed(home / "state.db").execute("SELECT count(*) FROM messages").fetchone() == (3,)
    assert not _migrate.journal_path(home).exists()


def test_an_interrupted_swap_is_completed(home: Path) -> None:
    database = next(d for d in _migrate.discover(home, KEY) if d.relative == "state.db")
    prepared = _migrate.prepare(database, KEY)
    _migrate.journal_path(home).parent.mkdir(parents=True, exist_ok=True)
    _migrate.journal_path(home).write_text(
        json.dumps({"swaps": [{"path": str(database.path), "prepared": str(prepared)}]}), encoding="utf-8"
    )
    _migrate.journal_path(home).chmod(0o600)
    _migrate.journal_path(home).parent.chmod(0o700)
    dbcrypt.arm(home)  # crash point: armed, not swapped

    _migrate.journal_path(home).chmod(0o600)
    before = database.path.read_bytes()
    with pytest.raises(_migrate.MigrationError, match="legacy journal"):
        _migrate.resume(home)
    assert database.path.read_bytes() == before
    assert prepared.exists() and _migrate.journal_path(home).exists()


def test_a_scheduled_conversion_runs_at_startup_then_the_shim_is_installed(
    home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setitem(sys.modules, "sqlite3", stdlib_sqlite3)
    monkeypatch.setitem(sys.modules, "sqlite3.dbapi2", sys.modules.get("sqlite3.dbapi2", stdlib_sqlite3))
    monkeypatch.setattr(dbcrypt, "sys", policy_sys("darwin"))
    monkeypatch.setattr(_migrate, "holders", _no_holders)
    _migrate.schedule(home)
    provider = _key.KeyProvider(environ={"HERMES_MEMORY_KEY": "hex:" + bytes(range(32)).hex()}, inject=lambda: 0)

    assert dbcrypt.install(home=home, provider=provider) is True
    assert not _is_plaintext(home / "state.db")
    assert not _migrate.pending_path(home).exists()
    import sqlite3

    assert sqlite3.connect(str(home / "state.db")).execute("SELECT count(*) FROM messages").fetchone() == (3,)


def test_without_a_key_the_scheduled_conversion_waits(home: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(sys.modules, "sqlite3", stdlib_sqlite3)
    monkeypatch.setattr(dbcrypt, "sys", policy_sys("darwin"))
    _migrate.schedule(home)
    provider = _key.KeyProvider(environ={}, inject=lambda: 0)

    assert dbcrypt.install(home=home, provider=provider) is False
    assert _is_plaintext(home / "state.db") and _migrate.pending_path(home).exists()
    assert sys.modules["sqlite3"] is stdlib_sqlite3


# -- decrypting back (before uninstalling) ---------------------------------------------


def test_decrypt_all_restores_plain_sqlite_and_disarms(home: Path) -> None:
    _migrate.migrate(home, KEY, arm=dbcrypt.arm, holders_of=_no_holders)
    report = _migrate.decrypt_all(home, KEY, holders_of=_no_holders)

    assert len(report.converted) == 4
    for relative in report.converted:
        conn = stdlib_sqlite3.connect(home / relative)
        assert conn.execute("SELECT count(*) FROM messages").fetchone() == (3,)
        assert conn.execute("PRAGMA application_id").fetchone() == (APP_ID,)
    assert stdlib_sqlite3.connect(home / "state.db").execute(
        "SELECT count(*) FROM messages_fts WHERE messages_fts MATCH 'りんご'"
    ).fetchone() == (3,)
    assert not dbcrypt.marker_path(home).exists() and not _migrate.journal_path(home).exists()


def test_an_interrupted_decryption_is_completed_and_disarmed(home: Path) -> None:
    _migrate.migrate(home, KEY, arm=dbcrypt.arm, holders_of=_no_holders)
    database = next(d for d in _migrate.discover(home, KEY) if d.relative == "state.db")
    prepared = _migrate.prepare_plain(database, KEY)
    _migrate.journal_path(home).write_text(
        json.dumps({"direction": "decrypt", "swaps": [{"path": str(database.path), "prepared": str(prepared)}]}),
        encoding="utf-8",
    )
    _migrate.journal_path(home).chmod(0o600)
    before = database.path.read_bytes()
    with pytest.raises(_migrate.MigrationError, match="legacy journal"):
        _migrate.resume(home)
    assert database.path.read_bytes() == before
    assert prepared.exists() and dbcrypt.marker_path(home).exists()


def test_a_scheduled_decryption_runs_at_startup_and_leaves_sqlite3_alone(
    home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setitem(sys.modules, "sqlite3", stdlib_sqlite3)
    monkeypatch.setattr(dbcrypt, "sys", policy_sys("darwin"))
    monkeypatch.setattr(_migrate, "holders", _no_holders)
    _migrate.migrate(home, KEY, arm=dbcrypt.arm, holders_of=_no_holders)
    _migrate.schedule_decrypt(home)
    provider = _key.KeyProvider(environ={"HERMES_MEMORY_KEY": "hex:" + bytes(range(32)).hex()}, inject=lambda: 0)

    assert dbcrypt.install(home=home, provider=provider) is False
    assert _is_plaintext(home / "state.db") and not _migrate.decrypt_pending_path(home).exists()
    assert sys.modules["sqlite3"] is stdlib_sqlite3


@pytest.mark.parametrize(("vulnerable", "expected"), [(True, "delete"), (False, "wal")])
def test_wal_is_kept_only_where_hermes_would_keep_it(
    home: Path, monkeypatch: pytest.MonkeyPatch, vulnerable: bool, expected: str
) -> None:
    """A SQLCipher build with SQLite's WAL-reset bug gets rollback-journal mode, as Hermes would choose."""
    monkeypatch.setattr(_migrate, "wal_reset_vulnerable", lambda _version: vulnerable)
    _migrate.migrate(home, KEY, arm=dbcrypt.arm, holders_of=_no_holders)
    assert _keyed(home / "state.db").execute("PRAGMA journal_mode").fetchone() == (expected,)


@pytest.mark.parametrize(
    ("version", "vulnerable"),
    [((3, 51, 1), True), ((3, 51, 3), False), ((3, 50, 7), False), ((3, 44, 6), False), ((3, 45, 1), True)],
)
def test_wal_reset_vulnerable_versions(version: tuple[int, int, int], vulnerable: bool) -> None:
    assert _migrate.wal_reset_vulnerable(version) is vulnerable


def test_conversion_keeps_each_files_permissions(home: Path) -> None:
    """state.db is owner-only (0600); the new file must not fall back to the umask (0644)."""
    (home / "state.db").chmod(0o600)
    (home / "shared-state.db").chmod(0o644)
    _migrate.migrate(home, KEY, arm=dbcrypt.arm, holders_of=_no_holders)
    assert (home / "state.db").stat().st_mode & 0o777 == 0o600
    assert (home / "shared-state.db").stat().st_mode & 0o777 == 0o644
    _migrate.decrypt_all(home, KEY, holders_of=_no_holders)
    assert (home / "state.db").stat().st_mode & 0o777 == 0o600


def test_encrypt_with_another_key_does_not_claim_everything_is_encrypted(
    home: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from mordred_hermes.wizard import databases_cli

    _migrate.migrate(home, KEY, arm=dbcrypt.arm, holders_of=_no_holders)
    wrong = _key.derive(bytes(32))
    monkeypatch.setattr(dbcrypt, "sys", policy_sys("darwin"))
    (home / "mordred/memory-vault.marker").write_bytes(b"memory-encryption enabled\n")
    (home / "mordred/memory-vault.marker").chmod(0o600)
    # Offline maintenance authenticates under EX; it never calls KeyProvider.
    monkeypatch.setattr(_migrate, "adopt_legacy", lambda *a, **k: None)
    monkeypatch.setattr(_migrate, "_authenticate", lambda root, supplied, lease: (None, wrong))
    assert databases_cli.databases_encrypt(home=home) == 1
    out = capsys.readouterr()
    assert "unreadable" in out.out + out.err and "state.db" in out.out + out.err
    assert "Every Hermes database is already encrypted" not in out.out


def test_files_that_are_not_sqlite_are_not_listed(home: Path) -> None:
    """Hermes keeps JSON beside state.db (``state.db.repair-attempts.json``); it is not an unreadable database."""
    (home / "state.db.repair-attempts.json").write_text('{"attempts": 1}', encoding="utf-8")
    (home / "empty.db").write_bytes(b"")
    relatives = {d.relative for d in _migrate.discover(home, KEY)}
    assert "state.db.repair-attempts.json" not in relatives and "empty.db" not in relatives
    assert "state.db" in relatives


def test_activity_database_keeps_rollback_even_on_safe_wal_version(home, monkeypatch):
    path = home / "plugin-data/mordred/mordred.db"
    _plain_db(path)
    monkeypatch.setattr(_migrate, "wal_reset_vulnerable", lambda version: False)
    _migrate.migrate(home, KEY, arm=dbcrypt.arm, holders_of=_no_holders)
    conn = _keyed(path)
    assert conn.execute("PRAGMA journal_mode").fetchone() == ("delete",)
    conn.close()


def test_sidecar_cleanup_refuses_foreign_symlink(tmp_path):
    target = tmp_path / "foreign"
    target.write_bytes(b"keep")
    target.chmod(0o600)
    sidecar = tmp_path / "state.db-wal"
    sidecar.symlink_to(target)
    with pytest.raises(_migrate.MigrationError):
        _migrate._cleanup_sidecars(tmp_path / "state.db")
    assert sidecar.is_symlink() and target.read_bytes() == b"keep"


# -- WAL sources: checkpoint before the revision, re-prove before the swap ---------------

#: Run in another process: commit rows that stay only in each database's -wal.
#: ``os._exit`` skips the close, which would otherwise checkpoint them into the main file.
_WAL_WRITER = """
import os, sys

keyed, paths = sys.argv[1] == "keyed", sys.argv[2:]
if keyed:
    import sqlcipher3.dbapi2 as sqlite3
    from mordred_hermes.dbcrypt import _key, _shim
else:
    import sqlite3
held = []
for path in paths:
    conn = sqlite3.connect(path)
    if keyed:
        _shim.apply_key(conn, _key.derive(bytes(range(32))))
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA wal_autocheckpoint = 0")
    conn.executemany("INSERT INTO messages (content) VALUES (?)", [(f"wal only {i}",) for i in range(3)])
    conn.commit()
    held.append(conn)
os._exit(0)
"""


def _wal_only_commits(*paths: Path, keyed: bool = False) -> None:
    subprocess.run(
        [sys.executable, "-c", _WAL_WRITER, "keyed" if keyed else "plain", *map(str, paths)], check=True, timeout=60
    )
    for path in paths:
        assert Path(f"{path}-wal").stat().st_size > 0  # committed frames on disk, not yet checkpointed
        if not keyed:
            assert b"wal only" not in path.read_bytes()


def _wal_size(path: Path) -> int:
    wal = Path(f"{path}-wal")
    return wal.stat().st_size if wal.exists() else 0


def _plain_rows(path: Path) -> list[str]:
    """Read without a read-write close, which would checkpoint (and so change) the file."""
    with closing(stdlib_sqlite3.connect(f"{path.as_uri()}?mode=ro", uri=True)) as conn:
        return [row[0] for row in conn.execute("SELECT content FROM messages ORDER BY id")]


def _journal_files(home: Path) -> list[dict[str, object]]:
    return json.loads(_migrate.journal_path(home).read_bytes())["files"]  # type: ignore[no-any-return]


_BASE_ROWS = [f"secret りんご {i}" for i in range(3)]
_WAL_ROWS = [f"wal only {i}" for i in range(3)]


@pytest.mark.parametrize("decrypting", [False, True], ids=["encrypt", "decrypt"])
def test_a_failed_export_of_a_wal_source_stays_resumable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, decrypting: bool
) -> None:
    """prepare()'s own checkpoint must not stale the recorded revision when the export then fails."""
    base = tmp_path / "hermes"
    path = base / "state.db"
    _plain_db(path)
    if decrypting:
        _migrate.migrate(base, KEY, arm=dbcrypt.arm, holders_of=_no_holders)
    _wal_only_commits(path, keyed=decrypting)

    class ExportFailed(Exception):
        pass

    def fail_mid_export(_version: tuple[int, ...]) -> bool:
        # Called by prepare()/prepare_plain() only after their source checkpoint
        # and sqlcipher_export (WAL sources), like an ENOSPC on the staged copy.
        raise ExportFailed

    real_vulnerable = _migrate.wal_reset_vulnerable
    monkeypatch.setattr(_migrate, "wal_reset_vulnerable", fail_mid_export)
    with pytest.raises(ExportFailed):
        if decrypting:
            _migrate.decrypt_all(base, KEY, holders_of=_no_holders)
        else:
            _migrate.migrate(base, KEY, arm=dbcrypt.arm, holders_of=_no_holders)

    (entry,) = _journal_files(base)
    assert entry["phase"] == "prepared"
    # The journal recorded the checkpointed file, which is what the failed export left.
    assert entry["source_revision"] == _migrate._revision(path)
    assert _wal_size(path) == 0
    if not decrypting:
        assert b"wal only" in path.read_bytes()

    monkeypatch.setattr(_migrate, "wal_reset_vulnerable", real_vulnerable)
    name = "prepare_plain" if decrypting else "prepare"
    real_prepare = getattr(_migrate, name)
    revisions: list[tuple[list[int], list[int]]] = []

    def recording(database: _migrate.Database, key: _key.DatabaseKey, **kwargs: object) -> Path:
        before = _migrate._revision(database.path)
        staged = real_prepare(database, key, **kwargs)
        revisions.append((before, _migrate._revision(database.path)))
        return staged  # type: ignore[no-any-return]

    monkeypatch.setattr(_migrate, name, recording)
    assert _migrate.resume(base, holders_of=_no_holders) is True

    # prepare()'s TRUNCATE checkpoint is now a no-op on the main file.
    assert revisions == [(entry["source_revision"], entry["source_revision"])]
    assert not _migrate.journal_path(base).exists()
    if decrypting:
        assert _plain_rows(path) == _BASE_ROWS + _WAL_ROWS
        assert not dbcrypt.marker_path(base).exists()
    else:
        assert not _is_plaintext(path) and b"wal only" not in path.read_bytes()
        rows = _keyed(path).execute("SELECT content FROM messages ORDER BY id").fetchall()
        assert [row[0] for row in rows] == _BASE_ROWS + _WAL_ROWS
        assert dbcrypt.marker_path(base).is_file()


def test_a_source_changed_after_its_revision_was_recorded_refuses(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Checkpointing first must not weaken the proof: a later committed write still refuses."""
    base = tmp_path / "hermes"
    path = base / "state.db"
    _plain_db(path)
    _wal_only_commits(path)

    class Crash(Exception):
        pass

    def crash(phase: str) -> None:
        if phase == "prepared":
            raise Crash

    monkeypatch.setattr(_migrate, "_transition", crash)
    with pytest.raises(Crash):
        _migrate.migrate(base, KEY, arm=dbcrypt.arm, holders_of=_no_holders)
    monkeypatch.setattr(_migrate, "_transition", lambda phase: None)
    with closing(stdlib_sqlite3.connect(path)) as conn:  # a closed writer; its close checkpoints
        conn.execute("UPDATE messages SET content = 'later committed writer'")
        conn.commit()
    assert _wal_size(path) == 0
    before = path.read_bytes()
    with pytest.raises(_migrate.MigrationError, match="unprepared source"):
        _migrate.resume(base, holders_of=_no_holders)
    assert path.read_bytes() == before and not dbcrypt.marker_path(base).exists()
    assert _migrate.journal_path(base).exists()


_SOURCES = ("shared-state.db", "state.db", "cron/executions.db", "profiles/work/state.db")


def test_a_holder_that_appears_before_the_swap_refuses_and_stays_recoverable(
    home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    armed: list[str] = []
    asked: list[list[Path]] = []

    def transition(phase: str) -> None:
        if phase == "armed":
            armed.append(phase)

    def late_holder(paths: list[Path]) -> list[int]:
        if not armed:
            return []
        asked.append(sorted(paths))
        return [4242]

    monkeypatch.setattr(_migrate, "_transition", transition)
    with pytest.raises(_migrate.MigrationError, match="open in other processes"):
        _migrate.migrate(home, KEY, arm=dbcrypt.arm, holders_of=late_holder)

    first = _journal_files(home)[0]["relative"]
    assert isinstance(first, str)
    assert asked == [sorted([home / first, home / (first + _migrate.PREPARED_SUFFIX)])]
    assert {entry["phase"] for entry in _journal_files(home)} == {"armed"}
    for relative in _SOURCES:
        assert _plain_rows(home / relative) == _BASE_ROWS
        assert Path(f"{home / relative}{_migrate.PREPARED_SUFFIX}").is_file()

    # The resume() route carries the same guard.
    armed.clear()
    with pytest.raises(_migrate.MigrationError, match="open in other processes"):
        _migrate.resume(home, holders_of=late_holder)
    assert all(_plain_rows(home / relative) == _BASE_ROWS for relative in _SOURCES)

    # Once the holder is gone the journal completes.
    assert _migrate.resume(home, holders_of=_no_holders) is True
    assert not _migrate.journal_path(home).exists() and dbcrypt.marker_path(home).is_file()
    for relative in _SOURCES:
        assert not _is_plaintext(home / relative)
        assert _keyed(home / relative).execute("SELECT count(*) FROM messages").fetchone() == (3,)


def test_a_wal_commit_after_export_refuses_the_swap_and_keeps_it(home: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A lease-less writer that committed into -wal and exited is invisible to holder scans."""
    sources = [home / relative for relative in _SOURCES]

    def foreign_commit(phase: str) -> None:
        if phase == "armed":
            _wal_only_commits(*sources)

    monkeypatch.setattr(_migrate, "_transition", foreign_commit)
    with pytest.raises(_migrate.MigrationError, match="WAL commits"):
        _migrate.migrate(home, KEY, arm=dbcrypt.arm, holders_of=_no_holders)
    monkeypatch.setattr(_migrate, "_transition", lambda phase: None)

    def state() -> dict[Path, tuple[bytes, bytes, bytes]]:
        return {
            path: (
                path.read_bytes(),
                Path(f"{path}-wal").read_bytes(),
                Path(f"{path}{_migrate.PREPARED_SUFFIX}").read_bytes(),
            )
            for path in sources
        }

    before = state()
    assert {(entry["phase"], entry["wal_checkpointed"]) for entry in _journal_files(home)} == {("armed", True)}
    # Recovery refuses the same way and never discards the commits.
    with pytest.raises(_migrate.MigrationError, match="WAL commits"):
        _migrate.resume(home, holders_of=_no_holders)
    assert state() == before and _migrate.journal_path(home).exists()
    for path in sources:
        assert _plain_rows(path) == _BASE_ROWS + _WAL_ROWS


@pytest.mark.parametrize("proof", [False, True], ids=["restore-entry", "conversion-entry"])
def test_the_swap_guards_wal_content_only_after_an_export_truncated_it(tmp_path: Path, proof: bool) -> None:
    """Every swap re-checks holders. Only conversion entries (prepare() emptied the WAL) also
    refuse WAL content: dbcrypt._backup restore entries replace the destination by design."""
    root = tmp_path / "hermes"
    path = root / "state.db"
    _plain_db(path)
    _wal_only_commits(path)  # e.g. frames a killed runtime left behind
    staged = Path(f"{path}{_migrate.PREPARED_SUFFIX}")
    _plain_db(staged, rows=1)
    entry: dict[str, object] = {
        "relative": "state.db",
        "prepared": "state.db" + _migrate.PREPARED_SUFFIX,
        "source_identity": _migrate._file_identity(path),
        "source_revision": _migrate._revision(path),
        "prepared_identity": _migrate._file_identity(staged),
    }
    if proof:
        entry["wal_checkpointed"] = True
    with pytest.raises(_migrate.MigrationError, match="open in other processes"):
        _migrate._replace_swap(root, entry, lambda _paths: [4242])
    assert staged.exists() and _wal_size(path) > 0
    if proof:
        with pytest.raises(_migrate.MigrationError, match="WAL commits"):
            _migrate._replace_swap(root, entry, _no_holders)
        assert staged.exists() and _plain_rows(path) == _BASE_ROWS + _WAL_ROWS
    else:
        _migrate._replace_swap(root, entry, _no_holders)
        assert not staged.exists() and not Path(f"{path}-wal").exists()
        assert _plain_rows(path) == _BASE_ROWS[:1]
