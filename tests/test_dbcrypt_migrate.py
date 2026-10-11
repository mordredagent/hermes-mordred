"""Converting an existing Hermes home's databases to SQLCipher (dbcrypt._migrate)."""

from __future__ import annotations

import json
import sqlite3 as stdlib_sqlite3
import sys
from pathlib import Path

import pytest

pytest.importorskip("sqlcipher3")

from mordred_hermes import dbcrypt
from mordred_hermes.dbcrypt import _key, _migrate, _shim

KEY = _key.derive(bytes(range(32)))
APP_ID = 682968903


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


def test_a_failure_while_preparing_changes_nothing(home: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    real = _migrate.prepare
    calls: list[str] = []

    def flaky(database: _migrate.Database, key: _key.DatabaseKey) -> Path:
        calls.append(database.relative)
        if len(calls) == 2:
            raise _migrate.MigrationError("boom")
        return real(database, key)

    monkeypatch.setattr(_migrate, "prepare", flaky)
    with pytest.raises(_migrate.MigrationError, match="boom"):
        _migrate.migrate(home, KEY, arm=dbcrypt.arm, holders_of=_no_holders)
    assert all(_is_plaintext(home / r) for r in ("state.db", "shared-state.db", "cron/executions.db"))
    assert not dbcrypt.marker_path(home).exists()
    assert not list(home.rglob(f"*{_migrate.PREPARED_SUFFIX}"))


def test_a_run_stopped_before_arming_is_completed_and_armed(home: Path) -> None:
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
    dbcrypt.arm(home)  # crash point: armed, not swapped

    assert _migrate.resume(home) is True
    assert not _is_plaintext(home / "state.db")
    assert _keyed(home / "state.db").execute("SELECT count(*) FROM messages").fetchone() == (3,)
    assert not _migrate.journal_path(home).exists()


def test_a_scheduled_conversion_runs_at_startup_then_the_shim_is_installed(
    home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setitem(sys.modules, "sqlite3", stdlib_sqlite3)
    monkeypatch.setitem(sys.modules, "sqlite3.dbapi2", sys.modules.get("sqlite3.dbapi2", stdlib_sqlite3))
    monkeypatch.setattr(sys, "platform", "darwin")
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
    monkeypatch.setattr(sys, "platform", "darwin")
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
    assert _migrate.resume(home) is True
    assert _is_plaintext(home / "state.db") and not dbcrypt.marker_path(home).exists()


def test_a_scheduled_decryption_runs_at_startup_and_leaves_sqlite3_alone(
    home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setitem(sys.modules, "sqlite3", stdlib_sqlite3)
    monkeypatch.setattr(sys, "platform", "darwin")
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
    monkeypatch.setattr(sys, "platform", "darwin")
    monkeypatch.setattr(_key, "KeyProvider", lambda: lambda: wrong)
    assert databases_cli.databases_encrypt(home=home) == 0
    out = capsys.readouterr()
    assert "does not open" in out.out + out.err and "state.db" in out.out + out.err
    assert "Every Hermes database is already encrypted" not in out.out


def test_files_that_are_not_sqlite_are_not_listed(home: Path) -> None:
    """Hermes keeps JSON beside state.db (``state.db.repair-attempts.json``); it is not an unreadable database."""
    (home / "state.db.repair-attempts.json").write_text('{"attempts": 1}', encoding="utf-8")
    (home / "empty.db").write_bytes(b"")
    relatives = {d.relative for d in _migrate.discover(home, KEY)}
    assert "state.db.repair-attempts.json" not in relatives and "empty.db" not in relatives
    assert "state.db" in relatives
