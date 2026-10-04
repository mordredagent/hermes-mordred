"""SQLCipher database encryption (mordred_hermes.dbcrypt)."""

from __future__ import annotations

import shutil
import sqlite3 as stdlib_sqlite3
import struct
import sys
from pathlib import Path

import pytest

from mordred_hermes import dbcrypt
from mordred_hermes.dbcrypt import _key, _policy, _shim

MEMORY_KEY = bytes(range(32))


# -- which files ------------------------------------------------------------------


@pytest.mark.parametrize(
    ("relative", "expected"),
    [
        ("state.db", True),
        ("shared-state.db", True),
        ("cron/executions.db", True),
        ("telemetry/shared_metrics/metrics.sqlite3", True),
        ("state.db.pre-update-emergency-2026-10-03T17-23-09Z-1.bak", True),
        ("profiles/work/state.db", True),
        ("profiles/work/cron/deliveries.db", True),
        ("state.db-wal", False),
        ("state.db-shm", False),
        ("state.db.quarantine.lock", False),
        ("config.yaml", False),
        ("installs/abc/build.db", False),
        ("hermes-agent/x.db", False),
        ("mcp-installs/server/data.sqlite", False),
        ("skills/foo/notes.db", False),
        ("profiles/work/installs/x.db", False),
        ("mordred/vault/manifest.db", False),
    ],
)
def test_scope(tmp_path: Path, relative: str, expected: bool) -> None:
    assert _policy.in_scope(tmp_path / relative, tmp_path) is expected


def test_nothing_outside_the_hermes_home_is_in_scope(tmp_path: Path) -> None:
    assert not _policy.in_scope(tmp_path / "project" / "app.db", tmp_path / "home")


def test_a_profile_process_also_keys_the_root_homes_databases(tmp_path: Path) -> None:
    profile = tmp_path / "profiles" / "work"
    assert _policy.in_scope(tmp_path / "shared-state.db", profile)
    assert _policy.in_scope(profile / "state.db", profile)


@pytest.mark.parametrize(
    ("database", "uri", "expected"),
    [
        (":memory:", False, None),
        ("", False, None),
        ("/x/state.db", False, "/x/state.db"),
        (Path("/x/state.db"), False, "/x/state.db"),
        (b"/x/state.db", False, "/x/state.db"),
        ("file:///x/state.db?mode=ro", True, "/x/state.db"),
        ("file:/x/a%20b.db?mode=ro", True, "/x/a b.db"),
        ("file:mem?mode=memory&cache=shared", True, None),
    ],
)
def test_database_path(database: object, uri: bool, expected: str | None) -> None:
    assert _shim._database_path(database, uri) == expected


# -- the key ----------------------------------------------------------------------


def test_key_is_derived_not_stored() -> None:
    first, again = _key.derive(MEMORY_KEY), _key.derive(MEMORY_KEY)
    assert first == again and len(first.key) == 32 and len(first.salt) == 16
    assert first.key != MEMORY_KEY
    assert "redacted" in repr(first) and MEMORY_KEY.hex() not in repr(first)


def test_provider_injects_the_vault_env_once() -> None:
    environ: dict[str, str] = {}
    calls: list[int] = []

    def inject() -> int:
        calls.append(1)
        environ["HERMES_MEMORY_KEY"] = "hex:" + MEMORY_KEY.hex()
        return 1

    provider = _key.KeyProvider(environ=environ, inject=inject)
    assert provider() == _key.derive(MEMORY_KEY)
    assert provider() == _key.derive(MEMORY_KEY)
    assert calls == [1]


def test_provider_without_a_key_returns_none_after_one_injection() -> None:
    calls: list[int] = []
    provider = _key.KeyProvider(environ={}, inject=lambda: calls.append(1) or 0)
    assert provider() is None and provider() is None
    assert calls == [1]


# -- the sqlite3 replacement (real SQLCipher) ------------------------------------------


@pytest.fixture
def sqlcipher(tmp_path: Path) -> object:
    pytest.importorskip("sqlcipher3")
    home = tmp_path / "home"
    home.mkdir()
    key = _key.derive(MEMORY_KEY)
    state = {"key": key}
    module = _shim.build_module(key=lambda: state["key"], home=lambda: home, has_key=lambda: True)
    return type("Env", (), {"module": module, "home": home, "state": state, "key": key})


def test_hermes_databases_are_created_encrypted(sqlcipher: object) -> None:
    sq, home = sqlcipher.module, sqlcipher.home  # type: ignore[attr-defined]
    path = home / "state.db"
    conn = sq.connect(str(path))
    conn.execute("PRAGMA application_id = 682968903")
    conn.execute("CREATE TABLE messages (content TEXT)")
    conn.execute("CREATE VIRTUAL TABLE messages_fts USING fts5(content, tokenize='trigram')")
    conn.execute("INSERT INTO messages VALUES ('secret りんご')")
    conn.execute("INSERT INTO messages_fts VALUES ('secret りんご')")
    conn.commit()
    conn.close()

    raw = path.read_bytes()
    assert raw[:16] == _shim.SQLITE_MAGIC  # Hermes's header probes still work
    assert struct.unpack(">I", raw[68:72])[0] == 682968903
    assert b"secret" not in raw and "りんご".encode() not in raw
    with pytest.raises((stdlib_sqlite3.DatabaseError, UnicodeDecodeError)):
        stdlib_sqlite3.connect(str(path)).execute("SELECT * FROM messages").fetchall()

    again = sq.connect(f"file:{path}?mode=ro", uri=True)
    assert again.execute("SELECT content FROM messages").fetchone() == ("secret りんご",)
    assert again.execute("SELECT count(*) FROM messages_fts WHERE messages_fts MATCH 'りんご'").fetchone() == (1,)


def test_types_and_constants_match_what_hermes_uses(sqlcipher: object) -> None:
    sq = sqlcipher.module  # type: ignore[attr-defined]
    for name in (
        "Connection",
        "Cursor",
        "Row",
        "Error",
        "DatabaseError",
        "OperationalError",
        "IntegrityError",
        "SQLITE_BUSY",
        "SQLITE_CONSTRAINT_FOREIGNKEY",
        "SQLITE_LIMIT_VARIABLE_NUMBER",
        "sqlite_version",
        "complete_statement",
    ):
        assert hasattr(sq, name), name
    assert sq.dbapi2 is sq and getattr(sq, _shim.MARKER)
    conn = sq.connect(":memory:")
    with pytest.raises(sq.OperationalError):
        conn.execute("SELECT * FROM nope")


def test_a_backup_staged_outside_the_home_is_encrypted_not_refused(sqlcipher: object, tmp_path: Path) -> None:
    """``hermes backup`` stages each database next to the zip with ``Connection.backup()``.

    SQLCipher refuses to back an encrypted database up into a plaintext one, so
    the new destination gets the source's key (and stays readable as a copy).
    """
    import tempfile

    sq, home = sqlcipher.module, sqlcipher.home  # type: ignore[attr-defined]
    source = sq.connect(str(home / "state.db"))
    source.execute("CREATE TABLE t (a)")
    source.execute("INSERT INTO t VALUES ('secret')")
    source.commit()
    outside = tmp_path / "backups"
    outside.mkdir()
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False, dir=outside) as tmp:  # exists, 0 bytes
        staged = Path(tmp.name)
    reader = sq.connect(f"{(home / 'state.db').resolve().as_uri()}?mode=ro", uri=True, timeout=0.0)
    target = sq.connect(str(staged))
    reader.backup(target, pages=256)
    target.close()

    assert b"secret" not in staged.read_bytes()
    assert sq.connect(str(staged)).execute("SELECT a FROM t").fetchall() == [("secret",)]
    plain = sq.connect(str(outside / "plain.db"))  # unrelated databases stay plaintext
    plain.execute("CREATE TABLE p (a)")
    plain.commit()
    assert stdlib_sqlite3.connect(str(outside / "plain.db")).execute("SELECT * FROM p").fetchall() == []


def test_other_databases_stay_plain(sqlcipher: object, tmp_path: Path) -> None:
    sq = sqlcipher.module  # type: ignore[attr-defined]
    elsewhere = tmp_path / "project" / "app.db"
    elsewhere.parent.mkdir()
    conn = sq.connect(str(elsewhere))
    conn.execute("CREATE TABLE t (a)")
    conn.commit()
    conn.close()
    assert stdlib_sqlite3.connect(str(elsewhere)).execute("SELECT count(*) FROM t").fetchone() == (0,)


def test_an_encrypted_copy_outside_the_home_is_still_readable(sqlcipher: object, tmp_path: Path) -> None:
    sq, home = sqlcipher.module, sqlcipher.home  # type: ignore[attr-defined]
    conn = sq.connect(str(home / "kanban.db"))
    conn.execute("CREATE TABLE tasks (title TEXT)")
    conn.execute("INSERT INTO tasks VALUES ('x')")
    conn.commit()
    conn.close()
    staged = tmp_path / "export" / "kanban.db"
    staged.parent.mkdir()
    shutil.copy(home / "kanban.db", staged)
    assert sq.connect(str(staged)).execute("SELECT title FROM tasks").fetchone() == ("x",)


def test_without_the_key_hermes_databases_are_refused_not_created(sqlcipher: object) -> None:
    sq, home = sqlcipher.module, sqlcipher.home  # type: ignore[attr-defined]
    sqlcipher.state["key"] = None  # type: ignore[attr-defined]
    with pytest.raises(sq.OperationalError, match="encrypted"):
        sq.connect(str(home / "state.db"))
    assert not (home / "state.db").exists()


def test_a_plaintext_hermes_database_is_not_silently_opened(sqlcipher: object) -> None:
    sq, home = sqlcipher.module, sqlcipher.home  # type: ignore[attr-defined]
    plain = stdlib_sqlite3.connect(str(home / "state.db"))
    plain.execute("CREATE TABLE t (a)")
    plain.commit()
    plain.close()
    with pytest.raises((sq.DatabaseError, UnicodeDecodeError)):
        sq.connect(str(home / "state.db")).execute("SELECT * FROM t").fetchall()


def test_a_database_the_key_does_not_open_is_refused_at_connect(sqlcipher: object) -> None:
    """Another key (or a plaintext file) is refused up front with a clear error, file untouched.

    Otherwise Hermes sees "SQL logic error" or MemoryError on its first query.
    """
    sq, home, state = sqlcipher.module, sqlcipher.home, sqlcipher.state  # type: ignore[attr-defined]
    conn = sq.connect(str(home / "state.db"))
    conn.execute("CREATE TABLE t (a)")
    conn.commit()
    conn.close()
    plain = stdlib_sqlite3.connect(home / "kanban.db")
    plain.execute("CREATE TABLE k (a)")
    plain.commit()
    plain.close()
    before = {p.name: p.read_bytes() for p in home.iterdir()}

    state["key"] = _key.derive(bytes(32))  # a different memory key
    for name in ("state.db", "kanban.db"):
        with pytest.raises(sq.OperationalError, match="does not open"):
            sq.connect(str(home / name))
    assert {p.name: p.read_bytes() for p in home.iterdir()} == before
    sq.connect(str(home / "new.db")).execute("CREATE TABLE n (a)")  # a new database is still created


# -- arming -----------------------------------------------------------------------


def test_install_does_nothing_unless_armed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(sys.modules, "sqlite3", stdlib_sqlite3)
    monkeypatch.setattr(sys, "platform", "darwin")
    assert dbcrypt.install(home=tmp_path) is False
    assert sys.modules["sqlite3"] is stdlib_sqlite3


def test_install_swaps_sqlite3_when_armed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    pytest.importorskip("sqlcipher3")
    monkeypatch.setitem(sys.modules, "sqlite3", stdlib_sqlite3)
    monkeypatch.setitem(sys.modules, "sqlite3.dbapi2", sys.modules.get("sqlite3.dbapi2", stdlib_sqlite3))
    monkeypatch.setattr(sys, "platform", "darwin")
    dbcrypt.marker_path(tmp_path).parent.mkdir(parents=True)
    dbcrypt.marker_path(tmp_path).write_text("1")
    provider = _key.KeyProvider(environ={"HERMES_MEMORY_KEY": "hex:" + MEMORY_KEY.hex()}, inject=lambda: 0)

    assert dbcrypt.install(home=tmp_path, provider=provider) is True
    assert dbcrypt.is_installed()
    import sqlite3  # resolves to the replacement now

    assert getattr(sqlite3, _shim.MARKER)
    sqlite3.connect(str(tmp_path / "state.db")).execute("CREATE TABLE t (a)")
    assert b"CREATE TABLE" not in (tmp_path / "state.db").read_bytes()


def test_a_process_started_in_a_profile_home_uses_the_roots_marker(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Hermes starts gateways, Desktop chats and kanban workers with HERMES_HOME=<root>/profiles/<name>."""
    pytest.importorskip("sqlcipher3")
    from mordred_hermes import _home

    monkeypatch.setitem(sys.modules, "sqlite3", stdlib_sqlite3)
    monkeypatch.setitem(sys.modules, "sqlite3.dbapi2", sys.modules.get("sqlite3.dbapi2", stdlib_sqlite3))
    monkeypatch.setattr(sys, "platform", "darwin")
    profile = tmp_path / "profiles" / "work"
    profile.mkdir(parents=True)
    dbcrypt.arm(tmp_path)
    monkeypatch.setattr(_home, "hermes_home", lambda: profile)
    assert dbcrypt.root_home(profile) == tmp_path.resolve()
    assert dbcrypt.armed()
    provider = _key.KeyProvider(environ={"HERMES_MEMORY_KEY": "hex:" + MEMORY_KEY.hex()}, inject=lambda: 0)

    assert dbcrypt.install(provider=provider) is True
    import sqlite3

    sqlite3.connect(str(profile / "state.db")).execute("CREATE TABLE t (a)")
    with pytest.raises((stdlib_sqlite3.DatabaseError, UnicodeDecodeError)):
        stdlib_sqlite3.connect(str(profile / "state.db")).execute("SELECT * FROM t").fetchall()


def test_install_is_a_noop_off_macos(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(sys.modules, "sqlite3", stdlib_sqlite3)
    monkeypatch.setattr(sys, "platform", "linux")
    dbcrypt.marker_path(tmp_path).parent.mkdir(parents=True)
    dbcrypt.marker_path(tmp_path).write_text("1")
    assert dbcrypt.install(home=tmp_path) is False


# -- the vault env is unlocked once per process ------------------------------------------


def test_vault_env_injection_runs_once_per_process(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    from mordred_hermes.keyvault import _runtime_env

    calls: list[int] = []
    monkeypatch.setattr(sys, "platform", "darwin")
    monkeypatch.setattr(_runtime_env, "_INJECTED_INTO_OS_ENVIRON", False)
    monkeypatch.setattr(_runtime_env, "_hermes_home", lambda: tmp_path)
    monkeypatch.setattr(_runtime_env, "inject_vault_env", lambda **_k: calls.append(1) or 2)
    assert _runtime_env.install_vault_env_decrypt() == 2
    assert _runtime_env.install_vault_env_decrypt() == 0
    assert _runtime_env.install_vault_env_decrypt(environ={}) == 2  # explicit targets always run
    assert calls == [1, 1]
