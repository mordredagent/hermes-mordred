"""Real SQLCipher admission, held-object revocation and same-library monitoring."""

from __future__ import annotations

import gc
import os
import subprocess
import sys
import weakref

import pytest
import sqlcipher3.dbapi2 as sc

from mordred_hermes._database_contracts import DatabaseRefused
from mordred_hermes.dbcrypt._authority import Authority
from mordred_hermes.dbcrypt._key import derive
from mordred_hermes.dbcrypt._shim import apply_key
from tests.test_dbcrypt_authority import native_root as _native_root

native_root = _native_root


@pytest.fixture
def authority(native_root):
    value = Authority.acquire(native_root[0])
    yield value
    value.close()


def opener():
    from mordred_hermes.dbcrypt._connection import open_protected

    return open_protected


def raw_rows(path, key):
    conn = sc.connect(str(path))
    try:
        apply_key(conn, key)
        return conn.execute("SELECT value FROM records ORDER BY value").fetchall()
    finally:
        conn.close()


@pytest.mark.parametrize(
    "surface",
    [
        "execute",
        "executemany",
        "executescript",
        "cursor_execute",
        "fetchone",
        "fetchmany",
        "fetchall",
        "next",
        "commit",
        "exit",
        "isolation_level",
        "backup",
        "blob",
        "serialize",
        "iterdump",
        "authorizer",
        "extension",
        "cursor",
        "cursor_close",
        "rollback",
        "autocommit",
        "row_factory",
        "cursor_executemany",
        "cursor_executescript",
        "arraysize",
        "description",
        "total_changes",
    ],
)
def test_every_held_sql_surface_revalidates(native_root, authority, surface):
    root, _, material, _ = native_root
    path = root / "state.db"
    conn = opener()(path, authority=authority)
    conn.execute("CREATE TABLE records(value)")
    conn.execute("INSERT INTO records VALUES (1)")
    conn.commit()
    conn.execute("INSERT INTO records VALUES (2)")
    cursor = conn.execute("SELECT value FROM records ORDER BY value")
    assert cursor.connection is conn
    operations = {
        "execute": lambda: conn.execute("INSERT INTO records VALUES (3)"),
        "executemany": lambda: conn.executemany("INSERT INTO records VALUES (?)", [(3,)]),
        "executescript": lambda: conn.executescript("INSERT INTO records VALUES (3);"),
        "cursor_execute": lambda: cursor.execute("INSERT INTO records VALUES (3)"),
        "fetchone": cursor.fetchone,
        "fetchmany": cursor.fetchmany,
        "fetchall": cursor.fetchall,
        "next": lambda: next(iter(cursor)),
        "commit": conn.commit,
        "exit": lambda: conn.__exit__(None, None, None),
        "isolation_level": lambda: setattr(conn, "isolation_level", None),
        "backup": lambda: conn.backup(conn),
        "blob": lambda: conn.open_blob("records", "value", 1),
        "serialize": lambda: conn.serialize(),
        "iterdump": lambda: next(conn.iterdump()),
        "authorizer": lambda: conn.set_authorizer(None),
        "extension": lambda: conn.enable_load_extension(True),
        "cursor": conn.cursor,
        "cursor_close": cursor.close,
        "rollback": conn.rollback,
        "autocommit": lambda: setattr(conn, "autocommit", True),
        "row_factory": lambda: setattr(conn, "row_factory", sc.Row),
        "cursor_executemany": lambda: cursor.executemany("INSERT INTO records VALUES (?)", [(3,)]),
        "cursor_executescript": lambda: cursor.executescript("INSERT INTO records VALUES (3);"),
        "arraysize": lambda: setattr(cursor, "arraysize", 5),
        "description": lambda: cursor.description,
        "total_changes": lambda: conn.total_changes,
    }
    (root / "mordred/db-encryption.marker").unlink()
    with pytest.raises(DatabaseRefused):
        operations[surface]()
    assert authority.terminal
    assert raw_rows(path, derive(material)) == [(1,)]
    with pytest.raises(DatabaseRefused):
        cursor.fetchone()
    conn.close()


@pytest.mark.parametrize(
    "sql",
    [
        "ATTACH DATABASE ':memory:' AS other",
        "VACUUM INTO 'escape.db'",
        "PRAGMA key='wrong'",
        "PRAGMA writable_schema=ON",
        "SELECT load_extension('x')",
        "PRAGMA cipher_plaintext_header_size=0",
        "SELECT sqlcipher_export('main')",
    ],
)
def test_dangerous_sql_refused_before_io(native_root, authority, sql):
    conn = opener()(native_root[0] / "state.db", authority=authority)
    with pytest.raises(DatabaseRefused):
        conn.execute(sql)
    conn.close()


def test_wrong_key_no_recreate(native_root, authority):
    path = native_root[0] / "state.db"
    conn = sc.connect(str(path))
    apply_key(conn, derive(b"x" * 32))
    conn.execute("CREATE TABLE secret(value)")
    conn.commit()
    conn.close()
    before = path.stat(), path.read_bytes()
    with pytest.raises(DatabaseRefused):
        opener()(path, authority=authority)
    after = path.stat(), path.read_bytes()
    assert (after[0].st_dev, after[0].st_ino, after[1]) == (before[0].st_dev, before[0].st_ino, before[1])


def test_plaintext_under_marker_no_replacement(native_root, authority):
    path = native_root[0] / "state.db"
    conn = sc.connect(str(path))
    conn.execute("CREATE TABLE secret(value)")
    conn.commit()
    conn.close()
    before = path.read_bytes()
    with pytest.raises(DatabaseRefused):
        opener()(path, authority=authority)
    assert path.read_bytes() == before
    assert not list(path.parent.glob("*.corrupt*"))


def native_module(authority):
    from mordred_hermes.dbcrypt._shim import build_module

    return build_module(authority=authority)


@pytest.mark.parametrize("factory", [sc.Connection, lambda *a, **kw: sc.connect(*a, **kw)])
def test_factory_cannot_bypass_authority(native_root, authority, factory):
    path = native_root[0] / "state.db"
    with pytest.raises(DatabaseRefused):
        native_module(authority).connect(path, factory=factory)
    assert not path.exists()


@pytest.mark.parametrize("query", ["immutable=1", "nolock=1", "vfs=unix-none", "mode=memory", "cache=shared"])
def test_unsafe_uri_options_refused(native_root, authority, query):
    path = native_root[0] / "state.db"
    with pytest.raises(DatabaseRefused):
        native_module(authority).connect(f"file:{path}?{query}", uri=True)
    assert not path.exists()


def test_native_backup_detection_ignores_environment(native_root, authority, monkeypatch, tmp_path):
    monkeypatch.delenv("HERMES_MEMORY_KEY", raising=False)
    path = native_root[0] / "state.db"
    conn = opener()(path, authority=authority)
    conn.execute("CREATE TABLE records(value)")
    conn.commit()
    conn.close()
    foreign = tmp_path.parent / (tmp_path.name + "-foreign.db")
    foreign.write_bytes(path.read_bytes())
    try:
        with pytest.raises(DatabaseRefused):
            native_module(authority).connect(foreign)
    finally:
        foreign.unlink()


@pytest.mark.parametrize("replace", ["database", "profile", "directory"])
def test_held_path_identity_rechecked(native_root, authority, replace):
    root = native_root[0]
    directory = root / "profiles/work/cron"
    directory.mkdir(mode=0o700)
    path = directory / "executions.db"
    conn = opener()(path, authority=authority)
    cursor = conn.execute("SELECT 1")
    replaced = {"database": path, "profile": directory.parent, "directory": directory}[replace]
    replaced.rename(replaced.with_name(replaced.name + "-old"))
    if replace == "database":
        path.touch()
    else:
        replaced.mkdir(mode=0o700)
    with pytest.raises(DatabaseRefused):
        cursor.fetchone()
    assert authority.terminal


def test_close_unregisters_connection(native_root, authority):
    conn = opener()(native_root[0] / "state.db", authority=authority)
    ref = weakref.ref(conn)
    conn.close()
    del conn
    gc.collect()
    assert ref() is None
    authority.check()


def test_monitor_preserves_other_connection_locks(native_root, authority):
    from mordred_hermes.dbcrypt._monitor import monitor_runtime

    root, _, material, _ = native_root
    path = root / "state.db"
    conn = opener()(path, authority=authority)
    conn.execute("CREATE TABLE records(value)")
    conn.commit()
    conn.execute("BEGIN IMMEDIATE")
    conn.execute("INSERT INTO records VALUES (2)")
    assert monitor_runtime(authority) == ()
    code = """import sys
import sqlcipher3.dbapi2 as sc
from mordred_hermes.dbcrypt._key import derive
from mordred_hermes.dbcrypt._shim import apply_key
c = sc.connect(sys.argv[1], timeout=0)
apply_key(c, derive(bytes.fromhex(sys.argv[2])))
try:
 c.execute('BEGIN IMMEDIATE')
except sc.OperationalError as e:
 print('blocked' if 'locked' in str(e) else str(e))
else:
 print('UNLOCKED')
finally:
 c.close()
"""
    result = subprocess.run(
        [sys.executable, "-c", code, str(path), material.hex()],
        capture_output=True,
        text=True,
        env={**os.environ, "HERMES_HOME": str(root)},
        timeout=20,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "blocked"
    conn.rollback()
    conn.close()


def test_native_install_owns_one_guarded_authority(native_root, monkeypatch):
    from mordred_hermes import dbcrypt
    from mordred_hermes.dbcrypt import _hooks, _shim

    root, backend, _, _ = native_root
    monkeypatch.setattr(dbcrypt.sys, "platform", "darwin")
    monkeypatch.setattr(dbcrypt.sys, "argv", ["hermes"])
    monkeypatch.setattr(dbcrypt, "_PROVIDER", None)
    installed = []
    monkeypatch.setattr(_shim, "install_module", installed.append)
    monkeypatch.setenv("HERMES_MEMORY_KEY", "hex:" + "aa" * 32)
    assert dbcrypt.install(home=root)
    try:
        conn = installed[0].connect(root / "state.db")
        conn.execute("CREATE TABLE records(value)")
        conn.commit()
        assert _hooks._findings() == []
        assert sum(op == "ecdh" for op, _ in backend.calls) == 1
        (root / "mordred/db-encryption.marker").unlink()
        assert _hooks._findings()[0].violation
        with pytest.raises(DatabaseRefused):
            conn.execute("SELECT 1")
    finally:
        dbcrypt._PROVIDER.close()


def test_row_factory_receives_only_guarded_cursor(native_root, authority):
    conn = opener()(native_root[0] / "state.db", authority=authority)
    received = []

    def row(cursor, values):
        received.append(cursor.connection)
        return values

    conn.row_factory = row
    assert conn.execute("SELECT 1").fetchone() == (1,)
    assert received == [conn]
    conn.close()


def test_binding_generator_cannot_commit_after_revocation(native_root, authority):
    root = native_root[0]
    conn = opener()(root / "state.db", authority=authority)
    conn.execute("CREATE TABLE records(value)")
    conn.commit()

    def values():
        yield (1,)
        (root / "mordred/db-encryption.marker").unlink()
        yield (2,)

    with pytest.raises(DatabaseRefused):
        conn.executemany("INSERT INTO records VALUES (?)", values())
    assert raw_rows(root / "state.db", derive(native_root[2])) == []


def test_unprotected_sql_cannot_attach_protected_paths(native_root, authority):
    root = native_root[0]
    module = native_module(authority)
    conn = module.connect(":memory:")
    with pytest.raises(DatabaseRefused):
        conn.execute("ATTACH DATABASE ? AS escaped", (str(root / "state.db"),))
    with pytest.raises(DatabaseRefused):
        conn.set_authorizer(None)
    assert not (root / "state.db").exists()
    conn.close()


def test_activity_path_is_guarded(native_root, authority):
    root = native_root[0]
    path = root / "profiles/work/plugin-data/mordred/mordred.db"
    path.parent.mkdir(parents=True, mode=0o700)
    conn = opener()(path, authority=authority)
    conn.execute("CREATE TABLE records(value)")
    conn.execute("INSERT INTO records VALUES (1)")
    conn.commit()
    conn.close()
    assert raw_rows(path, derive(native_root[2])) == [(1,)]


def test_executemany_preserves_rowcount_and_lastrowid(native_root, authority):
    conn = opener()(native_root[0] / "state.db", authority=authority)
    conn.execute("CREATE TABLE records(value)")
    cursor = conn.executemany("INSERT INTO records VALUES (?)", ((i,) for i in range(3)))
    assert cursor.rowcount == 3
    assert cursor.lastrowid is None
    conn.close()


def test_denied_home_subdirectory_keeps_plaintext_policy(native_root, authority):
    path = native_root[0] / "tools/project.db"
    path.parent.mkdir(mode=0o700)
    conn = native_module(authority).connect(path)
    conn.execute("CREATE TABLE records(value)")
    conn.commit()
    conn.close()
    raw = sc.connect(str(path))
    try:
        assert raw.execute("SELECT count(*) FROM records").fetchone() == (0,)
    finally:
        raw.close()


@pytest.mark.filterwarnings("ignore:This process.*multi-threaded:DeprecationWarning")
def test_fork_held_connection_refuses_before_inherited_locks(native_root, authority):
    if not hasattr(os, "fork"):
        pytest.skip("POSIX fork only")
    import signal
    import threading

    conn = opener()(native_root[0] / "state.db", authority=authority)
    conn.execute("CREATE TABLE records(value)")
    conn.execute("INSERT INTO records VALUES (1)")
    ready, release = threading.Event(), threading.Event()

    def holder():
        with authority._lock:
            ready.set()
            release.wait(10)

    thread = threading.Thread(target=holder)
    thread.start()
    assert ready.wait(3)
    pid = os.fork()
    if pid == 0:
        signal.alarm(3)
        try:
            conn.commit()
        except DatabaseRefused:
            os._exit(0)
        except BaseException:
            os._exit(3)
        os._exit(2)
    release.set()
    thread.join(5)
    _, status = os.waitpid(pid, 0)
    assert os.waitstatus_to_exitcode(status) == 0
    conn.commit()
    assert conn.execute("SELECT value FROM records").fetchall() == [(1,)]
    conn.close()


def test_root_authority_rechecks_requested_profile_mapping(native_root, authority):
    root = native_root[0]
    conn = opener()(root / "profiles/work/state.db", authority=authority)
    cursor = conn.execute("SELECT 1")
    # A child cannot publish independent root authority after admission.
    (root / "profiles/work/mordred/db-key-source.json").write_bytes(b"foreign binding")
    with pytest.raises(DatabaseRefused):
        cursor.fetchone()
    assert authority.terminal


@pytest.mark.parametrize("surface", ["execute", "cursor", "executemany", "executescript"])
@pytest.mark.parametrize("explicit", [False, True])
def test_pending_autocommit_returning_cannot_commit_on_revocation(native_root, authority, surface, explicit):
    root, _, material, _ = native_root
    path = root / "state.db"
    conn = opener()(path, authority=authority)
    conn.execute("CREATE TABLE records(value)")
    conn.commit()
    conn.isolation_level = None
    if explicit:
        conn.execute("BEGIN")
    sql = "INSERT INTO records VALUES (1), (2) /* guard */ ReTuRnInG value"
    cursor = conn.cursor()
    operations = {
        "execute": lambda: conn.execute(sql),
        "cursor": lambda cursor=cursor: cursor.execute(sql),
        "executemany": lambda cursor=cursor: cursor.executemany(sql, [()]),
        "executescript": lambda cursor=cursor: cursor.executescript(sql + ";"),
    }
    with pytest.raises(DatabaseRefused):
        operations[surface]()
    (root / "mordred/db-encryption.marker").unlink()
    conn.close()
    del cursor
    gc.collect()
    assert raw_rows(path, derive(material)) == []


def test_returning_in_literals_identifiers_and_comments_is_benign(native_root, authority):
    conn = opener()(native_root[0] / "state.db", authority=authority)
    conn.execute('CREATE TABLE records("RETURNING", [returning value], `returning quote`)')
    conn.execute("INSERT INTO records VALUES (:returning, 2, 3)", {"returning": 1})
    assert conn.execute("SELECT 'RETURNING', 'it''s RETURNING' /* RETURNING */ -- RETURNING\n").fetchone() == (
        "RETURNING",
        "it's RETURNING",
    )
    assert conn.execute('SELECT "RETURNING" FROM records').fetchone() == (1,)
    conn.close()


def test_fork_normal_shutdown_cannot_finalize_inherited_handles(native_root):
    if not hasattr(os, "fork"):
        pytest.skip("POSIX fork only")
    root, _, material, _ = native_root
    code = """import gc, os, sys
from pathlib import Path
from types import SimpleNamespace
from mordred_hermes import _database_locking_posix as locks
from mordred_hermes.keyvault import _database_authority as custody
from mordred_hermes.dbcrypt import _authority
from mordred_hermes.dbcrypt._connection import open_protected
# Metadata and root leases are real. Only native unwrap is replaced.
custody.sys = SimpleNamespace(platform='linux')
locks.sys = SimpleNamespace(platform='linux')
_authority.load_database_source = lambda **kw: bytes.fromhex(sys.argv[2])
root = Path(sys.argv[1])
authority = _authority.Authority.acquire(root)
c = open_protected(root / 'fork.db', authority=authority)
c.execute('CREATE TABLE records(value)')
c.execute('INSERT INTO records VALUES (1)')
cur = c.execute('SELECT value FROM records')
pid = os.fork()
if pid == 0:
 del cur, c, authority
 gc.collect()
 sys.exit(0)
_, status = os.waitpid(pid, 0)
assert os.waitstatus_to_exitcode(status) == 74, status
c.commit()
assert c.execute('SELECT value FROM records').fetchall() == [(1,)]
c.close()
authority.close()
print('parent transaction intact; child shutdown refused')
"""
    result = subprocess.run(
        [sys.executable, "-c", code, str(root), material.hex()],
        capture_output=True,
        text=True,
        env={**os.environ, "HERMES_HOME": str(root)},
        timeout=20,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "parent transaction intact; child shutdown refused"


def test_native_install_cannot_reacquire_or_rebind(native_root, monkeypatch):
    from mordred_hermes import dbcrypt
    from mordred_hermes.dbcrypt import _shim

    root, backend, _, _ = native_root
    monkeypatch.setattr(dbcrypt.sys, "platform", "darwin")
    monkeypatch.setattr(dbcrypt.sys, "argv", ["hermes"])
    monkeypatch.setattr(dbcrypt, "_PROVIDER", None)
    monkeypatch.setattr(_shim, "install_module", lambda module: None)
    assert dbcrypt.install(home=root)
    provider = dbcrypt._PROVIDER
    try:
        assert dbcrypt.install(home=root)
        assert dbcrypt._PROVIDER is provider
        assert sum(op == "ecdh" for op, _ in backend.calls) == 1
        with pytest.raises(DatabaseRefused):
            dbcrypt.install(home=root / "profiles/work")
        provider.close()
        with pytest.raises(DatabaseRefused):
            dbcrypt.install(home=root)
    finally:
        provider.close()
        dbcrypt._PROVIDER.close()


def test_native_monitor_internal_error_revokes(native_root, authority, monkeypatch):
    from mordred_hermes.dbcrypt import _monitor

    conn = opener()(native_root[0] / "state.db", authority=authority)

    def broken(home):
        raise RuntimeError("scan unavailable")

    monkeypatch.setattr(_monitor, "_top_level", broken)
    assert _monitor.monitor_runtime(authority)[0].violation
    with pytest.raises(DatabaseRefused):
        conn.execute("SELECT 1")


def test_reentrant_revocation_retains_lease_until_rollback(native_root, authority):
    from mordred_hermes._database_contracts import DatabaseBusy
    from mordred_hermes._database_lifecycle import acquire_exclusive

    root = native_root[0]
    conn = opener()(root / "state.db", authority=authority)
    conn.execute("CREATE TABLE records(value)")
    conn.execute("INSERT INTO records VALUES (1)")

    def row(cursor, values):
        (root / "mordred/db-encryption.marker").unlink()
        with pytest.raises(DatabaseRefused):
            authority.check()
        with pytest.raises(DatabaseBusy), acquire_exclusive(root):
            pass
        return values

    conn.row_factory = row
    with pytest.raises(DatabaseRefused):
        conn.execute("SELECT value FROM records").fetchone()
    with acquire_exclusive(root):
        pass
    assert raw_rows(root / "state.db", derive(native_root[2])) == []


def test_empty_schema_encrypted_foreign_copy_is_not_plaintext(native_root, authority):
    root = native_root[0]
    path = root / "state.db"
    conn = opener()(path, authority=authority)
    conn.execute("PRAGMA user_version=17")
    conn.close()
    foreign = root.parent / (root.name + "-empty-foreign.db")
    foreign.write_bytes(path.read_bytes())
    try:
        with pytest.raises(DatabaseRefused):
            native_module(authority).connect(foreign)
    finally:
        foreign.unlink()


def test_native_registration_cannot_inject_binding_callbacks(native_root, authority):
    module = native_module(authority)
    before = dict(sc.adapters)
    try:
        with pytest.raises(DatabaseRefused):
            module.register_adapter(int, lambda value: value)
        with pytest.raises(DatabaseRefused):
            module.register_converter("external", lambda value: value)
    finally:
        sc.adapters.clear()
        sc.adapters.update(before)


def test_actual_activity_keyed_opener_accepts_guarded_connection(native_root, authority, monkeypatch):
    from mordred_hermes.activity import _gate
    from mordred_hermes.activity.store import ActivityStore

    root = native_root[0]
    profile = root / "profiles/work"
    path = profile / "plugin-data/mordred/mordred.db"
    path.parent.mkdir(parents=True, mode=0o700)
    monkeypatch.setattr(_gate, "_process_sqlite", lambda: native_module(authority))
    store = ActivityStore(path, _gate.keyed_opener)
    meta = store.initialize(profile)
    assert meta.profile_home == str(profile)
    with store.connection() as conn:
        assert conn.execute("SELECT value FROM activity_meta WHERE key='profile_home'").fetchone() == (str(profile),)
    memory = native_module(authority).connect(":memory:")
    try:
        assert memory.mordred_key is None
    finally:
        memory.close()


def test_only_exact_guarded_factory_is_admitted(native_root, authority):
    module = native_module(authority)

    class UnsafeSubclass(module.Connection):
        pass

    path = native_root[0] / "state.db"
    with pytest.raises(DatabaseRefused):
        module.connect(path, 5.0, 0, "", True, UnsafeSubclass)
    assert not path.exists()
    conn = module.connect(path, factory=module.Connection)
    try:
        assert conn.execute("SELECT 1").connection is conn
    finally:
        conn.close()
