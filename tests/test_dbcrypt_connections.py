"""Real SQLCipher admission, held-object revocation and same-library monitoring."""

from __future__ import annotations

import gc
import os
import subprocess
import sys
import weakref

import pytest
import sqlcipher3.dbapi2 as sc

from mordred_hermes._core._database_contracts import DatabaseRefused
from mordred_hermes.dbcrypt._authority import Authority
from mordred_hermes.dbcrypt._key import derive
from mordred_hermes.dbcrypt._shim import apply_key
from tests._dbcrypt_platform_support import policy_sys
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
        "PRAGMA textrekey='x'",
        "PRAGMA kdf_iter=1",
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


@pytest.mark.parametrize(
    ("name", "second", "denied"),
    [
        *[
            (n, "1", True)
            for n in (
                "textkey",
                "textrekey",
                "kdf_iter",
                "fast_kdf_iter",
                "rekey_kdf_iter",
                "rekey_cipher",
                "key",
                "rekey",
                "hexkey",
                "hexrekey",
                "cipher_page_size",
                "writable_schema",
                "temp_store_directory",
                "data_store_directory",
            )
        ],
        ("cipher_integrity_check", "1", True),
        ("cipher_version", "1", True),
        ("journal_mode", "off", True),
        *[("journal_mode", v, True) for v in ("o", "OF", "m", "me", "MEM", "", "walx", 1)],
        *[("journal_mode", v, False) for v in ("wal", "WAL", "delete", "truncate", "persist", None)],
        ("foreign_keys", "ON", False),
        ("foreign_keys", None, False),
        ("journal_mode", "wal", False),
        ("user_version", None, False),
        ("cipher_version", None, False),
        ("cipher_integrity_check", None, False),
        ("busy_timeout", "5000", False),
    ],
)
def test_sql_action_denied_pragma_policy(name, second, denied):
    from mordred_hermes.dbcrypt._connection import _sql_action_denied

    assert _sql_action_denied(sc.SQLITE_PRAGMA, name, second) is denied


def test_journal_mode_prefix_refused_and_wal_allowed(native_root, authority):
    conn = opener()(native_root[0] / "state.db", authority=authority)
    with pytest.raises(DatabaseRefused):
        conn.execute("PRAGMA journal_mode=o")
    conn.close()
    conn = opener()(native_root[0] / "state.db", authority=authority)
    assert conn.execute("PRAGMA journal_mode=wal").fetchall() == [("wal",)]
    conn.close()


def test_foreign_keys_pragma_still_executes(native_root, authority):
    conn = opener()(native_root[0] / "state.db", authority=authority)
    conn.execute("PRAGMA foreign_keys=ON")
    assert conn.execute("PRAGMA foreign_keys").fetchall() == [(1,)]
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


def test_same_inode_unread_page_corruption_refused_on_read_and_on_a_fresh_key(native_root, authority):
    path = native_root[0] / "state.db"
    conn = opener()(path, authority=authority)
    conn.execute("CREATE TABLE records(value)")
    conn.execute("INSERT INTO records VALUES (?)", (b"x" * 24000,))
    conn.commit()
    page_size = int(conn.execute("PRAGMA page_size").fetchone()[0])
    page_count = conn.execute("PRAGMA page_count").fetchone()[0]
    assert page_count > 3
    conn.close()
    before = path.stat()
    # Alter encrypted payload in the final overflow page, leaving schema intact.
    with path.open("r+b") as stream:
        offset = (page_count - 1) * page_size + 128
        stream.seek(offset)
        value = stream.read(1)
        stream.seek(offset)
        stream.write(bytes([value[0] ^ 1]))
    os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns))
    after = path.stat()
    assert (after.st_dev, after.st_ino, after.st_size, after.st_mode, after.st_mtime_ns) == (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mode,
        before.st_mtime_ns,
    )
    raw = sc.connect(str(path))
    try:
        apply_key(raw, derive(native_root[2]))
        # Schema-only admission would miss this authenticated-page corruption.
        assert raw.execute("SELECT count(*) FROM sqlite_master").fetchone() == (1,)
    finally:
        raw.close()
    # The whole-file pass already ran for this file under this key, so the
    # reopen is admitted; the same pass, run on demand, still finds the page.
    reopened = opener()(path, authority=authority)
    try:
        assert reopened.execute("PRAGMA cipher_integrity_check").fetchall()
    finally:
        reopened.close()
    # A freshly loaded key verifies the whole file again before admission.
    fresh = Authority.acquire(native_root[0])
    try:
        with pytest.raises(DatabaseRefused):
            opener()(path, authority=fresh)
    finally:
        fresh.close()


@pytest.mark.parametrize("journal_mode", ["delete", "wal"])
def test_external_committed_write_readable_on_reopen(native_root, authority, journal_mode):
    path = native_root[0] / "state.db"
    conn = opener()(path, authority=authority)
    assert conn.execute(f"PRAGMA journal_mode={journal_mode}").fetchone() == (journal_mode,)
    conn.execute("CREATE TABLE records(value)")
    conn.execute("INSERT INTO records VALUES (1)")
    conn.commit()
    conn.close()
    raw = sc.connect(str(path))
    try:
        apply_key(raw, derive(native_root[2]))
        raw.execute("INSERT INTO records VALUES (2)")
        raw.commit()
        if journal_mode == "wal":
            assert path.with_name(path.name + "-wal").stat().st_size > 32
        reopened = opener()(path, authority=authority)
        try:
            assert reopened.execute("SELECT value FROM records ORDER BY value").fetchall() == [(1,), (2,)]
        finally:
            reopened.close()
    finally:
        raw.close()


def test_each_sql_callback_keeps_one_full_metadata_observation(native_root, authority, monkeypatch):
    from mordred_hermes.dbcrypt import _authority, _connection

    conn = opener()(native_root[0] / "state.db", authority=authority)
    full_checks = 0
    callback_checks = {"authorizer": [], "progress": []}
    observe = _authority.observe_database_source

    def counted_observation(*, root):
        nonlocal full_checks
        full_checks += 1
        return observe(root=root)

    def counted_callback(name, callback):
        def run(self, *args):
            before = full_checks
            result = callback(self, *args)
            callback_checks[name].append(full_checks - before)
            return result

        return run

    monkeypatch.setattr(_authority, "observe_database_source", counted_observation)
    monkeypatch.setattr(
        _connection.ProtectedConnection,
        "_authorize",
        counted_callback("authorizer", _connection.ProtectedConnection._authorize),
    )
    monkeypatch.setattr(
        _connection.ProtectedConnection,
        "_progress",
        counted_callback("progress", _connection.ProtectedConnection._progress),
    )
    try:
        assert conn.execute(
            "WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<3000) SELECT sum(x) FROM n"
        ).fetchone() == (4501500,)
        for checks in callback_checks.values():
            assert checks
            assert set(checks) == {1}
    finally:
        conn.close()


@pytest.mark.parametrize("damage", ["marker", "native", "profile"])
def test_metadata_change_during_long_query_refuses(native_root, authority, monkeypatch, damage):
    from mordred_hermes.dbcrypt import _connection

    root = native_root[0]
    conn = opener()(root / "profiles/work/state.db", authority=authority)
    progress = _connection.ProtectedConnection._progress
    calls = 0

    def change_during_query(self):
        nonlocal calls
        calls += 1
        if calls == 3:
            if damage == "marker":
                (root / "mordred/db-encryption.marker").unlink()
            elif damage == "native":
                wrapped = root / "mordred/memory-key.wrapped"
                blob = bytearray(wrapped.read_bytes())
                blob[-1] ^= 1
                wrapped.write_bytes(blob)
            else:
                (root / "profiles/work/mordred/db-key-source.json").write_bytes(b"foreign binding")
        return progress(self)

    monkeypatch.setattr(_connection.ProtectedConnection, "_progress", change_during_query)
    try:
        with pytest.raises(DatabaseRefused):
            conn.execute(
                "WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<100000) SELECT sum(x) FROM n"
            ).fetchone()
        assert calls == 3
        assert authority.terminal
        assert conn._closed
    finally:
        conn.close()


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


def _owned_handles(authority):
    from mordred_hermes.dbcrypt._connection import _LIVE_OWNERS

    return [owner for owner in tuple(_LIVE_OWNERS) if owner._authority is authority]


def test_readiness_probe_without_close_releases_every_handle(native_root, authority):
    # Hermes's gateway readiness poll commits through ``with`` but never closes.
    path = native_root[0] / "state.db"
    conn = opener()(path, authority=authority)
    conn.execute("CREATE TABLE records(value)")
    conn.commit()
    conn.close()
    uri = f"file:{path.as_posix()}?mode=ro"
    gc.disable()  # Reference counting alone must release each abandoned handle.
    try:
        for _ in range(20):
            with native_module(authority).connect(uri, uri=True, timeout=1.0) as conn:
                conn.execute("PRAGMA query_only = ON")
                conn.execute("SELECT name FROM sqlite_master LIMIT 1").fetchone()
            ref = weakref.ref(conn)
            del conn
            assert ref() is None
            assert len(_owned_handles(authority)) <= 1  # The previous probe's raw handle is closed.
        # Each admission reaps the abandoned probes before it, so exactly the new one remains.
        probe = native_module(authority).connect(uri, uri=True, timeout=1.0)
        try:
            assert len(authority._connections) == 1
            assert len(_owned_handles(authority)) == 1
        finally:
            probe.close()
        assert len(authority._connections) == 0
        assert _owned_handles(authority) == []
    finally:
        gc.enable()


def test_owner_release_forgets_and_closes_its_vfs_when_raw_close_fails(authority):
    from mordred_hermes.dbcrypt._connection import _LIVE_OWNERS, _RawOwner

    events = []

    class Raw:
        def set_authorizer(self, _callback):
            pass

        def set_progress_handler(self, _handler, _steps):
            pass

        def rollback(self):
            events.append("rollback")

        def close(self):
            events.append("raw.close")
            raise sc.OperationalError("unable to close due to unfinalized statements")

    class Vfs:
        def close(self):
            events.append(("vfs.close", owner in _LIVE_OWNERS))

    class Facade:
        pass

    facade = Facade()
    owner = _RawOwner(authority, Vfs(), facade)
    owner._raw = Raw()
    with pytest.raises(sc.OperationalError):
        owner.release()
    # raw.close -> forget the owner -> close its VFS, even though raw.close raised.
    assert events == ["rollback", "raw.close", ("vfs.close", False)]
    assert owner not in _LIVE_OWNERS
    owner.release()  # Exactly once.
    assert events == ["rollback", "raw.close", ("vfs.close", False)]


def test_abandoned_uncommitted_write_is_rolled_back_before_lease_release(native_root, authority):
    from mordred_hermes._core._database_lifecycle import acquire_exclusive

    root, _, material, _ = native_root
    path = root / "state.db"
    conn = opener()(path, authority=authority)
    conn.execute("CREATE TABLE records(value)")
    conn.commit()
    conn.execute("BEGIN IMMEDIATE")
    conn.execute("INSERT INTO records VALUES (1)")
    ref = weakref.ref(conn)
    del conn
    assert ref() is None
    authority.close()
    assert authority._connections == []
    assert _owned_handles(authority) == []
    with acquire_exclusive(root):
        writer = sc.connect(str(path), timeout=0)
        try:
            apply_key(writer, derive(material))
            writer.execute("BEGIN IMMEDIATE")  # The abandoned write lock is gone.
            writer.rollback()
        finally:
            writer.close()
    assert raw_rows(path, derive(material)) == []


def test_next_admission_reclaims_abandoned_immediate_writer(native_root, authority):
    path = native_root[0] / "state.db"
    conn = opener()(path, authority=authority)
    conn.execute("CREATE TABLE records(value)")
    conn.commit()
    conn.execute("BEGIN IMMEDIATE")
    conn.execute("INSERT INTO records VALUES (1)")
    del conn
    second = opener()(path, authority=authority, timeout=0)
    try:
        second.execute("BEGIN IMMEDIATE")
        second.execute("INSERT INTO records VALUES (2)")
        second.commit()
        assert second.execute("SELECT value FROM records").fetchall() == [(2,)]
        assert len(authority._connections) == 1
    finally:
        second.close()
    assert authority._connections == [] and _owned_handles(authority) == []


@pytest.mark.parametrize("custom_rows", [False, True])
def test_live_cursor_pins_connection_until_dropped(native_root, authority, custom_rows):
    gc.disable()
    try:
        conn = opener()(native_root[0] / "state.db", authority=authority)
        if custom_rows:
            conn.row_factory = lambda cursor, values: ("row", *values)
        cursor = conn.execute("SELECT 1")
        ref = weakref.ref(conn)
        del conn
        assert ref() is not None
        assert cursor.fetchone() == (("row", 1) if custom_rows else (1,))
        del cursor
        assert ref() is None
    finally:
        gc.enable()


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
    monkeypatch.setattr(dbcrypt._runtime, "sys", policy_sys("darwin"))
    monkeypatch.setattr(sys, "argv", ["hermes"])
    monkeypatch.setattr(dbcrypt._runtime, "_PROVIDER", None)
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
        dbcrypt._runtime._PROVIDER.close()


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
from mordred_hermes._core import _database_locking_posix as locks
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


def test_fork_quarantines_abandoned_handle_pending_release(native_root):
    if not hasattr(os, "fork"):
        pytest.skip("POSIX fork only")
    root, _, material, _ = native_root
    code = """import gc, os, sys
from pathlib import Path
from types import SimpleNamespace
from mordred_hermes._core import _database_locking_posix as locks
from mordred_hermes.keyvault import _database_authority as custody
from mordred_hermes.dbcrypt import _authority
from mordred_hermes.dbcrypt._connection import _ABANDONED, _LIVE_CONNECTIONS, _LIVE_CURSORS, open_protected
custody.sys = SimpleNamespace(platform='linux')
locks.sys = SimpleNamespace(platform='linux')
_authority.load_database_source = lambda **kw: bytes.fromhex(sys.argv[2])
root = Path(sys.argv[1])
authority = _authority.Authority.acquire(root)
c = open_protected(root / 'fork.db', authority=authority)
c.execute('CREATE TABLE records(value)')
c.execute('INSERT INTO records VALUES (1)')
del c  # Abandoned with an open transaction; queued, not yet released.
assert len(_ABANDONED) == 1 and not _LIVE_CONNECTIONS and not _LIVE_CURSORS
pid = os.fork()
if pid == 0:
 del authority
 gc.collect()
 sys.exit(0)
_, status = os.waitpid(pid, 0)
assert os.waitstatus_to_exitcode(status) == 74, status
c = open_protected(root / 'fork.db', authority=authority, timeout=0)
assert not _ABANDONED
c.execute('BEGIN IMMEDIATE')
assert c.execute('SELECT value FROM records').fetchall() == []
c.rollback()
c.close()
authority.close()
print('abandoned handle quarantined; parent reclaimed it')
"""
    result = subprocess.run(
        [sys.executable, "-c", code, str(root), material.hex()],
        capture_output=True,
        text=True,
        env={**os.environ, "HERMES_HOME": str(root)},
        timeout=20,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "abandoned handle quarantined; parent reclaimed it"
    assert raw_rows(root / "fork.db", derive(material)) == []


def test_native_install_cannot_reacquire_or_rebind(native_root, monkeypatch):
    from mordred_hermes import dbcrypt
    from mordred_hermes.dbcrypt import _shim

    root, backend, _, _ = native_root
    monkeypatch.setattr(dbcrypt._runtime, "sys", policy_sys("darwin"))
    monkeypatch.setattr(sys, "argv", ["hermes"])
    monkeypatch.setattr(dbcrypt._runtime, "_PROVIDER", None)
    monkeypatch.setattr(_shim, "install_module", lambda module: None)
    assert dbcrypt.install(home=root)
    provider = dbcrypt._runtime._PROVIDER
    try:
        assert dbcrypt.install(home=root)
        assert dbcrypt._runtime._PROVIDER is provider
        assert sum(op == "ecdh" for op, _ in backend.calls) == 1
        with pytest.raises(DatabaseRefused):
            dbcrypt.install(home=root / "profiles/work")
        provider.close()
        with pytest.raises(DatabaseRefused):
            dbcrypt.install(home=root)
    finally:
        provider.close()
        dbcrypt._runtime._PROVIDER.close()


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
    from mordred_hermes._core._database_contracts import DatabaseBusy
    from mordred_hermes._core._database_lifecycle import acquire_exclusive

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


@pytest.mark.parametrize("journal_mode", ["delete", "wal"])
def test_writer_commits_while_another_connection_busy_waits(native_root, authority, journal_mode):
    import threading
    import time

    path = native_root[0] / "state.db"
    x = opener()(path, authority=authority)
    y = None
    try:
        assert x.execute(f"PRAGMA journal_mode={journal_mode}").fetchone() == (journal_mode,)
        x.execute("CREATE TABLE records(value)")
        x.commit()
        y = opener()(path, authority=authority, timeout=3, check_same_thread=False)
        x.execute("BEGIN IMMEDIATE")
        x.execute("INSERT INTO records VALUES (1)")
        waited, failures = [], []
        beginning = threading.Event()

        def write():
            started = time.monotonic()
            try:
                beginning.set()
                y.execute("BEGIN IMMEDIATE")  # Busy-waits for X inside SQLite.
                waited.append(time.monotonic() - started)
                y.execute("INSERT INTO records VALUES (2)")
                y.commit()
            except BaseException as error:
                failures.append(error)

        worker = threading.Thread(target=write)
        worker.start()
        assert beginning.wait(2)
        time.sleep(0.2)  # X still holds its write lock: Y must be waiting, not done.
        started = time.monotonic()
        x.commit()
        committed = time.monotonic() - started
        worker.join(5)
        assert not worker.is_alive()
        assert failures == []
        assert committed < 1.0
        assert len(waited) == 1 and 0.1 <= waited[0] < 2.0
        assert x.execute("SELECT value FROM records ORDER BY value").fetchall() == [(1,), (2,)]
    finally:
        if y is not None:
            y.close()
        x.close()


def test_cross_thread_revocation_defers_lease_for_in_flight_operation(native_root, authority):
    import threading

    from mordred_hermes._core._database_contracts import DatabaseBusy
    from mordred_hermes._core._database_lifecycle import acquire_exclusive

    root = native_root[0]
    x = opener()(root / "state.db", authority=authority)
    y = opener()(root / "state.db", authority=authority, check_same_thread=False)
    entered, release = threading.Event(), threading.Event()
    outcome = []

    def row(cursor, values):
        entered.set()
        release.wait(10)
        return values

    y.row_factory = row

    def read():
        try:
            outcome.append(y.execute("SELECT 1").fetchone())
        except BaseException as error:
            outcome.append(error)

    worker = threading.Thread(target=read)
    worker.start()
    try:
        assert entered.wait(3)
        revoker = threading.Thread(target=authority.invalidate, args=("test revocation",))
        revoker.start()
        revoker.join(2)
        assert not revoker.is_alive()  # Revocation never waits behind Y's SQL.
        assert authority.terminal and x._closed
        assert y._revoked and not y._closed  # Disposal is deferred to Y's own scope.
        with pytest.raises(DatabaseBusy), acquire_exclusive(root):
            pass
    finally:
        release.set()
        worker.join(5)
    assert not worker.is_alive()
    assert len(outcome) == 1 and isinstance(outcome[0], DatabaseRefused)
    assert y._closed
    with acquire_exclusive(root):
        pass


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
    from mordred_hermes import dbcrypt
    from mordred_hermes.dbcrypt._key import KeyProvider

    provider = KeyProvider(home=profile)
    monkeypatch.setattr(dbcrypt._runtime, "_PROVIDER", provider)
    try:
        store = ActivityStore(path, _gate.keyed_opener)
        meta = store.initialize(profile)
        assert meta.profile_home == str(profile)
        with store.connection() as conn:
            assert conn.execute("SELECT value FROM activity_meta WHERE key='profile_home'").fetchone() == (
                str(profile),
            )
    finally:
        provider.close()
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


@pytest.mark.parametrize("binding", ["cross-root", "root-to-profile", "profile-to-root"])
def test_first_install_refuses_provider_from_another_home(native_root, monkeypatch, binding):
    from mordred_hermes import dbcrypt
    from mordred_hermes._core._database_lifecycle import acquire_exclusive
    from mordred_hermes.dbcrypt import _shim
    from mordred_hermes.dbcrypt._key import KeyProvider
    from mordred_hermes.keyvault import _database_authority as custody
    from mordred_hermes.keyvault import _memory_key as memory
    from tests.test_dbcrypt_marker import encoded, put

    root, backend, _, _ = native_root
    requested, supplied = root, root / "profiles/work"
    if binding == "profile-to-root":
        requested, supplied = supplied, requested
    elif binding == "cross-root":
        supplied = root / "other-home"
        supplied.mkdir(mode=0o700)
        memory.ensure_linux_memory_key(home=supplied, backend=backend)
        (supplied / "mordred/memory-vault.marker").write_bytes(b"memory-encryption enabled\n")
        (supplied / "mordred/memory-vault.marker").chmod(0o600)
        with acquire_exclusive(supplied) as lease:
            snapshot = custody.enroll_database_source(root=supplied, lease=lease)
        put(supplied, encoded(snapshot))
    provider = KeyProvider(home=supplied)
    published = []
    monkeypatch.setattr(dbcrypt._runtime, "sys", policy_sys("darwin"))
    monkeypatch.setattr(sys, "argv", ["hermes"])
    monkeypatch.setattr(dbcrypt._runtime, "_PROVIDER", None)
    monkeypatch.setattr(_shim, "install_module", published.append)
    try:
        with pytest.raises(DatabaseRefused):
            dbcrypt.install(home=requested, provider=provider)
        assert published == []
        assert not (requested / "new.db").exists()
        assert dbcrypt._runtime._PROVIDER is None
    finally:
        provider.close()


def test_monitor_preserves_same_authority_exclusive_writer(native_root, authority):
    from mordred_hermes.dbcrypt._monitor import monitor_runtime

    path = native_root[0] / "state.db"
    conn = opener()(path, authority=authority)
    try:
        conn.execute("CREATE TABLE records(value)")
        assert conn.execute("PRAGMA journal_mode=DELETE").fetchone() == ("delete",)
        conn.execute("BEGIN EXCLUSIVE")
        conn.execute("INSERT INTO records VALUES (2)")
        findings = monitor_runtime(authority)
        assert not authority.terminal
        assert len(findings) == 1 and findings[0].code == "busy" and not findings[0].violation
        assert conn.in_transaction
        conn.commit()
        assert monitor_runtime(authority) == ()
        assert conn.execute("SELECT value FROM records").fetchall() == [(2,)]
    finally:
        conn.close()


def test_monitor_preserves_external_exclusive_writer(native_root, authority):
    from mordred_hermes.dbcrypt._monitor import monitor_runtime

    root, _, material, _ = native_root
    path = root / "state.db"
    conn = opener()(path, authority=authority)
    conn.execute("CREATE TABLE records(value)")
    conn.execute("PRAGMA journal_mode=DELETE")
    conn.close()
    code = """import sys
import sqlcipher3.dbapi2 as sc
from mordred_hermes.dbcrypt._key import derive
from mordred_hermes.dbcrypt._shim import apply_key
c = sc.connect(sys.argv[1], timeout=0)
apply_key(c, derive(bytes.fromhex(sys.argv[2])))
c.execute('BEGIN EXCLUSIVE')
c.execute('INSERT INTO records VALUES (3)')
print('locked', flush=True)
sys.stdin.readline()
c.commit()
c.close()
"""
    process = subprocess.Popen(
        [sys.executable, "-c", code, str(path), material.hex()],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env={**os.environ, "HERMES_HOME": str(root)},
    )
    try:
        assert process.stdout.readline().strip() == "locked"
        findings = monitor_runtime(authority)
        assert not authority.terminal
        assert len(findings) == 1 and findings[0].code == "busy" and not findings[0].violation
        # Admission callers also retain the driver's actual BUSY classification.
        with pytest.raises(sc.OperationalError) as error:
            opener()(path, authority=authority, readonly=True, timeout=0)
        assert error.value.sqlite_errorcode & 255 == sc.SQLITE_BUSY
    finally:
        _, stderr = process.communicate("release\n", timeout=20)
        assert process.returncode == 0, stderr
    assert monitor_runtime(authority) == ()
    assert raw_rows(path, derive(material)) == [(3,)]


@pytest.mark.parametrize("fetched", [False, True])
def test_closed_connection_retained_cursor_allows_normal_child_exit(native_root, fetched):
    if not hasattr(os, "fork"):
        pytest.skip("POSIX fork only")
    root, _, material, _ = native_root
    code = """import gc, os, sys
from pathlib import Path
from types import SimpleNamespace
from mordred_hermes._core import _database_locking_posix as locks
from mordred_hermes.keyvault import _database_authority as custody
from mordred_hermes.dbcrypt import _authority
from mordred_hermes.dbcrypt._connection import open_protected
custody.sys = SimpleNamespace(platform='linux')
locks.sys = SimpleNamespace(platform='linux')
_authority.load_database_source = lambda **kw: bytes.fromhex(sys.argv[2])
root = Path(sys.argv[1])
authority = _authority.Authority.acquire(root)
c = open_protected(root / 'fork.db', authority=authority)
c.execute('CREATE TABLE records(value)')
c.execute('INSERT INTO records VALUES (1)')
cur = c.execute('SELECT value FROM records')
if sys.argv[3] == 'True':
 assert cur.fetchall() == [(1,)]
c.close()
authority.close()
pid = os.fork()
if pid == 0:
 del cur, c, authority
 gc.collect()
 sys.exit(0)
_, status = os.waitpid(pid, 0)
assert os.waitstatus_to_exitcode(status) == 0, status
print('closed handles permit normal child exit')
"""
    result = subprocess.run(
        [sys.executable, "-c", code, str(root), material.hex(), str(fetched)],
        capture_output=True,
        text=True,
        env={**os.environ, "HERMES_HOME": str(root)},
        timeout=20,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "closed handles permit normal child exit"
    assert raw_rows(root / "fork.db", derive(material)) == []


def test_vfs_registration_released_when_driver_connect_fails(native_root, authority, monkeypatch):
    from types import SimpleNamespace

    from mordred_hermes.dbcrypt import _connection, _windows_vfs

    class NativeRegistration:
        def __init__(self):
            self.tokens = {17}

        def mordred_vfs_close_root(self, token):
            self.tokens.remove(token)
            return 0

    native = NativeRegistration()
    registration = _windows_vfs.VfsRegistration(native, 17, native_root[0], sc)
    # Exercise the Python ownership branch, never load/activate a native VFS.
    # The actual driver rejects the deliberately unregistered VFS name.
    monkeypatch.setattr(_connection, "os", SimpleNamespace(name="nt", getpid=os.getpid))
    monkeypatch.setattr(_windows_vfs, "NATIVE_QUALIFIED", True)
    monkeypatch.setattr(_windows_vfs, "windows_edition_admitted", lambda: True)
    monkeypatch.setattr(_windows_vfs, "classify_windows_database", lambda *a, **kw: native_root[0])
    monkeypatch.setattr(_windows_vfs, "register_checked_vfs", lambda *a, **kw: registration)
    monkeypatch.setattr(
        _windows_vfs,
        "checked_path_identity",
        lambda path, **kw: tuple(getattr(path.lstat(), field) for field in ("st_dev", "st_ino", "st_mode", "st_uid")),
    )
    with pytest.raises((sc.OperationalError, DatabaseRefused)):
        opener()(native_root[0] / "state.db", authority=authority)
    assert native.tokens == set()
    assert not (native_root[0] / "state.db").exists()
    assert not authority.terminal


def test_shared_windows_ownership_survives_monitor_backup_failed_open_and_terminal_close(
    native_root, authority, monkeypatch
):
    from mordred_hermes.dbcrypt._backup import backup_database
    from mordred_hermes.dbcrypt._monitor import monitor_runtime
    from tests._dbcrypt_windows_fakes import protected_windows_environment

    root = native_root[0]
    independent = Authority.acquire(root / "profiles/work")
    native = protected_windows_environment(monkeypatch)
    first = opener()(root / "state.db", authority=authority)
    second = opener()(root / "profiles/work/held.db", authority=independent)
    try:
        first.execute("CREATE TABLE records(value)")
        first.execute("INSERT INTO records VALUES (4)")
        first.commit()
        second.execute("CREATE TABLE records(value)")
        second.execute("INSERT INTO records VALUES (9)")
        second.commit()
        cursor = second.execute("SELECT value FROM records")
        assert monitor_runtime(authority) == ()
        bad = root / "wrong-key.db"
        bad.write_bytes(b"not an encrypted database")
        bad.chmod(0o600)
        with pytest.raises(DatabaseRefused):
            opener()(bad, authority=authority)
        bad.unlink()
        assert len(native.roots) == 1
        output = root.parent / "separate-backups"
        output.mkdir(mode=0o700)
        backup = backup_database(root / "state.db", output / "held.backup", authority=authority)
        assert backup.exists() and len(native.roots) == 1
        authority.close()
        assert first._closed and len(native.roots) == 1
        assert cursor.fetchall() == [(9,)]
        assert second.execute("SELECT value FROM records").fetchall() == [(9,)]
        second.close()
        assert native.roots == {}
        with pytest.raises(DatabaseRefused):
            cursor.fetchone()
    finally:
        first.close()
        second.close()
        independent.close()


@pytest.mark.parametrize("check_same_thread", [True, False])
def test_explicit_thread_policy_keeps_authority_admission(authority, check_same_thread):
    import threading

    conn = opener()(authority.root / "thread-policy.db", authority=authority, check_same_thread=check_same_thread)
    conn.execute("CREATE TABLE records(value TEXT)")
    conn.execute("INSERT INTO records VALUES ('日本語')")
    conn.commit()
    rows, failures = [], []

    def read():
        try:
            rows.extend(conn.execute("SELECT value FROM records").fetchall())
        except BaseException as error:
            failures.append(error)

    worker = threading.Thread(target=read)
    worker.start()
    worker.join(timeout=5)
    assert not worker.is_alive()
    if check_same_thread:
        assert rows == []
        assert len(failures) == 1 and isinstance(failures[0], sc.ProgrammingError)
    else:
        assert failures == []
        assert rows == [("日本語",)]
    conn.close()


@pytest.mark.parametrize("invalid", [None, 0, 1, "false"])
def test_invalid_thread_policy_refuses_before_creating(authority, invalid):
    path = authority.root / "invalid-thread-policy.db"
    with pytest.raises(DatabaseRefused):
        opener()(path, authority=authority, check_same_thread=invalid)
    assert not path.exists()


def _count_observations(monkeypatch):
    from mordred_hermes.dbcrypt import _authority

    calls = []
    observe = _authority.observe_database_source

    def counted(*, root):
        calls.append(root)
        return observe(root=root)

    monkeypatch.setattr(_authority, "observe_database_source", counted)
    return calls


def test_recheck_window_skips_repeated_observation_while_key_is_held(native_root, authority, monkeypatch):
    from mordred_hermes.dbcrypt import _authority

    monkeypatch.delenv(_authority.RECHECK_ENV, raising=False)
    assert _authority.recheck_seconds() == _authority.RECHECK_SECONDS
    conn = opener()(native_root[0] / "state.db", authority=authority)
    try:
        calls = _count_observations(monkeypatch)
        rows = conn.execute(
            "WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<3000) SELECT sum(x) FROM n"
        ).fetchall()
        assert rows == [(4501500,)]
        assert calls == []  # every callback ran inside the window
        now = _authority.time.monotonic()
        monkeypatch.setattr(_authority.time, "monotonic", lambda: now + _authority.RECHECK_SECONDS + 1)
        conn.execute("SELECT 1").fetchall()
        assert len(calls) == 1  # one full observation once the window has passed
    finally:
        conn.close()


def test_recheck_window_still_refuses_a_terminal_authority_at_once(native_root, authority, monkeypatch):
    from mordred_hermes.dbcrypt import _authority

    monkeypatch.delenv(_authority.RECHECK_ENV, raising=False)
    conn = opener()(native_root[0] / "state.db", authority=authority)
    authority.invalidate("test")
    with pytest.raises(DatabaseRefused):
        conn.execute("SELECT 1")


@pytest.mark.parametrize(("raw", "expected"), [("0", 0.0), ("5", 5.0), ("600", None), ("-1", None), ("x", None)])
def test_recheck_environment_only_shortens_the_window(monkeypatch, raw, expected):
    from mordred_hermes.dbcrypt import _authority

    monkeypatch.setenv(_authority.RECHECK_ENV, raw)
    assert _authority.recheck_seconds() == (_authority.RECHECK_SECONDS if expected is None else expected)


def test_whole_file_check_runs_once_per_file_under_one_key(native_root, authority):
    path = native_root[0] / "state.db"
    conn = opener()(path, authority=authority)
    conn.execute("CREATE TABLE records(value)")
    conn.commit()
    conn.close()
    verified = set(authority.verified_files)
    assert any(name == str(path) for name, _ in verified)
    again = opener()(path, authority=authority)
    again.close()
    assert authority.verified_files == verified


# A faithful copy of the connect_tracked() path of Hermes's
# hermes_cli/sqlite_safe_read.py (2026-11-19 checkout; docstrings trimmed).
# ``sqlite3`` is injected as a module global: Hermes sees either the guarded
# replacement module or the stdlib module it imported before the swap.
_HERMES_TRACKING_SOURCE = """
import secrets
import sys
import threading
from collections import deque
from pathlib import Path
from typing import Optional

_live_lock = threading.RLock()
_live_connections: dict[str, int] = {}
_released: deque[str] = deque()
_RELEASE_FUNCTION = f"_hermes_release_{secrets.token_hex(8)}"


class UntrackableConnectionError(RuntimeError):
    pass


def _key(path: Path | str) -> str:
    try:
        return str(Path(path).resolve())
    except OSError:
        return str(path)


def _canonical_db_path(conn: sqlite3.Connection) -> Optional[str]:
    try:
        row = conn.execute("PRAGMA database_list").fetchone()
    except sqlite3.Error:
        return None
    if not row or len(row) < 3 or not row[2]:
        return None
    return _key(row[2])


def _track_key(key: str, delta: int = 1) -> None:
    remaining = _live_connections.get(key, 0) + delta
    if remaining > 0:
        _live_connections[key] = remaining
    else:
        _live_connections.pop(key, None)


def _apply_releases() -> None:
    while _released:
        _track_key(_released.popleft(), -1)


class _ReleaseOnClose:
    __slots__ = ("armed", "key")

    def __init__(self, key: str) -> None:
        self.key = key
        self.armed = False

    def __call__(self) -> None:
        return None

    def __del__(self) -> None:
        if self.armed and _released is not None:
            _released.append(self.key)


def _live_main_key(key: str) -> Optional[str]:
    _apply_releases()
    if key in _live_connections:
        return key
    for suffix in ("-wal", "-shm"):
        if key.endswith(suffix) and key[:-len(suffix)] in _live_connections:
            return key[:-len(suffix)]
    return None


def has_live_connection(path: Path | str) -> bool:
    with _live_lock:
        return _live_main_key(_key(path)) is not None


class _TrackingMixin:
    _hermes_tracked_path: str | None = None

    def close(self) -> None:
        with _live_lock:
            super().close()
            self._hermes_tracked_path = None
            _apply_releases()


class TrackedConnection(_TrackingMixin, sqlite3.Connection):
    \"\"\"A sqlite3.Connection that untracks its path exactly once on close.\"\"\"


_tracked_factory_cache: dict[type, type] = {}


def _tracking_factory(factory: type) -> type:
    if factory is sqlite3.Connection:
        return TrackedConnection
    if issubclass(factory, _TrackingMixin):
        return factory
    cached = _tracked_factory_cache.get(factory)
    if cached is None:
        cached = type(f"Tracked{factory.__name__}", (_TrackingMixin, factory), {})
        _tracked_factory_cache[factory] = cached
    return cached


def connect_tracked(path, *, tracking_path=None, connect_fn=None, **kwargs):
    opener = connect_fn if connect_fn is not None else sqlite3.connect
    kwargs["factory"] = _tracking_factory(kwargs.get("factory", sqlite3.Connection))

    with _live_lock:
        conn = opener(str(path), **kwargs)
        try:
            resolved = _key(tracking_path) if tracking_path is not None else _canonical_db_path(conn)
            if resolved is None:
                return conn
            if not isinstance(conn, _TrackingMixin):
                conn = _retrofit_tracking(conn, resolved)
            _track_key(resolved)
            release = _ReleaseOnClose(resolved)
            try:
                before = sys.getrefcount(release)
                conn.create_function(_RELEASE_FUNCTION, 0, release)
                if sys.getrefcount(release) == before:
                    raise sqlite3.ProgrammingError("connection factory did not register the release function")
            except Exception:
                _track_key(resolved, -1)
                raise
            release.armed = True
            conn._hermes_tracked_path = resolved
            return conn
        except Exception:
            try:
                sqlite3.Connection.close(conn)
            except Exception:
                pass
            raise


def _retrofit_tracking(conn, resolved):
    cls = type(conn)
    try:
        conn.__class__ = _tracking_factory(cls)
        return conn
    except TypeError as exc:
        raise UntrackableConnectionError(f"connection to {resolved} uses factory {cls.__name__}") from exc
"""


def _hermes_tracking(sqlite3_module, monkeypatch=None, name="hermes_cli.sqlite_safe_read"):
    import types

    module = types.ModuleType(name)
    module.sqlite3 = sqlite3_module
    exec(compile(_HERMES_TRACKING_SOURCE, f"<{name}>", "exec"), module.__dict__)
    if monkeypatch is not None:
        monkeypatch.setitem(sys.modules, name, module)
    return module


def _hermes_for(native, hermes_sqlite3, monkeypatch):
    from mordred_hermes.dbcrypt._shim import stdlib_sqlite3

    return _hermes_tracking(native if hermes_sqlite3 == "protected" else stdlib_sqlite3(), monkeypatch)


def _stdlib_cannot_read(path):
    from mordred_hermes.dbcrypt._shim import stdlib_sqlite3

    stdlib = stdlib_sqlite3()
    conn = stdlib.connect(str(path))
    try:
        with pytest.raises(stdlib.DatabaseError):
            conn.execute("SELECT * FROM records").fetchall()
    finally:
        conn.close()


@pytest.mark.parametrize("hermes_sqlite3", ["protected", "stdlib"])
@pytest.mark.parametrize("factory", [None, "protected", "stdlib"])
def test_hermes_tracked_factory_opens_guarded_connection(native_root, authority, monkeypatch, hermes_sqlite3, factory):
    from mordred_hermes.dbcrypt._connection import ProtectedConnection
    from mordred_hermes.dbcrypt._shim import stdlib_sqlite3

    module = native_module(authority)
    stdlib = stdlib_sqlite3()
    hermes = _hermes_for(module, hermes_sqlite3, monkeypatch)
    expected_base = ProtectedConnection if hermes_sqlite3 == "protected" else stdlib.Connection
    assert hermes.TrackedConnection.__bases__ == (hermes._TrackingMixin, expected_base)
    path = native_root[0] / "state.db"
    key = str(path.resolve())
    factories = {"protected": module.Connection, "stdlib": stdlib.Connection}
    kwargs = {} if factory is None else {"factory": factories[factory]}
    conn = hermes.connect_tracked(path, connect_fn=module.connect, timeout=5.0, **kwargs)
    try:
        assert isinstance(conn, ProtectedConnection)
        assert isinstance(conn, hermes._TrackingMixin)
        assert conn._hermes_tracked_path == key
        assert hermes._live_connections == {key: 1}
        conn.execute("CREATE TABLE records(value)")
        conn.execute("INSERT INTO records VALUES (1)")
        conn.commit()
        cursor = conn.execute("SELECT value FROM records")
        assert cursor.connection is conn
        assert cursor.fetchall() == [(1,)]
        assert hermes.has_live_connection(path)
    finally:
        conn.close()
    # The raw handle's close freed the release sentinel; the mixin applied it.
    assert hermes._live_connections == {}
    assert not hermes._released
    assert not hermes.has_live_connection(path)
    assert conn._closed
    assert conn._hermes_tracked_path is None
    with pytest.raises(DatabaseRefused):
        conn.execute("SELECT 1")
    assert raw_rows(path, derive(native_root[2])) == [(1,)]
    _stdlib_cannot_read(path)
    assert _owned_handles(authority) == []
    authority.check()


@pytest.mark.parametrize("hermes_sqlite3", ["protected", "stdlib"])
def test_hermes_tracking_survives_annotation_introspection(native_root, authority, monkeypatch, hermes_sqlite3):
    import contextlib
    import typing

    from mordred_hermes.dbcrypt._connection import ProtectedConnection

    module = native_module(authority)
    hermes = _hermes_for(module, hermes_sqlite3, monkeypatch)
    for factory in (hermes.TrackedConnection, hermes._tracking_factory(ProtectedConnection)):
        assert factory.__annotations__ is not None
        # ProtectedConnection's own hints need not evaluate at runtime.
        with contextlib.suppress(NameError, TypeError):
            typing.get_type_hints(factory)
        # The introspection cached annotations in the class dict itself.
        assert set(vars(factory)) & {"__annotations__", "__annotate_func__", "__annotations_cache__"}
    path = native_root[0] / "state.db"
    for factory in (None, module.Connection):
        kwargs = {} if factory is None else {"factory": factory}
        conn = hermes.connect_tracked(path, connect_fn=module.connect, **kwargs)
        assert isinstance(conn, hermes._TrackingMixin)
        conn.close()
    assert hermes._live_connections == {}


def test_hermes_tracked_factory_is_dropped_not_instantiated(native_root, authority, monkeypatch):
    from mordred_hermes.dbcrypt._connection import ProtectedConnection

    module = native_module(authority)
    hermes = _hermes_tracking(module, monkeypatch)
    path = native_root[0] / "state.db"
    conn = module.connect(path, 5.0, 0, "", True, hermes.TrackedConnection)
    try:
        assert type(conn) is ProtectedConnection
        assert conn.execute("SELECT 1").fetchall() == [(1,)]
    finally:
        conn.close()


@pytest.mark.parametrize("hermes_sqlite3", ["protected", "stdlib"])
def test_hermes_release_sentinel_is_inert_from_sql(native_root, authority, monkeypatch, hermes_sqlite3):
    module = native_module(authority)
    hermes = _hermes_for(module, hermes_sqlite3, monkeypatch)
    path = native_root[0] / "state.db"
    conn = hermes.connect_tracked(path, connect_fn=module.connect)
    try:
        # The authorizer admits SQLITE_FUNCTION; the sentinel only returns NULL.
        assert conn.execute(f"SELECT {hermes._RELEASE_FUNCTION}()").fetchone() == (None,)
        assert hermes._live_connections == {str(path.resolve()): 1}
    finally:
        conn.close()
    assert hermes._live_connections == {}


def _create_function_call(case, hermes, monkeypatch):
    """(method, args, kwargs) for one refused registration on a guarded connection."""
    name = hermes._RELEASE_FUNCTION
    release = hermes._ReleaseOnClose("key")

    class Subclass(hermes._ReleaseOnClose):
        __slots__ = ()

    if case == "other_prefix":
        return "create_function", ("_hermes_releasx_" + name[-16:], 0, release), {}
    if case == "uppercase_hex":
        upper = "_hermes_release_" + name[-16:].upper()
        monkeypatch.setattr(hermes, "_RELEASE_FUNCTION", upper)
        return "create_function", (upper, 0, release), {}
    if case == "not_the_constant":
        other = "_hermes_release_" + ("0" * 16 if name[-16:] != "0" * 16 else "1" * 16)
        return "create_function", (other, 0, release), {}
    if case == "str_subclass":
        return "create_function", (type("Name", (str,), {})(name), 0, release), {}
    if case == "constant_not_str":
        monkeypatch.setattr(hermes, "_RELEASE_FUNCTION", type("Name", (str,), {})(name))
        return "create_function", (name, 0, release), {}
    if case == "narg_one":
        return "create_function", (name, 1, release), {}
    if case == "narg_false":
        return "create_function", (name, False, release), {}
    if case == "narg_negative":
        return "create_function", (name, -1, release), {}
    if case == "plain_callable":
        return "create_function", (name, 0, lambda: None), {}
    if case == "release_subclass":
        return "create_function", (name, 0, Subclass("key")), {}
    if case == "release_class_not_plain":

        class Base:
            pass

        class _ReleaseOnClose(Base):
            def __call__(self):
                return None

        monkeypatch.setattr(hermes, "_ReleaseOnClose", _ReleaseOnClose)
        return "create_function", (name, 0, _ReleaseOnClose()), {}
    if case == "deterministic_kwarg":
        return "create_function", (name, 0, release), {"deterministic": True}
    if case == "keyword_arguments":
        return "create_function", (), {"name": name, "narg": 0, "func": release}
    if case == "two_arguments":
        return "create_function", (name, 0), {}
    if case == "module_missing":
        monkeypatch.delitem(sys.modules, "hermes_cli.sqlite_safe_read")
        return "create_function", (name, 0, release), {}
    if case == "module_not_a_module":
        from types import SimpleNamespace

        monkeypatch.setitem(sys.modules, "hermes_cli.sqlite_safe_read", SimpleNamespace(**vars(hermes)))
        return "create_function", (name, 0, release), {}
    if case == "aggregate":
        return "create_aggregate", (name, 0, hermes._ReleaseOnClose), {}
    if case == "window_function":
        return "create_window_function", (name, 0, hermes._ReleaseOnClose), {}
    if case == "collation":
        return "create_collation", (name, release), {}
    raise AssertionError(case)


@pytest.mark.parametrize(
    "case",
    [
        "other_prefix",
        "uppercase_hex",
        "not_the_constant",
        "str_subclass",
        "constant_not_str",
        "narg_one",
        "narg_false",
        "narg_negative",
        "plain_callable",
        "release_subclass",
        "release_class_not_plain",
        "deterministic_kwarg",
        "keyword_arguments",
        "two_arguments",
        "module_missing",
        "module_not_a_module",
        "aggregate",
        "window_function",
        "collation",
    ],
)
def test_only_hermes_release_sentinel_function_is_admitted(native_root, authority, monkeypatch, case):
    module = native_module(authority)
    hermes = _hermes_tracking(module, monkeypatch)
    conn = module.connect(native_root[0] / "state.db")
    try:
        method, args, kwargs = _create_function_call(case, hermes, monkeypatch)
        with pytest.raises(DatabaseRefused, match="requires an authorized implementation"):
            getattr(conn, method)(*args, **kwargs)
        name = hermes._RELEASE_FUNCTION
        with pytest.raises(sc.OperationalError, match="no such function"):
            conn.execute(f"SELECT {name}()")
        assert conn.execute("SELECT 1").fetchone() == (1,)
    finally:
        conn.close()


def test_release_sentinel_admission_still_checks_authority(native_root, authority, monkeypatch):
    root = native_root[0]
    module = native_module(authority)
    hermes = _hermes_tracking(module, monkeypatch)
    conn = module.connect(root / "state.db")
    release = hermes._ReleaseOnClose("key")
    (root / "mordred/db-encryption.marker").unlink()
    with pytest.raises(DatabaseRefused):
        conn.create_function(hermes._RELEASE_FUNCTION, 0, release)
    assert authority.terminal
    conn.close()


@pytest.mark.parametrize("hermes_sqlite3", ["protected", "stdlib"])
def test_failed_hermes_registration_disposes_connection(native_root, authority, monkeypatch, hermes_sqlite3):
    from mordred_hermes.dbcrypt import _connection

    module = native_module(authority)
    hermes = _hermes_for(module, hermes_sqlite3, monkeypatch)
    # Upstream reads the constant at call time; an uppercase name fails admission.
    monkeypatch.setattr(hermes, "_RELEASE_FUNCTION", hermes._RELEASE_FUNCTION.upper())
    path = native_root[0] / "state.db"
    before = len(_connection._LIVE_CONNECTIONS)
    try:
        hermes.connect_tracked(path, connect_fn=module.connect)
    except DatabaseRefused:
        pass
    else:
        raise AssertionError("registration was admitted")
    assert hermes._live_connections == {}
    if hermes_sqlite3 == "protected":
        # sqlite3.Connection.close(conn) is ProtectedConnection.close: disposed at once.
        assert len(_connection._LIVE_CONNECTIONS) == before
        assert _owned_handles(authority) == []
    # Over the stdlib base, upstream's C close raises TypeError (swallowed); the
    # dropped facade's finalizer queues its owner and the next admission reaps it.
    gc.collect()
    module.connect(":memory:").close()
    assert len(_connection._LIVE_CONNECTIONS) == before
    assert _owned_handles(authority) == []
    authority.check()


def _refused_tracking_factory(case, hermes, monkeypatch):
    from mordred_hermes.dbcrypt._connection import ProtectedConnection
    from mordred_hermes.dbcrypt._shim import stdlib_sqlite3

    mixin = hermes._TrackingMixin

    class Extra:
        pass

    class GuardedSubclass(ProtectedConnection):
        pass

    if case == "extra_method":
        return type("TrackedProtectedConnection", (mixin, ProtectedConnection), {"execute": lambda self, *a: None})
    if case == "extra_attribute":
        return type("TrackedProtectedConnection", (mixin, ProtectedConnection), {"_hermes_tracked_path": "x"})
    if case == "foreign_mixin_module":
        other = _hermes_tracking(hermes.sqlite3, monkeypatch, name="other_hermes.sqlite_safe_read")
        return other.TrackedConnection
    if case == "module_not_loaded":
        monkeypatch.delitem(sys.modules, "hermes_cli.sqlite_safe_read")
        return hermes.TrackedConnection
    if case == "mixin_not_plain":

        class Base:
            pass

        class _TrackingMixin(Base):
            pass

        monkeypatch.setattr(hermes, "_TrackingMixin", _TrackingMixin)
        return type("TrackedProtectedConnection", (_TrackingMixin, ProtectedConnection), {})
    if case == "mixin_not_class":
        monkeypatch.setattr(hermes, "_TrackingMixin", object())
        return hermes.TrackedConnection
    if case == "three_bases":
        return type("TrackedProtectedConnection", (mixin, Extra, ProtectedConnection), {})
    if case == "reversed_bases":
        return type("TrackedProtectedConnection", (ProtectedConnection, mixin), {})
    if case == "mixin_over_sqlcipher":
        return type("TrackedConnection", (mixin, sc.Connection), {})
    if case == "mixin_over_guarded_subclass":
        return type("TrackedGuardedSubclass", (mixin, GuardedSubclass), {})
    if case == "tracked_subclass":
        return type("TrackedConnection", (hermes.TrackedConnection,), {})
    if case == "stdlib_subclass":
        return type("Connection", (stdlib_sqlite3().Connection,), {})
    if case == "guarded_subclass":
        return GuardedSubclass
    if case == "mixin_alone":
        return mixin
    if case == "not_a_type":
        return lambda *a, **kw: sc.connect(*a, **kw)
    raise AssertionError(case)


@pytest.mark.parametrize("hermes_sqlite3", ["protected", "stdlib"])
@pytest.mark.parametrize(
    "case",
    [
        "extra_method",
        "extra_attribute",
        "foreign_mixin_module",
        "module_not_loaded",
        "mixin_not_plain",
        "mixin_not_class",
        "three_bases",
        "reversed_bases",
        "mixin_over_sqlcipher",
        "mixin_over_guarded_subclass",
        "tracked_subclass",
        "stdlib_subclass",
        "guarded_subclass",
        "mixin_alone",
        "not_a_type",
    ],
)
def test_lookalike_tracking_factories_are_refused(native_root, authority, monkeypatch, hermes_sqlite3, case):
    module = native_module(authority)
    hermes = _hermes_for(module, hermes_sqlite3, monkeypatch)
    factory = _refused_tracking_factory(case, hermes, monkeypatch)
    path = native_root[0] / "state.db"
    with pytest.raises(DatabaseRefused, match="custom connection factories"):
        module.connect(path, factory=factory)
    with pytest.raises(DatabaseRefused, match="custom connection factories"):
        module.connect(path, 5.0, 0, "", True, factory)
    assert not path.exists()


@pytest.mark.parametrize("hermes_sqlite3", ["protected", "stdlib"])
def test_revocation_closes_and_releases_hermes_tracked_connection(native_root, authority, monkeypatch, hermes_sqlite3):
    root, _, material, _ = native_root
    path = root / "state.db"
    module = native_module(authority)
    hermes = _hermes_for(module, hermes_sqlite3, monkeypatch)
    conn = hermes.connect_tracked(path, connect_fn=module.connect)
    conn.execute("CREATE TABLE records(value)")
    conn.execute("INSERT INTO records VALUES (1)")
    conn.commit()
    conn.execute("INSERT INTO records VALUES (2)")
    cursor = conn.execute("SELECT value FROM records ORDER BY value")
    assert hermes.has_live_connection(path)
    (root / "mordred/db-encryption.marker").unlink()
    with pytest.raises(DatabaseRefused):
        conn.execute("INSERT INTO records VALUES (3)")
    assert authority.terminal
    assert conn._revoked
    assert conn._closed
    # Disposal closed the raw handle, so SQLite already freed the sentinel.
    assert not hermes.has_live_connection(path)
    assert hermes._live_connections == {}
    with pytest.raises(DatabaseRefused):
        cursor.fetchone()
    assert raw_rows(path, derive(material)) == [(1,)]
    conn.close()
    assert hermes._live_connections == {}
    assert conn._hermes_tracked_path is None
