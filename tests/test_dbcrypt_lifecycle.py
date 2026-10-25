"""Database conversions must exclude readers and preserve protection on failure."""

from __future__ import annotations

import os
import select
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest

from mordred_hermes import dbcrypt
from mordred_hermes.dbcrypt import _key, _migrate, _shim
from mordred_hermes.dbcrypt._locking import runtime_lease


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


def _database(home: Path) -> Path:
    path = home / "state.db"
    with sqlite3.connect(path) as conn:
        conn.execute("CREATE TABLE messages (content TEXT)")
        conn.execute("INSERT INTO messages VALUES ('before conversion')")
    conn.close()
    return path


def test_wrong_key_decryption_preserves_marker_and_all_databases(tmp_path: Path) -> None:
    pytest.importorskip("sqlcipher3")
    path = _database(tmp_path)
    key = _key.derive(bytes(range(32)))
    _migrate.migrate(tmp_path, key, arm=dbcrypt.arm, holders_of=lambda _: [])
    before = path.read_bytes()
    with pytest.raises(_migrate.MigrationError, match="unreadable"):
        _migrate.decrypt_all(tmp_path, _key.derive(bytes(32)), holders_of=lambda _: [])
    assert path.read_bytes() == before
    assert dbcrypt.marker_path(tmp_path).is_file()
    assert not _migrate.journal_path(tmp_path).exists()


_START_READER = """
import sys
from pathlib import Path
from mordred_hermes import dbcrypt
from mordred_hermes.dbcrypt import _key
sys.platform = 'darwin'
home = Path(sys.argv[1])
provider = _key.KeyProvider(environ={'HERMES_MEMORY_KEY': 'hex:' + bytes(range(32)).hex()}, inject=lambda: 0)
print('starting', flush=True)
dbcrypt.install(home=home, provider=provider)
print('ready', flush=True)
sys.stdin.readline()
import sqlite3
with sqlite3.connect(str(home / 'state.db')) as conn:
    conn.execute("INSERT INTO messages VALUES ('after conversion')")
conn.close()
"""


def test_a_starting_reader_waits_for_the_prepared_copy(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    pytest.importorskip("sqlcipher3")
    path = _database(tmp_path)
    key = _key.derive(bytes(range(32)))
    prepare = _migrate.prepare
    child: subprocess.Popen[str] | None = None

    def pause(database: _migrate.Database, key: _key.DatabaseKey, **kwargs) -> Path:
        nonlocal child
        copy = prepare(database, key, **kwargs)
        child = subprocess.Popen(
            [sys.executable, "-c", _START_READER, str(tmp_path)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        assert child.stdout is not None
        assert child.stdout.readline().strip() == "starting"
        # The handshake puts the child at install(), while the real converter
        # still owns its lock and its replacement file is already complete.
        assert not select.select([child.stdout], [], [], 0.3)[0], "reader bypassed the active conversion"
        return copy

    monkeypatch.setattr(_migrate, "prepare", pause)
    try:
        _migrate.migrate(tmp_path, key, arm=dbcrypt.arm, holders_of=lambda _: [])
        assert child is not None
        out, err = child.communicate("continue\n", timeout=15)
        assert child.returncode == 0, err
        assert "ready" in out
        sc = _migrate._sqlcipher()
        conn = sc.connect(str(path))
        try:
            _shim.apply_key(conn, key)
            assert conn.execute("SELECT content FROM messages ORDER BY rowid").fetchall() == [
                ("before conversion",),
                ("after conversion",),
            ]
        finally:
            conn.close()
    finally:
        if child is not None and child.poll() is None:
            child.kill()
            child.communicate()


def test_a_running_reader_prevents_conversion_even_before_opening_a_database(tmp_path: Path) -> None:
    pytest.importorskip("sqlcipher3")
    path = _database(tmp_path)
    before = path.read_bytes()
    child = subprocess.Popen(
        [sys.executable, "-c", _START_READER, str(tmp_path)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        assert child.stdout is not None
        assert child.stdout.readline().strip() == "starting"
        assert child.stdout.readline().strip() == "ready"
        with pytest.raises(_migrate.MigrationError, match=r"running|using|busy"):
            _migrate.migrate(tmp_path, _key.derive(bytes(range(32))), arm=dbcrypt.arm, holders_of=lambda _: [])
        assert path.read_bytes() == before
        assert not dbcrypt.marker_path(tmp_path).exists()
    finally:
        child.kill()
        child.communicate()


def test_enabling_an_empty_home_waits_for_existing_runtimes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    pytest.importorskip("sqlcipher3")
    from mordred_hermes.wizard import databases_cli

    monkeypatch.setattr(sys, "platform", "darwin")
    monkeypatch.setattr(sys, "argv", ["hermes"])
    assert dbcrypt.install(home=tmp_path) is False
    key = _key.derive(bytes(range(32)))
    monkeypatch.setattr(_key, "KeyProvider", lambda: lambda: key)
    assert databases_cli.databases_encrypt(home=tmp_path) == 1
    assert not dbcrypt.marker_path(tmp_path).exists()
    assert not _migrate.pending_path(tmp_path).exists()


@pytest.mark.skipif(not hasattr(os, "fork"), reason="POSIX fork lifetime")
def test_a_forked_runtime_keeps_its_lease_after_the_parent_exits(tmp_path: Path) -> None:
    pytest.importorskip("sqlcipher3")
    _database(tmp_path)
    script = """
import os, sys
from pathlib import Path
from mordred_hermes import dbcrypt
sys.platform = 'darwin'
dbcrypt.install(home=Path(sys.argv[1]))
if os.fork():
    os._exit(0)
print('child-ready', flush=True)
sys.stdin.readline()
"""
    child = subprocess.Popen(
        [sys.executable, "-c", script, str(tmp_path)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        assert child.stdout is not None
        assert child.stdout.readline().strip() == "child-ready"
        assert child.wait(timeout=10) == 0  # original runtime gone; forked worker still alive
        with pytest.raises(_migrate.MigrationError, match="running"):
            _migrate.migrate(tmp_path, _key.derive(bytes(range(32))), arm=dbcrypt.arm, holders_of=lambda _: [])
    finally:
        child.communicate("exit\n", timeout=10)


@pytest.mark.parametrize(
    "argv",
    [
        ["hermes-mordred", "databases", "status"],
        ["hermes-mordred", "--no-color", "databases", "encrypt", "--dry-run"],
        ["hermes-mordred", "--no-col", "uninstall", "--dry-run"],
        ["hermes", "--model", "mordred", "--no-restore-cwd", "mordred", "--profile", "work", "databases", "status"],
        ["hermes", "--profile=work", "mordred", "uninstall", "--dry-run"],
        ["hermes", "mordred", "-p", "work", "databases", "encrypt", "--dry-run"],
        ["hermes", "--profile", "work", "--model=x", "mordred", "databases", "status"],
    ],
)
def test_maintenance_startup_does_not_execute_pending_conversions(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, argv: list[str]
) -> None:
    pytest.importorskip("sqlcipher3")
    path = _database(tmp_path)
    before = path.read_bytes()
    monkeypatch.setattr(sys, "platform", "darwin")
    monkeypatch.setattr(sys, "argv", argv)
    monkeypatch.setitem(sys.modules, "sqlite3", sqlite3)
    monkeypatch.setitem(sys.modules, "sqlite3.dbapi2", sqlite3.dbapi2)
    _migrate.schedule(tmp_path)
    provider = _key.KeyProvider(environ={"HERMES_MEMORY_KEY": "hex:" + bytes(range(32)).hex()}, inject=lambda: 0)
    assert dbcrypt.install(home=tmp_path, provider=provider) is False
    assert path.read_bytes() == before
    assert _migrate.pending_path(tmp_path).exists()
    assert not dbcrypt.marker_path(tmp_path).exists()


@pytest.mark.parametrize(
    "argv",
    [
        ["hermes", "--model", "mordred", "databases", "status"],
        ["hermes", "--oneshot", "mordred databases", "mordred", "databases", "status"],
    ],
)
def test_agent_arguments_do_not_bypass_database_protection(monkeypatch: pytest.MonkeyPatch, argv: list[str]) -> None:
    monkeypatch.setattr(sys, "argv", argv)
    assert dbcrypt._maintenance_process() is False


def test_startup_joins_runtime_that_already_recovered_the_journal(tmp_path: Path) -> None:
    pytest.importorskip("sqlcipher3")
    _database(tmp_path)
    journal = _migrate.journal_path(tmp_path)
    journal.parent.mkdir(parents=True)
    journal.write_text('{"direction": "decrypt", "swaps": []}')
    script = """
import sys
from contextlib import contextmanager
from pathlib import Path
from mordred_hermes import dbcrypt
from mordred_hermes.dbcrypt import _migrate, _key
sys.platform = 'darwin'
original = _migrate.migration_lock
@contextmanager
def delayed(*args, **kwargs):
    print('recovering', flush=True)
    sys.stdin.readline()
    with original(*args, **kwargs):
        yield
_migrate.migration_lock = delayed
provider = _key.KeyProvider(environ={"HERMES_MEMORY_KEY": "hex:" + bytes(range(32)).hex()}, inject=lambda: 0)
dbcrypt.install(home=Path(sys.argv[1]), provider=provider)
print('ready', flush=True)
"""
    child = subprocess.Popen(
        [sys.executable, "-c", script, str(tmp_path)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        assert child.stdout is not None
        assert child.stdout.readline().strip() == "recovering"
        with _migrate.migration_lock(tmp_path):
            # Simulate the other authenticated recovery completing publication.
            journal.unlink()
        with runtime_lease(tmp_path):
            # Another startup now owns a lifetime reader lease. The child saw
            # the old journal, but must join this reader instead of needing EX.
            out, err = child.communicate("continue\n", timeout=3)
            assert child.returncode == 0, err
            assert "ready" in out
    finally:
        if child.poll() is None:
            child.kill()
            child.communicate()


@pytest.mark.parametrize("platform", ["linux", "win32"])
@pytest.mark.parametrize("configured", [False, True])
def test_native_platform_missing_prerequisites_refuses_before_sql_or_auth(
    tmp_path: Path, platform: str, configured: bool
) -> None:
    path = _database(tmp_path)
    before = path.read_bytes()
    if configured:
        dbcrypt.arm(tmp_path)
    marker = dbcrypt.marker_path(tmp_path)
    marker_before = marker.read_bytes() if configured else None
    script = """
import importlib.abc
import os
import sqlite3
import _sqlite3
import sys
from pathlib import Path
from unittest.mock import patch
# POSIX hosts exercise the real missing-fcntl boundary for Linux. Cross-host
# native domain adapters are unavailable dependencies, never mocked successes.
if sys.argv[2] == 'win32':
    missing_lock = 'mordred_hermes._database_locking_windows'
elif os.name == 'nt':
    missing_lock = 'mordred_hermes._database_locking_posix'
else:
    missing_lock = 'fcntl'
class Unavailable(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname == missing_lock or fullname == 'fcntl' or fullname.startswith('sqlcipher3'):
            raise ModuleNotFoundError(fullname, name=fullname)
for name in (missing_lock, 'fcntl'):
    sys.modules.pop(name, None)
sys.meta_path.insert(0, Unavailable())
sys.platform = sys.argv[2]
from mordred_hermes import dbcrypt
from mordred_hermes import _database_lifecycle
from mordred_hermes._database_contracts import DatabaseRefused
from mordred_hermes.dbcrypt._authority import Authority
from mordred_hermes.wizard import databases_cli
home = Path(sys.argv[1])
configured = sys.argv[3] == 'True'
forbidden_calls = []
def forbidden(*args, **kwargs):
    forbidden_calls.append('SQL, native authentication or passive lease acquisition')
    raise AssertionError('unavailable capability must not authenticate or open SQL')
sqlite3.connect = _sqlite3.connect = forbidden
Authority.acquire = forbidden
# Status must remain metadata-only even when the lock and SQLCipher cannot load.
with patch.object(_database_lifecycle, '_open', forbidden):
    status = dbcrypt.database_status(home)
    assert status.configured is configured
    assert status.capability == 'unavailable'
    assert status.authenticated is False
    assert status.dependencies == 1 + int(configured)
    reasons = {'SQLCipher driver extra is unavailable'}
    if sys.platform == 'win32':
        reasons |= {
            'Windows VFS native qualification is incomplete',
            'Windows SQLCipher driver pair is unqualified',
            'owned Windows VFS asset is unavailable',
        }
    assert status.reason in reasons, status
    assert databases_cli.databases_status(home=home) == 0
assert forbidden_calls == []
if configured:
    try:
        dbcrypt.install(home=home)
    except RuntimeError as exc:
        assert str(exc) == 'database runtime unavailable: ' + status.reason
    else:
        raise AssertionError('configured native runtime admitted unavailable capability')
else:
    # A plain native runtime still needs checked domain identity and lifetime
    # SH; the missing native adapter or fcntl must refuse before opening SQL.
    try:
        dbcrypt.install(home=home)
    except ModuleNotFoundError as exc:
        assert missing_lock == 'fcntl'
        assert exc.name == missing_lock, exc
    except DatabaseRefused as exc:
        assert missing_lock != 'fcntl'
        assert str(exc) == 'native database source is unavailable or invalid'
        assert isinstance(exc.__cause__, ModuleNotFoundError)
        assert exc.__cause__.name == missing_lock
    else:
        raise AssertionError('plain native runtime started without its lock dependency')
assert databases_cli.databases_encrypt(home=home) == 1
assert databases_cli.databases_decrypt(home=home) == 1
assert forbidden_calls == []
"""
    result = subprocess.run(
        [sys.executable, "-c", script, str(tmp_path), platform, str(configured)],
        env={**os.environ, "HERMES_HOME": str(tmp_path)},
        capture_output=True,
        text=True,
        timeout=15,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "capability: unavailable" in result.stdout.lower()
    assert "authenticated: not checked" in result.stdout.lower()
    assert path.read_bytes() == before
    assert (marker.read_bytes() if marker.exists() else None) == marker_before


def test_fresh_home_setup_bootstrap_initializes_only_the_legacy_boundary(tmp_path: Path) -> None:
    home = tmp_path / "fresh-hermes"
    script = r"""
import sys
from pathlib import Path
sys.platform = 'darwin'
sys.argv = ['hermes', 'setup']
from mordred_hermes._runtime_bootstrap import run
run()
"""
    result = subprocess.run(
        [sys.executable, "-c", script],
        env={**os.environ, "HERMES_HOME": str(home)},
        text=True,
        capture_output=True,
        timeout=15,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert home.is_dir() and (home / "mordred/db-encryption.lock").is_file()
    assert not (home / "state.db").exists()


def test_missing_identified_root_is_not_silently_recreated(tmp_path: Path) -> None:
    from mordred_hermes._database_contracts import DatabaseRefused
    from mordred_hermes._database_lifecycle import acquire_runtime

    missing = tmp_path / "missing-managed-root"
    with pytest.raises(DatabaseRefused), acquire_runtime(missing):
        pytest.fail("core authority recreated a missing identified root")
    assert not missing.exists()


def test_legacy_bootstrap_never_recreates_an_already_observed_root(tmp_path: Path) -> None:
    from mordred_hermes._database_contracts import DatabaseRefused

    root = tmp_path / "observed"
    root.mkdir()
    with runtime_lease(root):
        pass
    root.rename(tmp_path / "retired-observed")
    with pytest.raises(DatabaseRefused), runtime_lease(root):
        pytest.fail("legacy startup recreated a root it already knew")
    assert not root.exists()
    # This test owns no installed shim: explicitly retire its synthetic lifetime.
    from mordred_hermes.dbcrypt._locking import _LEASES

    context, _lease = _LEASES.pop(root.absolute())
    context.__exit__(None, None, None)


@pytest.mark.skipif(not hasattr(os, "fork"), reason="POSIX fork lifecycle")
@pytest.mark.parametrize("closed", [False, True])
def test_offline_sql_fork_quarantines_cursors_before_child_finalization(tmp_path, closed):
    script = r"""
import gc, os, sys
from pathlib import Path
from mordred_hermes.keyvault import kek
kek._noop_audit = lambda entry: None
import sqlcipher3.dbapi2 as sc
from mordred_hermes._database_lifecycle import acquire_exclusive
from mordred_hermes.dbcrypt._migrate import _offline_connection
root = Path(os.environ['HERMES_HOME'])
path = root / 'state.db'
raw = sc.connect(str(path))
raw.execute('CREATE TABLE data(value TEXT)')
raw.commit()
raw.close()
closed = sys.argv[1] == 'True'
with acquire_exclusive(root) as lease:
    with _offline_connection(path) as connection:
        connection.execute("INSERT INTO data VALUES ('pending parent')")
        cursor = connection.execute('SELECT value FROM data')
        if closed:
            connection.rollback()
            connection.close()
        child = os.fork()
        if child == 0:
            del connection, cursor
            gc.collect()
            sys.exit(0)
        _, status = os.waitpid(child, 0)
        assert os.waitstatus_to_exitcode(status) == (0 if closed else 74), status
        lease.assert_held(root)
        if not closed:
            assert cursor.fetchall() == [('pending parent',)]
            connection.commit()
with sc.connect(str(path)) as raw:
    assert raw.execute('SELECT value FROM data').fetchall() == ([] if closed else [('pending parent',)])
raw.close()
"""
    result = subprocess.run(
        [sys.executable, "-c", script, str(closed)],
        env={**os.environ, "HERMES_HOME": str(tmp_path)},
        text=True,
        capture_output=True,
        timeout=15,
    )
    assert result.returncode == 0, result.stdout + result.stderr
