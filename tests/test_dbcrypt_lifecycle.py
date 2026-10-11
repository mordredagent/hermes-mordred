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

    def pause(database: _migrate.Database, key: _key.DatabaseKey) -> Path:
        nonlocal child
        copy = prepare(database, key)
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
    assert databases_cli.databases_encrypt(home=tmp_path) == 0
    assert not dbcrypt.marker_path(tmp_path).exists()
    assert _migrate.pending_path(tmp_path).exists()


@pytest.mark.parametrize(
    "args", [["databases", "status"], ["databases", "encrypt", "--dry-run"], ["uninstall", "--dry-run"]]
)
def test_maintenance_startup_does_not_execute_pending_conversions(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, args: list[str]
) -> None:
    pytest.importorskip("sqlcipher3")
    path = _database(tmp_path)
    before = path.read_bytes()
    monkeypatch.setattr(sys, "platform", "darwin")
    monkeypatch.setattr(sys, "argv", ["hermes-mordred", *args])
    monkeypatch.setitem(sys.modules, "sqlite3", sqlite3)
    monkeypatch.setitem(sys.modules, "sqlite3.dbapi2", sqlite3.dbapi2)
    _migrate.schedule(tmp_path)
    provider = _key.KeyProvider(environ={"HERMES_MEMORY_KEY": "hex:" + bytes(range(32)).hex()}, inject=lambda: 0)
    assert dbcrypt.install(home=tmp_path, provider=provider) is False
    assert path.read_bytes() == before
    assert _migrate.pending_path(tmp_path).exists()
    assert not dbcrypt.marker_path(tmp_path).exists()


@pytest.mark.parametrize("platform", ["linux", "win32"])
@pytest.mark.parametrize("encrypted", [False, True])
def test_unsupported_platform_without_posix_or_sqlcipher(tmp_path: Path, platform: str, encrypted: bool) -> None:
    path = _database(tmp_path)
    before = path.read_bytes()
    if encrypted:
        dbcrypt.arm(tmp_path)
    script = """
import importlib.abc
import sys
from pathlib import Path
class Unavailable(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname == 'fcntl' or fullname.startswith('sqlcipher3'):
            raise ModuleNotFoundError(fullname)
sys.modules.pop('fcntl', None)
sys.meta_path.insert(0, Unavailable())
sys.platform = sys.argv[2]
from mordred_hermes import dbcrypt
from mordred_hermes.dbcrypt import _monitor
from mordred_hermes.wizard import databases_cli
home = Path(sys.argv[1])
if sys.argv[3] == 'True':
    try:
        dbcrypt.install(home=home)
    except RuntimeError as exc:
        assert 'macOS' in str(exc), str(exc)
    else:
        raise AssertionError('encrypted home was admitted on unsupported platform')
    assert any(f.code == 'unsupported_platform' for f in _monitor.check(home))
    assert databases_cli.databases_status(home=home) == 1
else:
    assert dbcrypt.install(home=home) is False
    assert _monitor.check(home) == []
    assert databases_cli.databases_status(home=home) == 0
assert databases_cli.databases_encrypt(home=home) == 1
assert databases_cli.databases_decrypt(home=home) == 1
"""
    result = subprocess.run(
        [sys.executable, "-c", script, str(tmp_path), platform, str(encrypted)],
        env={**os.environ, "HERMES_HOME": str(tmp_path)},
        capture_output=True,
        text=True,
        timeout=15,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "unsupported" in result.stdout.lower()
    assert path.read_bytes() == before
