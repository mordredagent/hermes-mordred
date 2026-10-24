"""Owned-I/O acceptance; explicitly gated, synthetic ordinary-user NTFS only."""

from __future__ import annotations

import ctypes
import json
import os
import subprocess
import sys
import uuid
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from mordred_hermes.dbcrypt._windows_vfs import register_checked_vfs

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        sys.platform != "win32" or os.environ.get("MORDRED_DBCRYPT_WINDOWS_VFS_TEST") != "1",
        reason="explicit ordinary-user Windows checked VFS acceptance",
    ),
]


@pytest.fixture
def fixture() -> Iterator[tuple[Any, Any, Path]]:
    import sqlcipher3.dbapi2 as driver

    from mordred_hermes._private_fs import open_private_directory

    assert not ctypes.windll.shell32.IsUserAnAdmin(), "elevation is not ordinary-user evidence"
    text = os.environ.get("MORDRED_DBCRYPT_TEST_ROOT")
    assert text, "explicit synthetic root required"
    parent = Path(text)
    assert parent.is_absolute() and parent.is_dir() and parent.name.startswith("mordred-dbcrypt-")
    root = parent / ("checked-" + uuid.uuid4().hex)
    with open_private_directory(root, create=True):
        pass
    registration = register_checked_vfs(driver, root=root)
    try:
        yield driver, registration, root
    finally:
        registration.close()


def connect(driver: Any, root: Path, name: str = "synthetic.db") -> Any:
    connection = driver.connect(f"file:{(root / name).as_posix()}?vfs=mordred_checked_v1", uri=True, timeout=0)
    connection.execute("PRAGMA key='synthetic acceptance fixture only'")
    return connection


def stats(registration: Any) -> dict[str, int]:
    native = registration._native
    native.mordred_vfs_stats.argtypes = [ctypes.c_uint64, ctypes.c_char_p, ctypes.c_int]
    native.mordred_vfs_stats.restype = ctypes.c_int
    buffer = ctypes.create_string_buffer(2048)
    assert native.mordred_vfs_stats(registration._token, buffer, len(buffer)) == 0
    return json.loads(buffer.value)


def test_rollback_wal_temp_vacuum_and_bootstrap_lifetime(fixture: tuple[Any, Any, Path]) -> None:
    driver, registration, root = fixture
    connection = connect(driver, root)
    try:
        assert connection.execute("PRAGMA temp_store").fetchone() == (2,)
        connection.execute("CREATE TABLE data(value TEXT)")
        connection.executemany("INSERT INTO data VALUES (?)", [(str(n) * 100,) for n in range(2000)])
        connection.commit()
        connection.execute("CREATE INDEX data_value ON data(value)")
        connection.execute("CREATE TEMP TABLE sorted AS SELECT * FROM data ORDER BY value")
        assert connection.execute("SELECT count(*) FROM sorted").fetchone() == (2000,)
        connection.commit()
        # VACUUM's internal ATTACH cannot yet be distinguished from a user
        # ATTACH safely. Refusal must precede changing the main database.
        before_vacuum = (root / "synthetic.db").read_bytes()
        with pytest.raises(driver.DatabaseError):
            connection.execute("VACUUM")
        assert (root / "synthetic.db").read_bytes() == before_vacuum
        assert connection.execute("PRAGMA journal_mode=WAL").fetchone() == ("wal",)
        connection.execute("INSERT INTO data VALUES ('wal fixture')")
        connection.commit()
        connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        with pytest.raises(RuntimeError, match="busy"):
            registration.close()
    finally:
        connection.close()
    counters = stats(registration)
    assert all(counters[name] > 0 for name in ("xOpen", "xDelete", "xShmMap", "xShmUnmap", "xSync", "xTruncate"))
    assert counters["created"] == counters["private_at_creation"]
    assert counters["unchecked_opens"] == 0
    assert not (root / "synthetic.db-shm").exists()
    assert not (root / "synthetic.db-wal").exists()
    keyless = driver.connect(str(root / "synthetic.db"))
    try:
        with pytest.raises(driver.DatabaseError):
            keyless.execute("SELECT * FROM data").fetchall()
    finally:
        keyless.close()


@pytest.mark.parametrize(
    "sql",
    [
        "ATTACH ':memory:' AS other",
        "PRAGMA temp_store=FILE",
        "SELECT load_extension('untrusted.dll')",
        "VACUUM INTO 'outside.db'",
    ],
)
def test_unsupported_sql_refuses_before_writes(fixture: tuple[Any, Any, Path], sql: str) -> None:
    driver, registration, root = fixture
    connection = connect(driver, root)
    try:
        connection.execute("CREATE TABLE data(value)")
        connection.commit()
        before = {p.name: p.read_bytes() for p in root.iterdir()}
        opened = stats(registration)["xOpen"]
        with pytest.raises(driver.DatabaseError):
            connection.execute(sql)
        assert stats(registration)["xOpen"] == opened
        assert {p.name: p.read_bytes() for p in root.iterdir()} == before
    finally:
        connection.close()


def test_hardlink_refuses_before_data_open(fixture: tuple[Any, Any, Path]) -> None:
    driver, registration, root = fixture
    connection = connect(driver, root)
    connection.execute("CREATE TABLE data(value)")
    connection.commit()
    connection.close()
    before = (root / "synthetic.db").read_bytes()
    os.link(root / "synthetic.db", root / "alias.db")
    opened = stats(registration)["data_opens"]
    with pytest.raises(driver.DatabaseError):
        connect(driver, root)
    assert stats(registration)["data_opens"] == opened
    assert (root / "synthetic.db").read_bytes() == before


def test_same_process_and_multiprocess_writer_exclusion(fixture: tuple[Any, Any, Path]) -> None:
    driver, _registration, root = fixture
    first, second = connect(driver, root), connect(driver, root)
    try:
        first.execute("CREATE TABLE data(value)")
        first.commit()
        for mode in ("DELETE", "WAL"):
            first.execute(f"PRAGMA journal_mode={mode}")
            first.execute("BEGIN IMMEDIATE")
            first.execute("INSERT INTO data VALUES ('uncommitted')")
            with pytest.raises(driver.OperationalError, match="locked"):
                second.execute("BEGIN IMMEDIATE")
            child = r"""
import sys
from pathlib import Path
import sqlcipher3.dbapi2 as driver
from mordred_hermes.dbcrypt._windows_vfs import register_checked_vfs
root = Path(sys.argv[1])
r = register_checked_vfs(driver, root=root)
c = driver.connect('file:' + (root / 'synthetic.db').as_posix() + '?vfs=' + r.name, uri=True, timeout=0)
c.execute("PRAGMA key='synthetic acceptance fixture only'")
try:
    c.execute('BEGIN IMMEDIATE')
except driver.OperationalError as error:
    assert 'locked' in str(error)
else:
    raise AssertionError('concurrent writer admitted')
c.close()
r.close()
"""
            result = subprocess.run(
                [sys.executable, "-c", child, str(root)], capture_output=True, text=True, timeout=30
            )
            assert result.returncode == 0, (result.stdout, result.stderr)
            first.rollback()
            second.execute("BEGIN IMMEDIATE")
            second.rollback()
    finally:
        first.close()
        second.close()


def test_sidecar_creation_race_has_no_public_window(fixture: tuple[Any, Any, Path]) -> None:
    # Root replacement attempts cannot succeed while the native lease pins it.
    # Creation DACL counters are native handle checks made before any data I/O.
    import threading

    driver, registration, root = fixture
    stop = threading.Event()
    replaced: list[bool] = []

    def race() -> None:
        while not stop.wait(0.001):
            try:
                root.rename(root.with_name(root.name + "-replaced"))
            except OSError:
                continue
            replaced.append(True)
            return

    thread = threading.Thread(target=race)
    thread.start()
    try:
        for index in range(12):
            connection = connect(driver, root, f"race-{index}.db")
            try:
                connection.execute("CREATE TABLE data(value)")
                connection.commit()
                connection.execute("PRAGMA journal_mode=WAL")
                connection.execute("INSERT INTO data VALUES ('synthetic')")
                connection.commit()
            finally:
                connection.close()
    finally:
        stop.set()
        thread.join(timeout=10)
    assert not thread.is_alive() and not replaced
    counters = stats(registration)
    assert counters["created"] >= 48
    assert counters["created"] == counters["private_at_creation"]
    assert counters["unchecked_opens"] == 0
