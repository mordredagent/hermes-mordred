"""Owned-I/O acceptance; explicitly gated, synthetic ordinary-user NTFS only."""

from __future__ import annotations

import ctypes
import json
import os
import subprocess
import sys
import uuid
from collections.abc import Iterator
from contextlib import contextmanager, suppress
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
    try:
        connection.execute("PRAGMA key='synthetic acceptance fixture only'")
    except BaseException:
        connection.close()
        raise
    return connection


def stats(registration: Any) -> dict[str, int]:
    native = registration._native
    native.mordred_vfs_stats.argtypes = [ctypes.c_uint64, ctypes.c_char_p, ctypes.c_int]
    native.mordred_vfs_stats.restype = ctypes.c_int
    buffer = ctypes.create_string_buffer(2048)
    assert native.mordred_vfs_stats(registration._token, buffer, len(buffer)) == 0
    return json.loads(buffer.value)


@contextmanager
def native_hook(registration: Any, callback: Any) -> Iterator[None]:
    assert hasattr(registration._native, "mordred_vfs_test_hook"), "run fault gates using -Target CheckedTest"
    hook_type = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_int, ctypes.c_void_p)
    setter = registration._native.mordred_vfs_test_hook
    setter.argtypes = [hook_type]
    setter.restype = None
    hook = hook_type(callback)
    setter(hook)
    try:
        yield
    finally:
        setter(hook_type())


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


def test_every_creation_handle_is_private_before_first_write(fixture: tuple[Any, Any, Path]) -> None:
    from mordred_hermes._private_fs._windows_api import OwnedHandle, get_api
    from mordred_hermes._private_fs._windows_security import validate_private

    driver, registration, root = fixture
    events: list[tuple[str, bool]] = []
    errors: list[str] = []

    def observe(stage: int, handle: int) -> int:
        if stage != 1:
            return 0
        try:
            # Borrow, never close, the actual handle returned by CREATE_NEW.
            borrowed = OwnedHandle(get_api(), handle)
            validate_private(borrowed, directory=False)
            name = get_api().final_path(borrowed)
            events.append((name, True))
        except Exception as error:
            errors.append(type(error).__name__)
            return 1
        return 0

    with native_hook(registration, observe):
        connection = connect(driver, root)
        try:
            connection.execute("CREATE TABLE data(value)")
            connection.commit()
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute("INSERT INTO data VALUES ('synthetic')")
            connection.commit()
        finally:
            connection.close()
    assert not errors
    assert all(private for _, private in events)
    assert any(name.endswith("synthetic.db") for name, _ in events)
    for suffix in ("-journal", "-wal", "-shm"):
        assert any(name.endswith(suffix) for name, _ in events)
    assert len(events) == stats(registration)["created"]


@pytest.mark.parametrize("stage", [2, 3, 4, 5, 6, 7, 8])
def test_injected_io_failure_never_commits_new_row(fixture: tuple[Any, Any, Path], stage: int) -> None:
    driver, registration, root = fixture
    connection = connect(driver, root)
    connection.execute("CREATE TABLE data(value)")
    connection.commit()
    # TRUNCATE deterministically exercises journal truncation on commit; WAL
    # exercises owned mapping. Other stages use rollback delete journals.
    if stage == 4:
        connection.execute("PRAGMA journal_mode=TRUNCATE")
    elif stage == 6:
        connection.execute("PRAGMA journal_mode=WAL")
    connection.close()
    hits: list[int] = []

    def fail(selected: int, _handle: int) -> int:
        if selected == stage:
            hits.append(selected)
            return 1
        return 0

    connection = None
    with native_hook(registration, fail):
        try:
            with pytest.raises(driver.DatabaseError):
                connection = connect(driver, root)
                connection.execute("INSERT INTO data VALUES ('must not commit')")
                connection.commit()
        finally:
            if connection is not None:
                with suppress(driver.DatabaseError):
                    connection.close()
    assert hits, "the selected actual-I/O boundary must have been exercised"
    connection = connect(driver, root)
    try:
        assert connection.execute("SELECT count(*) FROM data").fetchone() == (0,)
        assert connection.execute("PRAGMA integrity_check").fetchone() == ("ok",)
    finally:
        connection.close()


def test_junction_parent_refuses_before_data_open(fixture: tuple[Any, Any, Path]) -> None:
    from mordred_hermes._private_fs import open_private_directory

    driver, registration, root = fixture
    destination = root / "real"
    with open_private_directory(destination, create=True):
        pass
    link = root / "junction"
    result = subprocess.run(
        ["cmd.exe", "/d", "/c", "mklink", "/J", str(link), str(destination)],
        capture_output=True,
        text=True,
        timeout=20,
    )
    assert result.returncode == 0, result.stderr
    try:
        opened = stats(registration)["data_opens"]
        with pytest.raises(driver.DatabaseError):
            connect(driver, root, "junction/escaped.db")
        assert stats(registration)["data_opens"] == opened
        assert list(destination.iterdir()) == []
    finally:
        link.rmdir()


def test_changed_file_dacl_refuses_without_repair(fixture: tuple[Any, Any, Path]) -> None:
    driver, registration, root = fixture
    connection = connect(driver, root)
    connection.execute("CREATE TABLE data(value)")
    connection.commit()
    connection.close()
    path = root / "synthetic.db"
    before = path.read_bytes()
    subprocess.run(["icacls.exe", str(path), "/grant", "*S-1-1-0:(R)"], check=True, capture_output=True, timeout=20)
    opened = stats(registration)["data_opens"]
    with pytest.raises(driver.DatabaseError):
        connect(driver, root)
    assert stats(registration)["data_opens"] == opened
    assert path.read_bytes() == before


@pytest.mark.parametrize("mode", ["DELETE", "WAL"])
def test_crash_releases_locks_and_recovers_checked_files(fixture: tuple[Any, Any, Path], mode: str) -> None:
    driver, _registration, root = fixture
    connection = connect(driver, root)
    connection.execute("CREATE TABLE data(value)")
    connection.commit()
    connection.execute(f"PRAGMA journal_mode={mode}")
    connection.close()
    child = r"""
import os, sys
from pathlib import Path
import sqlcipher3.dbapi2 as driver
from mordred_hermes.dbcrypt._windows_vfs import register_checked_vfs
root = Path(sys.argv[1])
r = register_checked_vfs(driver, root=root)
c = driver.connect('file:' + (root / 'synthetic.db').as_posix() + '?vfs=' + r.name, uri=True)
c.execute("PRAGMA key='synthetic acceptance fixture only'")
c.execute('PRAGMA cache_size=4')
c.execute('BEGIN IMMEDIATE')
c.executemany('INSERT INTO data VALUES (?)', [('uncommitted' * 1000,) for _ in range(200)])
os._exit(23)
"""
    result = subprocess.run([sys.executable, "-c", child, str(root)], capture_output=True, text=True, timeout=60)
    assert result.returncode == 23, (result.stdout, result.stderr)
    connection = connect(driver, root)
    try:
        assert connection.execute("SELECT count(*) FROM data").fetchone() == (0,)
        assert connection.execute("PRAGMA integrity_check").fetchone() == ("ok",)
        connection.execute("INSERT INTO data VALUES ('recovered')")
        connection.commit()
    finally:
        connection.close()
