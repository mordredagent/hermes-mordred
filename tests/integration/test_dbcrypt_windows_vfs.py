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


# Test-only fresh-child bootstrap. Parent mode comes from its actual owning module
# and registration; the wheel gate separately proves distribution/device eligibility.
_CHECKED_VFS_CHILD_BOOTSTRAP = r"""
import os, sys
from pathlib import Path
if len(sys.argv) != 4 or sys.argv[2] not in ('source', 'packaged'):
    raise RuntimeError('invalid checked VFS child mode')
mode = sys.argv[2]
if mode == 'packaged' and 'MORDRED_DBCRYPT_CHECKED_LIBRARY' in os.environ:
    raise RuntimeError('packaged checked VFS child forbids DLL override')
if mode == 'source' and not os.environ.get('MORDRED_DBCRYPT_CHECKED_LIBRARY'):
    raise RuntimeError('source checked VFS child requires its explicit DLL')
expected_native = Path(sys.argv[3]).resolve(strict=True)
assert expected_native.is_file() and Path(sys.argv[3]).is_absolute()
if mode == 'source':
    override = Path(os.environ['MORDRED_DBCRYPT_CHECKED_LIBRARY'])
    if not override.is_absolute() or override.resolve(strict=True) != expected_native:
        raise RuntimeError('source checked VFS child DLL differs from parent')
from mordred_hermes.dbcrypt import _windows_vfs as vfs
if mode == 'packaged':
    import base64, hashlib
    from importlib.metadata import distribution
    assert vfs.driver_distribution_qualified(), 'packaged child requires its SQLCipher driver pair'
    packaged = vfs.packaged_library_path()
    assert packaged is not None and packaged.resolve(strict=True) == expected_native
    installed = distribution('hermes-mordred')
    entries = [entry for entry in installed.files or ()
               if str(entry) == 'mordred_hermes/_native/dbcrypt-vfs/mordred_dbcrypt_vfs.dll']
    assert len(entries) == 1 and Path(entries[0].locate()).resolve(strict=True) == expected_native
    assert entries[0].hash is not None and entries[0].hash.mode == 'sha256'
    observed = base64.urlsafe_b64encode(hashlib.sha256(expected_native.read_bytes()).digest()).rstrip(b'=').decode()
    assert entries[0].hash.value == observed, 'packaged child DLL differs from its distribution RECORD'
    # Inherit only this test's explicit packaged-parent eligibility choice.
    # The real production resolver, loader, driver and API-table checks stay intact.
    vfs.NATIVE_QUALIFIED = True
else:
    assert vfs.NATIVE_QUALIFIED is False, 'source child requires the explicit diagnostic path'
register_checked_vfs = vfs.register_checked_vfs
"""


def checked_vfs_child_args(registration: Any) -> tuple[str, str]:
    from mordred_hermes.dbcrypt import _windows_vfs

    native = Path(registration._native._name).resolve(strict=True)
    if _windows_vfs.NATIVE_QUALIFIED is True:
        assert "MORDRED_DBCRYPT_CHECKED_LIBRARY" not in os.environ
        packaged = _windows_vfs.packaged_library_path()
        assert packaged is not None and packaged.resolve(strict=True) == native
        return "packaged", str(native)
    if _windows_vfs.NATIVE_QUALIFIED is False:
        override = os.environ.get("MORDRED_DBCRYPT_CHECKED_LIBRARY")
        assert override and Path(override).is_absolute() and Path(override).resolve(strict=True) == native
        return "source", str(native)
    raise RuntimeError("invalid checked VFS parent mode")


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


@pytest.mark.parametrize("suffix", ["-journal", "-wal", "-shm"])
def test_forged_sidecar_hardlink_never_changes_target(fixture: tuple[Any, Any, Path], suffix: str) -> None:
    from mordred_hermes._private_fs import open_private_directory

    driver, _registration, root = fixture
    connection = connect(driver, root)
    connection.execute("CREATE TABLE data(value)")
    connection.commit()
    if suffix != "-journal":
        connection.execute("PRAGMA journal_mode=WAL")
    connection.close()
    with open_private_directory(root) as directory, directory.transaction() as transaction:
        transaction.create_bytes("sidecar-target", b"synthetic target must remain byte-identical")
    target = root / "sidecar-target"
    os.link(target, root / ("synthetic.db" + suffix))
    before_target = target.read_bytes()
    before_main = (root / "synthetic.db").read_bytes()
    connection = None
    try:
        with pytest.raises(driver.DatabaseError):
            connection = connect(driver, root)
            connection.execute("INSERT INTO data VALUES ('must not commit')")
            connection.commit()
    finally:
        if connection is not None:
            connection.close()
    assert target.read_bytes() == before_target
    assert (root / "synthetic.db").read_bytes() == before_main


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
            child = (
                _CHECKED_VFS_CHILD_BOOTSTRAP
                + r"""
import sys
from pathlib import Path
import sqlcipher3.dbapi2 as driver
root = Path(sys.argv[1])
r = register_checked_vfs(driver, root=root)
assert Path(r._native._name).resolve(strict=True) == expected_native
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
            )
            result = subprocess.run(
                [sys.executable, "-c", child, str(root), *checked_vfs_child_args(_registration)],
                capture_output=True,
                text=True,
                timeout=30,
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

    from mordred_hermes._private_fs._windows_api import get_api
    from mordred_hermes._private_fs._windows_security import validate_private

    driver, registration, root = fixture
    stop = threading.Event()
    replaced: list[bool] = []
    outcomes: list[str] = []
    payload = "Mordred race fixture must never appear as plaintext in any created file"

    def populate(name: str) -> None:
        connection = connect(driver, root, name)
        try:
            connection.execute("CREATE TABLE data(value)")
            connection.commit()
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute("INSERT INTO data VALUES (?)", (payload,))
            connection.commit()
        finally:
            connection.close()

    # Nonvacuous creation/callback evidence, independently of allowed refusals
    # under the adversarial rename race.
    populate("baseline.db")
    baseline = (root / "baseline.db").read_bytes()

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
            try:
                populate(f"race-{index}.db")
            except driver.OperationalError as error:
                # Pinning/identity admission may refuse during mutation. It
                # must never turn that refusal into an unchecked retry/open.
                assert str(error) in ("unable to open database file", "disk I/O error", "database is locked")
                outcomes.append("refused")
            else:
                outcomes.append("committed")
    finally:
        stop.set()
        thread.join(timeout=10)
    assert not thread.is_alive() and not replaced
    assert len(outcomes) == 12
    assert (root / "baseline.db").read_bytes() == baseline
    for path in root.iterdir():
        with get_api().open(str(path)) as handle:
            validate_private(handle, directory=False)
        assert payload.encode() not in path.read_bytes()
    counters = stats(registration)
    assert counters["created"] >= 4
    assert all(counters[name] > 0 for name in ("xOpen", "xDelete", "xShmMap", "xShmUnmap"))
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
                if stage == 4:
                    # Unlike WAL, TRUNCATE is connection-local: the mode set
                    # on the setup connection was lost when it closed.
                    assert connection.execute("PRAGMA journal_mode=TRUNCATE").fetchone() == ("truncate",)
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


def test_readonly_wal_reader_uses_owned_shm(fixture: tuple[Any, Any, Path]) -> None:
    driver, registration, root = fixture
    writer = connect(driver, root)
    reader = None
    try:
        writer.execute("PRAGMA journal_mode=WAL")
        writer.execute("CREATE TABLE data(value)")
        writer.execute("INSERT INTO data VALUES ('committed')")
        writer.commit()
        reader = driver.connect(
            f"file:{(root / 'synthetic.db').as_posix()}?mode=ro&vfs=mordred_checked_v1", uri=True, timeout=0
        )
        reader.execute("PRAGMA key='synthetic acceptance fixture only'")
        assert reader.execute("SELECT value FROM data").fetchall() == [("committed",)]
        with pytest.raises(driver.OperationalError):
            reader.execute("INSERT INTO data VALUES ('forbidden')")
        assert stats(registration)["xShmMap"] >= 2
    finally:
        if reader is not None:
            reader.close()
        writer.close()


def test_shm_shared_lock_is_idempotent_and_single_unlock_releases(fixture: tuple[Any, Any, Path]) -> None:
    _driver, registration, root = fixture
    native = registration._native
    assert hasattr(native, "mordred_vfs_test_shm_idempotence"), "use -Target CheckedTest"
    check = native.mordred_vfs_test_shm_idempotence
    check.argtypes = [ctypes.c_char_p, ctypes.POINTER(ctypes.c_int)]
    check.restype = ctypes.c_int
    results = (ctypes.c_int * 8)()
    assert check(str(root / "shm-idempotence.db").encode("utf-8"), results) == 0
    # Repeat SHARED, competing EXCLUSIVE busy, wrong-mode unlock refused,
    # one SHARED unlock, empty unlock, then competing EXCLUSIVE succeeds.
    assert list(results) == [0, 0, 5, 10 | (20 << 8), 0, 0, 0, 0]


def test_recovery_exclusive_lock_reports_own_reserved_state(fixture: tuple[Any, Any, Path]) -> None:
    _driver, registration, root = fixture
    native = registration._native
    assert hasattr(native, "mordred_vfs_test_recovery_lock"), "run callback gates using -Target CheckedTest"
    check = native.mordred_vfs_test_recovery_lock
    check.argtypes = [ctypes.c_char_p, ctypes.POINTER(ctypes.c_int)]
    check.restype = ctypes.c_int
    reserved = ctypes.c_int(-1)
    assert check(str(root / "recovery-lock.db").encode("utf-8"), ctypes.byref(reserved)) == 0
    # Recovery may jump from SHARED to EXCLUSIVE without acquiring a separate
    # RESERVED-byte lock. SQLite still requires this own lock to report true.
    assert reserved.value == 1


def test_inherited_dacl_race_cannot_broaden_a_created_journal(fixture: tuple[Any, Any, Path]) -> None:
    from mordred_hermes._private_fs._windows_api import OwnedHandle, get_api
    from mordred_hermes._private_fs._windows_security import validate_private

    driver, registration, root = fixture
    connection = connect(driver, root)
    connection.execute("CREATE TABLE data(value)")
    connection.commit()
    before = (root / "synthetic.db").read_bytes()
    events: list[bool] = []
    errors: list[str] = []

    def race(stage: int, handle: int) -> int:
        if stage != 1 or events:
            return 0
        try:
            borrowed = OwnedHandle(get_api(), handle)
            if not get_api().final_path(borrowed).endswith("-journal"):
                return 0
            # Change inheritance at the exact boundary between CREATE_NEW and
            # first data I/O. Protected creation must survive this mutation;
            # root revalidation must then refuse the pending transaction.
            subprocess.run(
                ["icacls.exe", str(root), "/grant", "*S-1-1-0:(OI)(CI)(IO)(R)"],
                check=True,
                capture_output=True,
                timeout=20,
            )
            validate_private(borrowed, directory=False)
            events.append(True)
        except Exception as error:
            errors.append(type(error).__name__)
            return 1
        return 0

    try:
        with native_hook(registration, race), pytest.raises(driver.DatabaseError):
            connection.execute("INSERT INTO data VALUES ('must not commit')")
            connection.commit()
    finally:
        # Removing only this test-added ACE restores the exact existing DACL.
        subprocess.run(["icacls.exe", str(root), "/remove:g", "*S-1-1-0"], check=True, capture_output=True, timeout=20)
        connection.close()
    assert events == [True] and not errors
    assert (root / "synthetic.db").read_bytes() == before
    for path in root.iterdir():
        with get_api().open(str(path)) as handle:
            validate_private(handle, directory=False)


@pytest.mark.parametrize("mode", ["DELETE", "WAL"])
def test_crash_releases_locks_and_recovers_checked_files(fixture: tuple[Any, Any, Path], mode: str) -> None:
    driver, _registration, root = fixture
    connection = connect(driver, root)
    connection.execute("CREATE TABLE data(value)")
    connection.commit()
    connection.execute(f"PRAGMA journal_mode={mode}")
    connection.close()
    child = (
        _CHECKED_VFS_CHILD_BOOTSTRAP
        + r"""
import os, sys
from pathlib import Path
import sqlcipher3.dbapi2 as driver
root = Path(sys.argv[1])
r = register_checked_vfs(driver, root=root)
assert Path(r._native._name).resolve(strict=True) == expected_native
c = driver.connect('file:' + (root / 'synthetic.db').as_posix() + '?vfs=' + r.name, uri=True)
c.execute("PRAGMA key='synthetic acceptance fixture only'")
c.execute('PRAGMA cache_size=4')
c.execute('BEGIN IMMEDIATE')
c.executemany('INSERT INTO data VALUES (?)', [('uncommitted' * 1000,) for _ in range(200)])
os._exit(23)
"""
    )
    result = subprocess.run(
        [sys.executable, "-c", child, str(root), *checked_vfs_child_args(_registration)],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 23, (result.stdout, result.stderr)
    connection = connect(driver, root)
    try:
        assert connection.execute("SELECT count(*) FROM data").fetchone() == (0,)
        assert connection.execute("PRAGMA integrity_check").fetchone() == ("ok",)
        connection.execute("INSERT INTO data VALUES ('recovered')")
        connection.commit()
    finally:
        connection.close()


def assert_observed_lifetimes(
    fixture: tuple[Any, Any, Path],
    *,
    plaintext_journal_control: bool = False,
    detections: list[tuple[int, str]] | None = None,
    completed_races: list[bool] | None = None,
) -> None:
    from mordred_hermes._private_fs._windows_api import FileId, OwnedHandle, get_api
    from mordred_hermes._private_fs._windows_security import check_private, validate_private

    driver, registration, root = fixture
    native = registration._native
    assert hasattr(native, "mordred_vfs_test_observer"), "use -Target CheckedTest"
    signature = ctypes.CFUNCTYPE(
        ctypes.c_int, ctypes.c_int, ctypes.c_void_p, ctypes.c_int64, ctypes.c_void_p, ctypes.c_int
    )
    setter = native.mordred_vfs_test_observer
    setter.argtypes = [signature]
    setter.restype = None
    failure_count = native.mordred_vfs_test_observer_failures
    failure_count.argtypes = []
    failure_count.restype = ctypes.c_long
    payload = b"Mordred race fixture must never appear as plaintext in any created file"
    snapshots: list[tuple[int, str, int]] = []
    creations: list[str] = []
    errors: list[str] = []
    active: dict[int, tuple[int, str, int, int, bytes]] = {}
    rollback_ready = False
    rollback_boundaries: list[int] = []
    names: dict[int, str] = {}
    identities: dict[str, tuple[int, bytes]] = {}

    def observe(stage: int, handle: int, offset: int, data: int, count: int) -> int:
        try:
            if offset == -3:
                errors.append("native snapshot failed")
                active.pop(handle, None)
                return 0
            if offset == -1:
                borrowed = OwnedHandle(get_api(), handle)  # Never close a borrowed handle.
                if stage == 1:
                    validate_private(borrowed, directory=False)
                else:
                    # Delete-pending handles remain valid for reads/ACL inspection.
                    check_private(get_api().descriptor(borrowed), get_api().user_sid())
                name = names.get(handle) if stage == 10 else None
                if name is None:
                    name = get_api().final_path(borrowed)
                names[handle] = name
                identifier = FileId()
                api = get_api()
                api.checked(api.GetInfo(handle, 18, ctypes.byref(identifier), ctypes.sizeof(identifier)), "identity")
                identity = (identifier.volume, bytes(identifier.identifier))
                if stage == 1:
                    identities[name] = identity
                else:
                    assert identities[name] == identity
                assert handle not in active
                assert 0 <= count <= 64 * 1024 * 1024
                active[handle] = (stage, name, count, 0, b"")
                if stage == 1:
                    creations.append(name)
            elif offset == -2:
                previous, name, expected, total, _tail = active[handle]
                assert previous == stage and total == expected == count
                active.pop(handle)
                if rollback_ready and stage in (4, 8) and name.endswith("rollback-observed.db-journal"):
                    rollback_boundaries.append(total)
                snapshots.append((stage, name, total))
                if stage == 10:
                    names.pop(handle, None)
            else:
                previous, name, expected, total, tail = active[handle]
                assert previous == stage and total == offset and 0 < count <= expected - total
                chunk = ctypes.string_at(data, count)
                inspect_marker = not plaintext_journal_control or (stage in (4, 8) and name.endswith("-journal"))
                if inspect_marker and payload in tail + chunk:
                    if detections is not None:
                        detections.append((stage, name))
                    raise AssertionError("plaintext marker in observed file")
                active[handle] = (stage, name, expected, total + count, (tail + chunk)[-len(payload) :])
        except BaseException as error:
            errors.append(repr(error))
            return 1
        return 0

    callback = signature(observe)
    before = stats(registration)["created"]
    setter(callback)
    try:
        # Commit marker-bearing pages in DELETE mode before changing them.
        # The second transaction must journal their before-images. The negative
        # control uses the same synthetic workload without a key and checks only
        # journal destructive boundaries, so an earlier main-file write cannot
        # satisfy that control accidentally.
        if plaintext_journal_control:
            connection = driver.connect(
                f"file:{(root / 'rollback-observed.db').as_posix()}?vfs=mordred_checked_v1", uri=True
            )
        else:
            connection = connect(driver, root, "rollback-observed.db")
        try:
            assert connection.execute("PRAGMA journal_mode=DELETE").fetchone() == ("delete",)
            connection.execute("CREATE TABLE data(id INTEGER PRIMARY KEY, value TEXT)")
            connection.executemany("INSERT INTO data VALUES (?, ?)", [(n, payload.decode()) for n in range(16)])
            connection.commit()
            assert connection.execute("SELECT count(*) FROM data WHERE value=?", (payload.decode(),)).fetchone() == (
                16,
            )
            rollback_ready = True
            connection.execute("UPDATE data SET value='replacement synthetic value'")
            connection.commit()
            assert connection.execute("PRAGMA integrity_check").fetchone() == ("ok",)
        finally:
            connection.close()
        if not plaintext_journal_control:
            # Original twelve race outcomes and physical no-rename checks stay.
            test_sidecar_creation_race_has_no_public_window(fixture)
            if completed_races is not None:
                completed_races.append(True)
    finally:
        setter(signature())
        assert failure_count() == 0, (
            "native observer failed; permitted SQLite refusals cannot qualify incomplete evidence"
        )
    assert rollback_boundaries and all(size > 0 for size in rollback_boundaries)
    assert not errors and not active and not names
    assert len(creations) == stats(registration)["created"] - before
    for suffix in (".db", "-journal", "-wal", "-shm"):
        assert any(name.endswith(suffix) for name in creations)
        assert any(name.endswith(suffix) and stage == 10 for stage, name, _ in snapshots)
    # Actual nonempty encrypted companions were inspected while still present,
    # before deletion/truncation and while SHM views were still mapped.
    assert any(stage in (4, 8) and name.endswith("-journal") and size for stage, name, size in snapshots)
    assert any(stage == 9 and name.endswith("-wal") and size for stage, name, size in snapshots)
    assert any(stage == 11 and name.endswith("-shm") and size for stage, name, size in snapshots)


def test_checkedtest_raced_file_lifetimes_include_ephemeral_contents(fixture: tuple[Any, Any, Path]) -> None:
    assert_observed_lifetimes(fixture)


@pytest.mark.parametrize("fault", [30, 31, 32])
def test_checkedtest_incomplete_observation_cannot_pass_as_race_refusal(
    fixture: tuple[Any, Any, Path], fault: int
) -> None:
    from mordred_hermes._private_fs._windows_api import OwnedHandle, get_api

    _driver, registration, _root = fixture
    hits: list[int] = []
    errors: list[str] = []
    completed: list[bool] = []

    def inject(stage: int, handle: int) -> int:
        if stage != fault * 100 + 10 or hits:
            return 0
        try:
            name = get_api().final_path(OwnedHandle(get_api(), handle))
            # Fail the final main-file close snapshot after successful admission
            # and writes. The unchanged race must still accept all outcomes.
            if name.endswith("race-0.db"):
                hits.append(fault)
                return 1
        except BaseException as error:
            errors.append(repr(error))
        return 0

    with native_hook(registration, inject), pytest.raises(AssertionError, match="native observer failed"):
        assert_observed_lifetimes(fixture, completed_races=completed)
    assert hits == [fault] and not errors
    assert completed == [True], "the unchanged race must accept its outcomes before the observer rejects evidence"


def test_checkedtest_plaintext_rollback_journal_is_detected(fixture: tuple[Any, Any, Path]) -> None:
    detections: list[tuple[int, str]] = []
    with pytest.raises(AssertionError, match="native observer failed"):
        assert_observed_lifetimes(fixture, plaintext_journal_control=True, detections=detections)
    assert any(stage in (4, 8) and name.endswith("rollback-observed.db-journal") for stage, name in detections)


def test_wal_multiregion_reader_checkpoint_restart(fixture: tuple[Any, Any, Path]) -> None:
    driver, _registration, root = fixture
    writer, reader = connect(driver, root), connect(driver, root)
    payload = "multi-region synthetic encrypted payload: " + "x" * 6000
    try:
        assert writer.execute("PRAGMA journal_mode=WAL").fetchone() == ("wal",)
        writer.execute("PRAGMA wal_autocheckpoint=0")
        writer.execute("CREATE TABLE data(id INTEGER PRIMARY KEY, value TEXT)")
        writer.execute("INSERT INTO data VALUES (0, ?)", (payload,))
        writer.commit()
        reader.execute("BEGIN")
        assert reader.execute("SELECT count(*) FROM data").fetchone() == (1,)
        writer.executemany("INSERT INTO data VALUES (?, ?)", [(n, payload) for n in range(1, 4601)])
        writer.commit()
        page_size = writer.execute("PRAGMA page_size").fetchone()[0]
        wal = root / "synthetic.db-wal"
        assert (wal.stat().st_size - 32) // (page_size + 24) > 4096
        assert (root / "synthetic.db-shm").stat().st_size >= 65536
        assert b"multi-region synthetic encrypted payload:" not in wal.read_bytes()
        assert reader.execute("SELECT count(*) FROM data").fetchone() == (1,)
        busy, frames, copied = writer.execute("PRAGMA wal_checkpoint(RESTART)").fetchone()
        assert busy == 1 and frames > 4096 and copied < frames
        reader.rollback()
        assert writer.execute("PRAGMA wal_checkpoint(RESTART)").fetchone()[0] == 0
        assert reader.execute("SELECT count(*), sum(id) FROM data").fetchone() == (4601, 10582300)
        writer.execute("INSERT INTO data VALUES (4601, ?)", (payload,))
        writer.commit()
        assert writer.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone() == (0, 0, 0)
        assert writer.execute("PRAGMA integrity_check").fetchone() == ("ok",)
        assert b"multi-region synthetic encrypted payload:" not in (root / "synthetic.db").read_bytes()
    finally:
        reader.close()
        writer.close()
    assert not (root / "synthetic.db-wal").exists()
    assert not (root / "synthetic.db-shm").exists()
    reopened = connect(driver, root)
    try:
        assert reopened.execute("SELECT count(*), sum(id) FROM data").fetchone() == (4602, 10586901)
        assert reopened.execute("PRAGMA integrity_check").fetchone() == ("ok",)
    finally:
        reopened.close()


@pytest.mark.parametrize("query", ["immutable=1", "nolock=1", "cache=shared", "unknown=value", "%69mmutable=1"])
def test_native_uri_refusal_has_zero_data_opens(fixture: tuple[Any, Any, Path], query: str) -> None:
    driver, registration, root = fixture
    before = stats(registration)
    with pytest.raises(driver.DatabaseError):
        connection = driver.connect(f"file:{(root / 'refused.db').as_posix()}?vfs=mordred_checked_v1&{query}", uri=True)
        connection.close()
    after = stats(registration)
    assert after["data_opens"] == before["data_opens"]
    assert after["created"] == before["created"]
    assert list(root.iterdir()) == []


@pytest.mark.parametrize("component", ["ancestor", "root", "child"])
def test_pinned_directories_refuse_replacement_during_io(fixture: tuple[Any, Any, Path], component: str) -> None:
    from mordred_hermes._private_fs import open_private_directory

    driver, _registration, root = fixture
    child = root / "child"
    with open_private_directory(child, create=True):
        pass
    connection = connect(driver, root, "child/pinned.db")
    try:
        connection.execute("CREATE TABLE data(value)")
        connection.commit()
        selected = {"ancestor": root.parent, "root": root, "child": child}[component]
        destination = selected.with_name(selected.name + "-must-not-move")
        assert not destination.exists()
        with pytest.raises(OSError):
            selected.rename(destination)
        assert selected.is_dir() and not destination.exists()
        connection.execute("INSERT INTO data VALUES ('retained identity')")
        connection.commit()
        assert connection.execute("SELECT value FROM data").fetchall() == [("retained identity",)]
        assert connection.execute("PRAGMA integrity_check").fetchone() == ("ok",)
    finally:
        connection.close()


def qualification_manifest() -> dict[str, Any]:
    from mordred_hermes._private_fs._windows_api import get_api

    value = os.environ.get("MORDRED_DBCRYPT_QUALIFICATION_MANIFEST")
    assert value, "native qualification requires the owned non-NTFS/reparse fixture manifest"
    manifest = json.loads(Path(value).read_text(encoding="utf-8-sig"))
    assert manifest["schema"] == 1
    assert manifest["owner_sid"] == get_api().sid_text(get_api().user_sid())
    root = Path(os.environ["MORDRED_DBCRYPT_TEST_ROOT"])
    assert Path(manifest["reparse_root"]).parent == root
    assert Path(manifest["reparse_root"]).name == "qualification-reparse"
    assert Path(manifest["non_ntfs_root"]).name.startswith("mordred-dbcrypt-")
    return manifest


def test_native_non_ntfs_root_refuses(fixture: tuple[Any, Any, Path]) -> None:
    from mordred_hermes._private_fs._windows_api import get_api

    _driver, registration, _root = fixture
    manifest = qualification_manifest()
    path = Path(manifest["non_ntfs_root"])
    api = get_api()
    # Establish an actual fixed non-NTFS volume, not merely a manifest label.
    assert path.is_absolute() and path.is_dir()
    api.validate_drive(path.anchor)
    with api.open(str(path)) as handle:
        fs = ctypes.create_unicode_buffer(32)
        api.checked(api.VolumeInfo(handle.value, None, 0, None, None, None, fs, len(fs)), "volume")
        assert fs.value in ("FAT32", "exFAT", "ReFS") and fs.value == manifest["filesystem"]
    before = sorted(p.name for p in path.iterdir())
    counters = stats(registration)
    token = ctypes.c_uint64()
    assert registration._native.mordred_vfs_register_root(str(path), ctypes.byref(token)) != 0
    assert token.value == 0
    assert stats(registration)["data_opens"] == counters["data_opens"]
    assert sorted(p.name for p in path.iterdir()) == before


@pytest.mark.parametrize("name,tag", [("direct-link.db", 0xA000000C), ("unknown-tag.db", 0x00000042)])
def test_native_file_reparse_refuses_before_data_open(fixture: tuple[Any, Any, Path], name: str, tag: int) -> None:
    from mordred_hermes._private_fs._windows_api import get_api

    driver, _registration, _root = fixture
    manifest = qualification_manifest()
    root = Path(manifest["reparse_root"])
    target = root / "sentinel.bin"
    assert target.read_bytes() == b"mordred synthetic reparse target must not change\n"
    # FILE_ATTRIBUTE_TAG_INFO follows an OPEN_REPARSE_POINT handle, never its target.
    with get_api().open(str(root / name)) as handle:
        info = (ctypes.c_uint32 * 2)()
        query = ctypes.WinDLL("kernel32", use_last_error=True).GetFileInformationByHandleEx
        query.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32]
        query.restype = ctypes.c_int
        assert query(handle.value, 9, ctypes.byref(info), ctypes.sizeof(info))
        assert info[0] & 0x400 and info[1] == tag
    registration = register_checked_vfs(driver, root=root)
    try:
        before = stats(registration)
        with pytest.raises(driver.DatabaseError):
            connect(driver, root, name)
        after = stats(registration)
        assert after["data_opens"] == before["data_opens"]
        assert after["created"] == before["created"]
        assert target.read_bytes() == b"mordred synthetic reparse target must not change\n"
    finally:
        registration.close()


@pytest.mark.parametrize("failed_lock", [1, 2, 3, 4])
def test_checkedtest_recovery_lock_transition_failure_releases_handles(
    fixture: tuple[Any, Any, Path], failed_lock: int
) -> None:
    driver, registration, root = fixture
    check = registration._native.mordred_vfs_test_recovery_lock
    check.argtypes = [ctypes.c_char_p, ctypes.POINTER(ctypes.c_int)]
    check.restype = ctypes.c_int
    calls: list[int] = []

    def fail(stage: int, _handle: int) -> int:
        if stage == 7:
            calls.append(stage)
            return int(len(calls) == failed_lock)
        return 0

    path = str(root / "recovery-fault.db").encode()
    reserved = ctypes.c_int(-1)
    with native_hook(registration, fail):
        assert check(path, ctypes.byref(reserved)) != 0
    assert len(calls) >= failed_lock
    assert check(path, ctypes.byref(reserved)) == 0 and reserved.value == 1
    connection = connect(driver, root, "recovery-fault.db")
    try:
        connection.execute("CREATE TABLE data(value)")
        connection.execute("INSERT INTO data VALUES ('after failed transition')")
        connection.commit()
        assert connection.execute("PRAGMA integrity_check").fetchone() == ("ok",)
    finally:
        connection.close()


@pytest.mark.parametrize("failed_lock", [1, 2, 3, 4, 5, 6, 7])
def test_checkedtest_shm_lock_transition_failure_releases_handles(
    fixture: tuple[Any, Any, Path], failed_lock: int
) -> None:
    _driver, registration, root = fixture
    check = registration._native.mordred_vfs_test_shm_idempotence
    check.argtypes = [ctypes.c_char_p, ctypes.POINTER(ctypes.c_int)]
    check.restype = ctypes.c_int
    calls: list[int] = []

    def fail(stage: int, _handle: int) -> int:
        if stage == 7:
            calls.append(stage)
            return int(len(calls) == failed_lock)
        return 0

    path = str(root / "shm-fault.db").encode()
    results = (ctypes.c_int * 8)()
    expected = [0, 0, 5, 5130, 0, 0, 0, 0]
    with native_hook(registration, fail):
        rc = check(path, results)
    assert len(calls) >= failed_lock
    assert rc != 0 or list(results) != expected
    assert check(path, results) == 0
    assert list(results) == expected


@pytest.mark.parametrize("failure_stage", [20, 21, 22])
def test_checkedtest_initialization_failure_rolls_back_in_fresh_process(
    fixture: tuple[Any, Any, Path], failure_stage: int
) -> None:
    _driver, _registration, root = fixture
    child = r"""
import ctypes, os, sys
from pathlib import Path
import sqlcipher3.dbapi2 as driver
from mordred_hermes.dbcrypt._windows_vfs import register_checked_vfs
root, stage = Path(sys.argv[1]), int(sys.argv[2])
native = ctypes.CDLL(os.environ['MORDRED_DBCRYPT_CHECKED_LIBRARY'])
signature = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_int, ctypes.c_void_p)
hits = []
def fail(actual, handle):
    if actual == stage:
        hits.append(actual)
        return 1
    return 0
hook = signature(fail)
native.mordred_vfs_test_hook.argtypes = [signature]
native.mordred_vfs_test_hook.restype = None
native.mordred_vfs_test_hook(hook)
try:
    register_checked_vfs(driver, root=root)
except driver.DatabaseError:
    pass
else:
    raise AssertionError('injected checked initialization succeeded')
assert hits == [stage], hits
native.mordred_vfs_test_hook(signature())
# No VFS or auto-extension callback may remain from failed initialization.
try:
    driver.connect('file:' + (root / 'must-not-exist.db').as_posix() + '?vfs=mordred_checked_v1', uri=True)
except driver.OperationalError as error:
    assert 'no such vfs' in str(error).lower(), str(error)
else:
    raise AssertionError('failed VFS remained registered')
assert not (root / 'must-not-exist.db').exists()
with driver.connect(':memory:') as memory:
    assert memory.execute('SELECT 41+1').fetchone() == (42,)
r = register_checked_vfs(driver, root=root)
c = driver.connect('file:' + (root / 'recovered-init.db').as_posix() + '?vfs=' + r.name, uri=True)
c.execute("PRAGMA key='synthetic acceptance fixture only'")
c.execute('CREATE TABLE data(value)')
c.execute("INSERT INTO data VALUES ('initialization recovered')")
c.commit()
assert c.execute('SELECT value FROM data').fetchone() == ('initialization recovered',)
assert c.execute('PRAGMA integrity_check').fetchone() == ('ok',)
c.close()
r.close()
assert b'initialization recovered' not in (root / 'recovered-init.db').read_bytes()
"""
    result = subprocess.run(
        [sys.executable, "-c", child, str(root), str(failure_stage)], capture_output=True, text=True, timeout=60
    )
    assert result.returncode == 0, (result.stdout, result.stderr)


def test_distinct_sqlite_library_cannot_replace_checked_api(fixture: tuple[Any, Any, Path]) -> None:
    _driver, _registration, root = fixture
    child = (
        _CHECKED_VFS_CHILD_BOOTSTRAP
        + r"""
import os, sqlite3, sys
from pathlib import Path
import sqlcipher3.dbapi2 as cipher
root = Path(sys.argv[1])
r = register_checked_vfs(cipher, root=root)
assert Path(r._native._name).resolve(strict=True) == expected_native
foreign = sqlite3.connect(':memory:')
assert foreign.execute('PRAGMA cipher_version').fetchone() is None
foreign.enable_load_extension(True)
try:
    foreign.execute('SELECT load_extension(?, ?)',
                    (r._native._name, 'sqlite3_mordredvfs_init'))
except sqlite3.DatabaseError as error:
    assert 'initialization' in str(error).lower(), str(error)
else:
    raise AssertionError('distinct SQLite API table admitted')
finally:
    foreign.enable_load_extension(False)
assert foreign.execute('SELECT 6*7').fetchone() == (42,)
foreign.close()
with sqlite3.connect(':memory:') as later:
    assert later.execute('SELECT 42').fetchone() == (42,)
for index in range(2):
    c = cipher.connect('file:' + (root / 'retained-api.db').as_posix() + '?vfs=' + r.name, uri=True)
    c.execute("PRAGMA key='synthetic acceptance fixture only'")
    if index == 0:
        c.execute('CREATE TABLE data(value)')
        c.execute("INSERT INTO data VALUES ('retained original API')")
        c.commit()
    assert c.execute('SELECT value FROM data').fetchone() == ('retained original API',)
    assert c.execute('PRAGMA integrity_check').fetchone() == ('ok',)
    c.close()
r.close()
"""
    )
    result = subprocess.run(
        [sys.executable, "-c", child, str(root), *checked_vfs_child_args(_registration)],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, (result.stdout, result.stderr)


def test_wal_reader_in_another_process_blocks_restart_until_release(fixture: tuple[Any, Any, Path]) -> None:
    import queue
    import threading

    driver, _registration, root = fixture
    writer = connect(driver, root)
    child = (
        _CHECKED_VFS_CHILD_BOOTSTRAP
        + r"""
import sys
from pathlib import Path
import sqlcipher3.dbapi2 as driver
root = Path(sys.argv[1])
r = register_checked_vfs(driver, root=root)
assert Path(r._native._name).resolve(strict=True) == expected_native
c = driver.connect('file:' + (root / 'synthetic.db').as_posix() + '?vfs=' + r.name, uri=True, timeout=0)
c.execute("PRAGMA key='synthetic acceptance fixture only'")
c.execute('BEGIN')
assert c.execute('SELECT count(*) FROM data').fetchone() == (1,)
print('snapshot held', flush=True)
assert sys.stdin.readline().strip() == 'release'
assert c.execute('SELECT count(*) FROM data').fetchone() == (1,)
c.rollback()
assert c.execute('SELECT count(*) FROM data').fetchone() == (201,)
assert c.execute('PRAGMA integrity_check').fetchone() == ('ok',)
c.close()
r.close()
"""
    )
    process = None
    ready: queue.Queue[str] = queue.Queue()
    waiter = None
    try:
        writer.execute("PRAGMA journal_mode=WAL")
        writer.execute("PRAGMA wal_autocheckpoint=0")
        writer.execute("CREATE TABLE data(value)")
        writer.execute("INSERT INTO data VALUES ('initial')")
        writer.commit()
        process = subprocess.Popen(
            [sys.executable, "-c", child, str(root), *checked_vfs_child_args(_registration)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        assert process.stdout is not None
        waiter = threading.Thread(target=lambda: ready.put(process.stdout.readline()), daemon=True)
        waiter.start()
        assert ready.get(timeout=30).strip() == "snapshot held"
        writer.executemany("INSERT INTO data VALUES (?)", [("committed across processes",)] * 200)
        writer.commit()
        assert writer.execute("PRAGMA wal_checkpoint(RESTART)").fetchone()[0] == 1
        waiter.join(timeout=5)
        output, error = process.communicate("release\n", timeout=30)
        assert process.returncode == 0, (output, error)
        assert writer.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone() == (0, 0, 0)
        assert writer.execute("PRAGMA integrity_check").fetchone() == ("ok",)
    finally:
        if process is not None and process.poll() is None:
            process.kill()
            process.communicate(timeout=10)
        if waiter is not None:
            waiter.join(timeout=5)
        writer.close()
    assert not (root / "synthetic.db-wal").exists()
    assert not (root / "synthetic.db-shm").exists()
    assert b"committed across processes" not in (root / "synthetic.db").read_bytes()


def test_wal_multiregion_commit_survives_process_crash(fixture: tuple[Any, Any, Path]) -> None:
    driver, _registration, root = fixture
    child = (
        _CHECKED_VFS_CHILD_BOOTSTRAP
        + r"""
import os, sys
from pathlib import Path
import sqlcipher3.dbapi2 as driver
root = Path(sys.argv[1])
r = register_checked_vfs(driver, root=root)
assert Path(r._native._name).resolve(strict=True) == expected_native
c = driver.connect('file:' + (root / 'synthetic.db').as_posix() + '?vfs=' + r.name, uri=True)
c.execute("PRAGMA key='synthetic acceptance fixture only'")
c.execute('PRAGMA journal_mode=WAL')
c.execute('PRAGMA wal_autocheckpoint=0')
c.execute('CREATE TABLE data(id INTEGER PRIMARY KEY, value TEXT)')
c.executemany('INSERT INTO data VALUES (?, ?)', [(n, 'committed crash payload:' + 'x'*6000) for n in range(4601)])
c.commit()
assert (root / 'synthetic.db-shm').stat().st_size >= 65536
os._exit(23)
"""
    )
    result = subprocess.run(
        [sys.executable, "-c", child, str(root), *checked_vfs_child_args(_registration)],
        capture_output=True,
        text=True,
        timeout=180,
    )
    assert result.returncode == 23, (result.stdout, result.stderr)
    assert (root / "synthetic.db-shm").stat().st_size >= 65536
    assert b"committed crash payload:" not in (root / "synthetic.db-wal").read_bytes()
    recovered = connect(driver, root)
    try:
        page_size = recovered.execute("PRAGMA page_size").fetchone()[0]
        assert ((root / "synthetic.db-wal").stat().st_size - 32) // (page_size + 24) > 4096
        assert recovered.execute("SELECT count(*), sum(id) FROM data").fetchone() == (4601, 10582300)
        assert recovered.execute("PRAGMA integrity_check").fetchone() == ("ok",)
        assert recovered.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone() == (0, 0, 0)
    finally:
        recovered.close()
    assert not (root / "synthetic.db-wal").exists()
    assert not (root / "synthetic.db-shm").exists()


@pytest.mark.parametrize("component", ["ancestor", "root", "child"])
def test_checkedtest_replacement_at_each_companion_creation(fixture: tuple[Any, Any, Path], component: str) -> None:
    from mordred_hermes._private_fs import open_private_directory
    from mordred_hermes._private_fs._windows_api import OwnedHandle, get_api
    from mordred_hermes._private_fs._windows_security import validate_private

    driver, registration, root = fixture
    child = root / "race-child"
    with open_private_directory(child, create=True):
        pass
    selected = {"ancestor": root.parent, "root": root, "child": child}[component]
    destination = selected.with_name(selected.name + "-must-not-move")
    assert not destination.exists()
    events: list[str] = []
    errors: list[str] = []

    def attempt(stage: int, handle: int) -> int:
        if stage != 1:
            return 0
        try:
            borrowed = OwnedHandle(get_api(), handle)
            validate_private(borrowed, directory=False)
            name = get_api().final_path(borrowed)
            try:
                selected.rename(destination)
            except OSError:
                pass
            else:
                raise AssertionError("pinned directory was replaced")
            validate_private(borrowed, directory=False)
            assert selected.is_dir() and not destination.exists()
            events.append(name)
        except BaseException as error:
            errors.append(repr(error))
            return 1
        return 0

    with native_hook(registration, attempt):
        connection = connect(driver, root, "race-child/synthetic.db")
        try:
            connection.execute("CREATE TABLE data(value)")
            connection.commit()
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute("INSERT INTO data VALUES ('companion mutation fixture')")
            connection.commit()
            assert connection.execute("PRAGMA integrity_check").fetchone() == ("ok",)
        finally:
            connection.close()
    assert not errors and not destination.exists()
    for suffix in (".db", "-journal", "-wal", "-shm"):
        assert any(name.endswith(suffix) for name in events)
    assert len(events) == stats(registration)["created"]


@pytest.mark.parametrize("suffix", ["-wal", "-shm"])
def test_checkedtest_inherited_dacl_race_on_wal_companion(fixture: tuple[Any, Any, Path], suffix: str) -> None:
    from mordred_hermes._private_fs._windows_api import OwnedHandle, get_api
    from mordred_hermes._private_fs._windows_security import validate_private

    driver, registration, root = fixture
    connection = connect(driver, root)
    connection.execute("CREATE TABLE data(value)")
    connection.commit()
    connection.execute("PRAGMA journal_mode=WAL")
    connection.close()
    before = (root / "synthetic.db").read_bytes()
    events: list[str] = []
    errors: list[str] = []
    changed: list[bool] = []

    def attempt(stage: int, handle: int) -> int:
        if stage != 1 or events:
            return 0
        try:
            borrowed = OwnedHandle(get_api(), handle)
            name = get_api().final_path(borrowed)
            if not name.endswith(suffix):
                return 0
            subprocess.run(
                ["icacls.exe", str(root), "/grant", "*S-1-1-0:(OI)(CI)(IO)(R)"],
                check=True,
                capture_output=True,
                timeout=20,
            )
            changed.append(True)
            validate_private(borrowed, directory=False)
            events.append(name)
        except BaseException as error:
            errors.append(repr(error))
            return 1
        return 0

    connection = None
    try:
        with native_hook(registration, attempt), pytest.raises(driver.DatabaseError):
            connection = connect(driver, root)
            connection.execute("INSERT INTO data VALUES ('must not commit')")
            connection.commit()
    finally:
        if changed:
            subprocess.run(
                ["icacls.exe", str(root), "/remove:g", "*S-1-1-0"],
                check=True,
                capture_output=True,
                timeout=20,
            )
        if connection is not None:
            connection.close()
    assert len(events) == 1 and not errors
    assert (root / "synthetic.db").read_bytes() == before
    recovered = connect(driver, root)
    try:
        assert recovered.execute("SELECT count(*) FROM data").fetchone() == (0,)
        assert recovered.execute("PRAGMA integrity_check").fetchone() == ("ok",)
    finally:
        recovered.close()


@pytest.mark.parametrize(
    "name", ["refused.db:stream", "trailing.", "trailing ", "CON", "encoded%252f.db", "../outside.db"]
)
def test_native_ambiguous_path_refuses_without_creating(fixture: tuple[Any, Any, Path], name: str) -> None:
    driver, registration, root = fixture
    before = stats(registration)
    with pytest.raises(driver.DatabaseError):
        connection = connect(driver, root, name)
        connection.close()
    assert stats(registration)["data_opens"] == before["data_opens"]
    assert stats(registration)["created"] == before["created"]
    assert list(root.iterdir()) == []
    assert not (root.parent / "outside.db").exists()


@pytest.mark.parametrize(
    "uri",
    [
        "file://server/share/refused.db",
        "file:////server/share/refused.db",
        "file:////%3f/C:/refused.db",
        "file:C:drive-relative.db",
    ],
)
def test_native_namespace_uri_refusal_has_zero_data_opens(fixture: tuple[Any, Any, Path], uri: str) -> None:
    driver, registration, root = fixture
    before = stats(registration)
    with pytest.raises(driver.DatabaseError):
        connection = driver.connect(uri + "?vfs=mordred_checked_v1", uri=True)
        connection.close()
    assert stats(registration)["data_opens"] == before["data_opens"]
    assert stats(registration)["created"] == before["created"]
    assert list(root.iterdir()) == []


@contextmanager
def directory_delete_trace(
    registration: Any, parent: Path, target: Path, *, fail_stage: int = 0
) -> Iterator[tuple[list[int], list[str]]]:
    from mordred_hermes._private_fs._windows_api import OwnedHandle, get_api
    from mordred_hermes._private_fs._windows_security import check_private, validate_private

    api = get_api()
    # Capture expected physical identity, then close this test handle so it
    # cannot mask a missing production directory pin during rename attempts.
    with api.open(str(parent)) as handle:
        validate_private(handle, directory=True)
        expected_identity = api.metadata(handle).identity
        expected_path = api.final_path(handle)
    events: list[int] = []
    errors: list[str] = []
    deleting = False

    def trace(stage: int, handle: int) -> int:
        nonlocal deleting
        try:
            if stage == 40:
                borrowed = OwnedHandle(api, handle)
                name = api.final_path(borrowed)
                if name.casefold() != (expected_path + "\\" + target.name).casefold():
                    return 0
                check_private(api.descriptor(borrowed), api.user_sid())
                deleting = True
                events.append(stage)
            elif stage == 41 and deleting:
                assert not handle, "closed handles cannot be borrowed by an observer"
                assert not target.exists(), "deletion must complete before the directory barrier"
                events.append(stage)
            elif stage in (42, 43, 44):
                borrowed = OwnedHandle(api, handle)
                validate_private(borrowed, directory=True)
                api.validate_volume(borrowed)
                assert api.metadata(borrowed).identity == expected_identity
                assert api.final_path(borrowed).casefold() == expected_path.casefold()
                if stage == 44:
                    assert not deleting, "supplemental parent admission must precede disposition"
                else:
                    assert deleting and 41 in events and not target.exists()
                    events.append(stage)
                for selected in dict.fromkeys((registration.root.parent, registration.root, parent)):
                    moved = selected.with_name(selected.name + "-syncdir-move")
                    assert not moved.exists()
                    try:
                        selected.rename(moved)
                    except OSError:
                        pass
                    else:
                        moved.rename(selected)
                        raise AssertionError("original directory pin was not retained")
            else:
                return 0
            return int(stage == fail_stage)
        except BaseException as error:
            errors.append(repr(error))
            return 1

    with native_hook(registration, trace):
        yield events, errors


def directory_delete_target(root: Path, nested: bool) -> tuple[Path, Path]:
    from mordred_hermes._private_fs import open_private_directory

    parent = root / "nested-delete" if nested else root
    with open_private_directory(parent, create=nested) as directory, directory.transaction() as transaction:
        transaction.create_bytes("owned-delete.fixture", b"synthetic checked deletion fixture")
    return parent, parent / "owned-delete.fixture"


def checked_delete(registration: Any, target: Path, sync_dir: int) -> int:
    delete = registration._native.mordred_vfs_test_delete
    delete.argtypes = [ctypes.c_char_p, ctypes.c_int]
    delete.restype = ctypes.c_int
    return int(delete(str(target).encode("utf-8"), sync_dir))


@pytest.mark.parametrize("nested", [False, True])
@pytest.mark.parametrize("sync_dir", [0, 1])
def test_checkedtest_directory_delete_flush_order_and_immediate_parent(
    fixture: tuple[Any, Any, Path], nested: bool, sync_dir: int
) -> None:
    _driver, registration, root = fixture
    parent, target = directory_delete_target(root, nested)
    with directory_delete_trace(registration, parent, target) as (events, errors):
        rc = checked_delete(registration, target, sync_dir)
    assert rc == 0 and not errors, (rc, errors)
    assert events == ([40, 41, 42, 43] if sync_dir else [40, 41])
    assert not target.exists()


@pytest.mark.parametrize("nested", [False, True])
@pytest.mark.parametrize("fail_stage,expected", [(41, 4106), (42, 1290)])
def test_checkedtest_directory_delete_propagates_close_and_flush_failure(
    fixture: tuple[Any, Any, Path], nested: bool, fail_stage: int, expected: int
) -> None:
    _driver, registration, root = fixture
    parent, target = directory_delete_target(root, nested)
    with directory_delete_trace(registration, parent, target, fail_stage=fail_stage) as (events, errors):
        rc = checked_delete(registration, target, 1)
    assert not errors, errors
    assert rc == expected, (rc, events)
    assert events == ([40, 41] if fail_stage == 41 else [40, 41, 42])
    # Failure is not a claim that disposition was rolled back. The real handle
    # closed; neither a close error nor a failed barrier may report success.
    assert not target.exists()


@pytest.mark.parametrize("nested", [False, True])
def test_checkedtest_directory_delete_extra_commit_requests_barrier(
    fixture: tuple[Any, Any, Path], nested: bool
) -> None:
    from mordred_hermes._private_fs import open_private_directory

    driver, registration, root = fixture
    parent = root / "nested-extra" if nested else root
    with open_private_directory(parent, create=nested):
        pass
    name = "nested-extra/extra.db" if nested else "extra.db"
    connection = connect(driver, root, name)
    try:
        assert connection.execute("PRAGMA journal_mode=DELETE").fetchone() == ("delete",)
        connection.execute("PRAGMA synchronous=EXTRA")
        assert connection.execute("PRAGMA synchronous").fetchone() == (3,)
        connection.execute("CREATE TABLE data(value)")
        connection.commit()
        with directory_delete_trace(registration, parent, parent / "extra.db-journal") as (events, errors):
            connection.execute("INSERT INTO data VALUES ('durability fixture')")
            connection.commit()
        assert not errors, errors
        assert events == [40, 41, 42, 43]
        assert connection.execute("SELECT value FROM data").fetchone() == ("durability fixture",)
        assert connection.execute("PRAGMA integrity_check").fetchone() == ("ok",)
    finally:
        connection.close()
