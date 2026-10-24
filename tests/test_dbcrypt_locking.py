"""Root leases precede custody, exclude maintenance, and survive process faults."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

from tests._dbcrypt_support import database_lease_child


@pytest.mark.skipif(
    os.name == "nt", reason="POSIX native primitive; Windows lease qualification is Task 5's explicit gate"
)
def test_root_lease_precedes_custody(tmp_path: Path) -> None:
    from mordred_hermes._database_lifecycle import acquire_exclusive

    events = []
    with acquire_exclusive(tmp_path) as lease:
        lease.assert_held(tmp_path)
        events.append("database_exclusive")
        assert database_lease_child(tmp_path, "exclusive") == "busy"
        events.append("custody")
        lease.assert_held(tmp_path)
        events.append("database_operation")
    assert events == ["database_exclusive", "custody", "database_operation"]


def test_no_in_place_upgrade(tmp_path: Path) -> None:
    from mordred_hermes._database_contracts import DatabaseRefused
    from mordred_hermes._database_lifecycle import acquire_exclusive, acquire_runtime

    with acquire_runtime(tmp_path) as lease:
        lease.check()
        with pytest.raises(DatabaseRefused), acquire_exclusive(tmp_path):
            pytest.fail("a runtime cannot upgrade to native key mutation")


def test_closed_and_wrong_root_leases_refuse(tmp_path: Path) -> None:
    from mordred_hermes._database_contracts import DatabaseRefused
    from mordred_hermes._database_lifecycle import acquire_exclusive, acquire_runtime

    wrong = tmp_path / "other"
    wrong.mkdir()
    with acquire_exclusive(tmp_path) as lease:
        with pytest.raises(DatabaseRefused):
            lease.assert_held(wrong)
        assert list(wrong.iterdir()) == [], "checking a foreign root must not create authority files"
    with pytest.raises(DatabaseRefused):
        lease.assert_held(tmp_path)
    with acquire_runtime(tmp_path) as reader:
        reader.close()
        with pytest.raises(DatabaseRefused):
            reader.check()


@pytest.mark.skipif(
    os.name == "nt", reason="POSIX process acceptance; Windows lock/rename native gate follows in Task 5"
)
def test_multiprocess_shared_exclusive_and_crash_release(tmp_path: Path) -> None:
    from mordred_hermes._database_lifecycle import acquire_exclusive, acquire_runtime

    with acquire_runtime(tmp_path):
        assert database_lease_child(tmp_path, "runtime") == "acquired"
        assert database_lease_child(tmp_path, "exclusive") == "busy"
    assert database_lease_child(tmp_path, "exclusive") == "acquired"
    child = subprocess.Popen(
        [sys.executable, "-c", database_lease_child.script, str(tmp_path), "hold"],
        stdout=subprocess.PIPE,
        stdin=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        assert child.stdout is not None and child.stdout.readline().strip() == "acquired"
        assert database_lease_child(tmp_path, "exclusive") == "busy"
    finally:
        child.kill()
        child.communicate(timeout=10)
    with acquire_exclusive(tmp_path) as lease:
        lease.assert_held(tmp_path)


@pytest.mark.skipif(os.name == "nt", reason="POSIX pathname replacement; Windows denies rename and is gated in Task 5")
def test_root_and_lock_replacement_invalidate_runtime(tmp_path: Path) -> None:
    from mordred_hermes._database_contracts import DatabaseRefused
    from mordred_hermes._database_lifecycle import acquire_runtime

    root = tmp_path / "root"
    root.mkdir()
    with acquire_runtime(root) as lease:
        root.rename(tmp_path / "retired")
        root.mkdir()
        with pytest.raises(DatabaseRefused):
            lease.check()
    with acquire_runtime(root) as lease:
        lock = root / "mordred/db-encryption.lock"
        lock.unlink()
        lock.touch(mode=0o600)
        with pytest.raises(DatabaseRefused):
            lease.check()


def test_holder_visibility_unknown_refuses(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from mordred_hermes import _database_locking_posix as posix
    from mordred_hermes._database_contracts import DatabaseRefused

    database = tmp_path / "state.db"
    database.write_bytes(b"opaque")
    proc = tmp_path / "proc"
    proc.mkdir()
    real = os.scandir

    def denied(path):
        if Path(path) == proc:
            raise PermissionError("synthetic inaccessible proc")
        return real(path)

    monkeypatch.setattr(os, "scandir", denied)
    assert posix.linux_holders_of([database], proc=proc) is None
    with pytest.raises(DatabaseRefused):
        posix.assert_no_linux_holders([database], proc=proc)


def test_legacy_maintenance_reuses_preceding_exclusive_proof(tmp_path: Path) -> None:
    from mordred_hermes._database_lifecycle import acquire_exclusive
    from mordred_hermes.dbcrypt._locking import migration_lock

    with acquire_exclusive(tmp_path) as lease, migration_lock(tmp_path):
        lease.assert_held(tmp_path)


@pytest.mark.skipif(not hasattr(os, "fork"), reason="POSIX fork ownership")
def test_fork_discards_inherited_authority_without_unlocking_parent(tmp_path: Path) -> None:
    from mordred_hermes._database_lifecycle import acquire_runtime

    read, write = os.pipe()
    with acquire_runtime(tmp_path) as lease:
        pid = os.fork()
        if pid == 0:
            os.close(read)
            try:
                from mordred_hermes._database_contracts import DatabaseRefused

                try:
                    lease.check()
                except DatabaseRefused:
                    pass
                else:
                    raise AssertionError("inherited authority survived fork")
                with acquire_runtime(tmp_path, timeout=0) as fresh:
                    fresh.check()
                lease.close()  # Must not touch an already-discarded/reused descriptor.
                os.write(write, b"fresh")
            except BaseException:
                os.write(write, b"failed")
            finally:
                os._exit(0)
        os.close(write)
        try:
            assert os.read(read, 10) == b"fresh"
            assert os.waitpid(pid, 0)[1] == 0
            lease.check()
            assert database_lease_child(tmp_path, "exclusive") == "busy"
        finally:
            os.close(read)


@pytest.mark.skipif(
    os.name == "nt", reason="POSIX file permissions; checked Windows descriptor cases have their own tests"
)
@pytest.mark.parametrize("unsafe", ["permissions", "hardlink", "symlink"])
def test_unsafe_lock_refuses_without_repair(tmp_path: Path, unsafe: str) -> None:
    from mordred_hermes._database_contracts import DatabaseRefused
    from mordred_hermes._database_lifecycle import acquire_runtime

    folder = tmp_path / "mordred"
    folder.mkdir(mode=0o700)
    lock = folder / "db-encryption.lock"
    target = tmp_path / "target"
    target.write_bytes(b"unmodified")
    target.chmod(0o600)
    if unsafe == "symlink":
        lock.symlink_to(target)
    elif unsafe == "hardlink":
        os.link(target, lock)
    else:
        lock.write_bytes(b"unmodified")
        lock.chmod(0o644)
    with pytest.raises(DatabaseRefused), acquire_runtime(tmp_path):
        pytest.fail("unsafe lock admitted")
    assert target.read_bytes() == b"unmodified"
    if unsafe == "permissions":
        assert lock.stat().st_mode & 0o777 == 0o644


@pytest.mark.skipif(os.name == "nt", reason="POSIX ownership/mode admission; Windows uses checked token/DACL tests")
@pytest.mark.parametrize("change_before", [True, False])
def test_other_user_writable_root_refuses_without_repair(tmp_path: Path, change_before: bool) -> None:
    from mordred_hermes._database_contracts import DatabaseRefused
    from mordred_hermes._database_lifecycle import acquire_runtime

    root = tmp_path / "root"
    root.mkdir(mode=0o700)
    try:
        if change_before:
            root.chmod(0o777)
            with pytest.raises(DatabaseRefused), acquire_runtime(root):
                pytest.fail("a writable-by-others root was admitted")
            assert not (root / "mordred").exists()
        else:
            with acquire_runtime(root) as lease:
                root.chmod(0o777)
                with pytest.raises(DatabaseRefused):
                    lease.check()
        assert root.stat().st_mode & 0o777 == 0o777
    finally:
        root.chmod(0o700)
