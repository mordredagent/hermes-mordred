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
        with pytest.raises(DatabaseRefused):
            with acquire_exclusive(tmp_path):
                pytest.fail("a runtime cannot upgrade to native key mutation")


def test_closed_and_wrong_root_leases_refuse(tmp_path: Path) -> None:
    from mordred_hermes._database_contracts import DatabaseRefused
    from mordred_hermes._database_lifecycle import acquire_exclusive, acquire_runtime

    wrong = tmp_path / "other"
    wrong.mkdir()
    with acquire_exclusive(tmp_path) as lease:
        with pytest.raises(DatabaseRefused):
            lease.assert_held(wrong)
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
