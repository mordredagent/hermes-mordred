"""Legacy offline callers cannot consume runtime-native authority keys."""

from __future__ import annotations

import os

import pytest

from mordred_hermes._database_contracts import DatabaseRefused
from mordred_hermes.dbcrypt._key import KeyProvider
from tests.test_dbcrypt_authority import native_root as native_root


@pytest.mark.parametrize("command", ["encrypt", "decrypt"])
@pytest.mark.parametrize("dry_run", [False, True])
def test_native_offline_commands_use_ex_without_runtime_provider(native_root, monkeypatch, capsys, command, dry_run):
    from mordred_hermes import dbcrypt
    from mordred_hermes._database_lifecycle import current_thread_exclusive_leases
    from mordred_hermes.dbcrypt import _migrate
    from mordred_hermes.dbcrypt._capability import DatabaseStatus
    from mordred_hermes.wizard import databases_cli

    root, backend, _, _ = native_root
    before = {path: path.read_bytes() for path in root.rglob("*") if path.is_file()}
    monkeypatch.setattr(dbcrypt, "database_status", lambda home: DatabaseStatus(True, 1, "unknown", False, None))
    monkeypatch.setattr(KeyProvider, "__call__", lambda self: pytest.fail("offline command consumed runtime SH key"))
    calls = []

    def convert(home, key, **kwargs):
        assert home == root and key is None
        leases = current_thread_exclusive_leases()
        assert len(leases) == 1
        leases[0].assert_held(root)
        calls.append(command)
        return _migrate.Report()

    monkeypatch.setattr(_migrate, "migrate" if command == "encrypt" else "decrypt_all", convert)
    assert getattr(databases_cli, "databases_" + command)(home=root, dry_run=dry_run) == 0
    assert calls == ([] if dry_run else [command])
    assert backend.calls == []
    assert {path: path.read_bytes() for path in root.rglob("*") if path.is_file()} == before


@pytest.mark.parametrize("directory_mode", [0o700, 0o755])
def test_legacy_arm_cannot_downgrade_native_marker(native_root, directory_mode):
    from mordred_hermes import dbcrypt

    root, backend, _, _ = native_root
    (root / "mordred").chmod(directory_mode)
    before = {path: path.read_bytes() for path in root.rglob("*") if path.is_file()}
    with pytest.raises(DatabaseRefused):
        dbcrypt.arm(root)
    assert backend.calls == []
    assert {path: path.read_bytes() for path in root.rglob("*") if path.is_file()} == before


@pytest.mark.skipif(os.name != "posix", reason="POSIX legacy directory modes")
def test_legacy_arm_is_idempotent_in_owned_0755_directory(tmp_path):
    from mordred_hermes import dbcrypt

    directory = tmp_path / "mordred"
    directory.mkdir(mode=0o755)
    directory.chmod(0o755)
    dbcrypt.arm(tmp_path)
    marker = dbcrypt.marker_path(tmp_path)
    before_bytes = {path: path.read_bytes() for path in tmp_path.rglob("*") if path.is_file()}
    before_modes = {path: path.stat().st_mode for path in tmp_path.rglob("*")}
    before_identity = (marker.stat().st_dev, marker.stat().st_ino)
    dbcrypt.arm(tmp_path)
    assert marker.read_bytes() == b"1\n"
    assert directory.stat().st_mode & 0o777 == 0o755
    assert marker.stat().st_mode & 0o777 == 0o600
    assert (marker.stat().st_dev, marker.stat().st_ino) == before_identity
    assert {path: path.read_bytes() for path in tmp_path.rglob("*") if path.is_file()} == before_bytes
    assert {path: path.stat().st_mode for path in tmp_path.rglob("*")} == before_modes


@pytest.mark.skipif(os.name != "posix", reason="POSIX legacy directory/file admission")
@pytest.mark.parametrize("damage", ["unknown", "mode", "symlink", "hardlink", "directory", "fifo"])
def test_legacy_arm_in_0755_directory_refuses_unsafe_or_unknown_entries(tmp_path, damage):
    from mordred_hermes import dbcrypt

    directory = tmp_path / "mordred"
    directory.mkdir(mode=0o755)
    directory.chmod(0o755)
    dbcrypt.arm(tmp_path)
    marker = dbcrypt.marker_path(tmp_path)
    if damage == "unknown":
        marker.write_bytes(b"x\n")
    elif damage == "mode":
        marker.chmod(0o644)
    elif damage == "symlink":
        target = tmp_path / "target"
        marker.rename(target)
        marker.symlink_to(target)
    elif damage == "hardlink":
        (tmp_path / "alias").hardlink_to(marker)
    else:
        marker.unlink()
        if damage == "directory":
            marker.mkdir(mode=0o700)
        else:
            os.mkfifo(marker, mode=0o600)
    before_bytes = {path: path.read_bytes() for path in tmp_path.rglob("*") if path.is_file()}
    before_metadata = {path: (path.lstat().st_mode, path.lstat().st_ino) for path in tmp_path.rglob("*")}
    with pytest.raises(DatabaseRefused):
        dbcrypt.arm(tmp_path)
    assert {path: path.read_bytes() for path in tmp_path.rglob("*") if path.is_file()} == before_bytes
    assert {path: (path.lstat().st_mode, path.lstat().st_ino) for path in tmp_path.rglob("*")} == before_metadata
