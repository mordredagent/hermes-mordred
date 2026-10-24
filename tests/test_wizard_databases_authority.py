"""Legacy offline callers cannot consume runtime-native authority keys."""

from __future__ import annotations

import os

import pytest

from mordred_hermes._database_contracts import DatabaseRefused
from mordred_hermes.dbcrypt._key import KeyProvider
from tests.test_dbcrypt_authority import native_root as native_root


@pytest.mark.parametrize("command", ["encrypt", "decrypt"])
@pytest.mark.parametrize("dry_run", [False, True])
def test_native_offline_commands_refuse_before_key_or_mutation(native_root, monkeypatch, capsys, command, dry_run):
    from mordred_hermes.wizard import databases_cli

    root, backend, _, _ = native_root
    (root / "state.db").write_bytes(b"retained database bytes")
    (root / "mordred/db-encryption.pending").write_bytes(b"retained pending bytes")
    before = {path: path.read_bytes() for path in root.rglob("*") if path.is_file()}
    monkeypatch.setattr(databases_cli, "_preflight", lambda: None)

    def forbidden(self):
        pytest.fail("legacy offline command consumed a runtime-native bare key")

    monkeypatch.setattr(KeyProvider, "__call__", forbidden)
    operation = getattr(databases_cli, "databases_" + command)
    assert operation(home=root, dry_run=dry_run) == 1
    assert "offline" in capsys.readouterr().err.lower()
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
