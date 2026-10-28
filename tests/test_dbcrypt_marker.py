"""Strict marker codec and checked publication; no native key operations."""

from __future__ import annotations

import json
from dataclasses import asdict, replace

import pytest

from mordred_hermes._database_contracts import DatabaseRefused, NativeSnapshot
from mordred_hermes._database_lifecycle import acquire_exclusive
from mordred_hermes.keyvault._database_authority import resolve_database_domain


@pytest.fixture
def marker_root(tmp_path):
    directory = tmp_path / "mordred"
    directory.mkdir(mode=0o700)
    identity = resolve_database_domain(tmp_path).identities[0]
    provider = "secure-enclave" if identity.platform == "darwin" else "tpm"
    return tmp_path, NativeSnapshot(identity, provider, "a" * 32, "b" * 64)


def encoded(snapshot):
    return (
        json.dumps(
            {"version": 2, "format": "mordred-sqlcipher-v1", **asdict(snapshot)},
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        + b"\n"
    )


def put(root, raw):
    path = root / "mordred/db-encryption.marker"
    path.write_bytes(raw)
    path.chmod(0o600)
    return path


def test_marker_round_trip_requires_exclusive_lease(marker_root):
    from mordred_hermes.dbcrypt._marker import Marker, read_marker, write_marker

    root, snapshot = marker_root
    assert read_marker(root) is None
    with acquire_exclusive(root) as lease:
        write_marker(root, snapshot, lease=lease)
    path = root / "mordred/db-encryption.marker"
    assert path.read_bytes() == encoded(snapshot)
    assert path.stat().st_mode & 0o777 == 0o600
    assert read_marker(root) == Marker(snapshot)
    with pytest.raises(DatabaseRefused):
        write_marker(root, snapshot, lease=lease)
    assert path.read_bytes() == encoded(snapshot)


def test_missing_directory_is_unarmed(tmp_path):
    from mordred_hermes.dbcrypt._marker import read_marker

    assert read_marker(tmp_path) is None
    assert not (tmp_path / "mordred").exists()


def test_legacy_marker_is_explicit_and_never_upgraded(marker_root):
    from mordred_hermes.dbcrypt._marker import LegacyMarker, read_marker, write_marker

    root, snapshot = marker_root
    path = put(root, b"1\n")
    assert read_marker(root) == LegacyMarker(b"1\n")
    with acquire_exclusive(root) as lease, pytest.raises(DatabaseRefused):
        write_marker(root, snapshot, lease=lease)
    assert path.read_bytes() == b"1\n"


@pytest.mark.parametrize(
    "damage",
    [
        "extra",
        "missing",
        "duplicate",
        "bool",
        "version",
        "format",
        "float-volume",
        "bool-volume",
        "inode-hex",
        "owner",
        "generation",
        "digest",
        "provider",
        "root-extra",
        "space",
        "no-lf",
        "utf8",
    ],
)
def test_marker_unknown_fields_refuse_and_preserve_bytes(marker_root, damage):
    from mordred_hermes.dbcrypt._marker import read_marker, write_marker

    root, snapshot = marker_root
    value = json.loads(encoded(snapshot))
    if damage == "extra":
        value["unknown"] = 1
    elif damage == "missing":
        del value["generation"]
    elif damage == "bool":
        value["version"] = True
    elif damage == "version":
        value["version"] = 3
    elif damage == "format":
        value["format"] = "other"
    elif damage == "float-volume":
        value["root"]["volume"] = 1.0
    elif damage == "bool-volume":
        value["root"]["volume"] = True
    elif damage == "inode-hex":
        value["root"]["file_id"] = "0x123"
    elif damage == "owner":
        value["root"]["owner"] = "00"
    elif damage == "generation":
        value["generation"] = "A" * 32
    elif damage == "digest":
        value["record_sha256"] = "B" * 64
    elif damage == "provider":
        value["provider"] = "cng"
    elif damage == "root-extra":
        value["root"]["unknown"] = 1
    raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n"
    if damage == "duplicate":
        raw = raw.replace(b'"version":2', b'"version":2,"version":2')
    elif damage == "space":
        raw = b" " + raw
    elif damage == "no-lf":
        raw = raw[:-1]
    elif damage == "utf8":
        raw = b"\xff\n"
    path = put(root, raw)
    with pytest.raises(DatabaseRefused):
        read_marker(root)
    with acquire_exclusive(root) as lease, pytest.raises(DatabaseRefused):
        write_marker(root, snapshot, lease=lease)
    assert path.read_bytes() == raw


@pytest.mark.parametrize("damage", ["mode", "symlink", "hardlink", "directory"])
def test_unsafe_marker_refuses_without_modification(marker_root, damage):
    from mordred_hermes.dbcrypt._marker import read_marker

    root, snapshot = marker_root
    path = put(root, encoded(snapshot))
    if damage == "mode":
        path.chmod(0o644)
    elif damage == "symlink":
        target = root / "original"
        path.rename(target)
        path.symlink_to(target)
    elif damage == "hardlink":
        (root / "alias").hardlink_to(path)
    else:
        path.unlink()
        path.mkdir()
    with pytest.raises(DatabaseRefused):
        read_marker(root)


def test_write_rejects_foreign_root_and_changed_generation(marker_root, tmp_path):
    from mordred_hermes.dbcrypt._marker import write_marker

    root, snapshot = marker_root
    other = tmp_path / "other"
    other.mkdir(mode=0o700)
    with acquire_exclusive(other) as foreign, pytest.raises(DatabaseRefused):
        write_marker(root, snapshot, lease=foreign)
    with acquire_exclusive(root) as lease:
        write_marker(root, snapshot, lease=lease)
        with pytest.raises(DatabaseRefused):
            write_marker(root, replace(snapshot, generation="c" * 32), lease=lease)
        with pytest.raises(DatabaseRefused):
            write_marker(root, replace(snapshot, root=replace(snapshot.root, owner="999")), lease=lease)
    assert (root / "mordred/db-encryption.marker").read_bytes() == encoded(snapshot)


def test_forged_exclusive_lease_refused(marker_root):
    from mordred_hermes._database_lifecycle import ExclusiveLease
    from mordred_hermes.dbcrypt._marker import write_marker

    class ForgedLease(ExclusiveLease):
        def __init__(self):
            pass

        def assert_held(self, root):
            pass

    root, snapshot = marker_root
    with pytest.raises(DatabaseRefused):
        write_marker(root, snapshot, lease=ForgedLease())
    assert not (root / "mordred/db-encryption.marker").exists()


def test_windows_marker_encoding_uses_full_generation_and_file_id(marker_root, monkeypatch):
    from mordred_hermes._database_contracts import RootIdentity
    from mordred_hermes.dbcrypt import _marker
    from mordred_hermes.keyvault import _database_authority as custody

    root, _ = marker_root
    identity = RootIdentity("win32", 7, "01" * 16, "010100000000000515000000")
    snapshot = NativeSnapshot(identity, "cng", "c" * 64, "d" * 64)
    domain = custody.CheckedDatabaseDomain(root, root, (identity,))
    monkeypatch.setattr(_marker, "resolve_database_domain", lambda path: domain)
    path = put(root, encoded(snapshot))
    assert _marker.read_marker(root) == _marker.Marker(snapshot)
    for replacement in (replace(snapshot, generation="c" * 32), replace(snapshot, root=replace(identity, file_id="1"))):
        path.write_bytes(encoded(replacement))
        with pytest.raises(DatabaseRefused):
            _marker.read_marker(root)
