"""Offline adoption authenticates every existing cipher without changing bytes."""

from __future__ import annotations

from pathlib import Path

import pytest
import sqlcipher3.dbapi2 as sc

from mordred_hermes._database_contracts import DatabaseRefused
from mordred_hermes._database_lifecycle import acquire_exclusive
from mordred_hermes.dbcrypt import _migrate
from mordred_hermes.dbcrypt._authority import Authority
from mordred_hermes.dbcrypt._key import derive
from mordred_hermes.dbcrypt._marker import Marker, read_marker
from mordred_hermes.dbcrypt._shim import apply_key
from tests.test_dbcrypt_authority import native_root as native_root
from tests.test_keyvault_database_authority import mac_source as mac_source


def cipher(path, key):
    with sc.connect(str(path)) as conn:
        apply_key(conn, derive(key))
        conn.execute("CREATE TABLE messages (body TEXT)")
        conn.execute("INSERT INTO messages VALUES ('private 日本語')")
    conn.close()
    path.chmod(0o600)


def test_legacy_mixed_profile_keys_refuse_without_mutation(native_root, monkeypatch):
    root, _, key, _ = native_root
    marker = root / "mordred/db-encryption.marker"
    marker.write_bytes(b"1\n")
    cipher(root / "state.db", key)
    cipher(root / "profiles/work/state.db", bytes(range(32)))
    before = {p: p.read_bytes() for p in root.rglob("*.db")}
    monkeypatch.setattr(_migrate, "holders", lambda paths: [])
    with acquire_exclusive(root) as lease, pytest.raises(DatabaseRefused):
        _migrate.adopt_legacy(root, lease=lease)
    assert marker.read_bytes() == b"1\n"
    assert {p: p.read_bytes() for p in before} == before


def test_legacy_adoption_preserves_all_ciphertext(native_root, monkeypatch):
    root, _, key, snapshot = native_root
    marker = root / "mordred/db-encryption.marker"
    marker.write_bytes(b"1\n")
    for p in (root / "state.db", root / "profiles/work/state.db"):
        cipher(p, key)
    before = {p: p.read_bytes() for p in root.rglob("*.db")}
    monkeypatch.setattr(_migrate, "holders", lambda paths: [])
    with acquire_exclusive(root) as lease:
        assert _migrate.adopt_legacy(root, lease=lease) == snapshot
    assert read_marker(root) == Marker(snapshot)
    assert {p: p.read_bytes() for p in before} == before


def test_maintenance_never_acquires_shared_runtime_inside_exclusive(native_root, monkeypatch):
    root, _, key, _ = native_root
    cipher(root / "state.db", key)
    before = (root / "state.db").read_bytes()
    calls = []
    monkeypatch.setattr(Authority, "acquire", lambda *a: calls.append(a))
    with pytest.raises(DatabaseRefused):
        _migrate.decrypt_all(root, derive(bytes(32)), holders_of=lambda paths: [])
    assert calls == []
    assert (root / "state.db").read_bytes() == before


def test_historical_read_only_source_requires_exclusive(native_root):
    from mordred_hermes.keyvault import _database_authority as custody

    root, _, key, _ = native_root
    binding = root / "mordred/db-key-source.json"
    binding.unlink()
    with pytest.raises(DatabaseRefused):
        custody._load_historical_database_source(root=root, lease=None)
    with acquire_exclusive(root) as lease:
        assert custody._load_historical_database_source(root=root, lease=lease)[1] == key
    assert not binding.exists()


@pytest.mark.parametrize("mixed", [False, True])
def test_unbound_historical_adoption_proves_before_enrollment(native_root, monkeypatch, mixed):
    root, backend, key, _ = native_root
    binding = root / "mordred/db-key-source.json"
    binding.unlink()
    marker = root / "mordred/db-encryption.marker"
    marker.write_bytes(b"1\n")
    cipher(root / "state.db", key)
    cipher(root / "profiles/work/state.db", bytes(range(32)) if mixed else key)
    before = {p: p.read_bytes() for p in root.rglob("*.db")}
    monkeypatch.setattr(_migrate, "holders", lambda paths: [])
    backend.calls.clear()
    with acquire_exclusive(root) as lease:
        if mixed:
            with pytest.raises(DatabaseRefused):
                _migrate.adopt_legacy(root, lease=lease)
            assert not binding.exists()
            assert marker.read_bytes() == b"1\n"
        else:
            result = _migrate.adopt_legacy(root, lease=lease)
            assert read_marker(root) == Marker(result)
            assert sum(op == "ecdh" for op, _ in backend.calls) == 2
    assert {p: p.read_bytes() for p in before} == before


@pytest.mark.parametrize("damage", ["empty", "unknown-sidecar", "missing-key", "holder", "uncertain-holder"])
def test_adoption_uncertain_inventory_or_custody_refuses(native_root, monkeypatch, damage):
    root, backend, key, _ = native_root
    marker = root / "mordred/db-encryption.marker"
    marker.write_bytes(b"1\n")
    cipher(root / "state.db", key)
    if damage == "empty":
        (root / "empty.db").touch(mode=0o600)
    elif damage == "unknown-sidecar":
        (root / "missing.db-wal").touch(mode=0o600)
    elif damage == "missing-key":
        backend._keys.clear()
    monkeypatch.setattr(
        _migrate, "holders", lambda paths: [123] if damage == "holder" else None if damage == "uncertain-holder" else []
    )
    before = (root / "state.db").read_bytes()
    with acquire_exclusive(root) as lease, pytest.raises(DatabaseRefused):
        _migrate.adopt_legacy(root, lease=lease)
    assert marker.read_bytes() == b"1\n"
    assert (root / "state.db").read_bytes() == before


@pytest.mark.parametrize(
    "direction,phase",
    [
        (direction, phase)
        for direction in ("encrypt", "decrypt")
        for phase in ("prepared", "verified", "armed", "swapped", "complete", "removed")
    ]
    + [("adopt", phase) for phase in ("verified", "armed", "complete")],
)
def test_crash_at_every_durable_transition(native_root, monkeypatch, direction, phase):
    root, _, key, _ = native_root
    derived = derive(key)
    marker = root / "mordred/db-encryption.marker"
    for path in (root / "state.db", root / "profiles/work/state.db"):
        if direction == "encrypt":
            with sc.connect(str(path)) as conn:
                conn.execute("CREATE TABLE messages (body TEXT)")
                conn.execute("INSERT INTO messages VALUES ('private 日本語')")
            conn.close()
            path.chmod(0o600)
        else:
            cipher(path, key)
    if direction == "encrypt":
        marker.unlink()
    elif direction == "adopt":
        marker.write_bytes(b"1\n")
    monkeypatch.setattr(_migrate, "holders", lambda paths: [])

    class Crash(Exception):
        pass

    def crash(point):
        if point == phase:
            raise Crash

    monkeypatch.setattr(_migrate, "_transition", crash)
    with pytest.raises(Crash):
        if direction == "adopt":
            with acquire_exclusive(root) as lease:
                _migrate.adopt_legacy(root, lease=lease)
        elif direction == "decrypt":
            _migrate.decrypt_all(root, derived)
        else:
            _migrate.migrate(root, derived, arm=lambda root: pytest.fail("native used raw arm"))
    monkeypatch.setattr(_migrate, "_transition", lambda point: None)
    _migrate.resume(root)
    assert not _migrate.journal_path(root).exists()
    for path in (root / "state.db", root / "profiles/work/state.db"):
        with sc.connect(str(path)) as conn:
            if direction != "decrypt":
                apply_key(conn, derived)
            assert conn.execute("SELECT body FROM messages").fetchall() == [("private 日本語",)]
        conn.close()
    assert marker.exists() is (direction != "decrypt")


@pytest.mark.parametrize("name", ["db-encryption.journal.json", "db-encryption.pending", "db-decryption.pending"])
def test_direct_authority_refuses_recovery_before_native_unwrap(native_root, name):
    root, backend, _, _ = native_root
    record = root / "mordred" / name
    record.write_bytes(b"1\n")
    record.chmod(0o600)
    backend.calls.clear()
    with pytest.raises(DatabaseRefused):
        authority = Authority.acquire(root)
        authority.close()
    assert backend.calls == []


@pytest.mark.parametrize("damage", ["parent", "file", "journal-root", "journal-generation", "unreadable-directory"])
def test_recovery_refuses_replaced_identity_or_uncertain_inventory(native_root, monkeypatch, damage):
    import json
    import os

    root, _, key, _ = native_root
    marker = root / "mordred/db-encryption.marker"
    marker.unlink()
    path = root / "profiles/work/state.db"
    with sc.connect(str(path)) as conn:
        conn.execute("CREATE TABLE messages (body TEXT)")
        conn.execute("INSERT INTO messages VALUES ('source')")
    conn.close()
    path.chmod(0o600)
    monkeypatch.setattr(_migrate, "holders", lambda paths: [])

    def crash(phase):
        if phase == "verified":
            raise RuntimeError("crash")

    monkeypatch.setattr(_migrate, "_transition", crash)
    with pytest.raises(RuntimeError, match="crash"):
        _migrate.migrate(root, derive(key), arm=lambda root: None)
    monkeypatch.setattr(_migrate, "_transition", lambda phase: None)
    journal = _migrate.journal_path(root)
    if damage == "parent":
        previous = path.parent.with_name("previous")
        path.parent.rename(previous)
        path.parent.mkdir(mode=0o700)
        (previous / path.name).rename(path)
        (previous / (path.name + _migrate.PREPARED_SUFFIX)).rename(Path(str(path) + _migrate.PREPARED_SUFFIX))
    elif damage == "file":
        staged = Path(str(path) + _migrate.PREPARED_SUFFIX)
        replacement = staged.with_name("replacement")
        replacement.write_bytes(staged.read_bytes())
        replacement.chmod(0o600)
        replacement.replace(staged)
    elif damage.startswith("journal-"):
        data = json.loads(journal.read_bytes())
        if damage == "journal-root":
            data["root"]["file_id"] = "0"
        else:
            data["snapshot"]["generation"] = "f" * 32
        journal.write_text(json.dumps(data))
    else:
        original = os.scandir

        def deny(directory):
            if Path(directory) == path.parent:
                raise PermissionError("synthetic unreadable directory")
            return original(directory)

        monkeypatch.setattr(os, "scandir", deny)
    before = path.read_bytes()
    with pytest.raises(DatabaseRefused):
        _migrate.resume(root)
    assert path.read_bytes() == before and not marker.exists()


def test_recovery_refuses_closed_writer_changed_source(native_root, monkeypatch):
    root, _, key, _ = native_root
    (root / "mordred/db-encryption.marker").unlink()
    path = root / "state.db"
    with sc.connect(str(path)) as conn:
        conn.execute("CREATE TABLE messages (body TEXT)")
        conn.execute("INSERT INTO messages VALUES ('before')")
    conn.close()
    path.chmod(0o600)
    monkeypatch.setattr(_migrate, "holders", lambda paths: [])

    def crash(phase):
        if phase == "verified":
            raise RuntimeError("crash")

    monkeypatch.setattr(_migrate, "_transition", crash)
    with pytest.raises(RuntimeError, match="crash"):
        _migrate.migrate(root, derive(key), arm=lambda root: None)
    with sc.connect(str(path)) as conn:
        conn.execute("UPDATE messages SET body='later committed writer'")
    conn.close()
    before = path.read_bytes()
    monkeypatch.setattr(_migrate, "_transition", lambda phase: None)
    with pytest.raises(DatabaseRefused):
        _migrate.resume(root)
    assert path.read_bytes() == before


def test_recovery_cannot_omit_plaintext_database_from_conversion(native_root, monkeypatch):
    import json

    root, _, key, _ = native_root
    (root / "mordred/db-encryption.marker").unlink()
    path = root / "state.db"
    with sc.connect(str(path)) as conn:
        conn.execute("CREATE TABLE messages (body TEXT)")
    conn.close()
    path.chmod(0o600)
    monkeypatch.setattr(_migrate, "holders", lambda paths: [])

    def crash(phase):
        if phase == "prepared":
            raise RuntimeError("crash")

    monkeypatch.setattr(_migrate, "_transition", crash)
    with pytest.raises(RuntimeError, match="crash"):
        _migrate.migrate(root, derive(key), arm=lambda root: None)
    journal = _migrate.journal_path(root)
    data = json.loads(journal.read_bytes())
    data["files"] = []
    journal.write_text(json.dumps(data))
    monkeypatch.setattr(_migrate, "_transition", lambda phase: None)
    before = path.read_bytes()
    with pytest.raises((DatabaseRefused, sc.DatabaseError)):
        _migrate.resume(root)
    assert path.read_bytes() == before and not (root / "mordred/db-encryption.marker").exists()


@pytest.mark.parametrize("phase", ["retained", "published", "retired"])
@pytest.mark.parametrize("direction", ["encrypt", "decrypt"])
def test_retained_original_publication_recovers_missing_canonical(native_root, monkeypatch, direction, phase):
    root, _, key, _ = native_root
    path = root / "state.db"
    if direction == "encrypt":
        (root / "mordred/db-encryption.marker").unlink()
        with sc.connect(str(path)) as conn:
            conn.execute("CREATE TABLE messages (body TEXT)")
            conn.execute("INSERT INTO messages VALUES ('retained original')")
        conn.close()
        path.chmod(0o600)
    else:
        cipher(path, key)
    monkeypatch.setattr(_migrate, "_two_step_publication", lambda: True)
    monkeypatch.setattr(_migrate, "holders", lambda paths: [])

    def crash(point):
        if point == phase:
            raise RuntimeError("crash")

    monkeypatch.setattr(_migrate, "_transition", crash)
    with pytest.raises(RuntimeError, match="crash"):
        if direction == "encrypt":
            _migrate.migrate(root, derive(key), arm=lambda root: None)
        else:
            _migrate.decrypt_all(root, derive(key))
    if phase == "retained":
        assert not path.exists()
        assert list(root.glob("state.db.mordred-original-*"))
    monkeypatch.setattr(_migrate, "_transition", lambda phase: None)
    _migrate.resume(root)
    assert path.exists()
    assert not list(root.glob("state.db.mordred-original-*"))
    with sc.connect(str(path)) as conn:
        if direction == "encrypt":
            apply_key(conn, derive(key))
        assert conn.execute("SELECT count(*) FROM messages").fetchone() == (1,)
    conn.close()


def test_unbound_macos_vault_adoption_preserves_ciphertext(mac_source, monkeypatch):
    _, root, backend, _, _ = mac_source
    marker = root / "mordred/db-encryption.marker"
    marker.write_bytes(b"1\n")
    marker.chmod(0o600)
    cipher(root / "state.db", b"a" * 32)
    before = (root / "state.db").read_bytes()
    monkeypatch.setattr(_migrate, "holders", lambda paths: [])
    backend.calls.clear()
    with acquire_exclusive(root) as lease:
        snapshot = _migrate.adopt_legacy(root, lease=lease)
    assert snapshot.provider == "secure-enclave"
    assert read_marker(root) == Marker(snapshot)
    assert (root / "state.db").read_bytes() == before
    assert sum(op == "ecdh" for op, _ in backend.calls) == 2
