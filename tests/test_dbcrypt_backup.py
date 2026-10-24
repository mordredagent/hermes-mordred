"""Managed encrypted backups retain root-generation dependencies through crashes."""

from __future__ import annotations

import pytest

from mordred_hermes._database_contracts import DatabaseRefused
from mordred_hermes._database_inventory import assert_mutation_safe, scan_dependencies
from mordred_hermes._database_lifecycle import acquire_exclusive
from mordred_hermes.dbcrypt._authority import Authority
from tests.test_dbcrypt_adoption import cipher
from tests.test_dbcrypt_authority import native_root as native_root


def test_backup_roundtrip_and_dependency(native_root, monkeypatch):
    from mordred_hermes.dbcrypt import _backup, _migrate

    root, _, key, snapshot = native_root
    source = root / "state.db"
    cipher(source, key)
    destination = root.parent / (root.name + "-backup.db")
    authority = Authority.acquire(root)
    try:
        assert _backup.backup_database(source, destination, authority=authority) == destination
    finally:
        authority.close()
    assert b"private" not in destination.read_bytes()
    assert any(d.kind == "backup" for d in scan_dependencies(root).entries)
    monkeypatch.setattr(_migrate, "holders", lambda paths: [])
    with acquire_exclusive(root) as lease:
        with pytest.raises(DatabaseRefused):
            assert_mutation_safe(root, snapshot.generation, lease)
        _backup.restore_database(destination, source, lease=lease)
    assert source.exists()


def test_backup_publish_crash_retains_dependency(native_root, monkeypatch):
    from mordred_hermes.dbcrypt import _backup

    root, backend, key, snapshot = native_root
    cipher(root / "state.db", key)
    destination = root.parent / (root.name + "-backup.db")

    def crash(phase):
        if phase == "published":
            raise RuntimeError("crash")

    monkeypatch.setattr(_backup, "_transition", crash)
    authority = Authority.acquire(root)
    try:
        with pytest.raises(RuntimeError, match="crash"):
            _backup.backup_database(root / "state.db", destination, authority=authority)
    finally:
        authority.close()
    assert destination.exists()
    assert (root / "mordred/db-backups.journal.json").exists()
    with acquire_exclusive(root) as lease:
        # Isolate backup state: marker and original DB cannot explain refusal.
        (root / "state.db").unlink()
        (root / "mordred/db-encryption.marker").unlink()
        with pytest.raises(DatabaseRefused):
            assert_mutation_safe(root, snapshot.generation, lease)
        monkeypatch.setattr(_backup, "_transition", lambda phase: None)
        _backup.recover_backups(root, lease=lease)
        with pytest.raises(DatabaseRefused):
            assert_mutation_safe(root, snapshot.generation, lease)
    assert any(d.kind == "backup" for d in scan_dependencies(root).entries)

    assert all(operation != "delete" for operation, _ in backend.calls)


@pytest.mark.parametrize("damage", ["root", "generation", "identity", "schema", "sidecar"])
def test_restore_refuses_foreign_or_changed_backup(native_root, monkeypatch, damage):
    import json

    from mordred_hermes.dbcrypt import _backup, _migrate

    root, _, key, _ = native_root
    source = root / "state.db"
    cipher(source, key)
    destination = root.parent / (root.name + "-backup.db")
    authority = Authority.acquire(root)
    try:
        _backup.backup_database(source, destination, authority=authority)
    finally:
        authority.close()
    registry = root / "mordred/db-backups.json"
    if damage in {"root", "generation"}:
        value = json.loads(registry.read_bytes())
        if damage == "root":
            value["snapshot"]["root"]["file_id"] = "0"
        else:
            value["snapshot"]["generation"] = "f" * 32
        registry.write_text(json.dumps(value))
    elif damage == "identity":
        copy = destination.with_suffix(".copy")
        copy.write_bytes(destination.read_bytes())
        copy.chmod(0o600)
        copy.replace(destination)
    elif damage == "schema":
        import sqlcipher3.dbapi2 as sc

        from mordred_hermes.dbcrypt._key import derive
        from mordred_hermes.dbcrypt._shim import apply_key

        with sc.connect(str(destination)) as conn:
            apply_key(conn, derive(key))
            conn.execute("DROP TABLE messages")
        conn.close()
    else:
        (root / "missing.db-wal").touch(mode=0o600)
    before = source.read_bytes()
    monkeypatch.setattr(_migrate, "holders", lambda paths: [])
    with acquire_exclusive(root) as lease, pytest.raises(DatabaseRefused):
        _backup.restore_database(destination, source, lease=lease)
    assert source.read_bytes() == before


def test_registered_backup_inventory_has_physical_path_and_generation(native_root):
    from mordred_hermes.dbcrypt import _backup

    root, _, key, snapshot = native_root
    source = root / "state.db"
    cipher(source, key)
    destination = root.parent / (root.name + "-backup.db")
    authority = Authority.acquire(root)
    try:
        _backup.backup_database(source, destination, authority=authority)
        entries = scan_dependencies(root).entries
        assert any(
            e.path == destination and e.generation == snapshot.generation and e.kind == "backup" for e in entries
        )
        _backup.delete_backup(destination, authority=authority)
    finally:
        authority.close()
    assert not destination.exists()
    assert not (root / "mordred/db-backups.json").exists()


def test_backup_rejects_unchecked_destination_without_mutation(native_root):
    from mordred_hermes.dbcrypt import _backup

    root, _, key, _ = native_root
    source = root / "state.db"
    cipher(source, key)
    destination = root.parent / (root.name + "-backup.db")
    destination.symlink_to(source)
    before = source.read_bytes()
    authority = Authority.acquire(root)
    try:
        with pytest.raises((DatabaseRefused, OSError)):
            _backup.backup_database(source, destination, authority=authority)
    finally:
        authority.close()
    assert source.read_bytes() == before
    assert not (root / "mordred/db-backups.journal.json").exists()


def test_backup_refuses_wal_reset_vulnerable_source(native_root, monkeypatch):
    from mordred_hermes.dbcrypt import _backup, _migrate
    from mordred_hermes.dbcrypt._connection import open_protected

    root, _, key, _ = native_root
    source = root / "state.db"
    cipher(source, key)
    destination = root.parent / (root.name + "-backup.db")
    authority = Authority.acquire(root)
    try:
        connection = open_protected(source, authority=authority)
        assert connection.execute("PRAGMA journal_mode=WAL").fetchone() == ("wal",)
        connection.close()
        monkeypatch.setattr(_migrate, "wal_reset_vulnerable", lambda version: True)
        with pytest.raises(DatabaseRefused, match="WAL"):
            _backup.backup_database(source, destination, authority=authority)
        assert not destination.exists()
    finally:
        authority.close()


@pytest.mark.parametrize("phase", ["pending", "staged", "verified", "published", "registered"])
def test_backup_recovers_each_durable_publication(native_root, monkeypatch, phase):
    from mordred_hermes.dbcrypt import _backup, _migrate

    root, _, key, _ = native_root
    source = root / "state.db"
    cipher(source, key)
    destination = root.parent / (root.name + "-backup.db")

    def crash(point):
        if point == phase:
            raise RuntimeError("crash")

    monkeypatch.setattr(_backup, "_transition", crash)
    authority = Authority.acquire(root)
    try:
        with pytest.raises(RuntimeError, match="crash"):
            _backup.backup_database(source, destination, authority=authority)
    finally:
        authority.close()
    monkeypatch.setattr(_backup, "_transition", lambda phase: None)
    monkeypatch.setattr(_migrate, "holders", lambda paths: [])
    with acquire_exclusive(root) as lease:
        _backup.recover_backups(root, lease=lease)
    assert destination.exists()
    assert not (root / "mordred/db-backups.journal.json").exists()
    assert any(e.path == destination and e.kind == "backup" for e in scan_dependencies(root).entries)


def test_backup_deletion_crash_retains_dependency_until_reconciled(native_root, monkeypatch):
    from mordred_hermes.dbcrypt import _backup

    root, _, key, snapshot = native_root
    source = root / "state.db"
    cipher(source, key)
    destination = root.parent / (root.name + "-backup.db")
    authority = Authority.acquire(root)
    try:
        _backup.backup_database(source, destination, authority=authority)

        def crash(phase):
            if phase == "deleted":
                raise RuntimeError("crash")

        monkeypatch.setattr(_backup, "_transition", crash)
        with pytest.raises(RuntimeError, match="crash"):
            _backup.delete_backup(destination, authority=authority)
    finally:
        authority.close()
    assert not destination.exists()
    assert (root / "mordred/db-backups.json").exists()
    monkeypatch.setattr(_backup, "_transition", lambda phase: None)
    with acquire_exclusive(root) as lease:
        with pytest.raises(DatabaseRefused):
            assert_mutation_safe(root, snapshot.generation, lease)
        _backup.recover_backups(root, lease=lease)
    assert not (root / "mordred/db-backups.json").exists()
    assert not (root / "mordred/db-backups.journal.json").exists()


def test_backup_inventory_keeps_schema_proof_without_sql_literals(native_root):
    import sqlcipher3.dbapi2 as sc

    from mordred_hermes.dbcrypt import _backup
    from mordred_hermes.dbcrypt._key import derive
    from mordred_hermes.dbcrypt._shim import apply_key

    root, _, key, _ = native_root
    source = root / "state.db"
    with sc.connect(str(source)) as conn:
        apply_key(conn, derive(key))
        conn.execute("CREATE TABLE secrets (value TEXT DEFAULT 'schema literal stays private')")
    conn.close()
    source.chmod(0o600)
    authority = Authority.acquire(root)
    try:
        _backup.backup_database(source, root.parent / (root.name + "-backup.db"), authority=authority)
    finally:
        authority.close()
    assert b"schema literal stays private" not in (root / "mordred/db-backups.json").read_bytes()


def test_backup_never_observes_custody_inside_registry_lock(native_root, monkeypatch):
    from contextlib import contextmanager

    from mordred_hermes.dbcrypt import _authority, _backup

    root, _, key, _ = native_root
    cipher(root / "state.db", key)
    authority = Authority.acquire(root)
    held = []
    registry, observe = _backup._registry, _authority.observe_database_source

    @contextmanager
    def locked(root):
        with registry(root):
            held.append(True)
            try:
                yield
            finally:
                held.pop()

    def checked_observe(**kwargs):
        assert not held, "custody scope acquired after inventory lock"
        return observe(**kwargs)

    monkeypatch.setattr(_backup, "_registry", locked)
    monkeypatch.setattr(_authority, "observe_database_source", checked_observe)
    try:
        _backup.backup_database(root / "state.db", root.parent / (root.name + "-backup.db"), authority=authority)
    finally:
        authority.close()
