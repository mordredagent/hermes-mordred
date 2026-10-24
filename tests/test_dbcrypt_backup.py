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


@pytest.mark.parametrize("phase", ["verified", "published"])
@pytest.mark.parametrize("unknown", [False, True])
def test_backup_recovery_refuses_live_external_writer(native_root, monkeypatch, phase, unknown):
    import json
    import os
    from pathlib import Path

    import sqlcipher3.dbapi2 as sc

    from mordred_hermes.dbcrypt import _backup, _migrate
    from mordred_hermes.dbcrypt._key import derive
    from mordred_hermes.dbcrypt._shim import apply_key

    root, _, key, _ = native_root
    cipher(root / "state.db", key)
    destination = root.parent / (root.name + "-writer.backup")

    def crash(point):
        if point == phase:
            raise RuntimeError("crash")

    monkeypatch.setattr(_backup, "_transition", crash)
    authority = Authority.acquire(root)
    try:
        with pytest.raises(RuntimeError, match="crash"):
            _backup.backup_database(root / "state.db", destination, authority=authority)
    finally:
        authority.close()
    journal = root / "mordred/db-backups.journal.json"
    data = json.loads(journal.read_bytes())
    candidate = Path(data["prepared"]) if phase == "verified" else destination
    writer = sc.connect(str(candidate))
    try:
        apply_key(writer, derive(key))
        writer.execute("UPDATE messages SET body='pending external writer'")
        assert writer.in_transaction
        sidecar = Path(str(candidate) + "-journal")
        assert sidecar.exists()
        paths = (journal, candidate, sidecar)
        before = {path: path.read_bytes() for path in paths}
        called = []

        def holders(paths):
            called.append(paths)
            assert candidate in paths
            return None if unknown else [os.getpid()]

        monkeypatch.setattr(_migrate, "holders", holders)
        monkeypatch.setattr(_backup, "_transition", lambda phase: None)
        with acquire_exclusive(root) as lease, pytest.raises(DatabaseRefused):
            _backup.recover_backups(root, lease=lease)
        assert called and writer.in_transaction
        assert {path: path.read_bytes() for path in before} == before
        assert destination.exists() == (phase == "published")
        assert not (root / "mordred/db-backups.json").exists()
    finally:
        writer.rollback()
        writer.close()


_RECIPROCAL_RECOVERY = r"""
import os, sys, threading, contextlib
from pathlib import Path
base, parent, phase = Path(sys.argv[1]), sys.argv[2], sys.argv[3]
os.environ['HERMES_HOME'] = str(base)
from mordred_hermes.keyvault import kek
kek._noop_audit = lambda entry: None
from pytest import MonkeyPatch
from mordred_hermes._database_lifecycle import acquire_exclusive
from mordred_hermes.dbcrypt import _backup, _migrate
from mordred_hermes.dbcrypt._authority import Authority
from mordred_hermes.keyvault import _memory_key as memory
from tests.test_dbcrypt_authority import native_root
from tests.test_dbcrypt_adoption import cipher
mp = MonkeyPatch()
roots, backends = [], {}
for name in ('a', 'b'):
    root = base / name
    root.mkdir(mode=0o700)
    root, backend, key, _ = native_root.__wrapped__(root, mp)
    roots.append(root)
    backends[root] = backend
    cipher(root / 'state.db', key)
    (root / 'mordred/backup-registry').mkdir(mode=0o700)
mp.setattr(memory, 'linux_memory_backend', lambda home: backends[home])
def stop(point):
    if point == phase:
        raise RuntimeError('crash')
mp.setattr(_backup, '_transition', stop)
real_delete = _backup._recover_delete
if phase == 'delete':
    def pause_delete(*args):
        raise RuntimeError('crash')
    mp.setattr(_backup, '_recover_delete', pause_delete)
for root, other in ((roots[0], roots[1]), (roots[1], roots[0])):
    authority = Authority.acquire(root)
    try:
        try:
            _backup.backup_database(root / 'state.db', other / parent / (root.name + '.backup'), authority=authority)
            if phase == 'delete':
                _backup.delete_backup(other / parent / (root.name + '.backup'), authority=authority)
        except RuntimeError as exc:
            assert str(exc) == 'crash'
    finally:
        authority.close()
mp.setattr(_backup, '_recover_delete', real_delete)
mp.setattr(_backup, '_transition', lambda point: None)
originals = {root: (root / 'state.db').read_bytes() for root in roots}
mp.setattr(_migrate, 'holders', lambda paths: [])
barrier = threading.Barrier(2)
external_barrier = threading.Barrier(2)
real_registry, real_open = _backup._registry, _backup.open_private_directory
seen, held, external_seen, errors = set(), {}, set(), []
@contextlib.contextmanager
def registry(root):
    with real_registry(root):
        held[threading.get_ident()] = root
        try:
            if root not in seen:
                seen.add(root)
                barrier.wait(timeout=4)
            yield
        finally:
            held.pop(threading.get_ident(), None)
class Wrapped:
    def __init__(self, directory, path):
        self.directory, self.path = directory, path
    def __getattr__(self, name):
        return getattr(self.directory, name)
    @contextlib.contextmanager
    def transaction(self, *, blocking=True):
        with self.directory.transaction(blocking=blocking) as tx:
            # Force simultaneous real opposite metadata locks in preparing
            # recovery, where old code next writes its own root journal.
            if parent == 'mordred' and self.path.name == 'mordred':
                ident = threading.get_ident()
                if ident not in external_seen:
                    external_seen.add(ident)
                    external_barrier.wait(timeout=4)
            yield tx
@contextlib.contextmanager
def opened(path, **kwargs):
    with real_open(path, **kwargs) as directory:
        yield Wrapped(directory, path)
mp.setattr(_backup, '_registry', registry)
mp.setattr(_backup, 'open_private_directory', opened)
def recover(root):
    try:
        with acquire_exclusive(root) as lease:
            _backup.recover_backups(root, lease=lease)
    except BaseException as exc:
        errors.append(repr(exc))
threads = [threading.Thread(target=recover, args=(root,), daemon=True) for root in roots]
for thread in threads:
    thread.start()
for thread in threads:
    thread.join(timeout=3)
if any(thread.is_alive() for thread in threads):
    print('reciprocal directory locks deadlocked', flush=True)
    os._exit(92)
assert not errors, errors
for root, other in ((roots[0], roots[1]), (roots[1], roots[0])):
    assert (other / parent / (root.name + '.backup')).exists() == (phase != 'delete')
    assert (root / 'state.db').read_bytes() == originals[root]
    assert not (root / 'mordred/db-backups.journal.json').exists()
    assert (root / 'mordred/db-backups.json').exists() == (phase != 'delete')
mp.undo()
"""


@pytest.mark.parametrize(
    "parent,phase",
    [
        ("mordred/backup-registry", "pending"),
        ("mordred/backup-registry", "verified"),
        ("mordred/backup-registry", "delete"),
        ("mordred", "pending"),
    ],
)
def test_reciprocal_backup_recovery_has_no_directory_lock_cycle(tmp_path, parent, phase):
    import subprocess
    import sys

    result = subprocess.run(
        [sys.executable, "-c", _RECIPROCAL_RECOVERY, str(tmp_path), parent, phase],
        text=True,
        capture_output=True,
        timeout=20,
    )
    assert result.returncode == 0, result.stdout + result.stderr
