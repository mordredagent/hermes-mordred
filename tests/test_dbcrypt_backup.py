"""Managed encrypted backups retain root-generation dependencies through crashes."""

from __future__ import annotations

import errno
import json
import os
import shutil

import pytest

from mordred_hermes._core._database_contracts import DatabaseRefused
from mordred_hermes._core._database_inventory import assert_mutation_safe, scan_dependencies
from mordred_hermes._core._database_lifecycle import acquire_exclusive
from mordred_hermes.dbcrypt._authority import Authority
from tests.test_dbcrypt_adoption import cipher
from tests.test_dbcrypt_authority import native_root as native_root


def test_windows_backup_ancestor_parent_refuses_before_journal_or_staging(native_root, monkeypatch):
    from types import SimpleNamespace

    from mordred_hermes.dbcrypt import _backup, _windows_vfs

    root, _, key, _ = native_root
    source = root / "state.db"
    cipher(source, key)
    before = source.read_bytes()
    destination = root.parent / (root.name + "-ancestor.backup")
    authority = Authority.acquire(root)
    monkeypatch.setattr(_backup, "os", SimpleNamespace(name="nt"))
    monkeypatch.setattr(_windows_vfs, "NATIVE_QUALIFIED", True)
    monkeypatch.setattr(_windows_vfs, "windows_edition_admitted", lambda: True)
    try:
        with pytest.raises(DatabaseRefused, match=r"separate.*directory"):
            _backup.backup_database(source, destination, authority=authority)
        assert source.read_bytes() == before
        assert not destination.exists()
        assert not list(destination.parent.glob(destination.name + ".mordred-backup-*"))
        assert not (root / "mordred/db-backups.journal.json").exists()
        assert not (root / "mordred/backup-registry").exists()
    finally:
        authority.close()


def test_windows_backup_live_root_overlap_refuses_before_journal(native_root, monkeypatch):
    import sqlcipher3.dbapi2 as sc

    from mordred_hermes.dbcrypt import _backup, _windows_vfs
    from tests._dbcrypt_windows_fakes import protected_windows_environment

    root, _, key, _ = native_root
    source = root / "state.db"
    cipher(source, key)
    before = source.read_bytes()
    parent = root.parent / "other-backups"
    other = parent / "other-live-root"
    parent.mkdir(mode=0o700)
    other.mkdir(mode=0o700)
    native = protected_windows_environment(monkeypatch)
    registration = _windows_vfs.register_checked_vfs(sc, root=other)
    authority = Authority.acquire(root)
    try:
        with pytest.raises(DatabaseRefused, match=r"separate.*directory"):
            _backup.backup_database(source, parent / "refused.backup", authority=authority)
        assert source.read_bytes() == before
        assert list(parent.iterdir()) == [other]
        assert not (root / "mordred/db-backups.journal.json").exists()
        assert not (root / "mordred/backup-registry").exists()
        assert len(native.roots) == 1
    finally:
        authority.close()
        registration.close()


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
    from mordred_hermes.dbcrypt import _backup, _migrate

    root, backend, key, snapshot = native_root
    monkeypatch.setattr(_migrate, "holders", lambda paths: [])
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
from mordred_hermes._core._database_lifecycle import acquire_exclusive
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


@pytest.mark.parametrize("operation", ["publish", "delete"])
def test_uncertain_namespace_barrier_keeps_backup_intent_and_key_dependency(native_root, monkeypatch, operation):
    from contextlib import contextmanager

    from mordred_hermes._private_fs import PrivateFSError
    from mordred_hermes.dbcrypt import _backup, _migrate

    root, _, key, snapshot = native_root
    cipher(root / "state.db", key)
    destination = root.parent / (root.name + "-barrier.backup")
    opened = _backup.open_private_directory

    class Transaction:
        def __init__(self, tx):
            self.tx = tx

        def __getattr__(self, name):
            return getattr(self.tx, name)

        def rename_file(self, *args, **kwargs):
            self.tx.rename_file(*args, **kwargs)
            if operation == "publish":
                raise PrivateFSError("io", "directory_flush", commit_state="uncertain")

        def delete_file(self, *args, **kwargs):
            self.tx.delete_file(*args, **kwargs)
            if operation == "delete":
                raise PrivateFSError("io", "directory_flush", commit_state="uncertain")

    class Directory:
        def __init__(self, directory):
            self.directory = directory

        def __getattr__(self, name):
            return getattr(self.directory, name)

        @contextmanager
        def transaction(self, **kwargs):
            with self.directory.transaction(**kwargs) as tx:
                yield Transaction(tx)

    @contextmanager
    def fail_barrier(path, **kwargs):
        with opened(path, **kwargs) as directory:
            yield Directory(directory) if path == destination.parent else directory

    authority = Authority.acquire(root)
    try:
        if operation == "delete":
            _backup.backup_database(root / "state.db", destination, authority=authority)
        monkeypatch.setattr(_backup, "open_private_directory", fail_barrier)
        with pytest.raises(PrivateFSError) as error:
            if operation == "publish":
                _backup.backup_database(root / "state.db", destination, authority=authority)
            else:
                _backup.delete_backup(destination, authority=authority)
        assert error.value.commit_state == "uncertain"
    finally:
        authority.close()
    assert (root / "mordred/db-backups.journal.json").exists()
    assert destination.exists() == (operation == "publish")
    if operation == "delete":
        assert (root / "mordred/db-backups.json").exists()
    monkeypatch.setattr(_backup, "open_private_directory", opened)
    monkeypatch.setattr(_migrate, "holders", lambda paths: [])
    with acquire_exclusive(root) as lease:
        with pytest.raises(DatabaseRefused):
            assert_mutation_safe(root, snapshot.generation, lease)
        _backup.recover_backups(root, lease=lease)
    assert not (root / "mordred/db-backups.journal.json").exists()


def _crashed_backup(native_root, monkeypatch, phase, destination=None):
    """Leave a durable journal at a real transition, as a crash would."""
    from mordred_hermes.dbcrypt import _backup, _migrate

    root, _, key, _ = native_root
    source = root / "state.db"
    if not source.exists():
        cipher(source, key)
    destination = destination or root.parent / (root.name + "-backup.db")

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
    return destination


def _enospc(*_args, **_kwargs):
    raise OSError(errno.ENOSPC, "no space")


def test_backup_journal_refusal_names_recover_command(native_root, monkeypatch):
    from mordred_hermes._core._database_contracts import BackupRecoveryRequired
    from mordred_hermes.dbcrypt import _backup

    root, _, _, _ = native_root
    destination = _crashed_backup(native_root, monkeypatch, "published")
    other = root.parent / (root.name + "-other.backup")
    authority = Authority.acquire(root)
    try:
        with pytest.raises(BackupRecoveryRequired, match="databases backup recover"):
            _backup.backup_database(root / "state.db", other, authority=authority)
    finally:
        authority.close()
    with acquire_exclusive(root) as lease, pytest.raises(BackupRecoveryRequired, match="running or was interrupted"):
        _backup.export_database(root, destination, root.parent / (root.name + "-plain.db"), lease=lease)


def test_conversion_markers_keep_the_generic_refusal(native_root):
    from mordred_hermes._core._database_contracts import BackupRecoveryRequired
    from mordred_hermes.dbcrypt import _backup

    root, _, _, _ = native_root
    (root / "mordred/db-encryption.pending").write_bytes(b"")
    (root / "mordred/db-backups.journal.json").write_bytes(b"{}")
    with pytest.raises(DatabaseRefused, match="database maintenance requires recovery before backup") as refused:
        _backup._no_pending(root)
    assert not isinstance(refused.value, BackupRecoveryRequired)


def test_recover_without_journal_is_noop_before_authentication(native_root, monkeypatch):
    from mordred_hermes.dbcrypt import _backup, _migrate

    root, backend, _, _ = native_root
    backend.calls.clear()
    monkeypatch.setattr(_migrate, "_authenticate", lambda *a, **k: pytest.fail("authenticated"))
    with acquire_exclusive(root) as lease:
        result = _backup.recover_backups(root, lease=lease)
        assert result.outcome == "none" and result.path is None
        assert _backup.abandon_backup_journal(root, lease=lease, commit=True) is None
    assert backend.calls == []


def test_copy_failure_cleans_staging_and_journal_and_next_backup_succeeds(native_root, monkeypatch):
    from mordred_hermes.dbcrypt import _backup

    root, _, key, _ = native_root
    cipher(root / "state.db", key)
    destination = root.parent / (root.name + "-clean.backup")
    authority = Authority.acquire(root)
    try:
        with pytest.MonkeyPatch.context() as patch:
            patch.setattr(_backup, "_copy", _enospc)
            with pytest.raises(OSError, match="no space"):
                _backup.backup_database(root / "state.db", destination, authority=authority)
        assert not (root / "mordred/db-backups.journal.json").exists()
        assert not list(destination.parent.glob(destination.name + ".mordred-backup-*"))
        assert not destination.exists()
        assert not (root / "mordred/db-backups.json").exists()
        _backup.backup_database(root / "state.db", destination, authority=authority)
    finally:
        authority.close()
    assert any(e.path == destination and e.kind == "backup" for e in scan_dependencies(root).entries)


@pytest.mark.parametrize("phase", ["verified", "published"])
def test_abandon_preview_and_commit_remove_only_the_journal(native_root, monkeypatch, phase):
    from mordred_hermes.dbcrypt import _backup

    root, _, _, _ = native_root
    destination = _crashed_backup(native_root, monkeypatch, phase)
    journal = root / "mordred/db-backups.journal.json"
    data = json.loads(journal.read_bytes())
    staging = _backup.Path(data["prepared"])
    kept = destination if phase == "published" else staging
    before = kept.read_bytes()
    with acquire_exclusive(root) as lease:
        preview = _backup.abandon_backup_journal(root, lease=lease, commit=False)
        assert preview is not None and preview.removed is False
        assert journal.exists()
        assert (preview.destination, preview.staging) == (destination, staging)
        assert preview.phase == "verified"  # the journal phase stays verified once published
        assert preview.destination_state == ("present" if phase == "published" else "absent")
        assert preview.staging_state == ("absent" if phase == "published" else "present")
        done = _backup.abandon_backup_journal(root, lease=lease, commit=True, accept_unmanaged_copy=True)
    assert done is not None and done.removed is True
    assert not journal.exists()
    assert kept.read_bytes() == before
    assert not (root / "mordred/db-backups.json").exists()


def test_recover_reports_published_and_deleted_outcomes(native_root, monkeypatch):
    from mordred_hermes.dbcrypt import _backup

    root, _, _, _ = native_root
    destination = _crashed_backup(native_root, monkeypatch, "published")
    with acquire_exclusive(root) as lease:
        result = _backup.recover_backups(root, lease=lease)
    assert (result.outcome, result.path) == ("published", destination)

    def crash(point):
        if point == "deleted":
            raise RuntimeError("crash")

    monkeypatch.setattr(_backup, "_transition", crash)
    authority = Authority.acquire(root)
    try:
        with pytest.raises(RuntimeError, match="crash"):
            _backup.delete_backup(destination, authority=authority)
    finally:
        authority.close()
    monkeypatch.setattr(_backup, "_transition", lambda point: None)
    with acquire_exclusive(root) as lease:
        result = _backup.recover_backups(root, lease=lease)
    assert (result.outcome, result.path) == ("deleted", destination)


def _backup_failing_during_copy(native_root, during_copy):
    """Fail an ordinary copy after `during_copy(staged, journal)` disturbed the operation's state."""
    from mordred_hermes.dbcrypt import _backup

    root, _, key, _ = native_root
    cipher(root / "state.db", key)
    parent = root.parent / (root.name + "-destinations")
    parent.mkdir(mode=0o700)
    journal = root / "mordred/db-backups.journal.json"
    seen = {}

    def failing_copy(_source, staged, _authority):
        seen["staged"] = staged
        during_copy(staged, journal)
        _enospc()

    authority = Authority.acquire(root)
    try:
        with pytest.MonkeyPatch.context() as patch:
            patch.setattr(_backup, "_copy", failing_copy)
            with pytest.raises(OSError, match="no space"):
                _backup.backup_database(root / "state.db", parent / "one.backup", authority=authority)
    finally:
        authority.close()
    return journal, seen["staged"]


def test_cleanup_never_deletes_a_swapped_staging_file(native_root):
    def swap(staged, _journal):
        other = staged.with_name("unrelated")
        other.write_bytes(b"unrelated user data")
        other.chmod(0o600)
        os.replace(other, staged)  # same name, different inode

    journal, staged = _backup_failing_during_copy(native_root, swap)
    assert staged.read_bytes() == b"unrelated user data"
    assert journal.exists()


def test_cleanup_never_follows_a_staging_symlink_to_the_source(native_root):
    source = native_root[0] / "state.db"
    before = {}

    def swap(staged, _journal):
        before["source"] = source.read_bytes()
        staged.unlink()
        staged.symlink_to(source)

    journal, staged = _backup_failing_during_copy(native_root, swap)
    assert staged.is_symlink() and source.read_bytes() == before["source"]
    assert journal.exists()


def test_cleanup_retains_everything_when_the_journal_is_not_ours(native_root):
    edited = {}

    def edit(_staged, journal):
        data = json.loads(journal.read_bytes())
        data["transaction"] = "0" * 32
        journal.write_text(json.dumps(data, sort_keys=True, separators=(",", ":")) + "\n")
        edited["bytes"] = journal.read_bytes()

    journal, staged = _backup_failing_during_copy(native_root, edit)
    assert journal.read_bytes() == edited["bytes"]
    assert staged.exists()


def test_cleanup_leaves_a_replaced_destination_directory_alone(native_root):
    moved = {}

    def replace_parent(staged, _journal):
        parent = staged.parent
        moved["parent"] = parent.with_name(parent.name + "-moved")
        os.rename(parent, moved["parent"])
        parent.mkdir(mode=0o700)
        (parent / staged.name).write_bytes(b"decoy")
        (parent / staged.name).chmod(0o600)

    journal, staged = _backup_failing_during_copy(native_root, replace_parent)
    assert staged.read_bytes() == b"decoy"
    assert (moved["parent"] / staged.name).exists()
    assert journal.exists()


def test_journal_under_a_non_directory_is_absent(tmp_path):
    from mordred_hermes.dbcrypt import _backup

    (tmp_path / "mordred").write_bytes(b"not a directory")
    assert not _backup._journal_present(tmp_path)


def test_cleanup_failure_retains_journal_and_original_error(native_root, monkeypatch, caplog):
    from mordred_hermes.dbcrypt import _backup, _migrate

    root, _, key, _ = native_root
    cipher(root / "state.db", key)
    destination = root.parent / (root.name + "-retained.backup")

    def refuse(_path):
        raise RuntimeError("cleanup refused")

    authority = Authority.acquire(root)
    try:
        with pytest.MonkeyPatch.context() as patch:
            patch.setattr(_backup, "_copy", _enospc)
            patch.setattr(_migrate, "_cleanup_sidecars", refuse)
            with caplog.at_level("WARNING", logger="mordred.dbcrypt"), pytest.raises(OSError, match="no space"):
                _backup.backup_database(root / "state.db", destination, authority=authority)
    finally:
        authority.close()
    assert "databases backup recover" in caplog.text
    assert "cleanup refused" not in caplog.text and str(destination.parent) not in caplog.text
    assert (root / "mordred/db-backups.journal.json").exists()
    assert len(list(destination.parent.glob(destination.name + ".mordred-backup-*"))) == 1
    monkeypatch.setattr(_migrate, "holders", lambda paths: [])
    with acquire_exclusive(root) as lease:
        assert _backup.recover_backups(root, lease=lease).outcome == "published"
    assert destination.exists()


def test_cleanup_skips_when_authority_is_invalid(native_root, monkeypatch):
    from mordred_hermes.dbcrypt import _backup

    root, _, key, _ = native_root
    cipher(root / "state.db", key)
    destination = root.parent / (root.name + "-revoked.backup")
    authority = Authority.acquire(root)

    def revoked(*_args, **_kwargs):
        authority.invalidate("test")
        raise OSError(errno.ENOSPC, "no space")

    try:
        monkeypatch.setattr(_backup, "_copy", revoked)
        with pytest.raises((OSError, DatabaseRefused)):
            _backup.backup_database(root / "state.db", destination, authority=authority)
    finally:
        authority.close()
    assert (root / "mordred/db-backups.journal.json").exists()
    assert len(list(destination.parent.glob(destination.name + ".mordred-backup-*"))) == 1


def test_keyboard_interrupt_during_copy_retains_journal(native_root, monkeypatch):
    from mordred_hermes.dbcrypt import _backup, _migrate

    root, _, key, _ = native_root
    cipher(root / "state.db", key)
    destination = root.parent / (root.name + "-interrupted.backup")

    def interrupted(*_args, **_kwargs):
        raise KeyboardInterrupt

    authority = Authority.acquire(root)
    try:
        with pytest.MonkeyPatch.context() as patch:
            patch.setattr(_backup, "_copy", interrupted)
            with pytest.raises(KeyboardInterrupt):
                _backup.backup_database(root / "state.db", destination, authority=authority)
    finally:
        authority.close()
    assert (root / "mordred/db-backups.journal.json").exists()
    assert len(list(destination.parent.glob(destination.name + ".mordred-backup-*"))) == 1
    monkeypatch.setattr(_migrate, "holders", lambda paths: [])
    with acquire_exclusive(root) as lease:
        assert _backup.recover_backups(root, lease=lease).outcome == "published"


def test_uncertain_staging_flush_retains_journal(native_root, monkeypatch):
    from contextlib import contextmanager

    from mordred_hermes._private_fs import PrivateFSError
    from mordred_hermes.dbcrypt import _backup, _migrate

    root, _, key, _ = native_root
    cipher(root / "state.db", key)
    destination = root.parent / (root.name + "-flush.backup")
    opened = _backup.open_private_directory

    class Transaction:
        def __init__(self, tx):
            self.tx = tx

        def __getattr__(self, name):
            return getattr(self.tx, name)

        def flush_file(self, *_args, **_kwargs):
            raise PrivateFSError("io", "directory_flush", commit_state="uncertain")

    class Directory:
        def __init__(self, directory):
            self.directory = directory

        def __getattr__(self, name):
            return getattr(self.directory, name)

        @contextmanager
        def transaction(self, **kwargs):
            with self.directory.transaction(**kwargs) as tx:
                yield Transaction(tx)

    @contextmanager
    def uncertain(path, **kwargs):
        with opened(path, **kwargs) as directory:
            yield Directory(directory) if path == destination.parent else directory

    authority = Authority.acquire(root)
    try:
        with pytest.MonkeyPatch.context() as patch:
            patch.setattr(_backup, "open_private_directory", uncertain)
            with pytest.raises(PrivateFSError) as failure:
                _backup.backup_database(root / "state.db", destination, authority=authority)
        assert failure.value.commit_state == "uncertain"
    finally:
        authority.close()
    assert (root / "mordred/db-backups.journal.json").exists()
    assert len(list(destination.parent.glob(destination.name + ".mordred-backup-*"))) == 1
    monkeypatch.setattr(_migrate, "holders", lambda paths: [])
    with acquire_exclusive(root) as lease:
        assert _backup.recover_backups(root, lease=lease).outcome == "published"


def test_cleanup_crash_between_staging_and_journal_needs_abandon(native_root, monkeypatch):
    from mordred_hermes.dbcrypt import _backup, _migrate

    root, _, key, _ = native_root
    cipher(root / "state.db", key)
    destination = root.parent / (root.name + "-window.backup")
    journal = root / "mordred/db-backups.journal.json"

    def lost(_root, _name):
        raise RuntimeError("crash window")

    authority = Authority.acquire(root)
    try:
        with pytest.MonkeyPatch.context() as patch:
            patch.setattr(_backup, "_copy", _enospc)
            patch.setattr(_migrate, "_remove_record", lost)
            with pytest.raises(OSError, match="no space"):
                _backup.backup_database(root / "state.db", destination, authority=authority)
    finally:
        authority.close()
    assert journal.exists()
    assert not list(destination.parent.glob(destination.name + ".mordred-backup-*"))
    monkeypatch.setattr(_migrate, "holders", lambda paths: [])
    with acquire_exclusive(root) as lease:
        with pytest.raises(DatabaseRefused, match="ownership is uncertain"):
            _backup.recover_backups(root, lease=lease)
        preview = _backup.abandon_backup_journal(root, lease=lease, commit=False)
        assert preview is not None and preview.staging_state == "absent" and journal.exists()
        assert _backup.abandon_backup_journal(root, lease=lease, commit=True) is not None
    assert not journal.exists()
    authority = Authority.acquire(root)
    try:
        _backup.backup_database(root / "state.db", destination, authority=authority)
    finally:
        authority.close()


def test_abandon_refuses_delete_journal_and_recover_clears_it(native_root, monkeypatch):
    from mordred_hermes.dbcrypt import _backup

    root, _, key, _ = native_root
    cipher(root / "state.db", key)
    destination = root.parent / (root.name + "-deleting.backup")
    journal = root / "mordred/db-backups.journal.json"
    authority = Authority.acquire(root)
    try:
        _backup.backup_database(root / "state.db", destination, authority=authority)

        def crash(point):
            if point == "deleted":
                raise RuntimeError("crash")

        monkeypatch.setattr(_backup, "_transition", crash)
        with pytest.raises(RuntimeError, match="crash"):
            _backup.delete_backup(destination, authority=authority)
    finally:
        authority.close()
    monkeypatch.setattr(_backup, "_transition", lambda point: None)
    before = journal.read_bytes()
    with acquire_exclusive(root) as lease:
        with pytest.raises(DatabaseRefused, match="deletion in progress"):
            _backup.abandon_backup_journal(root, lease=lease, commit=True)
        assert journal.read_bytes() == before
        assert _backup.recover_backups(root, lease=lease).outcome == "deleted"
    assert not journal.exists()


@pytest.mark.parametrize("damage", ["corrupt", "generation", "paths"])
def test_abandon_and_recover_refuse_corrupt_or_foreign_journal(native_root, monkeypatch, damage):
    from mordred_hermes.dbcrypt import _backup

    root, _, _, _ = native_root
    _crashed_backup(native_root, monkeypatch, "published")
    journal = root / "mordred/db-backups.journal.json"
    data = json.loads(journal.read_bytes())
    if damage == "corrupt":
        journal.write_bytes(b"{not json")
    else:
        if damage == "generation":
            data["snapshot"]["generation"] = "0" * 32
        else:
            other = root.parent / (root.name + "-other-parent")
            other.mkdir(mode=0o700)
            data["prepared"] = str(other / _backup.Path(data["prepared"]).name)
        journal.write_text(json.dumps(data))
    before = journal.read_bytes()
    with acquire_exclusive(root) as lease:
        with pytest.raises(DatabaseRefused):
            _backup.recover_backups(root, lease=lease)
        for commit in (False, True):
            with pytest.raises(DatabaseRefused):
                _backup.abandon_backup_journal(root, lease=lease, commit=commit)
    assert journal.read_bytes() == before


def test_abandon_survives_removed_destination_directory(native_root, monkeypatch):
    from mordred_hermes._private_fs import PrivateFSError
    from mordred_hermes.dbcrypt import _backup

    root, _, _, _ = native_root
    gone = root.parent / (root.name + "-gone")
    gone.mkdir(mode=0o700)
    _crashed_backup(native_root, monkeypatch, "verified", destination=gone / "x.backup")
    shutil.rmtree(gone)
    journal = root / "mordred/db-backups.journal.json"
    with acquire_exclusive(root) as lease:
        with pytest.raises(PrivateFSError):
            _backup.recover_backups(root, lease=lease)
        preview = _backup.abandon_backup_journal(root, lease=lease, commit=False)
        assert preview is not None
        assert (preview.destination_state, preview.staging_state) == ("absent", "absent")
        assert journal.exists()
        assert _backup.abandon_backup_journal(root, lease=lease, commit=True) is not None
    assert not journal.exists()
    elsewhere = root.parent / (root.name + "-elsewhere.backup")
    authority = Authority.acquire(root)
    try:
        _backup.backup_database(root / "state.db", elsewhere, authority=authority)
    finally:
        authority.close()
    assert elsewhere.exists()


def test_abandon_reports_embedded_nul_paths_as_unknown(native_root, monkeypatch):
    from mordred_hermes.dbcrypt import _backup

    root, _, _, _ = native_root
    _crashed_backup(native_root, monkeypatch, "verified")
    journal = root / "mordred/db-backups.journal.json"
    data = json.loads(journal.read_bytes())
    parent = root.parent
    data["destination"] = str(parent / "x\x00y.backup")
    data["prepared"] = str(parent / "x\x00y.backup.mordred-backup-ab")
    journal.write_text(json.dumps(data))
    with acquire_exclusive(root) as lease:
        preview = _backup.abandon_backup_journal(root, lease=lease, commit=False)
    assert preview is not None
    assert (preview.destination_state, preview.staging_state) == ("unknown", "unknown")


def _publish_interrupted_after_link(native_root, monkeypatch, destination):
    """Really fail rename_file between its link and unlink, as a crash there would."""
    import os

    from mordred_hermes.dbcrypt import _backup

    root, _, key, _ = native_root
    cipher(root / "state.db", key)
    real_unlink = os.unlink

    def interrupted(path, *args, **kwargs):
        if ".mordred-backup-" in str(path):
            raise OSError(errno.EIO, "crash window")
        return real_unlink(path, *args, **kwargs)

    authority = Authority.acquire(root)
    try:
        with pytest.MonkeyPatch.context() as patch:
            patch.setattr(os, "unlink", interrupted)
            with pytest.raises(OSError):  # the transaction reports it as an uncertain commit
                _backup.backup_database(root / "state.db", destination, authority=authority)
    finally:
        authority.close()


@pytest.mark.skipif(os.name != "posix", reason="POSIX rename is link then unlink")
def test_recover_finishes_a_rename_interrupted_between_link_and_unlink(native_root, monkeypatch):
    from mordred_hermes.dbcrypt import _backup, _migrate

    root, _, _, _ = native_root
    destination = root.parent / (root.name + "-linked.backup")
    _publish_interrupted_after_link(native_root, monkeypatch, destination)
    journal = root / "mordred/db-backups.journal.json"
    staged = _backup.Path(json.loads(journal.read_bytes())["prepared"])
    assert destination.stat().st_ino == staged.stat().st_ino and destination.stat().st_nlink == 2
    monkeypatch.setattr(_migrate, "holders", lambda paths: [])
    with acquire_exclusive(root) as lease:
        result = _backup.recover_backups(root, lease=lease)
    assert result.outcome == "published" and result.path == destination
    assert not staged.exists() and destination.stat().st_nlink == 1 and not journal.exists()
    assert any(e.path == destination and e.kind == "backup" for e in scan_dependencies(root).entries)


@pytest.mark.skipif(os.name != "posix", reason="POSIX rename is link then unlink")
def test_recover_never_unlinks_a_two_name_inode_the_journal_does_not_record(native_root, monkeypatch):
    from mordred_hermes.dbcrypt import _backup, _migrate

    root, _, _, _ = native_root
    destination = root.parent / (root.name + "-unrecorded.backup")
    _publish_interrupted_after_link(native_root, monkeypatch, destination)
    journal = root / "mordred/db-backups.journal.json"
    data = json.loads(journal.read_bytes())
    staged = _backup.Path(data["prepared"])
    data["identity"][1] += 1
    journal.write_text(json.dumps(data))
    monkeypatch.setattr(_migrate, "holders", lambda paths: [])
    with acquire_exclusive(root) as lease, pytest.raises(DatabaseRefused, match="proof failed"):
        _backup.recover_backups(root, lease=lease)
    assert staged.exists() and destination.exists() and journal.exists()


@pytest.mark.skipif(os.name != "posix", reason="POSIX rename is link then unlink")
@pytest.mark.parametrize("state", ["distinct", "third_link", "missing_destination"])
def test_finish_interrupted_rename_refuses_anything_but_one_two_link_inode(tmp_path, state):
    import os

    from mordred_hermes._private_fs import PrivateFSError, open_private_directory

    tmp_path.chmod(0o700)
    source = tmp_path / "source"
    with open_private_directory(tmp_path) as directory, directory.transaction() as tx:
        tx.create_bytes("source", b"data")
        if state == "distinct":
            tx.create_bytes("target", b"other")
    if state != "distinct" and state != "missing_destination":
        os.link(source, tmp_path / "target")
    if state == "third_link":
        os.link(source, tmp_path / "third")
    with (
        open_private_directory(tmp_path) as directory,
        directory.transaction() as tx,
        pytest.raises(PrivateFSError),
    ):
        tx.finish_interrupted_rename("source", "target")
    assert source.read_bytes() == b"data"


def test_abandon_commit_keeps_the_journal_when_a_copy_may_remain(native_root, monkeypatch):
    from mordred_hermes.dbcrypt import _backup

    root, _, _, _ = native_root
    destination = _crashed_backup(native_root, monkeypatch, "published")
    journal = root / "mordred/db-backups.journal.json"
    before = journal.read_bytes()
    with acquire_exclusive(root) as lease:
        refused = _backup.abandon_backup_journal(root, lease=lease, commit=True)
        assert refused is not None and refused.removed is False and refused.copy_may_remain
        assert journal.read_bytes() == before
        accepted = _backup.abandon_backup_journal(root, lease=lease, commit=True, accept_unmanaged_copy=True)
    assert accepted is not None and accepted.removed is True
    assert not journal.exists() and destination.exists()


def test_abandon_commit_keeps_the_journal_when_a_path_is_unknown(native_root, monkeypatch):
    from mordred_hermes.dbcrypt import _backup

    root, _, _, _ = native_root
    _crashed_backup(native_root, monkeypatch, "verified")
    journal = root / "mordred/db-backups.journal.json"
    monkeypatch.setattr(_backup, "_lexical_state", lambda path: "unknown")
    with acquire_exclusive(root) as lease:
        plan = _backup.abandon_backup_journal(root, lease=lease, commit=True)
    assert plan is not None and plan.removed is False and journal.exists()


def test_abandon_after_registration_needs_no_acceptance_and_keeps_the_entry(native_root, monkeypatch):
    from mordred_hermes.dbcrypt import _backup

    root, _, _, _ = native_root
    destination = _crashed_backup(native_root, monkeypatch, "registered")
    journal = root / "mordred/db-backups.journal.json"
    with acquire_exclusive(root) as lease:
        plan = _backup.abandon_backup_journal(root, lease=lease, commit=True)
    assert plan is not None and plan.registered and not plan.copy_may_remain and plan.removed
    assert not journal.exists()
    assert any(e.path == destination and e.kind == "backup" for e in scan_dependencies(root).entries)


@pytest.mark.parametrize(
    "damage",
    [
        {"drop": "destination"},
        {"drop": "prepared"},
        {"drop": "identity"},
        {"drop": "verification"},
        {"drop": "source"},
        {"drop": "source_identity"},
        {"set": ("destination", 7)},
        {"set": ("identity", "x")},
        {"set": ("verification", None)},
    ],
)
def test_recover_refuses_malformed_journal_fields(native_root, monkeypatch, damage):
    from mordred_hermes.dbcrypt import _backup

    root, _, _, _ = native_root
    _crashed_backup(native_root, monkeypatch, "verified")
    journal = root / "mordred/db-backups.journal.json"
    data = json.loads(journal.read_bytes())
    if "drop" in damage:
        del data[damage["drop"]]
    else:
        data[damage["set"][0]] = damage["set"][1]
    journal.write_text(json.dumps(data))
    before = journal.read_bytes()
    with acquire_exclusive(root) as lease, pytest.raises(DatabaseRefused, match="malformed"):
        _backup.recover_backups(root, lease=lease)
    assert journal.read_bytes() == before


def test_backup_refuses_a_path_registered_to_a_removed_file_before_publishing(native_root):
    from mordred_hermes.dbcrypt import _backup

    root, _, key, _ = native_root
    cipher(root / "state.db", key)
    destination = root.parent / (root.name + "-stale.backup")
    authority = Authority.acquire(root)
    try:
        _backup.backup_database(root / "state.db", destination, authority=authority)
        destination.unlink()
        with pytest.raises(DatabaseRefused, match="already registered"):
            _backup.backup_database(root / "state.db", destination, authority=authority)
    finally:
        authority.close()
    assert not destination.exists()
    assert not (root / "mordred/db-backups.journal.json").exists()
    assert not list(destination.parent.glob(destination.name + ".mordred-backup-*"))


def test_recover_refuses_a_stale_registration_before_publishing(native_root, monkeypatch):
    from mordred_hermes.dbcrypt import _backup, _migrate

    root, _, _, _ = native_root
    destination = _crashed_backup(native_root, monkeypatch, "verified")
    journal = root / "mordred/db-backups.journal.json"
    data = json.loads(journal.read_bytes())
    entry = {"path": str(destination), "identity": [0, 0, 0, 0], "format": _backup._FORMAT, "verification": {}}
    with _backup._registry(root):
        _migrate._put_json(root, _backup._INVENTORY, {"version": 1, "snapshot": data["snapshot"], "entries": [entry]})
    with acquire_exclusive(root) as lease, pytest.raises(DatabaseRefused, match="already registered"):
        _backup.recover_backups(root, lease=lease)
    assert not destination.exists() and _backup.Path(data["prepared"]).exists() and journal.exists()


@pytest.mark.skipif(os.name != "posix", reason="patches the POSIX private-directory transaction")
def test_failure_creating_staging_releases_the_journal(native_root):
    from mordred_hermes._private_fs import _posix
    from mordred_hermes.dbcrypt import _backup

    root, _, key, _ = native_root
    cipher(root / "state.db", key)
    destination = root.parent / (root.name + "-nospace.backup")
    real_create = _posix._Transaction.create_bytes

    def create(self, name, data):
        if ".mordred-backup-" in name:
            _enospc()
        return real_create(self, name, data)

    authority = Authority.acquire(root)
    try:
        with pytest.MonkeyPatch.context() as patch:
            patch.setattr(_posix._Transaction, "create_bytes", create)
            with pytest.raises(OSError):  # the transaction wraps the failure as not committed
                _backup.backup_database(root / "state.db", destination, authority=authority)
        assert not (root / "mordred/db-backups.journal.json").exists()
        _backup.backup_database(root / "state.db", destination, authority=authority)
    finally:
        authority.close()


def test_unrecorded_staging_keeps_the_journal(native_root, caplog):
    from mordred_hermes.dbcrypt import _backup

    root, _, key, _ = native_root
    cipher(root / "state.db", key)
    destination = root.parent / (root.name + "-unrecorded-staging.backup")

    def lost(*_args):
        raise RuntimeError("journal update failed")

    authority = Authority.acquire(root)
    try:
        with pytest.MonkeyPatch.context() as patch:
            patch.setattr(_backup, "_update_pending", lost)
            with (
                caplog.at_level("WARNING", logger="mordred.dbcrypt"),
                pytest.raises(RuntimeError, match="update failed"),
            ):
                _backup.backup_database(root / "state.db", destination, authority=authority)
    finally:
        authority.close()
    assert (root / "mordred/db-backups.journal.json").exists()
    assert list(destination.parent.glob(destination.name + ".mordred-backup-*"))
    assert "backup cleanup stopped" in caplog.text


def test_cleanup_removes_the_staging_sidecars(native_root):
    sidecars = []

    def plant(staged, _journal):
        for suffix in ("-journal", "-wal", "-shm"):
            sidecar = staged.with_name(staged.name + suffix)
            sidecar.write_bytes(b"")
            sidecar.chmod(0o600)
            sidecars.append(sidecar)

    _backup_failing_during_copy(native_root, plant)
    assert sidecars and not any(path.exists() for path in sidecars)
    assert not (native_root[0] / "mordred/db-backups.journal.json").exists()


def _registered_backup(native_root, monkeypatch):
    from mordred_hermes.dbcrypt import _backup, _migrate

    root, _, key, _ = native_root
    source = root / "state.db"
    cipher(source, key)
    backup = root.parent / (root.name + "-restore.backup")
    authority = Authority.acquire(root)
    try:
        _backup.backup_database(source, backup, authority=authority)
    finally:
        authority.close()
    monkeypatch.setattr(_migrate, "holders", lambda paths: [])
    return root, source, backup


def _restore_staging(source):
    from mordred_hermes.dbcrypt import _migrate

    return source.with_name(source.name + _migrate.PREPARED_SUFFIX)


def test_restore_fsync_failure_discards_staging_and_next_restore_succeeds(native_root, monkeypatch):
    from mordred_hermes.dbcrypt import _backup, _migrate

    root, source, backup = _registered_backup(native_root, monkeypatch)
    before = source.read_bytes()
    with acquire_exclusive(root) as lease:
        with pytest.MonkeyPatch.context() as patch:
            patch.setattr(_migrate, "_fsync_file", _enospc)
            with pytest.raises(OSError, match="no space"):
                _backup.restore_database(backup, source, lease=lease)
        assert not _restore_staging(source).exists()
        assert not _migrate.journal_path(root).exists()
        assert source.read_bytes() == before
        _migrate._inventory(root)  # no orphan left for later conversions to refuse
        _backup.restore_database(backup, source, lease=lease)
    assert not _restore_staging(source).exists()
    assert not _migrate.journal_path(root).exists()


def test_restore_verification_failure_discards_staging(native_root, monkeypatch):
    from mordred_hermes.dbcrypt import _backup, _migrate

    root, source, backup = _registered_backup(native_root, monkeypatch)
    staged = _restore_staging(source)
    real_schema = _migrate._schema

    def changed(path, key, **kwargs):
        return {"changed": True} if path == staged else real_schema(path, key, **kwargs)

    with acquire_exclusive(root) as lease:
        with pytest.MonkeyPatch.context() as patch:
            patch.setattr(_migrate, "_schema", changed)
            with pytest.raises(DatabaseRefused, match="backup changed during restore"):
                _backup.restore_database(backup, source, lease=lease)
        assert not staged.exists()
        assert not list(source.parent.glob(staged.name + "-*"))
        _migrate._inventory(root)
        _backup.restore_database(backup, source, lease=lease)


def test_restore_failure_never_deletes_a_replaced_staging_file(native_root, monkeypatch, caplog):
    from mordred_hermes.dbcrypt import _backup, _migrate

    root, source, backup = _registered_backup(native_root, monkeypatch)
    staged = _restore_staging(source)

    def swap_then_fail(path):
        # Another inode now holds the staging name; it is not ours to erase.
        replacement = path.with_name(path.name + ".other")
        replacement.write_bytes(b"not ours")
        replacement.chmod(0o600)
        os.replace(replacement, path)
        raise OSError(errno.ENOSPC, "no space")

    with acquire_exclusive(root) as lease:
        with pytest.MonkeyPatch.context() as patch:
            patch.setattr(_migrate, "_fsync_file", swap_then_fail)
            with pytest.raises(OSError, match="no space"):
                _backup.restore_database(backup, source, lease=lease)
        assert staged.read_bytes() == b"not ours"
        assert "staging cleanup stopped" in caplog.text
        with pytest.raises(_migrate.MigrationError, match="orphan prepared database"):
            _migrate._inventory(root)


def test_restore_journal_binding_failure_discards_staging(native_root, monkeypatch):
    from mordred_hermes.dbcrypt import _backup, _migrate

    root, source, backup = _registered_backup(native_root, monkeypatch)
    staged = _restore_staging(source)

    def unbindable(_root):
        # e.g. a group-writable or hard-linked database elsewhere under the root
        raise DatabaseRefused("database must be a checked regular owned file")

    with acquire_exclusive(root) as lease:
        with pytest.MonkeyPatch.context() as patch:
            patch.setattr(_migrate, "_inventory_binding", unbindable)
            with pytest.raises(DatabaseRefused, match="checked regular owned file"):
                _backup.restore_database(backup, source, lease=lease)
        assert not staged.exists()
        assert not list(source.parent.glob(staged.name + "-*"))
        assert not _migrate.journal_path(root).exists()
        _migrate._inventory(root)
        _backup.restore_database(backup, source, lease=lease)
    assert not staged.exists()
