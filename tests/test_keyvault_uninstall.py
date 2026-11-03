"""Real database proofs with controlled native hardware and holder inventories."""

from __future__ import annotations

import sqlite3

import pytest

from mordred_hermes._core._database_contracts import DatabaseRefused
from mordred_hermes._core._database_lifecycle import acquire_exclusive
from mordred_hermes.dbcrypt import _migrate
from tests.test_dbcrypt_adoption import cipher
from tests.test_linux_memory_database_guard import enrolled as enrolled


def plain(path):
    with sqlite3.connect(path) as connection:
        connection.execute("CREATE TABLE messages(body TEXT)")
        connection.execute("INSERT INTO messages VALUES ('hello')")
    connection.close()
    path.chmod(0o600)


def test_keyvault_consumes_explicit_deletion_proof_only(tmp_path, monkeypatch):
    from mordred_hermes.dbcrypt._uninstall import preflight, verified
    from mordred_hermes.keyvault._database_mutation import database_key_mutation

    monkeypatch.setattr(_migrate, "holders", lambda paths: [])
    plain(tmp_path / "state.db")
    with acquire_exclusive(tmp_path) as lease:
        with (
            verified(preflight(tmp_path, lease=lease, purge=False), lease=lease) as restore,
            pytest.raises(DatabaseRefused),
            database_key_mutation(root=tmp_path, generation=None, uninstall=restore),
        ):
            pytest.fail("restore authority granted deletion")
        with verified(preflight(tmp_path, lease=lease, purge=True), lease=lease) as deletion:
            with database_key_mutation(root=tmp_path, generation=None, uninstall=deletion):
                pass
            # No ambient bypass for reset or unrelated key mutations.
            with pytest.raises(DatabaseRefused), database_key_mutation(root=tmp_path, generation=None):
                pytest.fail("unrelated operation borrowed uninstall authority")


@pytest.mark.parametrize("empty_registry", [False, True])
def test_native_memory_deletion_uses_final_plaintext_proof(enrolled, monkeypatch, empty_registry):
    from types import SimpleNamespace

    from mordred_hermes.dbcrypt._uninstall import preflight, verified
    from mordred_hermes.keyvault import _database_authority as custody
    from mordred_hermes.keyvault import _memory_key as memory
    from mordred_hermes.keyvault._memory_key import delete_linux_memory_key
    from tests.test_dbcrypt_marker import encoded, put

    root, backend, _ops = enrolled
    monkeypatch.setattr(custody, "sys", SimpleNamespace(platform="linux"))
    from mordred_hermes._core import _database_locking_posix as locking

    monkeypatch.setattr(locking, "sys", SimpleNamespace(platform="linux"))
    monkeypatch.setattr(memory, "linux_memory_backend", lambda home: backend)
    key = memory.load_linux_memory_key(home=root, backend=backend)
    (root / "mordred/memory-vault.marker").write_bytes(b"memory-encryption enabled\n")
    (root / "mordred/memory-vault.marker").chmod(0o600)
    with acquire_exclusive(root) as lease:
        put(root, encoded(custody.enroll_database_source(root=root, lease=lease)))
    if empty_registry:
        from dataclasses import asdict

        _migrate._put_json(
            root,
            "db-backups.json",
            {"version": 1, "snapshot": asdict(custody.observe_database_source(root=root)), "entries": []},
        )
    cipher(root / "state.db", key)
    monkeypatch.setattr(_migrate, "holders", lambda paths: [])
    with acquire_exclusive(root) as lease:
        report = preflight(root, lease=lease, purge=True)
        _migrate.decrypt_all(root, None)
        with verified(report, lease=lease) as permit:
            delete_linux_memory_key(home=root, backend=backend, database_lease=lease, uninstall=permit)
    with acquire_exclusive(root) as lease:
        preflight(root, lease=lease, purge=True)
    assert not (root / "mordred/memory-key.wrapped").exists()
    assert not (root / "mordred/db-key-source.json").exists()
    with sqlite3.connect(root / "state.db") as connection:
        assert connection.execute("SELECT count(*) FROM messages").fetchone() == (1,)
