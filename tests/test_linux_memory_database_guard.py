"""Real capability/custody integration with only native hardware replaced."""

import pytest

from mordred_hermes._database_contracts import DatabaseRefused
from mordred_hermes.keyvault import _memory_key as memory
from mordred_hermes.keyvault._database_mutation import database_key_mutation
from mordred_hermes.keyvault._seckey_backend import _SecKeyBackend
from tests.test_keyvault_seckey_backend import _FakeOps


@pytest.fixture
def enrolled(tmp_path):
    ops = _FakeOps()
    backend = _SecKeyBackend(ops=ops, sw_ops=None, legacy_ops=None)
    memory.ensure_linux_memory_key(home=tmp_path, backend=backend)
    ops.calls.clear()
    return tmp_path, backend, ops


def test_checked_empty_domain_can_delete_native_memory(enrolled):
    home, backend, ops = enrolled
    memory.delete_linux_memory_key(home=home, backend=backend)
    assert not ops._keys
    assert not memory.memory_key_path(home).exists()
    assert sum(command == "delete" for command, _ in ops.calls) == 1


@pytest.mark.parametrize(
    "dependency",
    ["state.db", "state.db-wal", "mordred/db-encryption.pending", "backups/snapshot.zip"],
)
def test_database_dependency_preserves_memory_without_native_io(enrolled, dependency):
    home, backend, ops = enrolled
    path = home / dependency
    path.parent.mkdir(exist_ok=True)
    path.touch()
    before = memory.memory_key_path(home).read_bytes()
    with pytest.raises(DatabaseRefused):
        memory.delete_linux_memory_key(home=home, backend=backend)
    assert memory.memory_key_path(home).read_bytes() == before
    assert ops.calls == []


def test_preceding_database_lease_allows_nested_memory_delete(enrolled):
    home, backend, ops = enrolled
    with database_key_mutation(root=home, generation=None) as lease, memory.memory_key_lock(home):
        memory.delete_linux_memory_key(home=home, backend=backend, database_lease=lease)
    assert not ops._keys


def test_already_locked_memory_cannot_start_database_mutation(enrolled):
    home, backend, ops = enrolled
    with memory.memory_key_lock(home), pytest.raises(DatabaseRefused):
        memory.delete_linux_memory_key(home=home, backend=backend)
    assert ops.calls == []


def test_missing_wrapper_with_database_never_reenrolls(enrolled):
    home, backend, ops = enrolled
    memory.memory_key_path(home).unlink()
    (home / "state.db").touch()
    with pytest.raises(DatabaseRefused):
        memory.ensure_linux_memory_key(home=home, backend=backend)
    assert ops.calls == []
    assert not memory.memory_key_path(home).exists()


def test_checked_owner_expires_with_memory_custody(enrolled):
    from mordred_hermes.keyvault._native_deletion import _issue_native_owner, _owned_delete_scope

    home, backend, ops = enrolled
    with database_key_mutation(root=home, generation=None) as lease, memory.memory_key_lock(home):
        with memory._native_memory_custody(home, backend) as scope:
            owner = _issue_native_owner(scope, native_key_id=memory.memory_key_id(home), backend=backend)
        with pytest.raises(DatabaseRefused), _owned_delete_scope(owner, backend=backend, database_lease=lease):
            pytest.fail("expired custody granted native deletion")
    assert ops.calls == []
    with pytest.raises(TypeError):
        memory.MemoryKeyCustody()


def test_child_memory_preserves_possible_legacy_root_dependencies(tmp_path):
    child = tmp_path / "profiles" / "personal"
    child.mkdir(parents=True, mode=0o700)
    ops = _FakeOps()
    backend = _SecKeyBackend(ops=ops, sw_ops=None, legacy_ops=None)
    memory.ensure_linux_memory_key(home=child, backend=backend)
    ops.calls.clear()
    (tmp_path / "state.db").touch()
    with pytest.raises(DatabaseRefused):
        memory.delete_linux_memory_key(home=child, backend=backend)
    assert memory.memory_key_path(child).exists()
    assert ops.calls == []


def test_cli_dependency_refusal_precedes_memory_disable(enrolled, monkeypatch):
    from mordred_hermes.wizard import memory_cli

    home, backend, ops = enrolled
    (home / "state.db").touch()
    monkeypatch.setattr(memory_cli, "disable", lambda **kwargs: pytest.fail("disable preceded dependency guard"))
    assert memory_cli.purge(home=home, root=home / "vault", backend=backend, platform="linux") == 1
    assert memory.memory_key_path(home).exists()
    assert ops.calls == []
