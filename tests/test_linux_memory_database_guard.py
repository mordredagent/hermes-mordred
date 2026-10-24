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
    [
        "state.db",
        "state.db-wal",
        "mordred/db-encryption.pending",
        "backups/snapshot.zip",
        "mordred/db-key-source.json.lock",
        "mordred/.db-key-source.json.lock",
        "profiles/work/mordred/db-key-source.json.lock",
    ],
)
def test_database_dependency_preserves_memory_without_native_io(enrolled, dependency):
    home, backend, ops = enrolled
    path = home / dependency
    path.parent.mkdir(parents=True, exist_ok=True)
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


@pytest.mark.parametrize("after_permit", [False, True])
def test_native_memory_owner_checks_actual_lock_at_use(enrolled, after_permit):
    from contextlib import ExitStack

    from mordred_hermes.keyvault._native_deletion import _issue_native_owner, _owned_delete_scope

    home, backend, ops = enrolled
    with (
        database_key_mutation(root=home, generation=None) as lease,
        memory.memory_key_lock(home),
        memory._native_memory_custody(home, backend) as scope,
        ExitStack() as permits,
    ):
        owner = _issue_native_owner(scope, native_key_id=memory.memory_key_id(home), backend=backend)
        if after_permit:
            permit = permits.enter_context(_owned_delete_scope(owner, backend=backend, database_lease=lease))
        lock = home / "mordred" / "memory-key.lock"
        lock.rename(lock.with_name("retired-memory-key.lock"))
        lock.touch(mode=0o600)
        with pytest.raises(DatabaseRefused):
            if not after_permit:
                permit = permits.enter_context(_owned_delete_scope(owner, backend=backend, database_lease=lease))
            backend.delete_enclave_key(memory.memory_key_id(home), deletion=permit)
    assert ops.calls == []


def test_fresh_memory_checks_dependencies_after_adoption_inspection(tmp_path, monkeypatch):
    ops = _FakeOps()
    backend = _SecKeyBackend(ops=ops, sw_ops=None, legacy_ops=None)
    original = memory._validate_adoption

    def inspect(home, key):
        original(home, key)
        (home / "state.db").touch()

    monkeypatch.setattr(memory, "_validate_adoption", inspect)
    with pytest.raises(DatabaseRefused):
        memory.ensure_linux_memory_key(home=tmp_path, backend=backend)
    assert ops.calls == []
    assert not memory.memory_key_path(tmp_path).exists()


def test_fresh_memory_checks_dependencies_before_wrapper_publication(tmp_path, monkeypatch):
    ops = _FakeOps()
    backend = _SecKeyBackend(ops=ops, sw_ops=None, legacy_ops=None)
    original = memory.wrap.unwrap_dek

    def verify(*args, **kwargs):
        result = original(*args, **kwargs)
        (tmp_path / "state.db").touch()
        return result

    monkeypatch.setattr(memory.wrap, "unwrap_dek", verify)
    with pytest.raises(DatabaseRefused):
        memory.ensure_linux_memory_key(home=tmp_path, backend=backend)
    assert len(ops._keys) == 1  # Retain successful/uncertain native creation.
    assert not memory.memory_key_path(tmp_path).exists()


@pytest.mark.parametrize("alias", [False, True])
@pytest.mark.parametrize("outcome", ["published", "uncertain", "source-lost"])
def test_published_memory_key_revokes_external_creation_receipt(tmp_path, monkeypatch, alias, outcome):
    from mordred_hermes.keyvault import wrap

    creator_ops = _FakeOps()
    creator = _SecKeyBackend(ops=creator_ops, sw_ops=None, legacy_ops=None)
    adopted_ops = _FakeOps() if alias else creator_ops
    adopted_ops._keys = creator_ops._keys
    adopted = _SecKeyBackend(ops=adopted_ops, sw_ops=None, legacy_ops=None)
    if outcome == "uncertain":
        publish = memory._publish

        def fail_after_link(path, blob):
            publish(path, blob)
            raise OSError("publication durability uncertain")

        monkeypatch.setattr(memory, "_publish", fail_after_link)
    with wrap.create_wrapping_key_scope(memory.memory_key_id(tmp_path), backend=creator) as receipt:
        if outcome == "uncertain":
            with pytest.raises(DatabaseRefused):
                memory.ensure_linux_memory_key(home=tmp_path, backend=adopted)
        else:
            memory.ensure_linux_memory_key(home=tmp_path, backend=adopted)
        assert memory.memory_key_path(tmp_path).exists()
        (tmp_path / "state.db").touch()
        if outcome == "source-lost":
            memory.memory_key_path(tmp_path).unlink()
            with pytest.raises(DatabaseRefused):
                memory.ensure_linux_memory_key(home=tmp_path, backend=adopted)
        with pytest.raises(DatabaseRefused):
            wrap.rollback_created_key(receipt)
    assert len(creator_ops._keys) == 1
    assert all(command != "delete" for command, _ in creator_ops.calls + adopted_ops.calls)


def test_adoption_before_receipt_registration_cannot_resurrect_rollback(tmp_path, monkeypatch):
    from mordred_hermes.keyvault import wrap

    creator_ops = _FakeOps()
    adopter_ops = _FakeOps()
    adopter_ops._keys = creator_ops._keys
    creator = _SecKeyBackend(ops=creator_ops, sw_ops=None, legacy_ops=None)
    adopter = _SecKeyBackend(ops=adopter_ops, sw_ops=None, legacy_ops=None)
    create = creator_ops.create_keypair

    def publish_before_response(tag, label, *, unattended=False):
        public = create(tag, label, unattended=unattended)
        memory.ensure_linux_memory_key(home=tmp_path, backend=adopter)
        (tmp_path / "state.db").touch()
        return public

    monkeypatch.setattr(creator_ops, "create_keypair", publish_before_response)
    with (
        pytest.raises(DatabaseRefused),
        wrap.create_wrapping_key_scope(memory.memory_key_id(tmp_path), backend=creator),
    ):
        pytest.fail("ownership handoff was missed before receipt registration")
    assert memory.memory_key_path(tmp_path).exists()
    assert creator_ops._keys
    assert all(command != "delete" for command, _ in creator_ops.calls + adopter_ops.calls)


def test_rollback_inflight_refuses_actual_adoption_before_source_visibility(tmp_path, monkeypatch):
    from mordred_hermes.keyvault import wrap

    creator_ops = _FakeOps()
    adopter_ops = _FakeOps()
    adopter_ops._keys = creator_ops._keys
    creator = _SecKeyBackend(ops=creator_ops, sw_ops=None, legacy_ops=None)
    adopter = _SecKeyBackend(ops=adopter_ops, sw_ops=None, legacy_ops=None)
    refused = []
    copy_public = creator_ops.copy_public_key

    def attempt_adoption_during_rollback(tag):
        public = copy_public(tag)
        try:
            memory.ensure_linux_memory_key(home=tmp_path, backend=adopter)
        except DatabaseRefused:
            refused.append(True)
        return public

    with wrap.create_wrapping_key_scope(memory.memory_key_id(tmp_path), backend=creator) as receipt:
        monkeypatch.setattr(creator_ops, "copy_public_key", attempt_adoption_during_rollback)
        wrap.rollback_created_key(receipt)
    assert refused == [True]
    assert not memory.memory_key_path(tmp_path).exists()
    assert not creator_ops._keys
    assert sum(command == "delete" for command, _ in creator_ops.calls + adopter_ops.calls) == 1
