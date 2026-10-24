"""Authenticated vault owners and effective memory-source mutation boundaries."""

from __future__ import annotations

import base64
import copy

import pytest

from mordred_hermes._database_contracts import DatabaseRefused
from mordred_hermes.keyvault import vault
from mordred_hermes.keyvault._database_mutation import database_key_mutation
from mordred_hermes.keyvault._identity import vault_identity
from mordred_hermes.keyvault._native_deletion import _owned_delete_scope
from mordred_hermes.keyvault._seckey_backend import _SecKeyBackend
from tests._keyvault_fakes import FakeAnchorStore
from tests._platform_test_helpers import require_legacy_file_vault
from tests.test_keyvault_seckey_backend import _FakeOps

KEY = b"a" * 32
ENV = b"HERMES_MEMORY_KEY=hex:" + KEY.hex().encode() + b"\nAPI_KEY=old\n"


@pytest.fixture
def source(tmp_path, monkeypatch):
    require_legacy_file_vault()
    from types import SimpleNamespace

    from mordred_hermes import _database_locking_posix
    from mordred_hermes.keyvault import _database_authority

    monkeypatch.setattr(_database_authority, "sys", SimpleNamespace(platform="darwin"))
    monkeypatch.setattr(_database_locking_posix, "sys", SimpleNamespace(platform="darwin"))
    (tmp_path / "mordred").mkdir(mode=0o700)
    root = tmp_path / "mordred/vault"
    selector = vault_identity(root)
    ops = _FakeOps()
    backend = _SecKeyBackend(ops=ops, sw_ops=None)
    backend.generate_enclave_key(selector)
    store = FakeAnchorStore()
    with database_key_mutation(root=tmp_path, generation=None) as lease:
        opened = vault.init_vault(
            root,
            key_id=selector,
            passphrase="synthetic",
            backend=backend,
            store=store,
            anchor_label=selector,
            database_lease=lease,
        )
    yield tmp_path, opened, backend, store, ops
    opened.close()


def durable(home):
    return {str(path.relative_to(home)): path.read_bytes() for path in home.rglob("*") if path.is_file()}


def test_memory_addition_without_preceding_lease_refuses_before_writes(source):
    home, opened, _, store, _ = source
    before = durable(home), list(store.calls)
    with pytest.raises(DatabaseRefused):
        opened.enroll_file(".env", ENV)
    assert durable(home) == before[0]
    assert not any(call[0] == "write" for call in store.calls[len(before[1]) :])


def test_genuine_owner_requires_live_scope_and_database_lease(source):
    home, opened, backend, _, ops = source
    with pytest.raises(DatabaseRefused):
        opened._native_delete_owner(backend)
    with database_key_mutation(root=home, generation=None) as lease:
        with opened._custody_scope():
            owner = opened._native_delete_owner(backend)
            with _owned_delete_scope(owner, backend=backend, database_lease=lease) as permit:
                backend.delete_enclave_key(opened._key_id, deletion=permit)
        with pytest.raises(DatabaseRefused), _owned_delete_scope(owner, backend=backend, database_lease=lease):
            pass
    assert len([call for call in ops.calls if call[0] == "delete"]) == 1


def test_manually_constructed_or_copied_vault_cannot_issue_owner(source):
    _, opened, backend, _, _ = source
    forged = vault.OpenVault(
        root=opened._root,
        key_id=opened._key_id,
        master=opened._master,
        manifest_=opened._manifest,
        store=opened._store,
        anchor_label=opened._label,
        wmk=opened._wmk,
    )
    for candidate in (forged, copy.copy(opened)):
        with pytest.raises(DatabaseRefused), candidate._custody_scope():
            candidate._native_delete_owner(backend)


def test_shared_env_effective_key_is_last_wins_without_interpolation():
    from mordred_hermes.keyvault._memory_env import effective_memory_key, parse_env

    payload = b"HERMES_MEMORY_KEY=bad\nHERMES_MEMORY_KEY=hex:" + KEY.hex().encode() + b"\nAPI_KEY=${HOME}\n"
    assert effective_memory_key(payload) == KEY
    assert parse_env(payload)["API_KEY"] == "${HOME}"
    assert effective_memory_key(None) is None
    for payload in (b"HERMES_MEMORY_KEY\n", b"HERMES_MEMORY_KEY=\n", b"HERMES_MEMORY_KEY='broken\n"):
        with pytest.raises(DatabaseRefused):
            effective_memory_key(payload)


def test_same_decoded_memory_key_and_other_files_need_no_lease(source):
    home, opened, _, _, _ = source
    with database_key_mutation(root=home, generation=None) as lease:
        opened.enroll_file(".env", ENV, database_lease=lease)
    alternate = b"HERMES_MEMORY_KEY=base64:" + base64.urlsafe_b64encode(KEY) + b"\nAPI_KEY=new\n"
    opened.enroll_file(".env", alternate)
    opened.enroll_file("config.yaml", b"name: new\n")
    assert opened.read_file(".env") == alternate


@pytest.mark.parametrize("operation", ["replace", "remove", "rekey"])
def test_source_change_without_proof_preserves_every_artifact(source, operation):
    home, opened, backend, store, ops = source
    with database_key_mutation(root=home, generation=None) as lease:
        opened.enroll_file(".env", ENV, database_lease=lease)
    before = durable(home), len(ops.calls)
    with pytest.raises(DatabaseRefused):
        if operation == "replace":
            opened.enroll_file(".env", ENV.replace(b"61", b"62"))
        elif operation == "remove":
            opened.unenroll_file(".env")
        else:
            vault.recover_to_device(
                opened._root,
                "synthetic",
                backend=backend,
                store=store,
                key_id=opened._key_id,
                anchor_label=opened._label,
            )
    assert durable(home) == before[0]
    assert not any(call[0] in {"create", "delete"} for call in ops.calls[before[1] :])


def test_factory_backend_substitution_refuses_before_native_io(source):
    home, opened, backend, _, ops = source
    with database_key_mutation(root=home, generation=None), opened._custody_scope():
        backend._ops = _FakeOps()
        with pytest.raises(DatabaseRefused):
            opened._native_delete_owner(backend)
    assert not any(call[0] == "delete" for call in ops.calls)


@pytest.mark.parametrize("operation", ["replace", "remove", "add", "rekey", "delete"])
@pytest.mark.parametrize(
    "dependency",
    [
        "state.db",
        "mordred/db-encryption.marker",
        "mordred/db-encryption.pending",
        "mordred/db-backups.json",
        "backups/root.tgz",
        "mordred/db-key-source.json.tmp",
        "profiles/work/mordred/db-key-source.json",
    ],
)
def test_final_guard_with_every_dependency_preserves_all_artifacts(source, operation, dependency):
    home, opened, backend, store, ops = source
    from mordred_hermes._database_lifecycle import acquire_exclusive

    with database_key_mutation(root=home, generation=None) as lease:
        if operation != "add":
            opened.enroll_file(".env", ENV, database_lease=lease)
    with acquire_exclusive(home) as lease:
        path = home / dependency
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        path.write_bytes(b"retained dependency")
        before = durable(home), list(store.calls), list(ops.calls)
        with pytest.raises(DatabaseRefused):
            if operation == "replace":
                opened.enroll_file(".env", ENV.replace(b"61", b"62"), database_lease=lease)
            elif operation == "remove":
                opened.unenroll_file(".env", database_lease=lease)
            elif operation == "add":
                opened.enroll_file(".env", ENV, database_lease=lease)
            elif operation == "rekey":
                vault.recover_to_device(
                    opened._root,
                    "synthetic",
                    backend=backend,
                    store=store,
                    key_id=opened._key_id,
                    anchor_label=opened._label,
                    database_lease=lease,
                )
            else:
                with opened._custody_scope():
                    owner = opened._native_delete_owner(backend)
                    with _owned_delete_scope(owner, backend=backend, database_lease=lease) as permit:
                        backend.delete_enclave_key(opened._key_id, deletion=permit)
        assert durable(home) == before[0]
        assert not any(call[0] == "write" for call in store.calls[len(before[1]) :])
        assert not any(call[0] in {"create", "delete"} for call in ops.calls[len(before[2]) :])


@pytest.fixture
def enrolled_source(source, monkeypatch):
    from mordred_hermes.keyvault import _database_authority as authority
    from mordred_hermes.keyvault._memory_env import effective_memory_key

    home, opened, _, _, _ = source
    with database_key_mutation(root=home, generation=None) as lease:
        opened.enroll_file(".env", ENV, database_lease=lease)
        # Enrollment's native load is separately tested in authority's containing
        # module; here reuse the already-authenticated source without hardware.
        monkeypatch.setattr(
            authority, "_load_posix", lambda root, identity, digest: effective_memory_key(opened.read_file(".env"))
        )
        snapshot = authority.enroll_database_source(root=home, lease=lease)
    return (*source, authority, snapshot)


def test_identical_decoded_key_and_other_files_preserve_exact_snapshot(enrolled_source):
    home, opened, _, _, _, authority, snapshot = enrolled_source
    before = (home / "mordred/db-key-source.json").read_bytes()
    opened.enroll_file(".env", b"HERMES_MEMORY_KEY=" + base64.urlsafe_b64encode(KEY).rstrip(b"=") + b"\nNEW=value\n")
    opened.enroll_file("config.yaml", b"new: value\n")
    assert authority.observe_database_source(root=home) == snapshot
    assert (home / "mordred/db-key-source.json").read_bytes() == before


@pytest.mark.parametrize("operation", ["replace", "remove", "rekey"])
def test_authorized_source_change_retires_old_binding(enrolled_source, operation):
    home, opened, backend, store, _, authority, snapshot = enrolled_source
    with database_key_mutation(root=home, generation=None) as lease:
        if operation == "replace":
            opened.enroll_file(".env", ENV.replace(b"61", b"62"), database_lease=lease)
        elif operation == "remove":
            opened.unenroll_file(".env", database_lease=lease)
        else:
            vault.recover_to_device(
                opened._root,
                "synthetic",
                backend=backend,
                store=store,
                key_id=opened._key_id,
                anchor_label=opened._label,
                database_lease=lease,
            ).close()
    assert not (home / "mordred/db-key-source.json").exists()
    with pytest.raises(DatabaseRefused):
        authority.observe_database_source(root=home)
    assert snapshot.generation


@pytest.mark.parametrize("damage", ["malformed", "symlink", "temporary"])
def test_broken_binding_cannot_be_repaired_by_source_change(source, damage):
    from mordred_hermes._database_lifecycle import acquire_exclusive

    home, opened, _, _, _ = source
    with database_key_mutation(root=home, generation=None) as lease:
        opened.enroll_file(".env", ENV, database_lease=lease)
    binding = home / "mordred/db-key-source.json"
    if damage == "symlink":
        binding.symlink_to(home / "missing")
    else:
        if damage == "temporary":
            binding = binding.with_suffix(".json.tmp")
        binding.write_bytes(b"broken binding")
        binding.chmod(0o600)
    before = durable(home) if damage != "symlink" else opened.generation
    with acquire_exclusive(home) as lease, pytest.raises(DatabaseRefused):
        opened.enroll_file(".env", ENV.replace(b"61", b"62"), database_lease=lease)
    assert (durable(home) if damage != "symlink" else opened.generation) == before


@pytest.mark.parametrize("kind", ["closed", "recovery", "selector", "store", "path", "cross-thread"])
def test_invalid_native_handle_refuses_before_native_io(source, kind):
    from concurrent.futures import ThreadPoolExecutor

    home, opened, backend, _, ops = source
    with database_key_mutation(root=home, generation=None) as lease, opened._custody_scope():
        if kind == "closed":
            opened.close()
        elif kind == "recovery":
            opened = vault.recover_vault(opened._root, "synthetic")
        elif kind == "selector":
            opened._key_id = "other-selector"
        elif kind == "store":
            opened._store = FakeAnchorStore()
        elif kind == "path":
            opened._root.rename(opened._root.with_name("retained-vault"))
            opened._root.mkdir(mode=0o700)
        if kind == "cross-thread":
            with ThreadPoolExecutor(max_workers=1) as pool, pytest.raises(DatabaseRefused):
                pool.submit(opened._native_delete_owner, backend).result()
        else:
            with pytest.raises(DatabaseRefused):
                owner = opened._native_delete_owner(backend)
                with _owned_delete_scope(owner, backend=backend, database_lease=lease):
                    pass
    assert not any(call[0] == "delete" for call in ops.calls)


def test_owner_cannot_revive_in_a_later_custody_scope(source):
    home, opened, backend, _, _ = source
    with database_key_mutation(root=home, generation=None) as lease:
        with opened._custody_scope():
            owner = opened._native_delete_owner(backend)
        with (
            opened._custody_scope(),
            pytest.raises(DatabaseRefused),
            _owned_delete_scope(owner, backend=backend, database_lease=lease),
        ):
            pass


def test_stale_preflight_cannot_replace_source_or_retire_binding(enrolled_source):
    home, opened, backend, store, _, _, _ = enrolled_source
    stale = vault.open_vault(
        opened._root, key_id=opened._key_id, backend=backend, store=store, anchor_label=opened._label
    )
    with stale, database_key_mutation(root=home, generation=None) as lease:
        opened.enroll_file("config.yaml", b"concurrent: commit\n")
        before = durable(home)
        with pytest.raises(vault.VaultError, match="stale"):
            stale.enroll_file(".env", ENV.replace(b"61", b"62"), database_lease=lease)
        assert durable(home) == before


def test_invalid_effective_key_never_commits_even_with_database_proof(source):
    home, opened, _, _, _ = source
    with database_key_mutation(root=home, generation=None) as lease:
        before = durable(home)
        with pytest.raises(DatabaseRefused):
            opened.enroll_file(".env", b"HERMES_MEMORY_KEY=bad\n", database_lease=lease)
        assert durable(home) == before


def test_factory_open_rejects_root_replacement_during_unwrap(source, monkeypatch):
    import shutil

    _, opened, backend, store, ops = source
    exchange = ops.key_exchange
    root = opened._root

    def replace_during_unwrap(tag, peer):
        secret = exchange(tag, peer)
        retained = root.with_name("retained-vault")
        root.rename(retained)
        shutil.copytree(retained, root)
        return secret

    monkeypatch.setattr(ops, "key_exchange", replace_during_unwrap)
    with pytest.raises(DatabaseRefused):
        vault.open_vault(root, key_id=opened._key_id, backend=backend, store=store, anchor_label=opened._label)


def test_database_lease_acquired_after_real_vault_custody_cannot_authorize_mutation(source):
    from mordred_hermes._database_lifecycle import acquire_exclusive

    home, opened, backend, _, ops = source
    with opened._custody_scope(), acquire_exclusive(home) as lease:
        before = durable(home)
        with pytest.raises(DatabaseRefused):
            opened.enroll_file(".env", ENV, database_lease=lease)
        owner = opened._native_delete_owner(backend)
        with pytest.raises(DatabaseRefused), _owned_delete_scope(owner, backend=backend, database_lease=lease):
            pass
        assert durable(home) == before
    assert not any(call[0] == "delete" for call in ops.calls)


def test_custom_vault_is_not_implicitly_an_independent_source(tmp_path):
    require_legacy_file_vault()
    root = tmp_path / "custom-vault"
    backend = _SecKeyBackend(ops=_FakeOps(), sw_ops=None)
    selector = vault_identity(root)
    backend.generate_enclave_key(selector)
    store = FakeAnchorStore()
    with (
        vault.init_vault(
            root, key_id=selector, passphrase="synthetic", backend=backend, store=store, anchor_label=selector
        ) as opened,
        database_key_mutation(root=tmp_path, generation=None) as lease,
    ):
        before = durable(tmp_path)
        with pytest.raises(DatabaseRefused):
            opened.enroll_file(".env", ENV, database_lease=lease)
        with opened._custody_scope(), pytest.raises(DatabaseRefused):
            opened._native_delete_owner(backend)
        assert durable(tmp_path) == before


def test_stale_native_owner_preflight_is_rechecked_at_delete_sink(source):
    home, opened, backend, store, ops = source
    with database_key_mutation(root=home, generation=None) as lease, opened._custody_scope():
        before_native = list(ops.calls)
        owner = opened._native_delete_owner(backend)
        assert ops.calls == before_native  # Metadata authority performs no second unwrap.
        with _owned_delete_scope(owner, backend=backend, database_lease=lease) as permit:
            with vault.open_vault(
                opened._root, key_id=opened._key_id, backend=backend, store=store, anchor_label=opened._label
            ) as concurrent:
                concurrent.enroll_file("config.yaml", b"concurrent: update\n")
            before = durable(home)
            with pytest.raises(DatabaseRefused):
                backend.delete_enclave_key(opened._key_id, deletion=permit)
            assert durable(home) == before
    assert not any(call[0] == "delete" for call in ops.calls)


def test_later_explicit_enrollment_gets_fresh_source_generation(enrolled_source):
    home, opened, _, _, _, authority, snapshot = enrolled_source
    with database_key_mutation(root=home, generation=None) as lease:
        opened.enroll_file(".env", ENV.replace(b"61", b"62"), database_lease=lease)
        assert not (home / "mordred/db-key-source.json").exists()
        new_snapshot = authority.enroll_database_source(root=home, lease=lease)
    assert new_snapshot.generation != snapshot.generation
    assert new_snapshot.record_sha256 == snapshot.record_sha256  # Stable wrapping header, fresh explicit generation.


def test_anchor_absent_reinitialization_preserves_retained_source_with_dependencies(source):
    home, opened, backend, store, ops = source
    with database_key_mutation(root=home, generation=None) as lease:
        opened.enroll_file(".env", ENV, database_lease=lease)
    store.delete(opened._label)
    (home / "state.db").write_bytes(b"retained database")
    before = durable(home), list(ops.calls)
    with pytest.raises(DatabaseRefused):
        vault.init_vault(
            opened._root,
            key_id=opened._key_id,
            passphrase="new synthetic",
            backend=backend,
            store=store,
            anchor_label=opened._label,
        )
    assert durable(home) == before[0]
    assert not any(call[0] in {"create", "delete"} for call in ops.calls[len(before[1]) :])


def test_lost_canonical_vault_cannot_initialize_over_database_dependencies(tmp_path):
    require_legacy_file_vault()
    root = tmp_path / "mordred/vault"
    backend = _SecKeyBackend(ops=_FakeOps(), sw_ops=None)
    selector = vault_identity(root)
    backend.generate_enclave_key(selector)
    (tmp_path / "state.db").write_bytes(b"database with lost native source")
    before = durable(tmp_path), list(backend._ops.calls)
    with pytest.raises(DatabaseRefused):
        vault.init_vault(
            root,
            key_id=selector,
            passphrase="synthetic",
            backend=backend,
            store=FakeAnchorStore(),
            anchor_label=selector,
        )
    assert durable(tmp_path) == before[0]
    assert not root.exists()
    assert backend._ops.calls == before[1]


def test_orphaned_source_cannot_be_reinitialized_even_with_dependency_free_exclusion(source):
    home, opened, backend, store, ops = source
    store.delete(opened._label)
    before = durable(home), list(ops.calls)
    with database_key_mutation(root=home, generation=None) as lease, pytest.raises(DatabaseRefused, match="retained"):
        vault.init_vault(
            opened._root,
            key_id=opened._key_id,
            passphrase="new synthetic",
            backend=backend,
            store=store,
            anchor_label=opened._label,
            database_lease=lease,
        )
    assert durable(home) == before[0]
    assert ops.calls == before[1]


@pytest.mark.parametrize(
    "dependency",
    [
        "state.db",
        "mordred/db-encryption.marker",
        "mordred/db-encryption.pending",
        "mordred/db-backups.json",
        "backups/root.tgz",
        "mordred/db-key-source.json.tmp",
        "profiles/work/mordred/db-key-source.json",
    ],
)
def test_lost_source_initialization_with_real_exclusion_preserves_every_dependency(tmp_path, dependency):
    require_legacy_file_vault()
    from mordred_hermes._database_lifecycle import acquire_exclusive

    root = tmp_path / "mordred/vault"
    backend = _SecKeyBackend(ops=_FakeOps(), sw_ops=None)
    selector = vault_identity(root)
    backend.generate_enclave_key(selector)
    with acquire_exclusive(tmp_path) as lease:
        path = tmp_path / dependency
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        path.write_bytes(b"retained dependency with lost native source")
        before = durable(tmp_path), list(backend._ops.calls)
        with pytest.raises(DatabaseRefused):
            vault.init_vault(
                root,
                key_id=selector,
                passphrase="synthetic",
                backend=backend,
                store=FakeAnchorStore(),
                anchor_label=selector,
                database_lease=lease,
            )
        assert durable(tmp_path) == before[0]
        assert not root.exists()
        assert backend._ops.calls == before[1]


def test_custom_orphan_ciphertext_is_not_a_fresh_independent_vault(tmp_path):
    require_legacy_file_vault()
    root = tmp_path / "custom"
    (root / "blobs").mkdir(mode=0o700, parents=True)
    root.chmod(0o700)
    (root / "blobs/orphan.blob").write_bytes(b"retained ciphertext")
    selector = vault_identity(root)
    backend = _SecKeyBackend(ops=_FakeOps(), sw_ops=None)
    backend.generate_enclave_key(selector)
    before = durable(tmp_path), list(backend._ops.calls)
    with pytest.raises(DatabaseRefused):
        vault.init_vault(
            root,
            key_id=selector,
            passphrase="synthetic",
            backend=backend,
            store=FakeAnchorStore(),
            anchor_label=selector,
        )
    assert durable(tmp_path) == before[0]
    assert backend._ops.calls == before[1]


def test_lost_vault_with_existing_valid_binding_is_not_silently_reinitialized(enrolled_source):
    import shutil

    home, opened, backend, store, ops, _, _ = enrolled_source
    shutil.rmtree(opened._root)
    with database_key_mutation(root=home, generation=None) as lease:
        before = durable(home), list(ops.calls)
        with pytest.raises(DatabaseRefused, match="binding"):
            vault.init_vault(
                opened._root,
                key_id=opened._key_id,
                passphrase="new synthetic",
                backend=backend,
                store=store,
                anchor_label=opened._label,
                database_lease=lease,
            )
        assert durable(home) == before[0]
        assert not opened._root.exists()
        assert ops.calls == before[1]


@pytest.mark.parametrize("lock_kind", ["vault", "lifecycle"])
@pytest.mark.parametrize("timing", ["after_scope_entry", "after_permit_issuance"])
def test_replaced_actual_custody_lock_refuses_native_ownership(source, lock_kind, timing):
    home, opened, backend, _, ops = source
    with database_key_mutation(root=home, generation=None) as lease, opened._custody_scope():
        lock = opened._root / ".lock" if lock_kind == "vault" else opened._root.parent / ".keyvault.lifecycle.lock"

        def replace_held_lock():
            before_identity = lock.stat().st_dev, lock.stat().st_ino
            retained = lock.with_name(lock.name + ".retained")
            lock.rename(retained)
            lock.touch(mode=0o600)
            assert (retained.stat().st_dev, retained.stat().st_ino) == before_identity
            assert (lock.stat().st_dev, lock.stat().st_ino) != before_identity

        if timing == "after_scope_entry":
            replace_held_lock()
            before_native = list(ops.calls)
            before_files = durable(home)
            with pytest.raises(DatabaseRefused):
                opened._native_delete_owner(backend)
        else:
            owner = opened._native_delete_owner(backend)
            with _owned_delete_scope(owner, backend=backend, database_lease=lease) as permit:
                replace_held_lock()
                before_native = list(ops.calls)
                before_files = durable(home)
                with pytest.raises(DatabaseRefused):
                    backend.delete_enclave_key(opened._key_id, deletion=permit)
        assert ops.calls == before_native
        assert durable(home) == before_files
