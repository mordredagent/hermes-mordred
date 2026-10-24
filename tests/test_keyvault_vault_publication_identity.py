"""New vault ownership cannot select another real provisioning transaction's key."""

import pytest

from mordred_hermes._database_contracts import DatabaseRefused
from mordred_hermes.keyvault import anchor, manifest, vault, vault_master
from mordred_hermes.keyvault._database_mutation import database_key_mutation
from mordred_hermes.keyvault._identity import vault_identity
from tests._keyvault_fakes import FakeAnchorStore
from tests._keyvault_receipt_ipc import make_backend
from tests._platform_test_helpers import legacy_file_vault as legacy_file_vault
from tests.test_keyvault_publication_receipts import finish, read, send, start


@pytest.mark.parametrize("operation", ["init", "recover"])
def test_other_root_vault_cannot_publish_a_live_pending_main_selector(tmp_path, legacy_file_vault, operation):
    from mordred_hermes.keyvault import _native_key_id as ids
    from mordred_hermes.keyvault import _storage

    a = start(tmp_path, "A")
    try:
        assert read(a)["ready"]
        backend, ops = make_backend(tmp_path)
        pending = ids.scoped_native_key_id(_storage.resolve_keyvault_dir(tmp_path), "default")
        other = tmp_path / "other-home"
        other.mkdir(mode=0o700)
        root = other / "mordred/vault"
        label = vault_identity(root)
        store = FakeAnchorStore()
        with database_key_mutation(root=other, generation=None) as lease:
            if operation == "recover":
                backend.generate_enclave_key(label)
                vault.init_vault(
                    root,
                    key_id=label,
                    anchor_label=label,
                    passphrase="synthetic",
                    backend=backend,
                    store=store,
                    database_lease=lease,
                ).close()
            before = {str(p.relative_to(other)): p.read_bytes() for p in other.rglob("*") if p.is_file()}
            calls = list(ops.calls), list(store.calls)
            with pytest.raises(DatabaseRefused):
                if operation == "init":
                    vault.init_vault(
                        root,
                        key_id=pending,
                        anchor_label=label,
                        passphrase="synthetic",
                        backend=backend,
                        store=store,
                        database_lease=lease,
                    )
                else:
                    vault.recover_to_device(
                        root,
                        "synthetic",
                        key_id=pending,
                        anchor_label=label,
                        backend=backend,
                        store=store,
                        database_lease=lease,
                    )
            assert before == {str(p.relative_to(other)): p.read_bytes() for p in other.rglob("*") if p.is_file()}
            assert calls == (ops.calls, store.calls)
        send(a, "rollback")
        assert read(a) == {"old_rollback": "refused", "native_deletes": 0}
        finish(a)
    finally:
        if a.poll() is None:
            a.kill()
            a.wait()


def test_vault_anchor_identity_is_required_before_directory_or_native_writes(tmp_path, legacy_file_vault):
    backend, ops = make_backend(tmp_path)
    root = tmp_path / "custom-vault"
    with pytest.raises(DatabaseRefused):
        vault.init_vault(
            root,
            key_id=vault_identity(root),
            anchor_label="foreign-anchor",
            passphrase="synthetic",
            backend=backend,
            store=FakeAnchorStore(),
        )
    assert not root.exists()
    assert ops.calls == []


def test_custom_derived_init_and_legacy_readonly_recovery_remain_supported(tmp_path, legacy_file_vault):
    from mordred_hermes.keyvault import _storage

    backend, _ = make_backend(tmp_path)
    own = tmp_path / "custom-vault"
    own_id = vault_identity(own)
    backend.generate_enclave_key(own_id)
    store = FakeAnchorStore()
    with vault.init_vault(
        own, key_id=own_id, anchor_label=own_id, passphrase="synthetic", backend=backend, store=store
    ):
        pass
    with vault.open_vault(own, key_id=own_id, anchor_label=own_id, backend=backend, store=store):
        pass
    # A historical artifact with an arbitrary ID is read-only compatibility,
    # not a new supported publication route under that arbitrary selector.
    legacy = tmp_path / "legacy-vault"
    (legacy / "blobs").mkdir(mode=0o700, parents=True)
    legacy.chmod(0o700)
    _storage.ensure_lock_file(legacy / ".lock")
    backend.generate_enclave_key("historical-key")
    sealed, master = vault_master.seal(key_id="historical-key", passphrase="synthetic", backend=backend)
    try:
        _storage.atomic_write(legacy / "recovery.mrkv", sealed.recovery)
        _storage.atomic_write(
            legacy / "manifest.0.mvmf",
            manifest.encode(
                manifest.VaultManifest(key_id="historical-key", wmk=sealed.wmk, files={}, generation=0), master
            ),
        )
        anchor.write_anchor(store, "historical-anchor", wmk=sealed.wmk, generation=0)
    finally:
        master.close()
    with vault.open_vault(
        legacy, key_id="historical-key", anchor_label="historical-anchor", backend=backend, store=store
    ):
        pass
    with vault.recover_vault(legacy, "synthetic"):
        pass
