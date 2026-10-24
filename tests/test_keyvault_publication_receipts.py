"""Checked source adoption revokes another transaction's rollback rights."""

import pytest

from mordred_hermes._database_contracts import DatabaseRefused
from mordred_hermes.keyvault import wrap
from mordred_hermes.keyvault._database_mutation import database_key_mutation
from mordred_hermes.keyvault._seckey_backend import _SecKeyBackend
from tests._platform_test_helpers import legacy_file_vault as legacy_file_vault
from tests.test_keyvault_seckey_backend import _FakeOps
from tests.test_windows_custody import fs as fs


def backend_pair():
    creator_ops = _FakeOps()
    adopter_ops = _FakeOps()
    adopter_ops._keys = creator_ops._keys
    return (
        _SecKeyBackend(ops=creator_ops, sw_ops=None, legacy_ops=None),
        _SecKeyBackend(ops=adopter_ops, sw_ops=None, legacy_ops=None),
        creator_ops,
        adopter_ops,
    )


@pytest.mark.parametrize("role", ["memory", "audit", "telegram"])
@pytest.mark.parametrize("uncertain", [False, True])
def test_windows_reconciliation_revokes_external_receipt(fs, monkeypatch, role, uncertain):
    custody, _, home, _ = fs
    creator, adopter, creator_ops, adopter_ops = backend_pair()
    with (
        database_key_mutation(root=home, generation=None) as lease,
        custody.windows_custody_session(home, create=True, backend=adopter) as session,
    ):
        # Stage a genuine interrupted native-create intent; reconciliation is
        # the supported adoption path for a key created after this journal.
        _, pending = session._begin(role, database_lease=lease)
        if uncertain:
            journal = session._journal

            def fail_verified(record, **kwargs):
                journal(record, **kwargs)
                if record.phase == "verified":
                    raise OSError("verified journal durability uncertain")

            monkeypatch.setattr(session, "_journal", fail_verified)
        with wrap.create_wrapping_key_scope(pending.record.native_key_id, backend=creator) as receipt:
            if uncertain:
                with pytest.raises(OSError):
                    session.reconcile_pending(role, database_lease=lease)
            else:
                session.reconcile_pending(role, database_lease=lease)
                assert session.lease(role).native_key_id == pending.record.native_key_id
            (home / "state.db").touch()
            with pytest.raises(DatabaseRefused):
                wrap.rollback_created_key(receipt)
    assert creator_ops._keys
    assert all(command != "delete" for command, _ in creator_ops.calls + adopter_ops.calls)


@pytest.mark.parametrize("operation", ["init", "recover"])
@pytest.mark.parametrize("uncertain", [False, True])
def test_vault_publication_revokes_external_receipt(tmp_path, monkeypatch, legacy_file_vault, operation, uncertain):
    from mordred_hermes.keyvault import vault
    from tests._keyvault_fakes import FakeAnchorStore

    root = tmp_path / "mordred" / "vault"
    selector = "vault-receipt-adoption"
    store = FakeAnchorStore()
    creator, adopter, creator_ops, adopter_ops = backend_pair()
    with database_key_mutation(root=tmp_path, generation=None) as lease:
        if operation == "recover":
            old = _SecKeyBackend(ops=_FakeOps(), sw_ops=None, legacy_ops=None)
            old.generate_enclave_key(selector)
            vault.init_vault(
                root,
                key_id=selector,
                passphrase="passphrase",
                backend=old,
                store=store,
                anchor_label="vault-receipts",
                database_lease=lease,
            ).close()
        if uncertain:
            write = vault.atomic_write

            def fail_manifest(path, data):
                write(path, data)
                if path.name.startswith("manifest."):
                    raise OSError("manifest durability uncertain")

            monkeypatch.setattr(vault, "atomic_write", fail_manifest)
        with wrap.create_wrapping_key_scope(selector, backend=creator) as receipt:

            def publish():
                if operation == "init":
                    return vault.init_vault(
                        root,
                        key_id=selector,
                        passphrase="passphrase",
                        backend=adopter,
                        store=store,
                        anchor_label="vault-receipts",
                        database_lease=lease,
                    )
                return vault.recover_to_device(
                    root,
                    "passphrase",
                    key_id=selector,
                    backend=adopter,
                    store=store,
                    anchor_label="vault-receipts",
                    database_lease=lease,
                )

            if uncertain:
                with pytest.raises(OSError):
                    publish()
            else:
                publish().close()
            assert tuple(root.glob("manifest.*"))
            (tmp_path / "state.db").touch()
            with pytest.raises(DatabaseRefused):
                wrap.rollback_created_key(receipt)
    assert creator_ops._keys
    assert all(command != "delete" for command, _ in creator_ops.calls + adopter_ops.calls)


@pytest.mark.parametrize("uncertain", [False, True])
def test_audit_duplicate_adoption_revokes_external_receipt(tmp_path, monkeypatch, uncertain):
    from mordred_hermes.keyvault import _native_key_id as ids
    from mordred_hermes.keyvault import _storage
    from mordred_hermes.keyvault._seckey_helper import _HelperSecKeyOps
    from mordred_hermes.keyvault.log_encryption import AUDIT_LOG_KEY_ID
    from mordred_hermes.wizard import _keyvault_init as init
    from tests.test_keyvault_checked_custody import _audit_backend, _owned

    root, _, adopter, _ = _owned(tmp_path, monkeypatch)
    keys, calls = _audit_backend(adopter, monkeypatch)
    creator = _SecKeyBackend(ops=_HelperSecKeyOps("/not/executed"), sw_ops=None, legacy_ops=None)
    selector = ids.scoped_native_key_id(root, AUDIT_LOG_KEY_ID)
    if uncertain:
        save = _storage.save_meta

        def fail_visible_ownership(root, meta):
            save(root, meta)
            if ids.AUDIT_KEY_FIELD in meta:
                raise OSError("audit ownership durability uncertain")

        monkeypatch.setattr(_storage, "save_meta", fail_visible_ownership)
    with wrap.create_wrapping_key_scope(selector, backend=creator) as receipt:
        with _storage.keyvault_lock(root):
            if uncertain:
                with pytest.raises(OSError):
                    init._provision_audit_log_key_locked(root, adopter, AUDIT_LOG_KEY_ID)
            else:
                init._provision_audit_log_key_locked(root, adopter, AUDIT_LOG_KEY_ID)
        assert ids.AUDIT_KEY_FIELD in _storage.load_meta(root)
        with pytest.raises(DatabaseRefused):
            wrap.rollback_created_key(receipt)
    assert keys
    assert not any(call["cmd"] == "delete" for call in calls)
