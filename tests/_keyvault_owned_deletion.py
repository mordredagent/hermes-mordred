"""Opt-in shared fake adapter for legacy reset/audit state-machine tests.

These substitutions test transaction recovery, not native permission issuance.
The real producer and boundary tests never install this adapter.
"""

from __future__ import annotations

import pytest

from mordred_hermes.keyvault import _native_key_id, _storage
from mordred_hermes.wizard import _keyvault_init, keyvault_cli
from tests._keyvault_fakes import FakeBackend


def install_fake_owned_deletion(monkeypatch: pytest.MonkeyPatch) -> None:
    original_delete = keyvault_cli._delete_wrapping_keys
    original_rollback = _keyvault_init._rollback_new_audit_key

    def delete(key_ids, *, root, backend, database_lease):
        if not isinstance(backend, FakeBackend):
            return original_delete(key_ids, root=root, backend=backend, database_lease=database_lease)
        journal = keyvault_cli._load_reset_journal(root)
        assert journal.key_ids == key_ids
        assert not journal.metadata_incomplete and not journal.retained_legacy
        failures = []
        for logical, selector in key_ids.items():
            try:
                backend.delete_enclave_key(selector)
            except Exception as exc:
                keyvault_cli._term.emit_error(f"could not delete native wrapping key {logical!r} ({exc})")
                failures.append(logical)
        return failures

    def rollback(root, backend, native_key_id, *, receipt=None):
        if not isinstance(backend, FakeBackend) or receipt is not None:
            return original_rollback(root, backend, native_key_id, receipt=receipt)
        try:
            assert native_key_id in _native_key_id._checked_metadata_targets(root).values()
            backend.delete_enclave_key(native_key_id)
            meta = _storage.load_meta(root)
            meta.pop(_native_key_id.AUDIT_KEY_FIELD, None)
            meta.pop(_native_key_id.PENDING_AUDIT_KEY_FIELD, None)
            _storage.save_meta(root, meta)
        except Exception:
            return

    monkeypatch.setattr(keyvault_cli, "_delete_wrapping_keys", delete)
    monkeypatch.setattr(_keyvault_init, "_rollback_new_audit_key", rollback)
