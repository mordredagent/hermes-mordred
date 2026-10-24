"""Provisioning rollback through the production native capability boundary."""

from pathlib import Path

import pytest

from mordred_hermes._database_contracts import DatabaseRefused
from mordred_hermes.keyvault import _native_key_id, _storage, api, recovery
from mordred_hermes.keyvault._seckey_backend import _SecKeyBackend
from tests._keyvault_lifecycle_helpers import _SPEC_PASSPHRASE, _SPEC_POW, _SPEC_SEED
from tests.test_keyvault_seckey_backend import _FakeOps


@pytest.mark.parametrize("operation", ["generate", "import"])
def test_failed_provisioning_deletes_only_its_created_key(monkeypatch, tmp_path, operation):
    ops = _FakeOps()
    backend = _SecKeyBackend(ops=ops, sw_ops=None, legacy_ops=None)
    real_write = _storage.atomic_write

    def fail_digest(path: Path, data: bytes) -> None:
        if path.suffix == ".commit":
            raise OSError("commit device full")
        real_write(path, data)

    monkeypatch.setattr(_storage, "atomic_write", fail_digest)
    # Isolate the post-authentication destination transaction. Recovery crypto
    # and verification are tested by the complete backup containing module.
    monkeypatch.setattr(
        recovery, "import_backup", lambda *args, **kwargs: b'{"version":1,"key_id":"default","envelopes":[]}'
    )
    with pytest.raises(OSError, match="commit device full"):
        if operation == "generate":
            handle, digest = api.prepare_generate(_SPEC_SEED, _SPEC_PASSPHRASE, _SPEC_POW)
            api.confirm_generate(handle, digest, backend=backend, audit_sink=lambda _: None, home=tmp_path)
        else:
            api.import_backup(
                b"authenticated backup",
                _SPEC_PASSPHRASE,
                seed_phrase=_SPEC_SEED,
                pow_bytes=_SPEC_POW,
                backend=backend,
                audit_sink=lambda _: None,
                home=tmp_path,
            )
    assert not ops._keys
    assert sum(command == "delete" for command, _ in ops.calls) == 1
    meta = _storage.load_meta(tmp_path / "mordred" / "keyvault")
    assert meta["keys"] == {}
    assert _native_key_id.PENDING_NATIVE_KEY_FIELD not in meta


def test_durable_ownership_ends_provisioning_rollback(monkeypatch, tmp_path):
    from mordred_hermes.keyvault import _secret_ops

    ops = _FakeOps()
    backend = _SecKeyBackend(ops=ops, sw_ops=None, legacy_ops=None)

    def fail_pending_cleanup(*args, **kwargs):
        raise OSError("pending cleanup failed")

    monkeypatch.setattr(_secret_ops, "_clear_pending_native_key_after_commit", fail_pending_cleanup)
    handle, digest = api.prepare_generate(_SPEC_SEED, _SPEC_PASSPHRASE, _SPEC_POW)
    with pytest.raises(OSError, match="pending cleanup failed"):
        api.confirm_generate(handle, digest, backend=backend, audit_sink=lambda _: None, home=tmp_path)
    assert len(ops._keys) == 1
    assert all(command != "delete" for command, _ in ops.calls)
    root = tmp_path / "mordred" / "keyvault"
    with pytest.raises(DatabaseRefused):
        backend.delete_enclave_key(_native_key_id.scoped_native_key_id(root, "default"))
    meta = _storage.load_meta(root)
    assert len(meta["keys"]) == 1
    assert _native_key_id.PENDING_NATIVE_KEY_FIELD in meta
