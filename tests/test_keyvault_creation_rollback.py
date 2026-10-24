"""Provisioning rollback through the production native capability boundary."""

from pathlib import Path

import pytest

from mordred_hermes._database_contracts import DatabaseRefused
from mordred_hermes.keyvault import _native_key_id, _storage, api, recovery
from mordred_hermes.keyvault._seckey_backend import _SecKeyBackend
from tests._keyvault_lifecycle_helpers import _SPEC_PASSPHRASE, _SPEC_POW, _SPEC_SEED
from tests._platform_test_helpers import legacy_secret_store as legacy_secret_store
from tests.test_keyvault_seckey_backend import _FakeOps

pytestmark = pytest.mark.usefixtures("legacy_secret_store")


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


def test_arbitrary_linux_receipt_refuses_before_native_generation(tmp_path):
    from mordred_hermes.keyvault import _memory_key, wrap

    ops = _FakeOps()
    backend = _SecKeyBackend(ops=ops, sw_ops=None, legacy_ops=None)
    with (
        pytest.raises((DatabaseRefused, TypeError)),
        wrap.create_wrapping_key_scope(_memory_key.memory_key_id(tmp_path), backend=backend),
    ):
        pytest.fail("arbitrary selector obtained rollback authority")
    assert ops.calls == []


@pytest.mark.parametrize("invalid", ["forged", "wrong-selector", "wrong-backend", "committed", "pending-changed"])
def test_receipt_requires_exact_live_pending_owner(tmp_path, invalid):
    from mordred_hermes.keyvault import wrap

    ops = _FakeOps()
    backend = _SecKeyBackend(ops=ops, sw_ops=None, legacy_ops=None)
    root = _storage.resolve_keyvault_dir(tmp_path)
    _storage.ensure_layout(root)
    with _storage.keyvault_custody(root, backend=backend) as custody:
        meta = _storage.load_meta(root)
        selector = _native_key_id.add_pending_native_key(root, meta, "default")
        _storage.save_meta(root, meta)
        supplied = custody
        target = backend
        if invalid == "forged":
            supplied = object.__new__(_storage.KeyvaultCustody)
        elif invalid == "wrong-selector":
            selector = "mordred-hermes.memory.arbitrary"
        elif invalid == "wrong-backend":
            target = _SecKeyBackend(ops=ops, sw_ops=None, legacy_ops=None)
        elif invalid == "committed":
            meta["keys"][wrap._key_id_hash("default").hex()] = {
                "key_id": "default",
                _native_key_id.NATIVE_KEY_ID_FIELD: selector,
            }
            _storage.save_meta(root, meta)
        else:
            meta.pop(_native_key_id.PENDING_NATIVE_KEY_FIELD)
            _storage.save_meta(root, meta)
        with (
            pytest.raises(DatabaseRefused),
            wrap.create_wrapping_key_scope("default", backend=target, custody=supplied, native_key_id=selector),
        ):
            pytest.fail("invalid creation custody admitted")
    assert ops.calls == []


def test_receipt_expired_by_real_custody_exit_and_reentry(tmp_path):
    from contextlib import ExitStack

    from mordred_hermes.keyvault import wrap

    ops = _FakeOps()
    backend = _SecKeyBackend(ops=ops, sw_ops=None, legacy_ops=None)
    root = _storage.resolve_keyvault_dir(tmp_path)
    _storage.ensure_layout(root)
    with ExitStack() as lifetime:
        with _storage.keyvault_custody(root, backend=backend) as custody:
            meta = _storage.load_meta(root)
            selector = _native_key_id.add_pending_native_key(root, meta, "default")
            _storage.save_meta(root, meta)
            receipt = lifetime.enter_context(
                wrap.create_wrapping_key_scope("default", backend=backend, custody=custody, native_key_id=selector)
            )
        before = list(ops.calls)
        with _storage.keyvault_custody(root, backend=backend), pytest.raises(DatabaseRefused):
            wrap.rollback_created_key(receipt)
        assert ops.calls == before
        assert ops._keys


def test_custody_exit_during_native_create_does_not_issue_receipt(tmp_path, monkeypatch):
    from contextlib import ExitStack

    from mordred_hermes.keyvault import wrap

    ops = _FakeOps()
    backend = _SecKeyBackend(ops=ops, sw_ops=None, legacy_ops=None)
    root = _storage.resolve_keyvault_dir(tmp_path)
    _storage.ensure_layout(root)
    with ExitStack() as lifetime:
        custody = lifetime.enter_context(_storage.keyvault_custody(root, backend=backend))
        meta = _storage.load_meta(root)
        selector = _native_key_id.add_pending_native_key(root, meta, "default")
        _storage.save_meta(root, meta)
        create = ops.create_keypair

        def close_after_create(*args, **kwargs):
            public = create(*args, **kwargs)
            lifetime.close()
            return public

        monkeypatch.setattr(ops, "create_keypair", close_after_create)
        with (
            pytest.raises(DatabaseRefused),
            wrap.create_wrapping_key_scope("default", backend=backend, custody=custody, native_key_id=selector),
        ):
            pytest.fail("closed owner obtained receipt")
    assert ops._keys
    assert all(command != "delete" for command, _ in ops.calls)


@pytest.mark.parametrize("lock_name", [".lock", "../.keyvault.lifecycle.lock"])
def test_replaced_real_lock_refuses_receipt_rollback(tmp_path, lock_name):
    from mordred_hermes.keyvault import wrap
    from tests._keyvault_creation_context import creation_scope

    ops = _FakeOps()
    backend = _SecKeyBackend(ops=ops, sw_ops=None, legacy_ops=None)
    root = _storage.resolve_keyvault_dir(tmp_path)
    with creation_scope("default", backend=backend, root=root) as receipt:
        path = root / lock_name
        path.rename(path.with_name(path.name + ".old"))
        path.write_bytes(b"")
        path.chmod(0o600)
        before = list(ops.calls)
        with pytest.raises(DatabaseRefused):
            wrap.rollback_created_key(receipt)
        assert ops.calls == before
    assert ops._keys


def test_helper_store_materialization_is_bound_after_success(tmp_path, monkeypatch):
    from mordred_hermes.keyvault import wrap
    from mordred_hermes.keyvault._seckey_helper import _HelperSecKeyOps
    from tests._keyvault_creation_context import creation_scope
    from tests.test_keyvault_native_deletion import _PUBLIC_KEY

    ops = _HelperSecKeyOps("/not/executed")
    backend = _SecKeyBackend(ops=ops, sw_ops=None, legacy_ops=None)
    calls = []

    def invoke(payload):
        calls.append(payload["cmd"])
        if payload["cmd"] == "generate":
            Path(ops._env_override[1]).mkdir(mode=0o700)
        return {"public_key_hex": _PUBLIC_KEY.hex(), "ok": True}

    monkeypatch.setattr(ops, "_invoke", invoke)
    with creation_scope("default", backend=backend) as receipt:
        wrap.rollback_created_key(receipt)
    assert calls == ["generate", "public_key", "delete"]


def test_helper_foreign_store_refuses_before_native_io(tmp_path, monkeypatch):
    import sys

    from mordred_hermes.keyvault import wrap
    from mordred_hermes.keyvault._seckey_helper import _HelperSecKeyOps

    root = _storage.resolve_keyvault_dir(tmp_path)
    _storage.ensure_layout(root)
    env_name = "MORDRED_SEKEY_STORE" if sys.platform == "darwin" else "MORDRED_TPMKEY_STORE"
    monkeypatch.delenv(env_name, raising=False)
    ops = _HelperSecKeyOps("/not/executed", env_override=(env_name, str(tmp_path / "foreign")))
    calls = []
    monkeypatch.setattr(ops, "_invoke", lambda payload: calls.append(payload))
    backend = _SecKeyBackend(ops=ops, sw_ops=None, legacy_ops=None)
    with _storage.keyvault_custody(root, backend=backend) as custody:
        meta = _storage.load_meta(root)
        selector = _native_key_id.add_pending_native_key(root, meta, "default")
        _storage.save_meta(root, meta)
        with (
            pytest.raises(DatabaseRefused),
            wrap.create_wrapping_key_scope("default", backend=backend, custody=custody, native_key_id=selector),
        ):
            pytest.fail("foreign store admitted")
    assert calls == []


def test_closed_actual_custody_descriptor_refuses_before_native_io(tmp_path):
    import os

    from mordred_hermes.keyvault import wrap

    backend = _SecKeyBackend(ops=_FakeOps(), sw_ops=None, legacy_ops=None)
    root = _storage.resolve_keyvault_dir(tmp_path)
    _storage.ensure_layout(root)
    # Deliberate descriptor sabotage must refuse. Unwinding also reports the
    # externally closed descriptor; neither error may cross native I/O.
    with pytest.raises(OSError), _storage.keyvault_custody(root, backend=backend) as custody:
        meta = _storage.load_meta(root)
        selector = _native_key_id.add_pending_native_key(root, meta, "default")
        _storage.save_meta(root, meta)
        os.close(_storage._checked_advisory_lock(root / ".lock").fd)
        with (
            pytest.raises(DatabaseRefused),
            wrap.create_wrapping_key_scope("default", backend=backend, custody=custody, native_key_id=selector),
        ):
            pytest.fail("closed descriptor admitted")
    assert backend._ops.calls == []


@pytest.mark.parametrize("origin", ["thread", "fork"])
def test_receipt_requires_creating_thread_and_process(tmp_path, origin):
    import os
    import threading

    from mordred_hermes.keyvault import wrap
    from tests._keyvault_creation_context import creation_scope

    ops = _FakeOps()
    backend = _SecKeyBackend(ops=ops, sw_ops=None, legacy_ops=None)
    with creation_scope("default", backend=backend) as receipt:
        before = list(ops.calls)
        if origin == "thread":
            refused = []

            def attempt():
                try:
                    wrap.rollback_created_key(receipt)
                except DatabaseRefused:
                    refused.append(True)

            worker = threading.Thread(target=attempt)
            worker.start()
            worker.join()
            assert refused == [True]
        else:
            if not hasattr(os, "fork"):
                pytest.skip("fork unavailable")
            child = os.fork()
            if child == 0:
                try:
                    wrap.rollback_created_key(receipt)
                except DatabaseRefused:
                    os._exit(0 if not _storage._ACTIVE_LOCK_FDS and ops.calls == before else 2)
                os._exit(3)
            assert os.waitstatus_to_exitcode(os.waitpid(child, 0)[1]) == 0
        assert ops.calls == before
    assert ops._keys


def test_receipt_admission_and_rollback_never_acquire_database_exclusion(tmp_path, monkeypatch):
    from mordred_hermes.keyvault import _database_mutation, wrap
    from tests._keyvault_creation_context import creation_scope

    backend = _SecKeyBackend(ops=_FakeOps(), sw_ops=None, legacy_ops=None)

    def forbidden(*args, **kwargs):
        pytest.fail("receipt attempted database broker acquisition")

    monkeypatch.setattr(_database_mutation, "database_key_mutation", forbidden)
    with creation_scope("default", backend=backend) as receipt:
        wrap.rollback_created_key(receipt)
    assert not backend._ops._keys


@pytest.mark.parametrize("copying", ["copy", "deepcopy", "pickle"])
def test_creation_receipt_cannot_be_copied_or_serialized(copying):
    import copy
    import pickle

    from mordred_hermes.keyvault import wrap
    from tests._keyvault_creation_context import creation_scope

    backend = _SecKeyBackend(ops=_FakeOps(), sw_ops=None, legacy_ops=None)
    with creation_scope("default", backend=backend) as receipt:
        before = list(backend._ops.calls)
        operation = {"copy": copy.copy, "deepcopy": copy.deepcopy, "pickle": pickle.dumps}[copying]
        with pytest.raises(DatabaseRefused):
            operation(receipt)
        assert backend._ops.calls == before
        wrap.rollback_created_key(receipt)
    assert not backend._ops._keys


def test_resumed_pending_transaction_cannot_mint_new_receipt(tmp_path):
    from mordred_hermes.keyvault import wrap

    backend = _SecKeyBackend(ops=_FakeOps(), sw_ops=None, legacy_ops=None)
    root = _storage.resolve_keyvault_dir(tmp_path)
    _storage.ensure_layout(root)
    with _storage.keyvault_lock(root):
        meta = _storage.load_meta(root)
        selector = _native_key_id.add_pending_native_key(root, meta, "default")
        _storage.save_meta(root, meta)
    with (
        _storage.keyvault_custody(root, backend=backend) as custody,
        pytest.raises(DatabaseRefused),
        wrap.create_wrapping_key_scope("default", backend=backend, custody=custody, native_key_id=selector),
    ):
        pytest.fail("resumed pending ownership obtained new rollback rights")
    assert backend._ops.calls == []


def test_completed_owner_cannot_recreate_lost_key_inside_same_custody(tmp_path):
    from mordred_hermes.keyvault import wrap

    ops = _FakeOps()
    backend = _SecKeyBackend(ops=ops, sw_ops=None, legacy_ops=None)
    root = _storage.resolve_keyvault_dir(tmp_path)
    _storage.ensure_layout(root)
    with _storage.keyvault_custody(root, backend=backend) as custody:
        meta = _storage.load_meta(root)
        selector = _native_key_id.add_pending_native_key(root, meta, "default")
        _storage.save_meta(root, meta)
        with wrap.create_wrapping_key_scope(
            "default", backend=backend, custody=custody, native_key_id=selector
        ) as receipt:
            key_hash = wrap._key_id_hash("default").hex()
            _storage.atomic_write(root / "digests" / (key_hash + ".commit"), b"d" * 32)
            meta["keys"][key_hash] = {"key_id": "default", _native_key_id.NATIVE_KEY_ID_FIELD: selector}
            _storage.save_meta(root, meta)
            wrap.commit_created_key(receipt)
            ops._keys.clear()  # Simulate lost native custody after successful ownership commit.
            before = list(ops.calls)
            with (
                pytest.raises(DatabaseRefused),
                wrap.create_wrapping_key_scope("default", backend=backend, custody=custody, native_key_id=selector),
            ):
                pytest.fail("completed owner re-created lost custody with new rollback rights")
            assert ops.calls == before
