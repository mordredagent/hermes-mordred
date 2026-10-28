"""Opt-in native-ops adapters preserve the actual custody/receipt protocol."""

import pytest

from mordred_hermes._database_contracts import DatabaseRefused
from mordred_hermes.keyvault import _native_deletion, _native_key_id, wrap
from mordred_hermes.keyvault._exceptions import WrapKeyAlreadyExists
from mordred_hermes.keyvault._native_deletion import NativeCreateReceipt
from mordred_hermes.keyvault._seckey_backend import _SecKeyBackend
from tests._keyvault_creation_context import creation_scope
from tests._keyvault_fakes import FakeBackend
from tests._keyvault_receipts import RegisterFakeBackend
from tests.test_keyvault_profile_native_ids import _AmbientStoreBackend
from tests.test_keyvault_seckey_backend import _FakeOps

pytestmark = pytest.mark.usefixtures("fake_native_creation_receipts")


def selector(receipt):
    return _native_deletion._receipts[receipt].binding[1]


def test_adapter_uses_real_custody_and_single_use_production_receipt():
    backend = FakeBackend()
    backend.generate_enclave_key("unrelated")
    with creation_scope("default", backend=backend) as receipt:
        physical = selector(receipt)
        assert type(receipt) is NativeCreateReceipt
        assert receipt.public_key == backend.get_enclave_public_key(physical)
        wrap.rollback_created_key(receipt)
        with pytest.raises(DatabaseRefused):
            wrap.rollback_created_key(receipt)
    assert set(backend._keys) == {"unrelated"}
    assert [call for call in backend.calls if call[0] == "delete"] == [("delete", physical)]


@pytest.mark.parametrize("commit", [False, True])
def test_scope_or_commit_revokes_receipt(commit):
    backend = FakeBackend()
    with creation_scope("default", backend=backend) as receipt:
        physical = selector(receipt)
        if commit:
            wrap.commit_created_key(receipt)
        else:
            assert receipt.public_key
    with pytest.raises(DatabaseRefused):
        wrap.rollback_created_key(receipt)
    assert set(backend._keys) == {physical}
    assert all(command != "delete" for command, _ in backend.calls)


@pytest.mark.parametrize("store", [False, True])
def test_replaced_store_or_public_key_cannot_delete(store):
    backend, replacement = FakeBackend(), FakeBackend()
    with creation_scope("default", backend=backend) as receipt:
        physical = selector(receipt)
        replacement.generate_enclave_key(physical)
        if store:
            backend._keys = replacement._keys
        else:
            backend._keys[physical] = replacement._keys[physical]
        with pytest.raises(DatabaseRefused):
            wrap.rollback_created_key(receipt)
    assert all(command != "delete" for command, _ in backend.calls)


def test_failed_or_duplicate_creation_has_no_receipt(tmp_path):
    class PublishedThenFailed(FakeBackend):
        def generate_enclave_key(self, key_id, *, unattended=None):
            super().generate_enclave_key(key_id, unattended=unattended)
            raise OSError("published then failed")

    backend = PublishedThenFailed()
    with pytest.raises(OSError), creation_scope("default", backend=backend):
        pytest.fail("failed create yielded a receipt")
    assert len(backend._keys) == 1
    root = tmp_path / "mordred/keyvault"
    existing = FakeBackend()
    existing.generate_enclave_key(_native_key_id.scoped_native_key_id(root, "default"))
    with pytest.raises(WrapKeyAlreadyExists), creation_scope("default", backend=existing, root=root):
        pytest.fail("duplicate yielded a receipt")
    assert all(command != "delete" for command, _ in existing.calls)


def test_native_registration_cannot_replace_actual_native_authority(fake_native_creation_receipts: RegisterFakeBackend):
    backend = _SecKeyBackend(ops=_FakeOps(), sw_ops=None, legacy_ops=None)
    fake_native_creation_receipts(_SecKeyBackend, lambda _: FakeBackend())
    with creation_scope("default", backend=backend) as receipt:
        assert type(receipt) is NativeCreateReceipt
        wrap.rollback_created_key(receipt)
    assert not backend._ops._keys


def test_exact_registered_wrapper_revalidates_store(fake_native_creation_receipts: RegisterFakeBackend):
    fake_native_creation_receipts(_AmbientStoreBackend, lambda backend: backend.active)
    backend = _AmbientStoreBackend(selected_root="initial")
    initial = backend.active
    with creation_scope("default", backend=backend) as receipt:
        backend.selected_root = "replacement"
        with pytest.raises(DatabaseRefused):
            wrap.rollback_created_key(receipt)
    assert initial._keys

    class UnregisteredWrapper(_AmbientStoreBackend):
        pass

    with pytest.raises(DatabaseRefused), creation_scope("default", backend=UnregisteredWrapper()):
        pytest.fail("subclass was registered implicitly")


def test_unrelated_protocol_is_not_adapted_and_missing_custody_is_never_optional():
    class Unrelated:
        def generate_enclave_key(self, *args, **kwargs):
            pytest.fail("unrelated native I/O attempted")

    with pytest.raises(DatabaseRefused), creation_scope("default", backend=Unrelated()):
        pytest.fail("unknown backend gained authority")
    with pytest.raises(TypeError), wrap.create_wrapping_key_scope("key", backend=FakeBackend()):
        pytest.fail("missing actual custody admitted")
