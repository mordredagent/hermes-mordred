"""Test-harness receipt rules; production authority has separate native tests."""

import pytest

from mordred_hermes._database_contracts import DatabaseRefused
from mordred_hermes.keyvault import wrap
from mordred_hermes.keyvault._exceptions import WrapKeyAlreadyExists
from mordred_hermes.keyvault._native_deletion import NativeCreateReceipt
from mordred_hermes.keyvault._seckey_backend import _SecKeyBackend
from tests._keyvault_fakes import FakeBackend
from tests._keyvault_receipts import RegisterFakeBackend
from tests.test_keyvault_profile_native_ids import _AmbientStoreBackend
from tests.test_keyvault_seckey_backend import _FakeOps

pytestmark = pytest.mark.usefixtures("fake_native_creation_receipts")


def test_rollback_deletes_only_created_selector_once() -> None:
    backend = FakeBackend()
    other = FakeBackend()
    backend.generate_enclave_key("logical")
    other.generate_enclave_key("physical")
    with wrap.create_wrapping_key_scope("logical", backend=backend, native_key_id="physical") as receipt:
        assert receipt.public_key == backend.get_enclave_public_key("physical")
        wrap.rollback_created_key(receipt)
        with pytest.raises(DatabaseRefused):
            wrap.rollback_created_key(receipt)
    assert set(backend._keys) == {"logical"}
    assert set(other._keys) == {"physical"}
    assert [call for call in backend.calls if call[0] == "delete"] == [("delete", "physical")]


@pytest.mark.parametrize("commit", [False, True])
def test_scope_exit_or_commit_revokes_rollback_without_deletion(commit: bool) -> None:
    backend = FakeBackend()
    with wrap.create_wrapping_key_scope("key", backend=backend) as receipt:
        if commit:
            wrap.commit_created_key(receipt)
            with pytest.raises(DatabaseRefused):
                wrap.rollback_created_key(receipt)
    with pytest.raises(DatabaseRefused):
        wrap.rollback_created_key(receipt)
    with pytest.raises(DatabaseRefused):
        _ = receipt.public_key
    assert set(backend._keys) == {"key"}
    assert all(operation != "delete" for operation, _ in backend.calls)


@pytest.mark.parametrize("replace_store", [False, True])
def test_replacement_key_or_store_is_preserved_and_consumes_receipt(replace_store: bool) -> None:
    backend = FakeBackend()
    replacement = FakeBackend()
    replacement.generate_enclave_key("key")
    with wrap.create_wrapping_key_scope("key", backend=backend) as receipt:
        if replace_store:
            backend._keys = replacement._keys
        else:
            backend._keys["key"] = replacement._keys["key"]
        with pytest.raises(DatabaseRefused, match="changed"):
            wrap.rollback_created_key(receipt)
        with pytest.raises(DatabaseRefused):
            wrap.rollback_created_key(receipt)
    assert backend.get_enclave_public_key("key") == replacement.get_enclave_public_key("key")
    assert all(operation != "delete" for operation, _ in backend.calls)


def test_failed_or_duplicate_creation_never_grants_rollback() -> None:
    class PublishedThenFailed(FakeBackend):
        def generate_enclave_key(self, key_id: str, *, unattended: bool | None = None) -> bytes:
            super().generate_enclave_key(key_id, unattended=unattended)
            raise OSError("published then failed")

    backend = PublishedThenFailed()
    with pytest.raises(OSError, match="published then failed"), wrap.create_wrapping_key_scope("key", backend=backend):
        pytest.fail("failed creation must not yield a receipt")
    assert set(backend._keys) == {"key"}
    existing = FakeBackend()
    existing.generate_enclave_key("key")
    with pytest.raises(WrapKeyAlreadyExists), wrap.create_wrapping_key_scope("key", backend=existing):
        pytest.fail("duplicate creation must not yield a receipt")
    assert all(operation != "delete" for operation, _ in backend.calls + existing.calls)


def test_native_backend_uses_production_receipts(fake_native_creation_receipts: RegisterFakeBackend) -> None:
    ops = _FakeOps()
    backend = _SecKeyBackend(ops=ops, sw_ops=None, legacy_ops=None)
    fake_native_creation_receipts(_SecKeyBackend, lambda _: FakeBackend())
    with wrap.create_wrapping_key_scope("key", backend=backend) as receipt:
        assert type(receipt) is NativeCreateReceipt
        wrap.rollback_created_key(receipt)
    assert not ops._keys


def test_exact_registered_wrapper_revalidates_selected_store(
    fake_native_creation_receipts: RegisterFakeBackend,
) -> None:
    fake_native_creation_receipts(_AmbientStoreBackend, lambda backend: backend.active)
    backend = _AmbientStoreBackend(selected_root="initial")
    initial = backend.active
    with wrap.create_wrapping_key_scope("key", backend=backend) as receipt:
        backend.selected_root = "replacement"
        with pytest.raises(DatabaseRefused, match="store changed"):
            wrap.rollback_created_key(receipt)
    assert set(initial._keys) == {"key"}
    assert all(operation != "delete" for operation, _ in initial.calls)

    class UnregisteredWrapper(_AmbientStoreBackend):
        pass

    with pytest.raises(DatabaseRefused), wrap.create_wrapping_key_scope("key", backend=UnregisteredWrapper()):
        pytest.fail("registering a wrapper must not register its subclasses")


def test_unrelated_protocol_backend_is_not_adapted() -> None:
    class UnrelatedBackend:
        def __init__(self) -> None:
            self._keys = {}
            self.calls = []

        def generate_enclave_key(self, key_id: str, *, unattended: bool | None = None) -> bytes:
            pytest.fail("duck-typed backends must reach production refusal")

    with pytest.raises(DatabaseRefused), wrap.create_wrapping_key_scope("key", backend=UnrelatedBackend()):
        pytest.fail("unrelated backend must not yield a receipt")
