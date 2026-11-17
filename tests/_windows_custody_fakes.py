"""Portable real-backend fixture with software native operations only."""

from mordred_hermes.keyvault._exceptions import WrapKeyNotFound
from mordred_hermes.keyvault._native_deletion import _assert_native_tag_delete
from mordred_hermes.keyvault._seckey_backend import _SecKeyBackend
from mordred_hermes.keyvault._seckey_errors import OPS_NOT_FOUND, _application_tag, _OpsError
from tests._keyvault_fakes import FakeBackend


def windows_test_backend(fake=None):
    """Keep legacy selector/counter assertions while testing the real delete gate."""
    fake = FakeBackend() if fake is None else fake
    selectors = {}

    class Ops:
        def selector(self, tag):
            if tag not in selectors:
                raise _OpsError(0, reason=OPS_NOT_FOUND)
            return selectors[tag]

        def create_keypair(self, tag, label, *, unattended=False):
            return fake.generate_enclave_key(self.selector(tag), unattended=unattended)

        def copy_public_key(self, tag):
            selector = self.selector(tag)
            try:
                return fake.get_enclave_public_key(selector)
            except WrapKeyNotFound:
                raise _OpsError(0, reason=OPS_NOT_FOUND) from None

        def key_exchange(self, tag, peer_pub):
            return fake.enclave_ecdh(self.selector(tag), peer_pub)

        def delete_key(self, tag):
            _assert_native_tag_delete(ops=self, tag=tag)
            fake.delete_enclave_key(self.selector(tag))

    backend = _SecKeyBackend(ops=Ops(), sw_ops=None, legacy_ops=None)
    generate = backend.generate_enclave_key

    def tracked_generate(selector, *, unattended=None):
        selectors[_application_tag(selector)] = selector
        return generate(selector, unattended=unattended)

    backend.generate_enclave_key = tracked_generate
    if hasattr(fake, "_keys"):
        backend._keys = fake._keys
    if hasattr(fake, "_path"):
        backend._path = fake._path
        backend.directory = fake.directory
    backend.calls = fake.calls
    return backend
