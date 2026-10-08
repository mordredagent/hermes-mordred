"""Process-local fake native key; no private bytes in argv, files, or diagnostics."""

from contextlib import ExitStack, contextmanager

from cryptography.hazmat.primitives.asymmetric import ec

from mordred_hermes import _audit_session, _config_io
from mordred_hermes._private_fs import PrivateFSError, open_private_directory
from mordred_hermes.keyvault import _windows_custody, windows_audit
from tests._keyvault_fakes import FakeBackend
from tests.test_windows_custody_profile import SID


class ProcessBackend(FakeBackend):
    def generate_enclave_key(self, key_id, *, unattended=None):
        self._keys[key_id] = ec.derive_private_key(1, ec.SECP256R1())
        return self.get_enclave_public_key(key_id)

    def bind(self, native_key_id):
        self._keys[native_key_id] = ec.derive_private_key(1, ec.SECP256R1())


def install_boundaries():
    @contextmanager
    def optional(path):
        with ExitStack() as stack:
            try:
                directory = stack.enter_context(open_private_directory(path))
            except PrivateFSError as exc:
                if exc.reason != "missing":
                    raise
                directory = None
            yield directory

    _config_io.open_confidential_directory = open_private_directory
    _config_io.open_optional_confidential_directory = optional
    _config_io.open_optional_private_directory = optional
    _windows_custody.open_optional_confidential_directory = optional
    _windows_custody.current_principal_id = lambda: SID
    windows_audit.open_optional_private_directory = optional
    _audit_session.fs.open_optional_private_directory = optional
