"""Independent native mail source; importing this module enables no consumer.

Windows creation/retirement belongs to a genuine WindowsCustodySession under
canonical custody locks, after explicit manifest v2 upgrade. The public
adapter only reads current mail custody. POSIX keeps the historical mail wire
ID and macOS helper location; Linux binds TPM storage to the supplied home.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import TYPE_CHECKING

from .._database_contracts import DatabaseRefused
from .wrap import NativeBackend

if TYPE_CHECKING:
    from ._native_deletion import NativeDeletePermit

KEY_ID = "mordred-hermes.mail.credentials.v1"


def mail_key_id(home: Path) -> str:
    """Stable logical MRKW identifier; physical ownership is backend-bound."""
    del home
    return KEY_ID


def _check_key(key_id: str) -> None:
    if key_id != KEY_ID:
        raise DatabaseRefused("native mail source refuses another key role")


class _MailBackend:
    def __init__(self, backend: NativeBackend) -> None:
        self._backend = backend

    def generate_enclave_key(self, key_id: str, *, unattended: bool | None = None) -> bytes:
        _check_key(key_id)
        return self._backend.generate_enclave_key(key_id, unattended=unattended)

    def get_enclave_public_key(self, key_id: str) -> bytes:
        _check_key(key_id)
        return self._backend.get_enclave_public_key(key_id)

    def enclave_ecdh(self, key_id: str, peer_pub: bytes) -> bytes:
        _check_key(key_id)
        return self._backend.enclave_ecdh(key_id, peer_pub)

    def delete_enclave_key(self, key_id: str, *, deletion: NativeDeletePermit | None = None) -> None:
        raise DatabaseRefused("mail deletion requires explicit owning custody")


class _WindowsMailBackend:
    def __init__(self, home: Path) -> None:
        self._home = home

    def generate_enclave_key(self, key_id: str, *, unattended: bool | None = None) -> bytes:
        raise DatabaseRefused("mail enrollment requires explicit owning Windows custody")

    def delete_enclave_key(self, key_id: str, *, deletion: NativeDeletePermit | None = None) -> None:
        raise DatabaseRefused("mail deletion requires explicit owning Windows custody")

    def get_enclave_public_key(self, key_id: str) -> bytes:
        from ._windows_custody import windows_custody_session

        _check_key(key_id)
        with windows_custody_session(self._home) as session:
            lease = session.lease("mail")
            backend = session.backend_for(lease)
            return backend.get_enclave_public_key(lease.native_key_id)

    def enclave_ecdh(self, key_id: str, peer_pub: bytes) -> bytes:
        from ._windows_custody import windows_custody_session

        _check_key(key_id)
        with windows_custody_session(self._home) as session:
            lease = session.lease("mail")
            return session.backend_for(lease).enclave_ecdh(lease.native_key_id, peer_pub)


def mail_backend(*, home: Path) -> NativeBackend:
    """Select only native mail custody, without enrollment or schema migration."""
    if sys.platform == "win32":
        return _WindowsMailBackend(home)
    from . import _seckey_helper
    from ._seckey_backend import _SecKeyBackend

    if sys.platform == "linux":
        finder = _seckey_helper.find_tpmkey_helper
    elif sys.platform == "darwin":
        finder = _seckey_helper.find_sekey_helper
    else:
        raise DatabaseRefused("native mail custody is unsupported on this platform")
    ops = _seckey_helper._helper_ops_or_none(finder)
    if ops is None:
        raise DatabaseRefused("native mail helper is unavailable")
    if sys.platform == "linux":
        ops = ops.with_store_override("MORDRED_TPMKEY_STORE", home / "mordred/keyvault/tpm")
        backend = _SecKeyBackend(ops=ops, sw_ops=None, legacy_ops=None)
    else:
        # Preserve the existing MailSecretStore/Telegram hardware helper binding.
        backend = _SecKeyBackend(ops=ops, sw_ops=None, legacy_ops=None)._for_keyvault_root(home / "mordred/keyvault")
    return _MailBackend(backend)
