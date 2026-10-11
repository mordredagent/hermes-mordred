"""The database key, derived from the key Mordred already manages.

No new key is created or stored. Hermes's agent-memory key
(``HERMES_MEMORY_KEY``, sealed in the vault and injected into every Hermes
process) is stretched with HKDF into a separate SQLCipher key, so the two uses
never share a value:

    key  = HKDF-SHA256(memory key, info="mordred sqlite v1")
    salt = HMAC-SHA256(key, "mordred sqlite salt v1")[:16]

The salt must be given explicitly because the file header is kept in
plaintext (see :mod:`._shim`); it is the same for every database so that
copies and renames Hermes makes (backups, quarantines) stay readable.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import threading
from collections.abc import Callable, MutableMapping
from dataclasses import dataclass
from typing import Final

_INFO: Final = b"mordred sqlite v1"
_SALT_LABEL: Final = b"mordred sqlite salt v1"
_LOCK: Final = threading.Lock()


@dataclass(frozen=True)
class DatabaseKey:
    key: bytes
    salt: bytes

    def __repr__(self) -> str:  # never print key material
        return "DatabaseKey(<redacted>)"


def derive(memory_key: bytes) -> DatabaseKey:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF

    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=_INFO).derive(memory_key)
    return DatabaseKey(key=key, salt=hmac.new(key, _SALT_LABEL, hashlib.sha256).digest()[:16])


def _memory_key(environ: MutableMapping[str, str]) -> bytes | None:
    from ..keyvault._memory_hook import _decode_env_key

    return _decode_env_key(environ)


def _inject_vault_env() -> int:
    from ..keyvault._runtime_env import install_vault_env_decrypt

    return install_vault_env_decrypt()


class KeyProvider:
    """Resolve the key once per process, on the first database that needs it.

    If ``HERMES_MEMORY_KEY`` is not in the environment yet (the plugin that
    injects it has not run), the vault-sealed ``.env`` is injected now — the
    same unlock the plugin would do, done once (it skips a second injection).
    """

    def __init__(
        self,
        environ: MutableMapping[str, str] | None = None,
        inject: Callable[[], int] = _inject_vault_env,
    ) -> None:
        self._environ = os.environ if environ is None else environ
        self._inject = inject
        self._cached: DatabaseKey | None = None
        self._injected = False

    def __call__(self) -> DatabaseKey | None:
        if self._cached is not None:
            return self._cached
        with _LOCK:
            if self._cached is None:
                memory_key = _memory_key(self._environ)
                if memory_key is None and not self._injected:
                    self._injected = True
                    self._inject()
                    memory_key = _memory_key(self._environ)
                if memory_key is not None:
                    self._cached = derive(memory_key)
        return self._cached
