"""The database key, derived from the key Mordred already manages.

No new key is created or stored. The root agent-memory key, freshly loaded
from native custody for each runtime, is stretched with HKDF into a separate
SQLCipher key, so the two uses never share a value:

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
from pathlib import Path
from typing import TYPE_CHECKING, Final

if TYPE_CHECKING:
    from ._authority import Authority

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
    """Bind production keys to root-native authority, preserving explicit seams.

    Explicit ``environ`` or ``inject`` arguments retain the portable provider
    used by existing offline callers. The default path never uses ambient key
    material or environment injection.
    """

    def __init__(
        self,
        environ: MutableMapping[str, str] | None = None,
        inject: Callable[[], int] | None = None,
        *,
        home: Path | None = None,
    ) -> None:
        if home is not None and (environ is not None or inject is not None):
            raise ValueError("native root binding cannot use an injected provider")
        self._native = environ is None and inject is None
        self._home = home
        self._authority: Authority | None = None
        self._lock = threading.RLock()
        self._pid = os.getpid()
        self._closed = False
        self._environ = os.environ if environ is None else environ
        self._inject = _inject_vault_env if inject is None else inject
        self._cached: DatabaseKey | None = None
        self._injected = False

    @property
    def runtime_native(self) -> bool:
        """Whether this provider requires runtime-native integration by its caller."""
        return self._native

    def __call__(self) -> DatabaseKey | None:
        if self._native:
            from .._database_contracts import DatabaseRefused
            from .._home import hermes_home
            from ._authority import Authority

            if self._pid != os.getpid():
                self._lock = threading.RLock()
                self.close()
                raise DatabaseRefused("database key provider cannot survive fork")
            with self._lock:
                if self._closed:
                    raise DatabaseRefused("database key provider is closed")
                if self._authority is None:
                    self._authority = Authority.acquire(self._home if self._home is not None else hermes_home())
                return self._authority.key
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

    def close(self) -> None:
        """Release a native runtime and refuse its reuse."""
        if self._pid != os.getpid():
            self._lock = threading.RLock()
        with self._lock:
            self._closed = True
            self._cached = None
            if self._authority is not None:
                self._authority.close()
