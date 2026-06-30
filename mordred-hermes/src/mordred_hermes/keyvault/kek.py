"""KEK (key-encryption-key) master-key helper.

Efficient envelope crypto on top of the Secure-Enclave wrapping key. The
problem with calling :func:`mordred_hermes.keyvault.api.encrypt` /
:func:`~mordred_hermes.keyvault.api.decrypt` per item is that every
*decrypt* performs a Secure-Enclave ECDH (the authorization boundary) —
a subprocess round-trip to the signed helper. For many items, or for data
that must be read frequently (``.env`` values, ``config.yaml``, agent
memory), that is wasteful.

The KEK pattern collapses it to a single Enclave operation per session:

1. :func:`seal_master_key` generates one random 32-byte master key and
   wraps it under the Enclave wrapping key (offline, no prompt). Persist
   the returned opaque blob anywhere — e.g. base64 in ``.env``. It is
   useless on any other machine (only this device's Enclave can unwrap
   it), so it is safe at rest.
2. :func:`open_master_key` unwraps it **once** through the Enclave (this
   is the only authorization point; with an unattended wrapping key it
   runs prompt-free) and returns a :class:`MasterKey`.
3. :meth:`MasterKey.encrypt` / :meth:`MasterKey.decrypt` then run pure
   software AES-GCM at memory speed — no further Enclave calls.

Security boundary: the master key lives in process RAM after
:func:`open_master_key`. The Enclave protects it *at rest on disk* and
*binds it to this device*; it does not protect against code already
running inside this process. That is the standard KEK/DEK tradeoff for
bulk performance — for per-operation user authorization use
``api.encrypt`` / ``api.decrypt`` instead.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from types import TracebackType

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from . import crypto, wrap
from .wrap import DEK_LEN, AuditSink, NativeBackend


def _noop_audit(_entry: dict[str, object]) -> None:
    """Default audit sink — discards entries when the caller passes none."""


def seal_master_key(key_id: str, *, backend: NativeBackend) -> bytes:
    """Generate a fresh master key and wrap it under ``key_id``.

    Returns the opaque wrapped blob to persist (e.g. base64 in ``.env``).
    Offline — uses only the Enclave public key, so it never prompts and
    emits no audit entry. Each call produces a new master key and a new
    blob. Raises :class:`~mordred_hermes.keyvault._exceptions.WrapKeyNotFound`
    if no wrapping key exists for ``key_id``.
    """
    master = secrets.token_bytes(DEK_LEN)
    try:
        return wrap.wrap_dek(master, key_id, backend=backend)
    finally:
        del master


def open_master_key(
    wrapped: bytes,
    key_id: str,
    *,
    backend: NativeBackend,
    audit_sink: AuditSink | None = None,
) -> MasterKey:
    """Unwrap ``wrapped`` through the Enclave and return a :class:`MasterKey`.

    This is the single authorization boundary: it calls ``enclave_ecdh``,
    which on macOS may prompt for Touch ID / passcode (an unattended
    wrapping key runs prompt-free). On success the wrapping layer emits a
    ``keyvault.unwrap_authorized`` audit entry to ``audit_sink``; when no
    sink is given the entry is discarded.

    Raises the same exceptions as
    :func:`mordred_hermes.keyvault.wrap.unwrap_dek` (e.g. ``WrapKeyNotFound``,
    ``WrapAuthCancelled``, ``WrapIntegrityError``).
    """
    sink = audit_sink if audit_sink is not None else _noop_audit
    master = wrap.unwrap_dek(wrapped, key_id, audit_sink=sink, backend=backend)
    return MasterKey(master)


class MasterKey:
    """An in-memory master key for software AES-GCM bulk crypto.

    Obtain one from :func:`open_master_key`. Holds the key in a mutable
    buffer so :meth:`close` can best-effort zero it; after close the
    instance refuses further use. Usable as a context manager.
    """

    __slots__ = ("_closed", "_key")

    def __init__(self, key: bytes) -> None:
        self._key = bytearray(key)
        self._closed = False

    def _key_bytes(self) -> bytes:
        if self._closed:
            raise ValueError("master key is closed")
        return bytes(self._key)

    def encrypt(self, plaintext: bytes, *, aad: bytes = b"") -> bytes:
        """AES-GCM encrypt ``plaintext``; returns ``nonce || ct || tag``."""
        return crypto.encrypt(self._key_bytes(), plaintext, aad=aad)

    def decrypt(self, blob: bytes, *, aad: bytes = b"") -> bytes:
        """AES-GCM decrypt a :meth:`encrypt` blob. Raises ``InvalidTag`` on
        tamper or ``aad`` mismatch."""
        return crypto.decrypt(self._key_bytes(), blob, aad=aad)

    def mac(self, data: bytes, *, info: bytes) -> bytes:
        """HMAC-SHA256 over ``data`` under a subkey derived from this master.

        For authenticating non-secret-but-integrity-critical state that must be
        bound to the master without being encrypted — e.g. the vault manifest
        (enrolled-file set + per-file ciphertext digests), whose contents must
        be readable to bootstrap the master but tamper-evident once it is open.

        ``info`` domain-separates independent MAC purposes: the subkey is
        ``HKDF-SHA256(master, info=info)``, so the same master yields unrelated
        tags for different ``info`` labels. Returns a 32-byte tag. Raises
        :class:`ValueError` if the master is closed. Compare with
        :func:`hmac.compare_digest` to verify.
        """
        subkey = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=info).derive(self._key_bytes())
        return hmac.new(subkey, data, hashlib.sha256).digest()

    def close(self) -> None:
        """Best-effort zero the key buffer and block further use. Idempotent.

        Python cannot guarantee secret erasure (interpreter copies may
        remain), but zeroing the primary buffer shrinks the exposure
        window versus leaving it for the GC.
        """
        if not self._closed:
            for i in range(len(self._key)):
                self._key[i] = 0
            self._closed = True

    def __enter__(self) -> MasterKey:
        return self

    def __exit__(
        self,
        _exc_type: type[BaseException] | None,
        _exc: BaseException | None,
        _tb: TracebackType | None,
    ) -> None:
        self.close()
