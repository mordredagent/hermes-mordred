"""Shared software-backend fake for Phase 4 keyvault tests.

A software P-256 keypair store standing in for the Secure Enclave, so
the wrap / AES-KW / AES-GCM paths run with real crypto on any platform
(``enclave_ecdh`` performs a real ECDH; ``denied_reason`` simulates an
authorization-prompt denial).

Mirrors the per-module ``FakeBackend`` in ``test_keyvault_wrap.py`` /
``test_keyvault_log_encryption.py`` — PR10 introduces this shared copy
rather than duplicating it a sixth time for the new CLI tests. The
existing per-module copies are intentionally left untouched;
consolidating them is a separate cleanup.

Not a ``test_*`` module, so pytest does not collect it.
"""

from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from mordred_hermes.keyvault._exceptions import WrapKeyNotFound
from mordred_hermes.keyvault.wrap import NativeBackendError, NativeErrorCode


class FakeBackend:
    """Software P-256 keypair store standing in for the Secure Enclave."""

    def __init__(self) -> None:
        self._keys: dict[str, ec.EllipticCurvePrivateKey] = {}
        self.denied_reason: NativeErrorCode | None = None
        self.calls: list[tuple[str, str]] = []

    def generate_enclave_key(self, key_id: str, *, unattended: bool | None = None) -> bytes:
        self.calls.append(("generate", key_id))
        if key_id in self._keys:
            raise WrapKeyNotFound(f"key {key_id!r} already exists")
        priv = ec.generate_private_key(ec.SECP256R1())
        self._keys[key_id] = priv
        return priv.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)

    def get_enclave_public_key(self, key_id: str) -> bytes:
        self.calls.append(("get_pub", key_id))
        if key_id not in self._keys:
            raise WrapKeyNotFound(f"no key for {key_id!r}")
        return self._keys[key_id].public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)

    def delete_enclave_key(self, key_id: str) -> None:
        self.calls.append(("delete", key_id))
        self._keys.pop(key_id, None)

    def enclave_ecdh(self, key_id: str, peer_pub: bytes) -> bytes:
        self.calls.append(("ecdh", key_id))
        if self.denied_reason is not None:
            raise NativeBackendError(self.denied_reason)
        if key_id not in self._keys:
            raise WrapKeyNotFound(f"no key for {key_id!r}")
        peer = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), peer_pub)
        return self._keys[key_id].exchange(ec.ECDH(), peer)


class FakeAnchorStore:
    """In-memory stand-in for the device-bound Keychain anchor store.

    Models a small non-secret key→value Keychain item that an offline
    attacker can read but not write (the real item is ``ThisDeviceOnly`` +
    ``AfterFirstUnlock``; a powered-off / stolen device cannot mint or edit
    it). Tests drive the vault's freshness pin (``SHA-256(wmk)`` +
    ``generation``) through this without any real Keychain.

    The fake never enforces write-protection — tests need to *set up* and
    *tamper* state freely; the real store's write-control is what the
    threat model actually leans on.
    """

    def __init__(self) -> None:
        self._items: dict[str, bytes] = {}
        self.calls: list[tuple[str, str]] = []

    def read(self, label: str) -> bytes | None:
        self.calls.append(("read", label))
        return self._items.get(label)

    def write(self, label: str, value: bytes) -> None:
        self.calls.append(("write", label))
        self._items[label] = value

    def delete(self, label: str) -> None:
        self.calls.append(("delete", label))
        self._items.pop(label, None)
