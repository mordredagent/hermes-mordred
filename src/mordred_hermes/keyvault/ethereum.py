"""Ethereum secp256k1 key generation, address derivation, and signing.

Extends the keyvault with Ethereum-specific operations:

- :func:`generate_ethereum_key` — generate a secp256k1 private key, store it
  encrypted in the keyvault via :func:`~mordred_hermes.keyvault.api.encrypt`,
  and return the ``(envelope_id, checksum_address)`` pair.
- :func:`get_ethereum_address` — derive the EIP-55 checksum address from a
  stored key (requires Enclave authorization to decrypt).
- :func:`sign_hash` — sign a 32-byte Ethereum message hash (requires Enclave
  authorization to decrypt). Compatible with EIP-191, EIP-712, and raw
  transaction hashes.

The raw 32-byte private key scalar is the only secret stored on disk;
it lives inside an AES-GCM MREN envelope under purpose
``"ethereum.key.v1"``. The plaintext key exists in process memory only
for the duration of the decrypt + sign operation, then the local
reference is dropped immediately (CPython GC-eligible within the
current frame).

Requires the ``ethereum`` optional-dependency extra::

    pip install "mordred-hermes[ethereum]"

which pulls in ``eth-keys`` (secp256k1 / EIP-55 / signing) and
``eth-hash[pycryptodome]`` (keccak-256 backend).
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .wrap import AuditSink, NativeBackend

# Purpose tag used for api.encrypt / api.decrypt calls.  Versioned so a
# future key-format change can introduce "ethereum.key.v2" without
# colliding with envelopes written by this version.
_PURPOSE = "ethereum.key.v1"

# secp256k1 private key is always a 32-byte (256-bit) big-endian scalar.
_SCALAR_BYTES = 32


@dataclass(frozen=True)
class EthereumSignature:
    """ECDSA signature in Ethereum wire format.

    ``v`` follows the legacy Ethereum convention: ``27`` or ``28``
    (recovery id 0 or 1 offset by 27).  Callers implementing EIP-155
    replay protection must adjust ``v`` to ``chain_id * 2 + 35/36``.

    ``r`` and ``s`` are 32-byte big-endian integers.  The concatenated
    65-byte form ``r || s || v`` is available via :attr:`as_bytes`.
    """

    v: int    # 27 or 28
    r: bytes  # 32 bytes, big-endian
    s: bytes  # 32 bytes, big-endian

    @property
    def as_bytes(self) -> bytes:
        """65-byte ``r || s || v`` representation."""
        return self.r + self.s + bytes([self.v])

    @property
    def hex(self) -> str:
        """65-byte ``r || s || v`` as a lowercase hex string (no 0x prefix)."""
        return self.as_bytes.hex()


def _eth_keys():  # type: ignore[return]
    """Lazy import of ``eth_keys``, with an actionable error if absent."""
    try:
        import eth_keys  # type: ignore[import-untyped]

        return eth_keys
    except ImportError as exc:
        raise ImportError(
            "eth-keys is required for Ethereum key operations. "
            'Install it with: pip install "mordred-hermes[ethereum]"'
        ) from exc


def generate_ethereum_key(
    key_id: str,
    *,
    backend: NativeBackend,
    audit_sink: AuditSink,
    home: Path | None = None,
) -> tuple[str, str]:
    """Generate a secp256k1 Ethereum private key and store it in the keyvault.

    The private key is drawn from ``os.urandom(32)``. The raw 32 bytes are
    encrypted via :func:`~mordred_hermes.keyvault.api.encrypt` (no
    biometric prompt at write time — the wrap step is offline).

    Args:
        key_id: Keyvault key identifier (e.g. ``"default"``).
        backend: :class:`~mordred_hermes.keyvault.wrap.NativeBackend`
            instance.
        audit_sink: Audit-entry callback (receives ``keyvault.*`` dicts).
        home: Override for the Hermes home directory; ``None`` uses the
            platform default.

    Returns:
        ``(envelope_id, address)`` where ``envelope_id`` is the opaque
        handle for future :func:`get_ethereum_address` / :func:`sign_hash`
        calls, and ``address`` is the EIP-55 checksum address
        (``"0x..."``).
    """
    from . import api

    eth = _eth_keys()

    # os.urandom(32) has negligible probability (~2^-127) of landing on
    # an invalid scalar (0 or curve order).  eth_keys.keys.PrivateKey
    # raises ValidationError on those two values; the loop exits in one
    # iteration in the overwhelming majority of cases.
    while True:
        try:
            priv = eth.keys.PrivateKey(os.urandom(_SCALAR_BYTES))
            break
        except Exception:  # noqa: BLE001
            continue

    priv_bytes: bytes = priv.to_bytes()
    try:
        envelope_id = api.encrypt(
            key_id,
            priv_bytes,
            _PURPOSE,
            backend=backend,
            audit_sink=audit_sink,
            home=home,
        )
        address: str = priv.public_key.to_checksum_address()
    finally:
        del priv_bytes
    return envelope_id, address


def get_ethereum_address(
    key_id: str,
    envelope_id: str,
    *,
    backend: NativeBackend,
    audit_sink: AuditSink,
    home: Path | None = None,
) -> str:
    """Return the EIP-55 checksum address for a stored Ethereum key.

    Decrypts the stored private key scalar (triggers Enclave authorization
    on macOS — Touch ID / passcode prompt), derives the address, then
    drops the key reference immediately.

    Args:
        key_id: Keyvault key identifier matching the one used at
            :func:`generate_ethereum_key` time.
        envelope_id: Opaque handle returned by :func:`generate_ethereum_key`.
        backend: :class:`~mordred_hermes.keyvault.wrap.NativeBackend`.
        audit_sink: Audit-entry callback.
        home: Override for the Hermes home directory.

    Returns:
        EIP-55 checksum address string (``"0x..."``).
    """
    from . import api

    eth = _eth_keys()
    priv_bytes = api.decrypt(
        key_id,
        envelope_id,
        _PURPOSE,
        backend=backend,
        audit_sink=audit_sink,
        home=home,
    )
    try:
        priv = eth.keys.PrivateKey(priv_bytes)
        return priv.public_key.to_checksum_address()
    finally:
        # Drop the last strong reference so CPython can reclaim the bytes
        # within the current frame.  bytes is immutable in CPython, so
        # in-place zeroing is not possible; shortening the reference
        # lifetime is the best available mitigation.
        del priv_bytes


def sign_hash(
    key_id: str,
    envelope_id: str,
    message_hash: bytes,
    *,
    backend: NativeBackend,
    audit_sink: AuditSink,
    home: Path | None = None,
) -> EthereumSignature:
    """Sign a 32-byte Ethereum message hash with a stored secp256k1 key.

    Decrypts the stored private key scalar (triggers Enclave authorization
    on macOS), signs ``message_hash``, then drops the key reference
    immediately.

    Callers are responsible for constructing ``message_hash`` correctly:

    - **EIP-191 personal sign**: ``keccak256("\\x19Ethereum Signed Message:\\n32" + hash)``
    - **EIP-712 typed data**: ``keccak256("\\x19\\x01" + domain_sep + struct_hash)``
    - **Raw transaction**: the 32-byte transaction hash from ``rlp.encode(tx)``

    Args:
        key_id: Keyvault key identifier.
        envelope_id: Opaque handle from :func:`generate_ethereum_key`.
        message_hash: Exactly 32 bytes to sign.
        backend: :class:`~mordred_hermes.keyvault.wrap.NativeBackend`.
        audit_sink: Audit-entry callback.
        home: Override for the Hermes home directory.

    Returns:
        :class:`EthereumSignature` with ``v`` (27 or 28), ``r`` (32 bytes),
        ``s`` (32 bytes).

    Raises:
        ValueError: ``message_hash`` is not exactly 32 bytes.
    """
    if len(message_hash) != _SCALAR_BYTES:
        raise ValueError(
            f"message_hash must be exactly {_SCALAR_BYTES} bytes, got {len(message_hash)}"
        )

    from . import api

    eth = _eth_keys()
    priv_bytes = api.decrypt(
        key_id,
        envelope_id,
        _PURPOSE,
        backend=backend,
        audit_sink=audit_sink,
        home=home,
    )
    try:
        priv = eth.keys.PrivateKey(priv_bytes)
        sig = priv.sign_msg_hash(message_hash)
        # eth_keys returns v as 0 or 1 (recovery id).  Ethereum legacy
        # format uses 27 or 28 (recovery id + 27).
        return EthereumSignature(
            v=sig.v + 27,
            r=sig.r.to_bytes(_SCALAR_BYTES, "big"),
            s=sig.s.to_bytes(_SCALAR_BYTES, "big"),
        )
    finally:
        del priv_bytes
