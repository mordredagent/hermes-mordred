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
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .wrap import AuditSink, NativeBackend

# Purpose tag used for api.encrypt / api.decrypt calls.  Versioned so a
# future key-format change can introduce "ethereum.key.v2" without
# colliding with envelopes written by this version.
_PURPOSE = "ethereum.key.v1"

# Purpose tag for the SE-encrypted BIP39 seed phrase backing the HD wallet
# (Option A). Distinct from _PURPOSE so a stored seed and a stored random
# key never collide in the keyvault ciphertext tree.
_SEED_PURPOSE = "bip39.seed.v1"

# BIP44 coin type for Ethereum (SLIP-44): m/44'/60'/account'/change/index.
_ETH_COIN_TYPE = 60

# secp256k1 private key is always a 32-byte (256-bit) big-endian scalar.
_SCALAR_BYTES = 32


def _bip44_eth_path(index: int, *, account: int = 0, change: int = 0) -> str:
    """Build the BIP44 Ethereum derivation path for an account index."""
    return f"m/44'/{_ETH_COIN_TYPE}'/{account}'/{change}/{index}"


@dataclass(frozen=True)
class EthereumSignature:
    """ECDSA signature in Ethereum wire format.

    ``v`` follows the legacy Ethereum convention: ``27`` or ``28``
    (recovery id 0 or 1 offset by 27).  Callers implementing EIP-155
    replay protection must adjust ``v`` to ``chain_id * 2 + 35/36``.

    ``r`` and ``s`` are 32-byte big-endian integers.  The concatenated
    65-byte form ``r || s || v`` is available via :attr:`as_bytes`.
    """

    v: int  # 27 or 28
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


def _eth_keys() -> Any:
    """Lazy import of ``eth_keys``, with an actionable error if absent."""
    try:
        import eth_keys

        return eth_keys
    except ImportError as exc:
        raise ImportError(
            'eth-keys is required for Ethereum key operations. Install it with: pip install "mordred-hermes[ethereum]"'
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
        except Exception:
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
        address: str = priv.public_key.to_checksum_address()
        return address
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
        raise ValueError(f"message_hash must be exactly {_SCALAR_BYTES} bytes, got {len(message_hash)}")

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


# ---------------------------------------------------------------------------
# HD wallet (BIP32/BIP44) — Option A: the BIP39 seed is stored SE-encrypted,
# and Ethereum accounts are derived deterministically from it on demand.
# ---------------------------------------------------------------------------


def store_seed_phrase(
    key_id: str,
    mnemonic: str,
    *,
    backend: NativeBackend,
    audit_sink: AuditSink,
    home: Path | None = None,
) -> str:
    """Encrypt a BIP39 mnemonic under the Enclave wrapping key and store it.

    The mnemonic's BIP39 checksum is validated first (any standard length,
    12-24 words — so an imported external wallet seed is accepted), then the
    UTF-8 bytes are encrypted via :func:`~mordred_hermes.keyvault.api.encrypt`
    under purpose ``"bip39.seed.v1"`` (offline wrap, no biometric prompt).

    Returns the ``envelope_id`` to pass to :func:`derive_ethereum_key` /
    :func:`sign_hash_hd`.

    Security note (Option A): the seed now exists at rest as ciphertext. The
    Enclave-wrapped DEK means a stolen ``.gcm`` is useless off this device,
    but a process running as this user (with an unattended wrapping key) can
    decrypt and derive every account — the same threat model the keyvault
    already documents (protects at-rest; does not protect a live-compromised
    host). The paper seed remains the cross-device recovery anchor.
    """
    from . import _bip39, api

    _bip39.validate_mnemonic(mnemonic)
    seed_bytes = mnemonic.encode("utf-8")
    try:
        return api.encrypt(
            key_id,
            seed_bytes,
            _SEED_PURPOSE,
            backend=backend,
            audit_sink=audit_sink,
            home=home,
        )
    finally:
        del seed_bytes


def derive_ethereum_key(
    key_id: str,
    seed_envelope_id: str,
    index: int,
    *,
    backend: NativeBackend,
    audit_sink: AuditSink,
    home: Path | None = None,
    bip39_passphrase: str = "",
    account: int = 0,
    change: int = 0,
) -> tuple[str, str]:
    """Derive a deterministic Ethereum account from the stored seed.

    Decrypts the SE-encrypted seed (triggers Enclave authorization — Touch
    ID / passcode unless the wrapping key is unattended), runs BIP39
    mnemonic→seed then BIP44 ``m/44'/60'/account'/change/index`` derivation,
    and returns ``(checksum_address, path)``. The plaintext seed and the
    derived private scalar live in memory only for the duration of the call.

    ``bip39_passphrase`` is the optional BIP39 "25th word" — independent of
    the keyvault's own Passphrase.
    """
    from . import _bip32, _bip39, api

    eth = _eth_keys()
    seed_bytes = api.decrypt(key_id, seed_envelope_id, _SEED_PURPOSE, backend=backend, audit_sink=audit_sink, home=home)
    priv_bytes: bytes | None = None
    try:
        mnemonic = seed_bytes.decode("utf-8")
        path = _bip44_eth_path(index, account=account, change=change)
        priv_bytes = _bip32.derive_path(_bip39.mnemonic_to_seed(mnemonic, bip39_passphrase), path)
        address: str = eth.keys.PrivateKey(priv_bytes).public_key.to_checksum_address()
        return address, path
    finally:
        del seed_bytes
        if priv_bytes is not None:
            del priv_bytes


def sign_hash_hd(
    key_id: str,
    seed_envelope_id: str,
    index: int,
    message_hash: bytes,
    *,
    backend: NativeBackend,
    audit_sink: AuditSink,
    home: Path | None = None,
    bip39_passphrase: str = "",
    account: int = 0,
    change: int = 0,
) -> EthereumSignature:
    """Sign a 32-byte hash with an HD-derived Ethereum account.

    Decrypts the SE-encrypted seed, derives the private key at
    ``m/44'/60'/account'/change/index``, signs ``message_hash``, then drops
    the key reference. See :func:`sign_hash` for the ``message_hash``
    construction rules (EIP-191 / EIP-712 / raw tx).
    """
    if len(message_hash) != _SCALAR_BYTES:
        raise ValueError(f"message_hash must be exactly {_SCALAR_BYTES} bytes, got {len(message_hash)}")

    from . import _bip32, _bip39, api

    eth = _eth_keys()
    seed_bytes = api.decrypt(key_id, seed_envelope_id, _SEED_PURPOSE, backend=backend, audit_sink=audit_sink, home=home)
    priv_bytes: bytes | None = None
    try:
        mnemonic = seed_bytes.decode("utf-8")
        path = _bip44_eth_path(index, account=account, change=change)
        priv_bytes = _bip32.derive_path(_bip39.mnemonic_to_seed(mnemonic, bip39_passphrase), path)
        sig = eth.keys.PrivateKey(priv_bytes).sign_msg_hash(message_hash)
        return EthereumSignature(
            v=sig.v + 27,
            r=sig.r.to_bytes(_SCALAR_BYTES, "big"),
            s=sig.s.to_bytes(_SCALAR_BYTES, "big"),
        )
    finally:
        del seed_bytes
        if priv_bytes is not None:
            del priv_bytes
