"""mordred_keyvault._bip32 — BIP32 / BIP44 hierarchical key derivation.

Derives secp256k1 private keys along a BIP44 path (``m/44'/60'/0'/0/i``
for Ethereum) from a BIP39 seed. Used by
:func:`mordred_hermes.keyvault.ethereum.derive_ethereum_key` so a single
SE-protected seed yields deterministic, recoverable Ethereum accounts.

Design note — **private-only derivation**. We always hold the parent
*private* key at every step (we start from the master private key and
walk down), so child derivation never needs elliptic-curve point
*addition*: the child scalar is simply ``(IL + k_par) mod n``. The only
public-key operation is serializing the parent's *compressed* public key
for the data input of an unhardened step, which we obtain from
``eth_keys`` (already a hard dependency of the ``ethereum`` extra). This
keeps the module free of any new EC-math dependency.

Vectors are pinned in ``tests/test_keyvault_bip32.py`` against the
Hardhat / Anvil default mnemonic (BIP44 ``m/44'/60'/0'/0/i``).
"""

from __future__ import annotations

import hashlib
import hmac

# secp256k1 group order n. A derived scalar must be in ``[1, n-1]``.
_SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

# BIP32: master generation HMAC key, and the hardened-index offset (2^31).
_MASTER_HMAC_KEY = b"Bitcoin seed"
_HARDENED_OFFSET = 0x80000000

_KEY_LEN = 32


def _eth_keys():  # type: ignore[return]
    """Lazy import of ``eth_keys`` with an actionable error if absent."""
    try:
        import eth_keys  # type: ignore[import-untyped]

        return eth_keys
    except ImportError as exc:
        raise ImportError(
            'eth-keys is required for BIP32 derivation. Install it with: pip install "mordred-hermes[ethereum]"'
        ) from exc


def _compressed_public_key(private_key: bytes) -> bytes:
    """Return the 33-byte SEC1 compressed public key for ``private_key``.

    ``eth_keys`` yields the 64-byte uncompressed point (``X || Y``); BIP32's
    unhardened CKD needs the compressed form ``(0x02|0x03) || X``.
    """
    eth = _eth_keys()
    pub = eth.keys.PrivateKey(private_key).public_key.to_bytes()  # 64 bytes: X || Y
    x, y = pub[:_KEY_LEN], pub[_KEY_LEN:]
    prefix = b"\x02" if (y[-1] & 1) == 0 else b"\x03"
    return prefix + x


def master_key_from_seed(seed: bytes) -> tuple[bytes, bytes]:
    """Derive the BIP32 master ``(private_key, chain_code)`` from a seed.

    ``I = HMAC-SHA512("Bitcoin seed", seed)``; the left 32 bytes are the
    master private key, the right 32 bytes the chain code. A master key of
    0 or >= n is invalid (BIP32 §"Master key generation").
    """
    i = hmac.new(_MASTER_HMAC_KEY, seed, hashlib.sha512).digest()
    il, ir = i[:_KEY_LEN], i[_KEY_LEN:]
    il_int = int.from_bytes(il, "big")
    if il_int == 0 or il_int >= _SECP256K1_N:
        raise ValueError("invalid BIP32 master key (IL out of range) — choose a different seed")
    return il, ir


def ckd_priv(private_key: bytes, chain_code: bytes, index: int) -> tuple[bytes, bytes]:
    """Derive a child ``(private_key, chain_code)`` from a parent (CKDpriv).

    ``index >= 2**31`` is a hardened child (uses ``0x00 || k_par`` as the
    HMAC data); otherwise the data is the parent's compressed public key.
    The child scalar is ``(IL + k_par) mod n`` (BIP32 §"Private parent ->
    private child key").
    """
    if index >= _HARDENED_OFFSET:
        data = b"\x00" + private_key + index.to_bytes(4, "big")
    else:
        data = _compressed_public_key(private_key) + index.to_bytes(4, "big")
    i = hmac.new(chain_code, data, hashlib.sha512).digest()
    il, ir = i[:_KEY_LEN], i[_KEY_LEN:]
    il_int = int.from_bytes(il, "big")
    if il_int >= _SECP256K1_N:
        raise ValueError("invalid BIP32 child key (IL >= n) — retry with the next index")
    child_int = (il_int + int.from_bytes(private_key, "big")) % _SECP256K1_N
    if child_int == 0:
        raise ValueError("invalid BIP32 child key (resulting scalar is 0) — retry with the next index")
    return child_int.to_bytes(_KEY_LEN, "big"), ir


def _parse_index(segment: str) -> int:
    """Parse one path segment ("44'", "60", "0h") into an integer index.

    The child number (before the hardened offset) must fit in 31 bits —
    BIP32 child numbers are a uint32 split into the hardened bit plus a
    31-bit index. Anything negative, non-integer, or ``>= 2**31`` raises
    :class:`ValueError` so a malformed path fails cleanly here rather than
    as an ``OverflowError`` deep inside :func:`ckd_priv`.
    """
    hardened = segment.endswith(("'", "h", "H"))
    raw = segment[:-1] if hardened else segment
    try:
        number = int(raw)
    except ValueError:
        raise ValueError(f"invalid BIP32 path segment: {segment!r}") from None
    if number < 0 or number >= _HARDENED_OFFSET:
        raise ValueError(f"BIP32 child number out of range [0, 2**31): {number}")
    return number + _HARDENED_OFFSET if hardened else number


def derive_path(seed: bytes, path: str) -> bytes:
    """Derive the 32-byte private key at ``path`` from ``seed``.

    ``path`` is a BIP32 string starting at the master, e.g.
    ``"m/44'/60'/0'/0/0"`` (Ethereum account 0). Hardened levels are marked
    with ``'`` (or ``h``/``H``).

    Raises :class:`ValueError` for a path that does not start at the master
    (``m``) or contains a non-integer segment.
    """
    segments = path.split("/")
    if not segments or segments[0] != "m":
        raise ValueError(f"BIP32 path must start at the master 'm/...': {path!r}")
    key, chain = master_key_from_seed(seed)
    for segment in segments[1:]:
        if segment == "":
            raise ValueError(f"empty segment in BIP32 path: {path!r}")
        key, chain = ckd_priv(key, chain, _parse_index(segment))
    return key
