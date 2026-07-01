"""Crypto primitives shared by the Mordred Extension gateway.

Mirrors the extension's ``src/lib/crypto.ts`` exactly so the two sides
interoperate:

- ECDH:  X25519 (raw 32-byte keys).
- KDF:   HKDF-SHA256, ``salt="mordred-extension-v1"``, ``info=<pairing code>``.
- AEAD:  AES-256-GCM, wire format ``🔒ENC:v1:{nonce_b64url}:{ct_b64url}`` where
         ``ct`` is ciphertext concatenated with the 16-byte GCM tag (the same
         layout the WebCrypto ``encrypt`` produces).

All base64url is unpadded, matching the extension.

See ``Mordred-Extension/SPEC.ja.md`` §3.4 / §4.1.
"""

from __future__ import annotations

import base64

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

ENC_PREFIX_V1 = "🔒ENC:v1:"
ENC_PREFIX_V2 = "🔒ENC:v2:"  # 🔒ENC:v2:{keyId}:{nonce}:{ct} (SPEC-v2 §1.2)
ENC_PREFIX = ENC_PREFIX_V1  # backward-compat alias
HKDF_SALT = b"mordred-extension-v1"
_NONCE_SIZE = 12


class DecryptError(Exception):
    """Raised when a ``🔒ENC:v1:`` blob cannot be decrypted/authenticated."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


# --------------------------------------------------------------------------- #
# base64url (unpadded)
# --------------------------------------------------------------------------- #


def b64u_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def b64u_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


# --------------------------------------------------------------------------- #
# Pairing key agreement (§3.4)
# --------------------------------------------------------------------------- #


def x25519_public_raw(priv: X25519PrivateKey) -> bytes:
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    return priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def derive_shared_key(priv: X25519PrivateKey, ext_pubkey_b64: str, code: str) -> bytes:
    """ECDH + HKDF → 32-byte AES key. Identical on both sides of the pairing."""
    ext_pub = X25519PublicKey.from_public_bytes(b64u_decode(ext_pubkey_b64))
    raw_shared = priv.exchange(ext_pub)
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=HKDF_SALT,
        info=code.encode("utf-8"),
    ).derive(raw_shared)


# --------------------------------------------------------------------------- #
# Slack message AEAD (§4.1)
# --------------------------------------------------------------------------- #


def is_encrypted(text: str) -> bool:
    t = text.lstrip()
    return t.startswith(ENC_PREFIX_V1) or t.startswith(ENC_PREFIX_V2)


def key_id(raw_key: bytes) -> str:
    """Short key fingerprint: base64url(SHA-256(key)[0:6]) — 8 chars (SPEC-v2 §1.2)."""
    import hashlib

    return b64u_encode(hashlib.sha256(raw_key).digest()[:6])


def hkdf_subkey(raw_key: bytes, salt: str, info: str) -> bytes:
    """HKDF-SHA256 derive a 32-byte sub-key from a raw key (SPEC-v2 §1.1)."""
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt.encode("utf-8"),
        info=info.encode("utf-8"),
    ).derive(raw_key)


def encrypt_message(aes_key: bytes, plaintext: str, *, nonce: bytes | None = None) -> str:
    """v1 encrypt (legacy single key). New code should prefer encrypt_message_v2."""
    if nonce is None:
        import os

        nonce = os.urandom(_NONCE_SIZE)
    ct = AESGCM(aes_key).encrypt(nonce, plaintext.encode("utf-8"), None)
    return f"{ENC_PREFIX_V1}{b64u_encode(nonce)}:{b64u_encode(ct)}"


def encrypt_message_v2(
    aes_key: bytes, plaintext: str, kid: str, *, nonce: bytes | None = None
) -> str:
    """v2 encrypt with an explicit key fingerprint (SPEC-v2 §1.2)."""
    if nonce is None:
        import os

        nonce = os.urandom(_NONCE_SIZE)
    ct = AESGCM(aes_key).encrypt(nonce, plaintext.encode("utf-8"), None)
    return f"{ENC_PREFIX_V2}{kid}:{b64u_encode(nonce)}:{b64u_encode(ct)}"


def parse_token(formatted: str) -> tuple[int, str | None, bytes, bytes]:
    """Parse a v1/v2 token → (version, key_id|None, nonce, ct). Raises DecryptError."""
    body = formatted.lstrip()
    try:
        if body.startswith(ENC_PREFIX_V2):
            p = body[len(ENC_PREFIX_V2) :].split(":")
            if len(p) != 3:
                raise DecryptError("malformed")
            return 2, p[0], b64u_decode(p[1]), b64u_decode(p[2])
        if body.startswith(ENC_PREFIX_V1):
            p = body[len(ENC_PREFIX_V1) :].split(":")
            if len(p) != 2:
                raise DecryptError("malformed")
            return 1, None, b64u_decode(p[0]), b64u_decode(p[1])
    except DecryptError:
        raise
    except Exception as exc:  # noqa: BLE001 — any decode failure is "malformed"
        raise DecryptError("malformed") from exc
    raise DecryptError("malformed")


def decrypt_message(aes_key: bytes, formatted: str) -> str:
    """Decrypt a v1 or v2 token with the given key (caller selects the key, e.g.
    by key_id from the keyring)."""
    _ver, _kid, nonce, ct = parse_token(formatted)
    try:
        pt = AESGCM(aes_key).decrypt(nonce, ct, None)
    except InvalidTag as exc:
        raise DecryptError("tampered") from exc
    return pt.decode("utf-8")
