"""Crypto primitives shared by the Mordred Extension gateway.

Mirrors the extension's ``src/lib/crypto.ts`` exactly so the two sides
interoperate:

- ECDH:  X25519 (raw 32-byte keys).
- KDF:   HKDF-SHA256, ``salt="mordred-extension-v1"``, ``info=<pairing code>``.
- AEAD: AES-256-GCM. Legacy v1/v2 helpers remain for stored/history
  compatibility. Gateway commands and replies use context-bound v3.

All base64url is unpadded, matching the extension.

See ``Mordred-Extension/SPEC.ja.md`` §3.4 / §4.1.
"""

from __future__ import annotations

import base64
import os
import secrets

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
ENC_PREFIX_V3 = "🔒ENC:v3:"
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
    return t.startswith((ENC_PREFIX_V1, ENC_PREFIX_V2, ENC_PREFIX_V3))


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
        nonce = os.urandom(_NONCE_SIZE)
    ct = AESGCM(aes_key).encrypt(nonce, plaintext.encode("utf-8"), None)
    return f"{ENC_PREFIX_V1}{b64u_encode(nonce)}:{b64u_encode(ct)}"


def encrypt_message_v2(aes_key: bytes, plaintext: str, kid: str, *, nonce: bytes | None = None) -> str:
    """v2 encrypt with an explicit key fingerprint (SPEC-v2 §1.2)."""
    if nonce is None:
        nonce = os.urandom(_NONCE_SIZE)
    ct = AESGCM(aes_key).encrypt(nonce, plaintext.encode("utf-8"), None)
    return f"{ENC_PREFIX_V2}{kid}:{b64u_encode(nonce)}:{b64u_encode(ct)}"


def _v3_aad(
    *,
    direction: str,
    platform: str,
    chat_id: str,
    thread_root: str | None,
    message_id: str,
    sequence: int,
    total: int,
) -> bytes:
    """Canonical, ambiguity-free AAD for an E2E v3 platform message.

    Each UTF-8 field is prefixed with an unsigned four-byte big-endian length.
    The sequence/count pair is encoded as fixed-width unsigned integers. This
    format is straightforward to reproduce with WebCrypto and avoids delimiter
    ambiguity in platform identifiers.
    """
    if direction not in {"command", "reply"}:
        raise ValueError("invalid v3 direction")
    if not platform or not chat_id:
        raise ValueError("v3 platform and chat_id are required")
    if isinstance(sequence, bool) or isinstance(total, bool) or not (0 <= sequence < total <= 65535):
        raise ValueError("invalid v3 sequence")

    fields = (
        b"mordred-e2e-v3",
        direction.encode("utf-8"),
        platform.lower().encode("utf-8"),
        chat_id.encode("utf-8"),
        (thread_root or "").encode("utf-8"),
        message_id.encode("ascii"),
    )
    encoded = bytearray()
    for field in fields:
        encoded.extend(len(field).to_bytes(4, "big"))
        encoded.extend(field)
    encoded.extend(sequence.to_bytes(2, "big"))
    encoded.extend(total.to_bytes(2, "big"))
    return bytes(encoded)


def _validate_v3_message_id(message_id: str) -> None:
    try:
        raw = b64u_decode(message_id)
    except Exception as exc:
        raise ValueError("invalid v3 message_id") from exc
    if len(raw) != 16 or b64u_encode(raw) != message_id:
        raise ValueError("invalid v3 message_id")


def encrypt_message_v3(
    aes_key: bytes,
    plaintext: str,
    kid: str,
    *,
    direction: str,
    platform: str,
    chat_id: str,
    thread_root: str | None,
    message_id: str | None = None,
    sequence: int = 0,
    total: int = 1,
    nonce: bytes | None = None,
) -> str:
    """Encrypt one context-bound v3 command/reply token.

    ``message_id`` is an authenticated protocol identifier generated before
    the platform assigns its own message ID. Gateway policy currently requires
    one token per platform message (``sequence=0,total=1``), while retaining
    the fields in the wire/AAD for an explicit future assembly protocol.
    """
    if len(kid) != 8 or b64u_encode(b64u_decode(kid)) != kid:
        raise ValueError("invalid v3 key id")
    if message_id is None:
        message_id = b64u_encode(secrets.token_bytes(16))
    _validate_v3_message_id(message_id)
    if nonce is None:
        nonce = os.urandom(_NONCE_SIZE)
    if len(nonce) != _NONCE_SIZE:
        raise ValueError("invalid v3 nonce")
    aad = _v3_aad(
        direction=direction,
        platform=platform,
        chat_id=chat_id,
        thread_root=thread_root,
        message_id=message_id,
        sequence=sequence,
        total=total,
    )
    ct = AESGCM(aes_key).encrypt(nonce, plaintext.encode("utf-8"), aad)
    return f"{ENC_PREFIX_V3}{kid}:{message_id}:{sequence}:{total}:{b64u_encode(nonce)}:{b64u_encode(ct)}"


def parse_token_v3(formatted: str) -> tuple[str, str, int, int, bytes, bytes]:
    """Parse a normalized v3 token without authenticating it."""
    body = formatted.lstrip()
    if not body.startswith(ENC_PREFIX_V3):
        raise DecryptError("malformed")
    parts = body[len(ENC_PREFIX_V3) :].split(":")
    if len(parts) != 6:
        raise DecryptError("malformed")
    kid, message_id, sequence_raw, total_raw, nonce_raw, ciphertext_raw = parts
    try:
        if not sequence_raw.isascii() or not sequence_raw.isdecimal():
            raise ValueError
        if not total_raw.isascii() or not total_raw.isdecimal():
            raise ValueError
        sequence = int(sequence_raw)
        total = int(total_raw)
        _validate_v3_message_id(message_id)
        nonce = b64u_decode(nonce_raw)
        ciphertext = b64u_decode(ciphertext_raw)
    except (ValueError, TypeError) as exc:
        raise DecryptError("malformed") from exc
    if len(kid) != 8 or b64u_encode(b64u_decode(kid)) != kid:
        raise DecryptError("malformed")
    if not (0 <= sequence < total <= 65535):
        raise DecryptError("malformed")
    return kid, message_id, sequence, total, nonce, ciphertext


def decrypt_message_v3(
    aes_key: bytes,
    formatted: str,
    *,
    direction: str,
    platform: str,
    chat_id: str,
    thread_root: str | None,
) -> str:
    """Authenticate and decrypt one context-bound v3 token."""
    kid, message_id, sequence, total, nonce, ciphertext = parse_token_v3(formatted)
    del kid
    aad = _v3_aad(
        direction=direction,
        platform=platform,
        chat_id=chat_id,
        thread_root=thread_root,
        message_id=message_id,
        sequence=sequence,
        total=total,
    )
    try:
        plaintext = AESGCM(aes_key).decrypt(nonce, ciphertext, aad)
    except InvalidTag as exc:
        raise DecryptError("tampered") from exc
    try:
        return plaintext.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise DecryptError("malformed") from exc


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
    except Exception as exc:
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
