"""MREN envelope codec — the byte-layout half of the keyvault API.

Pure wire-format encode/decode for the ``MREN`` envelope, split out of
:mod:`mordred_hermes.keyvault.api` so the orchestration layer (``encrypt`` /
``decrypt`` / ``export_backup`` / ``import_backup`` + managed storage) and the
wire format are independently readable and testable. api.py re-imports these
symbols, so ``api._encode_envelope`` etc. remain valid.

No filesystem, storage, or :class:`NativeBackend` dependency — every function
here is a pure transform over ``bytes``. Wire format is frozen in SPEC.md
§"PR4 API contract / MREN envelope".
"""

from __future__ import annotations

import hashlib
import hmac
import secrets

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from ._exceptions import WrapParseError

# ----------------------------- MREN envelope constants -----------------------------
# Wire format frozen in SPEC.md §"PR4 API contract / MREN envelope".

_ENVELOPE_MAGIC = b"MREN"
_ENVELOPE_VERSION = 1
_KEY_ID_HASH_LEN = 16
_PURPOSE_HASH_LEN = 16
_WRAPPED_DEK_LEN = 127  # PR3 MRKW blob, SPEC §"Wrap wire format & algorithm"
_AES_BLOB_LEN_FIELD_LEN = 4
_ENVELOPE_AAD_LEN = 4 + 1 + _KEY_ID_HASH_LEN + _PURPOSE_HASH_LEN + _WRAPPED_DEK_LEN  # 164
_ENVELOPE_HEADER_LEN = _ENVELOPE_AAD_LEN + _AES_BLOB_LEN_FIELD_LEN  # 168
_AES_NONCE_LEN = 12
_AES_TAG_LEN = 16


def _hash_id(value: str) -> bytes:
    """Return the first 16 bytes of ``sha256(value.encode("utf-8"))``.

    Used for both ``key_id_hash`` and ``purpose_hash`` (same algorithm
    and width).
    """
    return hashlib.sha256(value.encode("utf-8")).digest()[:_KEY_ID_HASH_LEN]


def _encode_envelope_from_hashes(
    dek: bytes,
    plaintext: bytes,
    key_id_hash: bytes,
    purpose_hash: bytes,
    wrapped_dek_blob: bytes,
) -> bytes:
    """Build an MREN envelope from the pre-hashed key_id / purpose.

    Layout (SPEC.md §"PR4 API contract / MREN envelope"):

        magic(4) || version(1) || key_id_hash(16) || purpose_hash(16) ||
        wrapped_dek(127) || aes_blob_len(4 BE) ||
        aes_blob = nonce(12) || ciphertext(N) || tag(16)

    AAD = the first 164 bytes; AES-GCM tag therefore covers every field
    except ``aes_blob`` itself.

    The hash-input form (rather than cleartext ``key_id`` / ``purpose``)
    exists because :func:`import_backup` reconstructs envelopes from a
    manifest that only carries ``purpose_hash`` — the cleartext purpose is
    unrecoverable from a stored envelope. :func:`_encode_envelope` is the
    cleartext-input wrapper used by :func:`encrypt`.
    """
    if len(wrapped_dek_blob) != _WRAPPED_DEK_LEN:
        raise ValueError(f"wrapped_dek must be exactly {_WRAPPED_DEK_LEN} bytes")
    aad = _ENVELOPE_MAGIC + bytes([_ENVELOPE_VERSION]) + key_id_hash + purpose_hash + wrapped_dek_blob
    # Use ``if/raise`` rather than ``assert`` so the check is not stripped
    # under ``python -O`` / ``PYTHONOPTIMIZE=1`` (in-tree code-reviewer MEDIUM).
    if len(aad) != _ENVELOPE_AAD_LEN:
        raise AssertionError(f"internal error: assembled AAD is {len(aad)} bytes, expected {_ENVELOPE_AAD_LEN}")
    nonce = secrets.token_bytes(_AES_NONCE_LEN)
    ct_tag = AESGCM(dek).encrypt(nonce, plaintext, aad)
    aes_blob = nonce + ct_tag
    return aad + len(aes_blob).to_bytes(_AES_BLOB_LEN_FIELD_LEN, "big") + aes_blob


def _encode_envelope(
    dek: bytes,
    plaintext: bytes,
    key_id: str,
    purpose: str,
    wrapped_dek_blob: bytes,
) -> bytes:
    """Build an MREN envelope (AAD-bound AES-GCM) from a pre-wrapped DEK.

    Thin wrapper over :func:`_encode_envelope_from_hashes` that hashes the
    cleartext ``key_id`` / ``purpose`` first.
    """
    return _encode_envelope_from_hashes(dek, plaintext, _hash_id(key_id), _hash_id(purpose), wrapped_dek_blob)


def _split_envelope(blob: bytes, expected_key_id_hash: bytes) -> tuple[bytes, bytes, bytes, bytes]:
    """Structurally validate an MREN envelope and return its fields.

    Returns ``(aad, purpose_hash, wrapped_dek_blob, aes_blob)``. Validates
    length, magic, version, the ``key_id_hash`` match, and the
    ``aes_blob_len`` framing; does NOT check ``purpose_hash`` because
    :func:`export_backup` reads the purpose straight off the envelope (the
    cleartext ``purpose`` is unrecoverable from a stored envelope) and
    :func:`_parse_envelope` layers the purpose check on top.

    The ``key_id_hash`` compare uses :func:`hmac.compare_digest`.
    """
    if len(blob) < _ENVELOPE_HEADER_LEN:
        raise WrapParseError(f"envelope too short: {len(blob)} bytes, expected at least {_ENVELOPE_HEADER_LEN}")
    if blob[0:4] != _ENVELOPE_MAGIC:
        raise WrapParseError(f"envelope magic mismatch: {blob[0:4]!r}")
    if blob[4] != _ENVELOPE_VERSION:
        raise WrapParseError(f"envelope version mismatch: {blob[4]}")

    if not hmac.compare_digest(blob[5 : 5 + _KEY_ID_HASH_LEN], expected_key_id_hash):
        raise WrapParseError("envelope key_id_hash does not match expected key_id")

    purpose_offset = 5 + _KEY_ID_HASH_LEN
    purpose_hash = blob[purpose_offset : purpose_offset + _PURPOSE_HASH_LEN]
    wrapped_dek_start = purpose_offset + _PURPOSE_HASH_LEN
    wrapped_dek_blob = blob[wrapped_dek_start : wrapped_dek_start + _WRAPPED_DEK_LEN]
    aes_blob_len_offset = wrapped_dek_start + _WRAPPED_DEK_LEN  # = 164
    declared_len = int.from_bytes(blob[aes_blob_len_offset : aes_blob_len_offset + _AES_BLOB_LEN_FIELD_LEN], "big")
    if len(blob) != _ENVELOPE_HEADER_LEN + declared_len:
        raise WrapParseError(
            f"envelope aes_blob_len mismatch: header says {declared_len}, actual {len(blob) - _ENVELOPE_HEADER_LEN}"
        )
    # codex second-pass P2-A: aes_blob must hold at least one AES-GCM nonce
    # plus the 16-byte tag. Anything shorter is structurally invalid; reject
    # BEFORE unwrap_dek so a truncated envelope cannot spend a biometric
    # prompt and emit keyvault.unwrap_authorized only to fail at AES-GCM.
    if declared_len < _AES_NONCE_LEN + _AES_TAG_LEN:
        raise WrapParseError(
            f"envelope aes_blob too short: {declared_len} bytes, "
            f"need at least {_AES_NONCE_LEN + _AES_TAG_LEN} (nonce + tag)"
        )
    aad = blob[:_ENVELOPE_AAD_LEN]
    aes_blob = blob[_ENVELOPE_HEADER_LEN:]
    return aad, purpose_hash, wrapped_dek_blob, aes_blob


def _parse_envelope(
    blob: bytes,
    expected_key_id: str,
    expected_purpose: str,
) -> tuple[bytes, bytes, bytes]:
    """Validate the MREN header and return ``(aad, wrapped_dek_blob, aes_blob)``.

    Raises :exc:`mordred_hermes.keyvault._exceptions.WrapParseError` on any
    structural mismatch, magic/version disagreement, key_id_hash mismatch,
    or purpose_hash mismatch. The purpose_hash compare uses
    :func:`hmac.compare_digest` so cross-purpose attempts cannot be
    distinguished by timing (the wrap layer is then never reached, so the
    user is not prompted — codex HIGH #2).
    """
    aad, purpose_hash, wrapped_dek_blob, aes_blob = _split_envelope(blob, _hash_id(expected_key_id))
    if not hmac.compare_digest(purpose_hash, _hash_id(expected_purpose)):
        raise WrapParseError("envelope purpose_hash does not match expected purpose")
    return aad, wrapped_dek_blob, aes_blob
