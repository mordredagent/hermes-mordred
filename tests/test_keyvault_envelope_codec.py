"""Unit tests for the extracted MREN envelope codec (``_envelope_codec``).

These pin the wire-format constants and the pure encode → split → parse
round-trip in isolation from the api.py orchestration layer
(``encrypt`` / ``decrypt`` / ``export_backup``). The codec is the
byte-layout half of the keyvault API; api.py keeps the storage / id /
validation orchestration and re-imports these symbols.

Wire format is frozen in SPEC.md §"PR4 API contract / MREN envelope".
"""

from __future__ import annotations

import hashlib

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from mordred_hermes.keyvault import _envelope_codec as codec
from mordred_hermes.keyvault._exceptions import WrapParseError


def _opaque_wrapped_dek() -> bytes:
    """A 127-byte blob the codec carries verbatim (it never unwraps it)."""
    return bytes(codec._WRAPPED_DEK_LEN)


class TestEncodeSplitParseRoundTrip:
    def test_encode_then_split_returns_aad_bound_fields(self) -> None:
        dek = bytes(32)
        plaintext = b"hello mordred"
        key_id, purpose = "kid", "secret"

        blob = codec._encode_envelope(dek, plaintext, key_id, purpose, _opaque_wrapped_dek())
        aad, purpose_hash, wrapped, aes_blob = codec._split_envelope(
            blob, hashlib.sha256(key_id.encode()).digest()[:16]
        )

        assert purpose_hash == hashlib.sha256(purpose.encode()).digest()[:16]
        assert wrapped == _opaque_wrapped_dek()
        # AAD-bound AES-GCM: the same dek + aad must recover the plaintext.
        nonce, ct_tag = aes_blob[: codec._AES_NONCE_LEN], aes_blob[codec._AES_NONCE_LEN :]
        assert AESGCM(dek).decrypt(nonce, ct_tag, aad) == plaintext

    def test_parse_enforces_purpose(self) -> None:
        dek = bytes(32)
        blob = codec._encode_envelope(dek, b"x", "kid", "right-purpose", _opaque_wrapped_dek())
        codec._parse_envelope(blob, "kid", "right-purpose")  # correct purpose parses
        with pytest.raises(WrapParseError):
            codec._parse_envelope(blob, "kid", "wrong-purpose")

    def test_split_rejects_key_id_mismatch(self) -> None:
        dek = bytes(32)
        blob = codec._encode_envelope(dek, b"x", "kid", "purpose", _opaque_wrapped_dek())
        with pytest.raises(WrapParseError):
            codec._split_envelope(blob, codec._hash_id("other-kid"))

    def test_encode_rejects_wrong_wrapped_dek_len(self) -> None:
        with pytest.raises(ValueError):
            codec._encode_envelope(bytes(32), b"x", "kid", "purpose", b"too-short")

    def test_split_rejects_truncated_blob(self) -> None:
        with pytest.raises(WrapParseError):
            codec._split_envelope(b"MREN" + bytes(10), codec._hash_id("kid"))
