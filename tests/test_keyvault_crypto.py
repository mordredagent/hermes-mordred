"""Tests for ``mordred_hermes.keyvault.crypto`` — AES-GCM primitives.

Phase 4 PR1 first RED → GREEN target. The module wraps
``cryptography.hazmat.primitives.ciphers.aead.AESGCM`` to produce a
self-contained blob carrying its own nonce, so callers do not have to
manage nonce uniqueness manually.

Wire format (returned by :func:`encrypt`, consumed by :func:`decrypt`):

    nonce(12) || ciphertext || tag(16)

AES-GCM key sizes accepted: 128 / 192 / 256 bit. The keyvault uses 256-bit
data-encryption keys (DEKs) per SPEC §Plugin: ``mordred_keyvault``.
"""

from __future__ import annotations

import pytest
from cryptography.exceptions import InvalidTag


class TestAesGcmRoundtrip:
    def test_encrypt_then_decrypt_returns_plaintext(self) -> None:
        from mordred_hermes.keyvault import crypto

        key = b"\x00" * 32
        plaintext = b"hello mordred"
        blob = crypto.encrypt(key, plaintext, aad=b"v1")

        assert crypto.decrypt(key, blob, aad=b"v1") == plaintext

    @pytest.mark.parametrize(
        ("key", "plaintext"),
        [
            # ``aad`` defaults to empty bytes — must roundtrip when omitted.
            pytest.param(b"\x11" * 32, b"no aad here", id="empty_aad_default"),
            # AES-128 (16-byte key) must work — DEKs are 256-bit but the
            # primitive itself supports the smaller sizes per FIPS 197.
            pytest.param(b"\xab" * 16, b"x", id="aes128_key"),
            # AES-192 (24-byte key) — closes the gap between the AES-128
            # and AES-256 coverage so the docstring claim of "128 / 192 /
            # 256 bit" is exercised end-to-end.
            pytest.param(b"\xcc" * 24, b"phase4 review L1", id="aes192_key"),
        ],
    )
    def test_roundtrip_without_aad(self, key: bytes, plaintext: bytes) -> None:
        from mordred_hermes.keyvault import crypto

        blob = crypto.encrypt(key, plaintext)

        assert crypto.decrypt(key, blob) == plaintext

    def test_encrypt_produces_unique_nonce_per_call(self) -> None:
        """Same key + plaintext + AAD must produce different blobs across calls.

        AES-GCM is catastrophically broken under nonce reuse with the same
        key (CVE-class), so :func:`encrypt` MUST generate a fresh random
        nonce on every invocation. We assert that across N calls all
        blobs differ — a constant-nonce regression would collide.
        """
        from mordred_hermes.keyvault import crypto

        key = b"\x42" * 32
        plaintext = b"identical input"
        blobs = {crypto.encrypt(key, plaintext, aad=b"same") for _ in range(8)}

        assert len(blobs) == 8

    def test_encrypted_blob_carries_nonce_prefix(self) -> None:
        """Wire format is ``nonce(12) || ciphertext || tag(16)``. Two blobs
        encrypting the same plaintext must share no nonce — the 12-byte
        prefix is what differs (the ciphertext+tag after it will also
        differ because the keystream depends on the nonce)."""
        from mordred_hermes.keyvault import crypto

        key = b"\x55" * 32
        a = crypto.encrypt(key, b"abc")
        b = crypto.encrypt(key, b"abc")

        assert a[:12] != b[:12]


class TestAesGcmAuthenticatedFailures:
    def test_decrypt_tampered_ciphertext_raises_invalid_tag(self) -> None:
        from mordred_hermes.keyvault import crypto

        key = b"\x00" * 32
        blob = bytearray(crypto.encrypt(key, b"sensitive", aad=b"v1"))
        # Flip a bit inside the ciphertext region (after the 12-byte nonce).
        blob[15] ^= 0x01

        with pytest.raises(InvalidTag):
            crypto.decrypt(key, bytes(blob), aad=b"v1")

    def test_decrypt_wrong_key_raises_invalid_tag(self) -> None:
        from mordred_hermes.keyvault import crypto

        blob = crypto.encrypt(b"\x00" * 32, b"sensitive")

        with pytest.raises(InvalidTag):
            crypto.decrypt(b"\x01" * 32, blob)

    def test_decrypt_wrong_aad_raises_invalid_tag(self) -> None:
        """AAD is authenticated — supplying a different AAD on decrypt
        must fail the GCM tag check. This is what binds a DEK to its
        purpose label (e.g. ``aad=b"audit-log"`` vs ``aad=b"backup"``)."""
        from mordred_hermes.keyvault import crypto

        key = b"\x00" * 32
        blob = crypto.encrypt(key, b"sensitive", aad=b"audit-log")

        with pytest.raises(InvalidTag):
            crypto.decrypt(key, blob, aad=b"backup")

    def test_decrypt_truncated_blob_raises(self) -> None:
        """A blob too short to contain ``nonce || ct || tag`` must raise —
        cryptography's AESGCM rejects short ciphertexts."""
        from mordred_hermes.keyvault import crypto

        key = b"\x00" * 32
        blob = crypto.encrypt(key, b"sensitive")

        with pytest.raises(InvalidTag):
            # Strip the last byte → tag is now incomplete.
            crypto.decrypt(key, blob[:-1])

    @pytest.mark.parametrize("short_blob", [b"", b"\x00" * 5, b"\x00" * 12, b"\x00" * 27])
    def test_decrypt_blob_shorter_than_nonce_plus_tag_raises_invalid_tag(self, short_blob: bytes) -> None:
        """A blob structurally too short for ``nonce(12) || tag(16)`` must
        surface as :class:`InvalidTag` — the documented tamper/corruption
        signal — not as a raw ``ValueError`` from AESGCM's nonce-size check.
        Without an explicit guard the error type flips between the two
        depending on how many bytes survived truncation (< 12 vs < 28)."""
        from mordred_hermes.keyvault import crypto

        with pytest.raises(InvalidTag):
            crypto.decrypt(b"\x00" * 32, short_blob)


class TestAesGcmKeyLengthValidation:
    @pytest.mark.parametrize("bad_key", [b"", b"\x00" * 1, b"\x00" * 15, b"\x00" * 31, b"\x00" * 33, b"\x00" * 64])
    def test_encrypt_rejects_non_standard_key_size(self, bad_key: bytes) -> None:
        """AES-GCM only accepts 128 / 192 / 256-bit keys (FIPS 197).
        cryptography's AESGCM raises ``ValueError`` for any other size."""
        from mordred_hermes.keyvault import crypto

        with pytest.raises(ValueError):
            crypto.encrypt(bad_key, b"x")
