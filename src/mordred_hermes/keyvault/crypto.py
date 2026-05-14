"""mordred_keyvault.crypto — AES-GCM primitives.

Self-contained blob carries its own 96-bit nonce so callers do not have
to manage nonce uniqueness manually. Wire format:

    nonce(12) || ciphertext || tag(16)

AES-GCM key sizes accepted: 128 / 192 / 256 bit. The keyvault uses 256-bit
data-encryption keys (DEKs) per SPEC §Plugin: ``mordred_keyvault``.
"""

from __future__ import annotations

from os import urandom

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

_NONCE_SIZE = 12


def encrypt(key: bytes, plaintext: bytes, *, aad: bytes = b"") -> bytes:
    """Encrypt ``plaintext`` with AES-GCM and return ``nonce || ct || tag``."""
    nonce = urandom(_NONCE_SIZE)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, aad)
    return nonce + ciphertext


def decrypt(key: bytes, blob: bytes, *, aad: bytes = b"") -> bytes:
    """Decrypt a blob produced by :func:`encrypt`. Raises ``InvalidTag`` on tamper."""
    nonce, ciphertext = blob[:_NONCE_SIZE], blob[_NONCE_SIZE:]
    return AESGCM(key).decrypt(nonce, ciphertext, aad)
