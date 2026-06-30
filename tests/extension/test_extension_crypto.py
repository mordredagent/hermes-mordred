"""Crypto interop tests — both sides of the pairing must derive the same key,
and the AES-GCM wire format must round-trip."""

from __future__ import annotations

import os

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from gateway import extension_crypto as xc


def test_b64url_roundtrip_unpadded():
    raw = os.urandom(20)
    enc = xc.b64u_encode(raw)
    assert "=" not in enc
    assert xc.b64u_decode(enc) == raw


def test_shared_key_agreement_both_sides_match():
    code = "MORT-ABCDEFGH-JKLMNPQR"
    ext_priv = X25519PrivateKey.generate()
    hermes_priv = X25519PrivateKey.generate()
    ext_pub_b64 = xc.b64u_encode(xc.x25519_public_raw(ext_priv))
    hermes_pub_b64 = xc.b64u_encode(xc.x25519_public_raw(hermes_priv))

    hermes_key = xc.derive_shared_key(hermes_priv, ext_pub_b64, code)
    ext_key = xc.derive_shared_key(ext_priv, hermes_pub_b64, code)

    assert hermes_key == ext_key
    assert len(hermes_key) == 32


def test_shared_key_differs_with_code():
    ext_priv = X25519PrivateKey.generate()
    hermes_priv = X25519PrivateKey.generate()
    ext_pub_b64 = xc.b64u_encode(xc.x25519_public_raw(ext_priv))
    k1 = xc.derive_shared_key(hermes_priv, ext_pub_b64, "MORT-AAAAAAAA-BBBBBBBB")
    k2 = xc.derive_shared_key(hermes_priv, ext_pub_b64, "MORT-AAAAAAAA-CCCCCCCC")
    assert k1 != k2


def test_message_encrypt_decrypt_roundtrip():
    key = os.urandom(32)
    msg = "こんにちは、Mordred 🔒"
    blob = xc.encrypt_message(key, msg)
    assert blob.startswith(xc.ENC_PREFIX)
    assert xc.is_encrypted(blob)
    assert xc.decrypt_message(key, blob) == msg


def test_decrypt_wrong_key_is_tampered():
    blob = xc.encrypt_message(os.urandom(32), "secret")
    try:
        xc.decrypt_message(os.urandom(32), blob)
    except xc.DecryptError as e:
        assert e.reason == "tampered"
    else:
        raise AssertionError("expected DecryptError")


def test_decrypt_malformed():
    for bad in ["not encrypted", "🔒ENC:v1:onlyonepart", "🔒ENC:v1:a:b:c"]:
        try:
            xc.decrypt_message(os.urandom(32), bad)
        except xc.DecryptError as e:
            assert e.reason == "malformed"
        else:
            raise AssertionError(f"expected malformed for {bad!r}")
