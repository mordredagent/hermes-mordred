"""WebAuthn assertion verification (§3.5). We synthesize a valid assertion with
a P-256 key and check the gateway accepts it and rejects tampered variants."""

from __future__ import annotations

import hashlib
import json

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from mordred_hermes.extension import extension_crypto as xc
from mordred_hermes.extension import extension_pairing as pairing


@pytest.fixture(autouse=True)
def _isolated_home(tmp_path, monkeypatch):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))


def _make_assertion(priv: ec.EllipticCurvePrivateKey, cred_id: str, nonce: bytes, *, uv=True):
    client = {"type": "webauthn.get", "challenge": xc.b64u_encode(nonce), "origin": "x"}
    client_json = json.dumps(client).encode()
    flags = 0x05 if uv else 0x01  # UP always; UV optional
    auth_data = b"\x00" * 32 + bytes([flags]) + b"\x00\x00\x00\x00"
    sig = priv.sign(auth_data + hashlib.sha256(client_json).digest(), ec.ECDSA(hashes.SHA256()))
    return {
        "credential_id": cred_id,
        "authenticator_data": xc.b64u_encode(auth_data),
        "client_data_json": xc.b64u_encode(client_json),
        "signature": xc.b64u_encode(sig),
    }


def _register(priv: ec.EllipticCurvePrivateKey, cred_id: str):
    spki = priv.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    pairing.save_webauthn_credential(cred_id, xc.b64u_encode(spki))


def test_valid_assertion_accepted():
    priv = ec.generate_private_key(ec.SECP256R1())
    _register(priv, "cred-1")
    nonce = b"\x33" * 32
    assert pairing.has_webauthn_credential() is True
    assert pairing.verify_webauthn_assertion(nonce, _make_assertion(priv, "cred-1", nonce)) is True


def test_wrong_nonce_rejected():
    priv = ec.generate_private_key(ec.SECP256R1())
    _register(priv, "cred-1")
    good = _make_assertion(priv, "cred-1", b"\x33" * 32)
    assert pairing.verify_webauthn_assertion(b"\x44" * 32, good) is False


def test_wrong_key_rejected():
    priv = ec.generate_private_key(ec.SECP256R1())
    _register(priv, "cred-1")
    attacker = ec.generate_private_key(ec.SECP256R1())
    nonce = b"\x33" * 32
    forged = _make_assertion(attacker, "cred-1", nonce)
    assert pairing.verify_webauthn_assertion(nonce, forged) is False


def test_missing_uv_flag_rejected():
    priv = ec.generate_private_key(ec.SECP256R1())
    _register(priv, "cred-1")
    nonce = b"\x33" * 32
    no_uv = _make_assertion(priv, "cred-1", nonce, uv=False)
    assert pairing.verify_webauthn_assertion(nonce, no_uv) is False


def test_clear_credential():
    priv = ec.generate_private_key(ec.SECP256R1())
    _register(priv, "cred-1")
    pairing.clear_webauthn_credential()
    assert pairing.has_webauthn_credential() is False
