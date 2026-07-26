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

_EXTENSION_ID = "abcdefghijklmnopabcdefghijklmnop"
_ORIGIN = f"chrome-extension://{_EXTENSION_ID}"
_RP_ID = _ORIGIN


@pytest.fixture(autouse=True)
def _isolated_home(tmp_path, monkeypatch):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    pairing._save_pairing(
        pairing.Pairing(
            aes_key=b"\x01" * 32,
            ext_token="webauthn-test-token",
            ext_pubkey_b64="test-extension",
            hermes_pubkey_b64="test-hermes",
            paired_at=1.0,
        )
    )


def _make_assertion(
    priv: ec.EllipticCurvePrivateKey,
    cred_id: str,
    nonce: bytes,
    *,
    uv=True,
    origin: str = _ORIGIN,
    rp_id: str = _RP_ID,
    cross_origin: bool = False,
):
    client = {
        "type": "webauthn.get",
        "challenge": xc.b64u_encode(nonce),
        "origin": origin,
        "crossOrigin": cross_origin,
    }
    client_json = json.dumps(client).encode()
    flags = 0x05 if uv else 0x01  # UP always; UV optional
    auth_data = hashlib.sha256(rp_id.encode()).digest() + bytes([flags]) + b"\x00\x00\x00\x00"
    sig = priv.sign(auth_data + hashlib.sha256(client_json).digest(), ec.ECDSA(hashes.SHA256()))
    return {
        "credential_id": cred_id,
        "authenticator_data": xc.b64u_encode(auth_data),
        "client_data_json": xc.b64u_encode(client_json),
        "signature": xc.b64u_encode(sig),
    }


def _register(priv: ec.EllipticCurvePrivateKey, cred_id: str):
    spki = priv.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    pairing.save_webauthn_credential(cred_id, xc.b64u_encode(spki), origin=_ORIGIN)


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


def test_wrong_origin_rejected():
    priv = ec.generate_private_key(ec.SECP256R1())
    _register(priv, "cred-1")
    nonce = b"\x33" * 32
    assertion = _make_assertion(priv, "cred-1", nonce, origin="chrome-extension://attacker")
    assert pairing.verify_webauthn_assertion(nonce, assertion) is False


def test_cross_origin_rejected():
    priv = ec.generate_private_key(ec.SECP256R1())
    _register(priv, "cred-1")
    nonce = b"\x33" * 32
    assertion = _make_assertion(priv, "cred-1", nonce, cross_origin=True)
    assert pairing.verify_webauthn_assertion(nonce, assertion) is False


def test_wrong_rp_id_hash_rejected():
    priv = ec.generate_private_key(ec.SECP256R1())
    _register(priv, "cred-1")
    nonce = b"\x33" * 32
    assertion = _make_assertion(priv, "cred-1", nonce, rp_id="attacker.invalid")
    assert pairing.verify_webauthn_assertion(nonce, assertion) is False


def test_extension_hostname_only_rp_id_hash_is_rejected():
    """Chromium maps the default host RP ID to the full extension origin."""
    priv = ec.generate_private_key(ec.SECP256R1())
    _register(priv, "cred-1")
    nonce = b"\x33" * 32
    assertion = _make_assertion(priv, "cred-1", nonce, rp_id=_EXTENSION_ID)
    assert pairing.verify_webauthn_assertion(nonce, assertion) is False


def test_rp_id_derivation_supports_chromium_default_only():
    assert pairing._rp_id_for_origin(_ORIGIN) == _ORIGIN
    assert pairing._rp_id_for_origin("moz-extension://random-document-uuid") is None


def test_legacy_credential_is_bound_to_current_connection_origin():
    priv = ec.generate_private_key(ec.SECP256R1())
    spki = priv.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    pairing.save_webauthn_credential("cred-1", xc.b64u_encode(spki))
    nonce = b"\x33" * 32
    assertion = _make_assertion(priv, "cred-1", nonce)
    assert pairing.verify_webauthn_assertion(nonce, assertion, expected_origin=_ORIGIN) is True
    stored = json.loads(pairing._webauthn_path().read_text("utf-8"))
    assert stored["origin"] == _ORIGIN
    assert stored["transport_origin"] == _ORIGIN
    assert xc.b64u_decode(stored["rp_id_hash"]) == hashlib.sha256(_RP_ID.encode()).digest()


def test_legacy_firefox_credential_migrates_with_signed_origin_and_rp_hash():
    priv = ec.generate_private_key(ec.SECP256R1())
    spki = priv.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    pairing.save_webauthn_credential("cred-1", xc.b64u_encode(spki))
    nonce = b"\x33" * 32
    ceremony_origin = "moz-extension://stable-webauthn-origin"
    transport_origin = "moz-extension://installed-document-origin"
    assertion = _make_assertion(
        priv,
        "cred-1",
        nonce,
        origin=ceremony_origin,
        rp_id="firefox-external-rp-id",
    )

    assert (
        pairing.verify_webauthn_assertion(
            nonce,
            assertion,
            expected_origin=transport_origin,
        )
        is True
    )
    stored = json.loads(pairing._webauthn_path().read_text("utf-8"))
    assert stored["origin"] == ceremony_origin
    assert stored["transport_origin"] == transport_origin
    assert "rp_id" not in stored
    assert xc.b64u_decode(stored["rp_id_hash"]) == hashlib.sha256(b"firefox-external-rp-id").digest()

    # The migrated record pins all three signed/transport bindings.
    next_nonce = b"\x44" * 32
    next_assertion = _make_assertion(
        priv,
        "cred-1",
        next_nonce,
        origin=ceremony_origin,
        rp_id="firefox-external-rp-id",
    )
    assert (
        pairing.verify_webauthn_assertion(
            next_nonce,
            next_assertion,
            expected_origin=transport_origin,
        )
        is True
    )
    assert (
        pairing.verify_webauthn_assertion(
            next_nonce,
            next_assertion,
            expected_origin="moz-extension://different-install",
        )
        is False
    )
    wrong_origin = _make_assertion(
        priv,
        "cred-1",
        next_nonce,
        origin="moz-extension://different-ceremony",
        rp_id="firefox-external-rp-id",
    )
    assert pairing.verify_webauthn_assertion(next_nonce, wrong_origin, expected_origin=transport_origin) is False
    wrong_rp = _make_assertion(
        priv,
        "cred-1",
        next_nonce,
        origin=ceremony_origin,
        rp_id="different-rp",
    )
    assert pairing.verify_webauthn_assertion(next_nonce, wrong_rp, expected_origin=transport_origin) is False


@pytest.mark.parametrize(
    ("mutation", "expected_origin"),
    [
        ("wrong_nonce", "moz-extension://installed-document-origin"),
        ("wrong_signature", "moz-extension://installed-document-origin"),
        ("missing_uv", "moz-extension://installed-document-origin"),
        ("cross_origin", "moz-extension://installed-document-origin"),
        ("wrong_scheme", "moz-extension://installed-document-origin"),
    ],
)
def test_invalid_legacy_firefox_assertion_never_migrates(mutation, expected_origin):
    priv = ec.generate_private_key(ec.SECP256R1())
    spki = priv.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    pairing.save_webauthn_credential("cred-1", xc.b64u_encode(spki))
    nonce = b"\x33" * 32
    assertion_nonce = b"\x44" * 32 if mutation == "wrong_nonce" else nonce
    assertion_priv = ec.generate_private_key(ec.SECP256R1()) if mutation == "wrong_signature" else priv
    assertion = _make_assertion(
        assertion_priv,
        "cred-1",
        assertion_nonce,
        uv=mutation != "missing_uv",
        origin=("chrome-extension://wrong-scheme" if mutation == "wrong_scheme" else "moz-extension://stable-origin"),
        rp_id="firefox-external-rp-id",
        cross_origin=mutation == "cross_origin",
    )

    assert pairing.verify_webauthn_assertion(nonce, assertion, expected_origin=expected_origin) is False
    stored = json.loads(pairing._webauthn_path().read_text("utf-8"))
    assert set(stored) == {
        "credential_id",
        "pairing_token_hash",
        "public_key",
    }


def test_legacy_binding_write_failure_refuses_authentication(monkeypatch):
    priv = ec.generate_private_key(ec.SECP256R1())
    spki = priv.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    pairing.save_webauthn_credential("cred-1", xc.b64u_encode(spki))
    nonce = b"\x33" * 32
    assertion = _make_assertion(priv, "cred-1", nonce)
    monkeypatch.setattr(pairing, "_write_private", lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("disk")))

    assert pairing.verify_webauthn_assertion(nonce, assertion, expected_origin=_ORIGIN) is False


def test_clear_credential():
    priv = ec.generate_private_key(ec.SECP256R1())
    _register(priv, "cred-1")
    pairing.clear_webauthn_credential()
    assert pairing.has_webauthn_credential() is False
