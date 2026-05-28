"""Tests for ``mordred_hermes.keyvault.ethereum``.

Uses ``FakeBackend`` (software P-256 stand-in for the Secure Enclave) so
the full generate → store → address → sign → verify flow runs on any
platform without a real Keychain or Touch ID prompt.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from mordred_hermes.keyvault.ethereum import (
    EthereumSignature,
    _PURPOSE,
    generate_ethereum_key,
    get_ethereum_address,
    sign_hash,
)
from tests._keyvault_fakes import FakeBackend


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _wrap_backend(tmp_path: Path) -> tuple[FakeBackend, list[dict], dict]:
    """Return (backend, audit_log, kwargs) wired to tmp_path."""
    backend = FakeBackend()
    backend.generate_enclave_key("default")
    log: list[dict] = []
    kwargs: dict = {"backend": backend, "audit_sink": log.append, "home": tmp_path}
    return backend, log, kwargs


# ---------------------------------------------------------------------------
# generate_ethereum_key
# ---------------------------------------------------------------------------


def test_generate_returns_envelope_id_and_checksum_address(tmp_path: Path) -> None:
    _, _, kw = _wrap_backend(tmp_path)
    envelope_id, address = generate_ethereum_key("default", **kw)

    assert isinstance(envelope_id, str) and len(envelope_id) > 0
    assert address.startswith("0x")
    assert len(address) == 42


def test_generate_stores_envelope_on_disk(tmp_path: Path) -> None:
    _, _, kw = _wrap_backend(tmp_path)
    generate_ethereum_key("default", **kw)

    gcm_files = list(tmp_path.rglob("*.gcm"))
    assert len(gcm_files) == 1, "expected exactly one ciphertext envelope"


def test_generate_two_keys_produce_different_addresses(tmp_path: Path) -> None:
    _, _, kw = _wrap_backend(tmp_path)
    _, addr1 = generate_ethereum_key("default", **kw)
    _, addr2 = generate_ethereum_key("default", **kw)
    assert addr1 != addr2


# ---------------------------------------------------------------------------
# get_ethereum_address
# ---------------------------------------------------------------------------


def test_get_address_matches_generate(tmp_path: Path) -> None:
    _, _, kw = _wrap_backend(tmp_path)
    envelope_id, expected_address = generate_ethereum_key("default", **kw)
    recovered_address = get_ethereum_address("default", envelope_id, **kw)
    assert recovered_address == expected_address


def test_get_address_emits_unwrap_authorized(tmp_path: Path) -> None:
    _, log, kw = _wrap_backend(tmp_path)
    envelope_id, _ = generate_ethereum_key("default", **kw)
    log.clear()
    get_ethereum_address("default", envelope_id, **kw)
    reasons = [e.get("reason") for e in log]
    assert "keyvault.unwrap_authorized" in reasons


def test_get_address_wrong_envelope_id_raises(tmp_path: Path) -> None:
    # A valid-format envelope_id that was never written raises FileNotFoundError.
    _, _, kw = _wrap_backend(tmp_path)
    with pytest.raises(OSError):
        get_ethereum_address("default", "AAAAAAAAAAAAAAAAAAAAAA", **kw)


# ---------------------------------------------------------------------------
# sign_hash
# ---------------------------------------------------------------------------


def test_sign_hash_produces_valid_signature(tmp_path: Path) -> None:
    import eth_keys  # type: ignore[import-untyped]

    _, _, kw = _wrap_backend(tmp_path)
    envelope_id, address = generate_ethereum_key("default", **kw)

    msg_hash = hashlib.sha256(b"hello mordred").digest()
    sig = sign_hash("default", envelope_id, msg_hash, **kw)

    assert isinstance(sig, EthereumSignature)
    assert sig.v in {27, 28}
    assert len(sig.r) == 32
    assert len(sig.s) == 32

    # Recover public key from signature and verify it matches the address.
    eth_sig = eth_keys.keys.Signature(
        vrs=(sig.v - 27, int.from_bytes(sig.r, "big"), int.from_bytes(sig.s, "big"))
    )
    recovered_pub = eth_sig.recover_public_key_from_msg_hash(msg_hash)
    assert recovered_pub.to_checksum_address() == address


def test_sign_hash_as_bytes_is_65_bytes(tmp_path: Path) -> None:
    _, _, kw = _wrap_backend(tmp_path)
    envelope_id, _ = generate_ethereum_key("default", **kw)
    sig = sign_hash("default", envelope_id, hashlib.sha256(b"test").digest(), **kw)
    assert len(sig.as_bytes) == 65
    assert len(sig.hex) == 130


def test_sign_hash_different_messages_different_sigs(tmp_path: Path) -> None:
    _, _, kw = _wrap_backend(tmp_path)
    envelope_id, _ = generate_ethereum_key("default", **kw)
    sig1 = sign_hash("default", envelope_id, hashlib.sha256(b"msg1").digest(), **kw)
    sig2 = sign_hash("default", envelope_id, hashlib.sha256(b"msg2").digest(), **kw)
    assert sig1.r != sig2.r or sig1.s != sig2.s


def test_sign_hash_wrong_length_raises(tmp_path: Path) -> None:
    _, _, kw = _wrap_backend(tmp_path)
    envelope_id, _ = generate_ethereum_key("default", **kw)
    with pytest.raises(ValueError, match="32 bytes"):
        sign_hash("default", envelope_id, b"too-short", **kw)


def test_sign_hash_emits_unwrap_authorized(tmp_path: Path) -> None:
    _, log, kw = _wrap_backend(tmp_path)
    envelope_id, _ = generate_ethereum_key("default", **kw)
    log.clear()
    sign_hash("default", envelope_id, hashlib.sha256(b"x").digest(), **kw)
    reasons = [e.get("reason") for e in log]
    assert "keyvault.unwrap_authorized" in reasons


# ---------------------------------------------------------------------------
# EthereumSignature dataclass
# ---------------------------------------------------------------------------


def test_ethereum_signature_as_bytes() -> None:
    r = bytes(range(32))
    s = bytes(range(32, 64))
    sig = EthereumSignature(v=27, r=r, s=s)
    assert sig.as_bytes == r + s + b"\x1b"
    assert sig.hex == (r + s + b"\x1b").hex()


def test_ethereum_signature_is_frozen() -> None:
    sig = EthereumSignature(v=27, r=b"\x00" * 32, s=b"\x00" * 32)
    with pytest.raises((AttributeError, TypeError)):
        sig.v = 28  # type: ignore[misc]


# ---------------------------------------------------------------------------
# _PURPOSE constant
# ---------------------------------------------------------------------------


def test_purpose_constant_is_versioned() -> None:
    assert _PURPOSE == "ethereum.key.v1"
