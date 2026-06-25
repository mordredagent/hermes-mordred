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
    _PURPOSE,
    EthereumSignature,
    generate_ethereum_key,
    get_ethereum_address,
    sign_hash,
)
from tests._keyvault_fakes import FakeBackend

# eth-keys lives in the optional `ethereum` extra, which CI does not install
# (only dev / keyvault / macos). Skip the whole module when it is absent so the
# suite stays green without forcing every environment to pull eth-keys; the
# tests still run wherever `pip install "mordred-hermes[ethereum]"` is present.
pytest.importorskip("eth_keys")

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
    eth_sig = eth_keys.keys.Signature(vrs=(sig.v - 27, int.from_bytes(sig.r, "big"), int.from_bytes(sig.s, "big")))
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


# ---------------------------------------------------------------------------
# HD wallet: store_seed_phrase + derive_ethereum_key + sign_hash_hd
# (Option A — seed is stored SE-encrypted, keys derived deterministically)
# ---------------------------------------------------------------------------

_HARDHAT_MNEMONIC = "test test test test test test test test test test test junk"
_HARDHAT_ADDR0 = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
_HARDHAT_ADDR1 = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"


def test_store_seed_phrase_returns_envelope_id_and_writes_seed_envelope(tmp_path: Path) -> None:
    from mordred_hermes.keyvault.ethereum import _SEED_PURPOSE, store_seed_phrase

    _, _, kw = _wrap_backend(tmp_path)
    env_id = store_seed_phrase("default", _HARDHAT_MNEMONIC, **kw)
    assert isinstance(env_id, str) and len(env_id) > 0

    # The seed envelope lives under the bip39.seed.v1 purpose hash, distinct
    # from the random-key purpose (ethereum.key.v1).
    purpose_hash_hex = hashlib.sha256(_SEED_PURPOSE.encode()).digest()[:16].hex()
    seed_envelopes = list((tmp_path / "mordred" / "keyvault" / "ciphertexts").rglob(f"{purpose_hash_hex}/*.gcm"))
    assert len(seed_envelopes) == 1


def test_store_seed_phrase_rejects_invalid_checksum(tmp_path: Path) -> None:
    from mordred_hermes.keyvault.ethereum import store_seed_phrase

    _, _, kw = _wrap_backend(tmp_path)
    bad = "test test test test test test test test test test test test"  # bad BIP39 checksum
    with pytest.raises(ValueError):
        store_seed_phrase("default", bad, **kw)


def test_derive_ethereum_key_matches_known_bip44_address(tmp_path: Path) -> None:
    from mordred_hermes.keyvault.ethereum import derive_ethereum_key, store_seed_phrase

    _, log, kw = _wrap_backend(tmp_path)
    seed_env = store_seed_phrase("default", _HARDHAT_MNEMONIC, **kw)

    addr0, path0 = derive_ethereum_key("default", seed_env, 0, **kw)
    addr1, _ = derive_ethereum_key("default", seed_env, 1, **kw)

    assert addr0 == _HARDHAT_ADDR0
    assert addr1 == _HARDHAT_ADDR1
    assert path0 == "m/44'/60'/0'/0/0"
    # Decrypting the seed goes through the Enclave -> one unwrap_authorized
    # audit entry per derive.
    assert any(e.get("reason") == "keyvault.unwrap_authorized" for e in log)


def test_derive_ethereum_key_is_deterministic(tmp_path: Path) -> None:
    from mordred_hermes.keyvault.ethereum import derive_ethereum_key, store_seed_phrase

    _, _, kw = _wrap_backend(tmp_path)
    seed_env = store_seed_phrase("default", _HARDHAT_MNEMONIC, **kw)
    assert derive_ethereum_key("default", seed_env, 7, **kw) == derive_ethereum_key("default", seed_env, 7, **kw)


def test_sign_hash_hd_recovers_to_derived_address(tmp_path: Path) -> None:
    from eth_keys import keys

    from mordred_hermes.keyvault.ethereum import derive_ethereum_key, sign_hash_hd, store_seed_phrase

    _, _, kw = _wrap_backend(tmp_path)
    seed_env = store_seed_phrase("default", _HARDHAT_MNEMONIC, **kw)
    addr, _ = derive_ethereum_key("default", seed_env, 0, **kw)

    message_hash = hashlib.sha256(b"hello mordred").digest()
    sig = sign_hash_hd("default", seed_env, 0, message_hash, **kw)

    # Reconstruct an eth_keys Signature (v back to recovery id 0/1) and
    # recover the signer; it must equal the derived address.
    rec_sig = keys.Signature(vrs=(sig.v - 27, int.from_bytes(sig.r, "big"), int.from_bytes(sig.s, "big")))
    recovered = rec_sig.recover_public_key_from_msg_hash(message_hash).to_checksum_address()
    assert recovered == addr


def test_derive_bip39_passphrase_changes_address(tmp_path: Path) -> None:
    from mordred_hermes.keyvault.ethereum import derive_ethereum_key, store_seed_phrase

    _, _, kw = _wrap_backend(tmp_path)
    seed_env = store_seed_phrase("default", _HARDHAT_MNEMONIC, **kw)
    plain, _ = derive_ethereum_key("default", seed_env, 0, **kw)
    with_pass, _ = derive_ethereum_key("default", seed_env, 0, bip39_passphrase="secret25thword", **kw)
    assert plain != with_pass


def test_derive_account_and_change_alter_path_and_address(tmp_path: Path) -> None:
    from mordred_hermes.keyvault.ethereum import derive_ethereum_key, store_seed_phrase

    _, _, kw = _wrap_backend(tmp_path)
    seed_env = store_seed_phrase("default", _HARDHAT_MNEMONIC, **kw)

    base_addr, base_path = derive_ethereum_key("default", seed_env, 0, **kw)
    acct_addr, acct_path = derive_ethereum_key("default", seed_env, 0, account=1, **kw)
    chg_addr, chg_path = derive_ethereum_key("default", seed_env, 0, change=1, **kw)

    assert base_path == "m/44'/60'/0'/0/0"
    assert acct_path == "m/44'/60'/1'/0/0"
    assert chg_path == "m/44'/60'/0'/1/0"
    assert len({base_addr, acct_addr, chg_addr}) == 3


def test_derive_rejects_negative_index(tmp_path: Path) -> None:
    from mordred_hermes.keyvault.ethereum import derive_ethereum_key, store_seed_phrase

    _, _, kw = _wrap_backend(tmp_path)
    seed_env = store_seed_phrase("default", _HARDHAT_MNEMONIC, **kw)
    with pytest.raises(ValueError):
        derive_ethereum_key("default", seed_env, -1, **kw)


# ---------------------------------------------------------------------------
# list_seed_envelope_ids — HD seed discovery (owns the ciphertext layout so
# the wizard CLI does not have to reach into _envelope_codec)
# ---------------------------------------------------------------------------


def test_list_seed_envelope_ids_empty_when_no_seed(tmp_path: Path) -> None:
    from mordred_hermes.keyvault.ethereum import list_seed_envelope_ids

    assert list_seed_envelope_ids("default", home=tmp_path) == []


def test_list_seed_envelope_ids_returns_every_stored_seed(tmp_path: Path) -> None:
    from mordred_hermes.keyvault.ethereum import list_seed_envelope_ids, store_seed_phrase

    _, _, kw = _wrap_backend(tmp_path)
    id1 = store_seed_phrase("default", _HARDHAT_MNEMONIC, **kw)
    id2 = store_seed_phrase("default", _HARDHAT_MNEMONIC, **kw)

    assert list_seed_envelope_ids("default", home=tmp_path) == sorted([id1, id2])


def test_list_seed_envelope_ids_is_scoped_to_key_id(tmp_path: Path) -> None:
    from mordred_hermes.keyvault.ethereum import list_seed_envelope_ids, store_seed_phrase

    _, _, kw = _wrap_backend(tmp_path)
    store_seed_phrase("default", _HARDHAT_MNEMONIC, **kw)

    assert list_seed_envelope_ids("other-key", home=tmp_path) == []
