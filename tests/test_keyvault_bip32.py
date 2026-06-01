"""Tests for ``mordred_hermes.keyvault._bip32`` — BIP32/BIP44 derivation.

Pure-crypto unit tests (no Secure Enclave / Keychain): they pin the new
derivation module against published, widely-reproduced vectors so a future
refactor cannot silently change derived addresses.

- BIP44 Ethereum (``m/44'/60'/0'/0/i``) — the well-known Hardhat / Anvil
  default mnemonic "test test ... junk". Accounts 0-2 and account 0's
  private key are stable constants reproduced by every Ethereum dev tool.

Collected only when the ``ethereum`` extra is installed (``eth_keys`` is
needed to turn a derived private scalar into a checksum address).
"""

from __future__ import annotations

import pytest

from mordred_hermes.keyvault import _bip32, _bip39

# eth_keys turns a derived private scalar into a checksum address; it lives in
# the optional `ethereum` extra, which CI does not install (only dev / keyvault
# / macos). Skip the whole module when it is absent (matches the docstring).
pytest.importorskip("eth_keys")

_HARDHAT_MNEMONIC = "test test test test test test test test test test test junk"
_HARDHAT_ADDRESSES = {
    0: "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
    1: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
    2: "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC",
}
_HARDHAT_ACCOUNT0_PRIVKEY_HEX = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"


def _seed() -> bytes:
    return _bip39.mnemonic_to_seed(_HARDHAT_MNEMONIC)


def test_master_key_from_seed_returns_32_byte_key_and_chaincode() -> None:
    key, chain = _bip32.master_key_from_seed(_seed())
    assert len(key) == 32
    assert len(chain) == 32


def test_bip44_derives_known_account0_private_key() -> None:
    priv = _bip32.derive_path(_seed(), "m/44'/60'/0'/0/0")
    assert priv.hex() == _HARDHAT_ACCOUNT0_PRIVKEY_HEX


@pytest.mark.parametrize("index,expected_address", list(_HARDHAT_ADDRESSES.items()))
def test_bip44_derives_known_ethereum_addresses(index: int, expected_address: str) -> None:
    keys = pytest.importorskip("eth_keys").keys
    priv = _bip32.derive_path(_seed(), f"m/44'/60'/0'/0/{index}")
    assert keys.PrivateKey(priv).public_key.to_checksum_address() == expected_address


def test_derive_path_is_deterministic() -> None:
    p = "m/44'/60'/0'/0/5"
    assert _bip32.derive_path(_seed(), p) == _bip32.derive_path(_seed(), p)


def test_derive_path_rejects_non_master_prefix() -> None:
    with pytest.raises(ValueError):
        _bip32.derive_path(_seed(), "44'/60'/0'/0/0")  # missing leading "m"


def test_hardened_and_unhardened_indices_differ() -> None:
    assert _bip32.derive_path(_seed(), "m/44'/60'/0'/0/0") != _bip32.derive_path(_seed(), "m/44'/60'/0'/0/0'")


def test_derive_path_rejects_negative_index() -> None:
    with pytest.raises(ValueError):
        _bip32.derive_path(_seed(), "m/44'/60'/0'/0/-1")


def test_derive_path_rejects_oversized_index() -> None:
    # 2**32 cannot be serialized into the 4-byte BIP32 child number field.
    with pytest.raises(ValueError):
        _bip32.derive_path(_seed(), "m/44'/60'/0'/0/4294967296")


def test_derive_path_rejects_hardened_overflow() -> None:
    # A child number >= 2**31 is invalid before the hardened offset is added.
    with pytest.raises(ValueError):
        _bip32.derive_path(_seed(), "m/44'/60'/0'/0/2147483648'")


def test_derive_path_rejects_non_integer_segment() -> None:
    with pytest.raises(ValueError):
        _bip32.derive_path(_seed(), "m/44'/60'/0'/0/abc")
