"""Tests for ``mordred_hermes.keyvault._bip39`` — BIP39 mnemonic generation.

Phase 4 PR10 step-A RED → GREEN target.

``keyvault init`` (PR10) generates the 24-word Seed Phrase the user
transcribes by hand. v1 supports only 256-bit entropy (24 words), per
SPEC.md §"Key hierarchy" ("ユーザは 24-word Seed と Passphrase を物理的に手書き").

Fixed vectors are the canonical Trezor BIP39 English test vectors for
256-bit entropy with no passphrase.
"""

from __future__ import annotations

import pytest

from mordred_hermes.keyvault import _bip39

# Canonical BIP39 English test vectors (256-bit entropy).
ALL_ZERO_ENTROPY = b"\x00" * 32
ALL_ZERO_MNEMONIC = (
    "abandon abandon abandon abandon abandon abandon abandon abandon "
    "abandon abandon abandon abandon abandon abandon abandon abandon "
    "abandon abandon abandon abandon abandon abandon abandon art"
)
ALL_FF_ENTROPY = b"\xff" * 32
ALL_FF_MNEMONIC = "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote"


class TestWordlist:
    def test_wordlist_has_2048_words(self) -> None:
        assert len(_bip39.WORDLIST) == 2048

    def test_wordlist_is_sorted_and_unique(self) -> None:
        assert list(_bip39.WORDLIST) == sorted(_bip39.WORDLIST)
        assert len(set(_bip39.WORDLIST)) == 2048

    def test_wordlist_bounds(self) -> None:
        assert _bip39.WORDLIST[0] == "abandon"
        assert _bip39.WORDLIST[-1] == "zoo"


class TestEntropyToMnemonic:
    def test_all_zero_vector(self) -> None:
        assert _bip39.entropy_to_mnemonic(ALL_ZERO_ENTROPY) == ALL_ZERO_MNEMONIC

    def test_all_ff_vector(self) -> None:
        assert _bip39.entropy_to_mnemonic(ALL_FF_ENTROPY) == ALL_FF_MNEMONIC

    def test_produces_24_words(self) -> None:
        words = _bip39.entropy_to_mnemonic(ALL_ZERO_ENTROPY).split(" ")
        assert len(words) == 24

    def test_rejects_non_256_bit_entropy(self) -> None:
        with pytest.raises(ValueError):
            _bip39.entropy_to_mnemonic(b"\x00" * 16)


class TestMnemonicToEntropy:
    def test_round_trip_zero(self) -> None:
        assert _bip39.mnemonic_to_entropy(ALL_ZERO_MNEMONIC) == ALL_ZERO_ENTROPY

    def test_round_trip_ff(self) -> None:
        assert _bip39.mnemonic_to_entropy(ALL_FF_MNEMONIC) == ALL_FF_ENTROPY

    def test_rejects_bad_checksum(self) -> None:
        # Swap the last word — the BIP39 checksum no longer matches.
        tampered = ALL_ZERO_MNEMONIC.rsplit(" ", 1)[0] + " zoo"
        with pytest.raises(ValueError):
            _bip39.mnemonic_to_entropy(tampered)

    def test_rejects_unknown_word(self) -> None:
        bad = ALL_ZERO_MNEMONIC.rsplit(" ", 1)[0] + " notabip39word"
        with pytest.raises(ValueError):
            _bip39.mnemonic_to_entropy(bad)

    def test_rejects_wrong_word_count(self) -> None:
        with pytest.raises(ValueError):
            _bip39.mnemonic_to_entropy("abandon abandon abandon")


class TestGenerateMnemonic:
    def test_generates_24_words_in_wordlist(self) -> None:
        mnemonic = _bip39.generate_mnemonic()
        words = mnemonic.split(" ")
        assert len(words) == 24
        assert all(w in _bip39.WORDLIST for w in words)

    def test_generated_mnemonic_has_valid_checksum(self) -> None:
        # mnemonic_to_entropy raises on a bad checksum; a clean round-trip
        # back through entropy_to_mnemonic proves the generated phrase is valid.
        mnemonic = _bip39.generate_mnemonic()
        entropy = _bip39.mnemonic_to_entropy(mnemonic)
        assert len(entropy) == 32
        assert _bip39.entropy_to_mnemonic(entropy) == mnemonic

    def test_generates_distinct_phrases(self) -> None:
        assert _bip39.generate_mnemonic() != _bip39.generate_mnemonic()


# Canonical TREZOR BIP39 seed vector (bitcoin/bips bip-0039): the
# 256-bit-zero entropy mnemonic with passphrase "TREZOR" derives this
# 64-byte seed via PBKDF2-HMAC-SHA512 (2048 rounds, salt "mnemonic"||pass).
_TREZOR_MNEMONIC = (
    "abandon abandon abandon abandon abandon abandon abandon abandon "
    "abandon abandon abandon about"
)
_TREZOR_PASSPHRASE = "TREZOR"
_TREZOR_SEED_HEX = (
    "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e5349553"
    "1f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04"
)
_HARDHAT_MNEMONIC = "test test test test test test test test test test test junk"


class TestMnemonicToSeed:
    def test_matches_trezor_vector(self) -> None:
        seed = _bip39.mnemonic_to_seed(_TREZOR_MNEMONIC, _TREZOR_PASSPHRASE)
        assert seed.hex() == _TREZOR_SEED_HEX
        assert len(seed) == 64

    def test_default_passphrase_is_empty(self) -> None:
        assert _bip39.mnemonic_to_seed(_HARDHAT_MNEMONIC) == _bip39.mnemonic_to_seed(_HARDHAT_MNEMONIC, "")

    def test_passphrase_changes_output(self) -> None:
        assert _bip39.mnemonic_to_seed(_HARDHAT_MNEMONIC, "") != _bip39.mnemonic_to_seed(_HARDHAT_MNEMONIC, "extra")
