"""Tests for ``mordred_hermes.keyvault.pow`` — Proof-of-Work artifact.

Phase 4 PR10 step-A RED → GREEN target.

PoW algorithm frozen in SPEC.md §"Proof-of-Work (PoW) algorithm":
a seed-bound leading-zero-bits counter search over
``BLAKE3(MRPOW\\x01 || normalized_seed || n.to_bytes(8, "little"))``.
The winning 32-byte digest is ``pow_bytes``; ``top4`` feeds the
verification digest. ``compute_pow`` takes an already-normalized seed
(normalization is the caller's responsibility, mirroring ``digest.py``).
"""

from __future__ import annotations

import pytest

from mordred_hermes.keyvault import pow as kvpow

# SPEC fixed vectors — canonical regression anchors for the PoW algorithm.
# Any change that perturbs these requires a SPEC update + PR description note.
SPEC_SEED = "test seed"
SPEC_POW_D8 = bytes.fromhex("00faa270f9d4a1047cd3f00002d6bd6c3ded6d151e2542ee21742a4665b56ac2")
SPEC_POW_D8_N = 519
SPEC_POW_D20 = bytes.fromhex("00000df459e58f525449c530a547d48ba70e488f7ed15f9c810ae7a76bd0e7c9")
SPEC_POW_D20_N = 1449850


class TestSpecFixedVectors:
    """SPEC §"Proof-of-Work (PoW) algorithm" pinned vectors."""

    def test_difficulty_8_worked_example(self) -> None:
        assert kvpow.compute_pow(SPEC_SEED, difficulty_bits=8) == SPEC_POW_D8

    def test_production_difficulty_constant(self) -> None:
        assert kvpow.POW_DIFFICULTY_BITS == 20

    def test_production_difficulty_vector(self) -> None:
        assert kvpow.compute_pow(SPEC_SEED) == SPEC_POW_D20

    def test_top4_of_production_vector(self) -> None:
        assert kvpow.compute_pow(SPEC_SEED)[:4] == bytes.fromhex("00000df4")

    def test_prefix_is_domain_separated(self) -> None:
        assert kvpow.POW_PREFIX == b"MRPOW\x01"


class TestProperties:
    def test_deterministic(self) -> None:
        a = kvpow.compute_pow(SPEC_SEED, difficulty_bits=8)
        b = kvpow.compute_pow(SPEC_SEED, difficulty_bits=8)
        assert a == b

    def test_seed_bound(self) -> None:
        a = kvpow.compute_pow("alpha seed", difficulty_bits=8)
        b = kvpow.compute_pow("beta seed", difficulty_bits=8)
        assert a != b

    def test_output_is_32_bytes(self) -> None:
        assert len(kvpow.compute_pow(SPEC_SEED, difficulty_bits=8)) == 32

    def test_satisfies_requested_difficulty(self) -> None:
        out = kvpow.compute_pow(SPEC_SEED, difficulty_bits=12)
        assert kvpow.leading_zero_bits(out) >= 12

    def test_difficulty_zero_returns_first_hash(self) -> None:
        out = kvpow.compute_pow(SPEC_SEED, difficulty_bits=0)
        assert len(out) == 32

    def test_negative_difficulty_rejected(self) -> None:
        with pytest.raises(ValueError):
            kvpow.compute_pow(SPEC_SEED, difficulty_bits=-1)

    def test_excessive_difficulty_rejected(self) -> None:
        # A difficulty above the 256-bit digest width can never be met.
        with pytest.raises(ValueError):
            kvpow.compute_pow(SPEC_SEED, difficulty_bits=257)


class TestLeadingZeroBits:
    @pytest.mark.parametrize(
        ("hexval", "expected"),
        [
            ("ff" + "00" * 31, 0),
            ("80" + "00" * 31, 0),
            ("7f" + "00" * 31, 1),
            ("00" + "ff" + "00" * 30, 8),
            ("00" + "00" + "80" + "00" * 29, 16),
            ("00" + "00" + "00" + "01" + "00" * 28, 31),
            ("00" * 32, 256),
        ],
    )
    def test_count(self, hexval: str, expected: int) -> None:
        assert kvpow.leading_zero_bits(bytes.fromhex(hexval)) == expected
