"""Tests for ``mordred_hermes.keyvault.digest`` — BLAKE3 verification digest.

Phase 4 PR2 second RED → GREEN target (after ``crypto.py`` AES-GCM
primitives in PR1).

The digest binds together SeedPhrase + Passphrase + PoW so cross-machine
recovery can detect mis-transcription before unwrapping the secret.
Canonical algorithm is frozen in
``mordred-docs/dev/SPEC.md §Key generation and verification digest``:

    H               := BLAKE3 (32-byte digest mode)
    seed_hash       := H(SeedPhrase as UTF-8 bytes)
    pass_hash       := H(Passphrase as UTF-8 bytes)
    top4            := PoW_bytes[0:4]
    masked_pass[0:4]  := pass_hash[0:4] XOR top4
    masked_pass[4:32] := pass_hash[4:32]
    digest          := H(seed_hash || masked_pass)        # 32 bytes

Unicode normalization (NFKD + casefold + single-space collapse) is the
caller's responsibility — implemented by ``api.generate`` (Phase 4 PR4),
not by ``compute_digest``. PoW is precomputed by the caller; the digest
module does not re-hash it.
"""

from __future__ import annotations

import pytest

# SPEC fixed vector (canonical regression anchor for the digest algorithm).
# Any future change that perturbs these values requires a SPEC update + PR
# description note.
SPEC_SEED = "test seed"
SPEC_PASS = "test pass"
SPEC_POW = bytes.fromhex("deadbeef" + "00" * 28)
SPEC_SEED_HASH = bytes.fromhex("c18818fa275b46e46836d45540512fb2561a66924b2962d6675ef71c7cdcecf0")
SPEC_PASS_HASH = bytes.fromhex("734cedd9a49ec88207d0c58f757899bd2dc21cf65b6fa0958ff40c81e4ee08eb")
SPEC_MASKED_PASS = bytes.fromhex("ade15336a49ec88207d0c58f757899bd2dc21cf65b6fa0958ff40c81e4ee08eb")
SPEC_DIGEST = bytes.fromhex("25c17b1e1b249dd278f6de52e6e0dddf855fe9943177c99c5428fc1c321b5c93")


class TestSpecFixedVector:
    """SPEC §Key generation and verification digest pinned vector.

    Regression anchor for the digest algorithm. If this ever breaks,
    the PR must explicitly update SPEC.md alongside the code.
    """

    def test_compute_digest_matches_spec_vector(self) -> None:
        from mordred_hermes.keyvault import digest

        assert digest.compute_digest(SPEC_SEED, SPEC_PASS, SPEC_POW) == SPEC_DIGEST


class TestTop4:
    def test_top4_returns_first_four_bytes(self) -> None:
        from mordred_hermes.keyvault import digest

        assert digest.top4(bytes.fromhex("deadbeefcafebabe" + "00" * 24)) == bytes.fromhex("deadbeef")

    def test_top4_accepts_exactly_four_bytes(self) -> None:
        from mordred_hermes.keyvault import digest

        assert digest.top4(b"\x01\x02\x03\x04") == b"\x01\x02\x03\x04"

    def test_top4_rejects_under_four_bytes(self) -> None:
        from mordred_hermes.keyvault import digest

        with pytest.raises(ValueError):
            digest.top4(b"\x01\x02\x03")


class TestComputeDigestDeterminism:
    def test_same_inputs_produce_same_digest(self) -> None:
        from mordred_hermes.keyvault import digest

        a = digest.compute_digest("seed-1", "pass-1", b"\x42" * 32)
        b = digest.compute_digest("seed-1", "pass-1", b"\x42" * 32)
        assert a == b

    def test_digest_is_32_bytes(self) -> None:
        """BLAKE3 default digest length is 32 bytes; SPEC algorithm
        specifies H is BLAKE3 in 32-byte mode."""
        from mordred_hermes.keyvault import digest

        result = digest.compute_digest("s", "p", b"\x00" * 32)
        assert len(result) == 32


class TestComputeDigestSensitivity:
    def test_seed_change_changes_digest(self) -> None:
        from mordred_hermes.keyvault import digest

        a = digest.compute_digest("seed-A", "pass", b"\x00" * 32)
        b = digest.compute_digest("seed-B", "pass", b"\x00" * 32)
        assert a != b

    def test_passphrase_change_changes_digest(self) -> None:
        from mordred_hermes.keyvault import digest

        a = digest.compute_digest("seed", "pass-A", b"\x00" * 32)
        b = digest.compute_digest("seed", "pass-B", b"\x00" * 32)
        assert a != b

    def test_pow_top4_change_changes_digest(self) -> None:
        """Different ``top4(PoW)`` must produce different digests — this
        is the cross-machine recovery anti-replay property."""
        from mordred_hermes.keyvault import digest

        a = digest.compute_digest("seed", "pass", b"\x00" * 32)
        b = digest.compute_digest("seed", "pass", b"\xff\xff\xff\xff" + b"\x00" * 28)
        assert a != b

    def test_pow_bytes_4_onward_do_not_affect_digest(self) -> None:
        """SPEC algorithm uses ONLY ``PoW_bytes[:4]`` — any change to bytes
        beyond index 3 must be ignored. Protects against attackers
        crafting PoWs with mismatched tails."""
        from mordred_hermes.keyvault import digest

        a = digest.compute_digest("seed", "pass", b"\xde\xad\xbe\xef" + b"\x00" * 28)
        b = digest.compute_digest("seed", "pass", b"\xde\xad\xbe\xef" + b"\xff" * 28)
        assert a == b


class TestXorWidth:
    """Codex review #1 BLOCKER: SPEC formula ``hash(Passphrase) ⊕ top4(PoW)``
    was ambiguous (XOR top 4 bytes only, or extend to 32). Canonical
    answer: XOR affects ONLY the first 4 bytes of pass_hash.

    Third-pass note (codex LOW-4, 2026-05-14): the first two tests
    compare SPEC fixture constants against each other — they prove
    the SPEC vector is internally consistent but do NOT exercise the
    implementation. The two new tests below derive ``pass_hash`` from
    :mod:`blake3` directly and probe :func:`compute_digest` to ensure
    the impl honors the canonical XOR width.
    """

    def test_pass_hash_tail_passes_through_unchanged(self) -> None:
        """``masked_pass[4:]`` must equal ``pass_hash[4:]`` — no XOR is
        applied beyond index 3. Self-consistency of the SPEC fixture
        vector."""
        assert SPEC_MASKED_PASS[4:] == SPEC_PASS_HASH[4:]

    def test_pass_hash_head_xored_with_top4(self) -> None:
        """``masked_pass[:4] == pass_hash[:4] XOR top4(pow)`` —
        self-consistency of the SPEC fixture vector."""
        expected_head = bytes(p ^ t for p, t in zip(SPEC_PASS_HASH[:4], SPEC_POW[:4], strict=True))
        assert SPEC_MASKED_PASS[:4] == expected_head

    def test_compute_digest_xor_width_via_implementation(self) -> None:
        """End-to-end: compute pass_hash from :mod:`blake3` directly,
        construct what masked_pass MUST be under the canonical
        algorithm (first 4 bytes XOR'd, rest unchanged), then feed
        ``H(seed_hash || masked_pass)`` through BLAKE3 and compare to
        ``compute_digest`` output.

        Codex LOW-4 (2026-05-14): the previous two tests proved the
        SPEC fixture was internally consistent but did not exercise
        the impl. If a regression made ``compute_digest`` XOR the
        full 32 bytes (with zero-pad) or skip the XOR entirely, those
        tests still passed. This test exercises the impl end-to-end
        against a model built from primitives, so any drift trips.
        """
        from blake3 import blake3

        from mordred_hermes.keyvault import digest

        seed = "round-trip seed"
        passphrase = "round-trip pass"
        pow_bytes = bytes.fromhex("12345678" + "ab" * 28)

        # Build the expected digest by hand from BLAKE3 primitives.
        seed_hash = blake3(seed.encode("utf-8")).digest()
        pass_hash = blake3(passphrase.encode("utf-8")).digest()
        expected_masked = bytes(p ^ t for p, t in zip(pass_hash[:4], pow_bytes[:4], strict=True)) + pass_hash[4:]
        expected_digest = blake3(seed_hash + expected_masked).digest()

        # Impl output must match the hand-built value.
        actual = digest.compute_digest(seed, passphrase, pow_bytes)
        assert actual == expected_digest

    def test_compute_digest_tail_of_pow_does_not_leak_into_pass_hash_tail(self) -> None:
        """A regression that XORs ``pow_bytes`` against ``pass_hash``
        as 32-byte zero-padded values would let bytes [4:] of pow_bytes
        affect ``masked_pass[4:]``. Canonical uses only ``pow_bytes[:4]``,
        so two PoWs with same top4 but different tail must produce the
        same digest."""
        from mordred_hermes.keyvault import digest

        pow_a = b"\xde\xad\xbe\xef" + b"\x00" * 28
        pow_b = b"\xde\xad\xbe\xef" + b"\xa5" * 28
        a = digest.compute_digest("s", "p", pow_a)
        b = digest.compute_digest("s", "p", pow_b)
        assert a == b


class TestVerifyDigest:
    def test_verify_digest_succeeds_on_match(self) -> None:
        from mordred_hermes.keyvault import digest

        # Should not raise.
        digest.verify_digest(SPEC_SEED, SPEC_PASS, SPEC_POW, expected=SPEC_DIGEST)

    def test_verify_digest_raises_on_mismatch(self) -> None:
        from mordred_hermes.keyvault import digest

        wrong = bytes(32)
        with pytest.raises(digest.VerificationDigestMismatch):
            digest.verify_digest(SPEC_SEED, SPEC_PASS, SPEC_POW, expected=wrong)

    def test_verify_digest_rejects_short_expected(self) -> None:
        """Codex review #6: digest is always 32 bytes. An ``expected`` of
        the wrong length must NOT trigger constant-time compare on
        mismatched-size inputs — instead raise the same mismatch
        exception, so callers can't smuggle in length confusion."""
        from mordred_hermes.keyvault import digest

        with pytest.raises(digest.VerificationDigestMismatch):
            digest.verify_digest(SPEC_SEED, SPEC_PASS, SPEC_POW, expected=b"\x00" * 31)

    def test_verify_digest_rejects_long_expected(self) -> None:
        """Companion to short_expected: 33-byte ``expected`` is also a
        mismatch (the algorithm only ever emits 32 bytes)."""
        from mordred_hermes.keyvault import digest

        with pytest.raises(digest.VerificationDigestMismatch):
            digest.verify_digest(SPEC_SEED, SPEC_PASS, SPEC_POW, expected=b"\x00" * 33)

    def test_verify_digest_uses_constant_time_compare(self, monkeypatch) -> None:  # type: ignore[no-untyped-def]
        """The implementation MUST use ``hmac.compare_digest`` (or
        equivalent timing-safe primitive). Verified via monkeypatched
        spy. Rationale: a timing attack on the verification step could
        leak the first-byte boundary at which the user's transcribed
        digest differs from the canonical one, narrowing the attacker's
        search space.
        """
        import hmac as _hmac

        from mordred_hermes.keyvault import digest

        real_compare = _hmac.compare_digest
        calls: list[tuple[bytes, bytes]] = []

        def spy(a: object, b: object) -> bool:
            calls.append((bytes(a), bytes(b)))  # type: ignore[arg-type]
            return real_compare(a, b)  # type: ignore[arg-type]

        # Patch the symbol that digest.py imported, not the global one.
        monkeypatch.setattr(digest, "_compare_digest", spy, raising=True)
        digest.verify_digest(SPEC_SEED, SPEC_PASS, SPEC_POW, expected=SPEC_DIGEST)

        assert calls, "verify_digest must route equality through a timing-safe primitive (e.g. hmac.compare_digest)"


class TestVerificationDigestMismatchException:
    def test_exception_is_value_error_subclass(self) -> None:
        """The exception must be a ``ValueError`` so callers using
        ``except ValueError:`` for input-validation handling catch it
        naturally, without special-casing the keyvault module."""
        from mordred_hermes.keyvault.digest import VerificationDigestMismatch

        assert issubclass(VerificationDigestMismatch, ValueError)
