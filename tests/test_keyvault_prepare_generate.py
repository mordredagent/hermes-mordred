"""Tests for the in-memory ``prepare_generate`` lifecycle phase."""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from mordred_hermes.keyvault import api
from tests._keyvault_lifecycle_helpers import (
    _SPEC_DIGEST,
    _SPEC_PASSPHRASE,
    _SPEC_POW,
    _SPEC_SEED,
)

# ============================ prepare_generate (in-memory phase) ============================
#
# Contract frozen in SPEC.md §"PR4 API contract / Two-phase generate":
#
#     def prepare_generate(
#         seed_phrase: str,
#         passphrase: str,
#         pow_bytes: bytes,
#     ) -> tuple[SeedDisplayHandle, bytes]:
#         # In-memory only. Computes digest from normalized inputs.
#         # NO Keychain creation, NO meta.json write, NO digests/ commit,
#         # NO audit emit. Pure function with respect to disk state.
#
# Normalization split (SPEC.md §"Mordred normalization", codex HIGH #1):
#   - seed_phrase: NFKD + strip Cf chars + casefold + collapse whitespace
#   - passphrase: NFKD only — case and whitespace are entropy, must NOT collapse


class TestPrepareGenerateSeedNormalization:
    """Seed phrase: NFKD + Cf-strip + casefold + whitespace-collapse.

    BIP39 word-list tolerance — typo-noise (mixed case, extra spaces,
    non-ASCII whitespace forms, invisible Cf chars from clipboard
    injection) collapses to the same digest as a clean reference input.
    """

    def test_seed_zwsp_stripped_via_cf_category(self) -> None:
        """U+200B ZERO WIDTH SPACE is Cf-category — NFKD-stable and not a
        whitespace split, so without explicit Cf-strip it would silently
        change the digest. The strip closes the clipboard-injection gap
        (code-reviewer MEDIUM-1, 2026-05-15).
        """
        _, ref = api.prepare_generate("test seed", _SPEC_PASSPHRASE, _SPEC_POW)
        _, with_zwsp = api.prepare_generate("te​st seed", _SPEC_PASSPHRASE, _SPEC_POW)
        assert ref == with_zwsp

    def test_seed_japanese_precomposed_equals_decomposed(self) -> None:
        """NFKD decomposes Japanese precomposed dakuon (e.g. が U+304C) into
        base + combining mark (か U+304B + U+3099). The two input forms
        must produce the same digest.
        """
        precomposed = "がぎぐげご"
        decomposed = "がぎぐげご"
        _, d_pre = api.prepare_generate(precomposed, _SPEC_PASSPHRASE, _SPEC_POW)
        _, d_dec = api.prepare_generate(decomposed, _SPEC_PASSPHRASE, _SPEC_POW)
        assert d_pre == d_dec


class TestPrepareGeneratePassphraseNormalization:
    """Passphrase: NFKD only. Case and whitespace are entropy.

    Casefold-collapse on the passphrase would conflate distinct Unicode
    strings; whitespace-collapse drops entropy. The split exists exactly
    so the passphrase preserves what the user actually typed (codex HIGH
    #1). NFKD is still applied so Japanese precomposed/decomposed
    equivalence holds.
    """

    def test_passphrase_case_change_changes_digest(self) -> None:
        """A casefold of the passphrase would silently mask a typo at
        recovery time. Recovery requires reproducing the exact case.
        """
        _, lower = api.prepare_generate(_SPEC_SEED, "secret", _SPEC_POW)
        _, upper = api.prepare_generate(_SPEC_SEED, "SECRET", _SPEC_POW)
        assert lower != upper

    def test_passphrase_extra_whitespace_changes_digest(self) -> None:
        _, single = api.prepare_generate(_SPEC_SEED, "a b", _SPEC_POW)
        _, double = api.prepare_generate(_SPEC_SEED, "a  b", _SPEC_POW)
        assert single != double

    def test_passphrase_zwsp_changes_digest(self) -> None:
        """Passphrase normalization does NOT strip Cf chars — a user who
        chose to embed an invisible char did so intentionally and must
        reproduce the exact bytes on recovery.
        """
        _, clean = api.prepare_generate(_SPEC_SEED, "secret", _SPEC_POW)
        _, with_zwsp = api.prepare_generate(_SPEC_SEED, "sec​ret", _SPEC_POW)
        assert clean != with_zwsp

    def test_passphrase_japanese_precomposed_equals_decomposed(self) -> None:
        """NFKD is applied to the passphrase, so Japanese precomposed and
        decomposed forms still produce the same digest — this is the only
        normalization gate that fires on the passphrase side.
        """
        precomposed = "がぎぐげご"
        decomposed = "がぎぐげご"
        _, d_pre = api.prepare_generate(_SPEC_SEED, precomposed, _SPEC_POW)
        _, d_dec = api.prepare_generate(_SPEC_SEED, decomposed, _SPEC_POW)
        assert d_pre == d_dec


class TestPrepareGenerateHandleBehavior:
    """The returned ``SeedDisplayHandle`` holds the *normalized* seed and
    expires roughly 60s from the call site (default TTL from SPEC).
    """

    def test_handle_consume_returns_normalized_seed(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Casefold and whitespace-collapse must have been applied to the
        bytes the handle carries — PR5's display flow renders this string
        back to the user, so it has to match what compute_digest hashed.
        """
        monkeypatch.setenv("HERMES_HOME", str(tmp_path))
        before = sorted(tmp_path.rglob("*"))
        seed = "  TEST\t  SEED\u00a0 "
        handle, digest = api.prepare_generate(seed, _SPEC_PASSPHRASE, _SPEC_POW)
        second, _ = api.prepare_generate(seed, _SPEC_PASSPHRASE, _SPEC_POW)
        assert handle is not second
        assert sorted(tmp_path.rglob("*")) == before
        assert handle.consume() == "test seed"
        assert second.consume() == "test seed"
        assert digest == _SPEC_DIGEST

    def test_handle_deadline_is_approximately_60s_in_future(self) -> None:
        """Default TTL per SPEC: ``time.monotonic() + 60.0``. White-box
        check against ``_deadline`` so the wipe-on-expiry path is
        actually reachable from the value baked in here.
        """
        before = time.monotonic()
        handle, _ = api.prepare_generate(_SPEC_SEED, _SPEC_PASSPHRASE, _SPEC_POW)
        after = time.monotonic()
        # The deadline must lie in the window [before+60, after+60] —
        # the only ambiguity is the time spent inside the call.
        deadline = handle._deadline  # type: ignore[attr-defined]
        assert before + 60.0 <= deadline <= after + 60.0
