"""Tests for ``scripts/keyvault_offline_digest.py`` — operator-facing tool.

The standalone script is what an operator runs on an air-gapped second
device during ``keyvault init`` step 4 (SPEC §"keyvault init flow"). It
must reproduce the canonical ``digest.compute_digest`` output without
importing any ``mordred_hermes`` code, so it can be carried to an
isolated machine that only has ``python3`` + ``blake3`` installed.

These tests pin three properties:

1. ``--self-test`` exits 0 and validates the SPEC fixed vector.
2. Interactive (stdin) mode produces the same digest as
   :func:`mordred_hermes.keyvault.digest.compute_digest`.
3. The script source contains no ``mordred_hermes`` imports — a static
   check that the offline-portable invariant is not silently broken by
   a future refactor.

The third check is intentionally a grep, not a runtime test: the script
might never import mordred_hermes at runtime even if it referenced it,
but the *file* dependency would still break the air-gap workflow.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

# Locate the script via the worktree root (this file is
# <worktree>/mordred-hermes/tests/<this>.py).
_REPO_ROOT = Path(__file__).resolve().parents[2]
_SCRIPT = _REPO_ROOT / "scripts" / "keyvault_offline_digest.py"

# Reuse the canonical SPEC vector from test_keyvault_digest. Keeping the
# constants duplicated locally would let the two test files drift; the
# regression anchor lives in test_keyvault_digest and we import it.
from tests.test_keyvault_digest import (  # noqa: E402
    SPEC_DIGEST,
    SPEC_PASS,
    SPEC_POW,
    SPEC_SEED,
)


def _run(stdin: str, *args: str) -> subprocess.CompletedProcess[str]:
    """Run the script with the current Python interpreter and given stdin."""
    return subprocess.run(
        [sys.executable, str(_SCRIPT), *args],
        input=stdin,
        capture_output=True,
        text=True,
        timeout=30,
    )


class TestSelfTest:
    def test_self_test_exits_zero(self) -> None:
        """``--self-test`` validates SPEC fixed vector and exits 0."""
        result = _run("", "--self-test")
        assert result.returncode == 0, (
            f"--self-test failed: stdout={result.stdout!r} stderr={result.stderr!r}"
        )

    def test_self_test_mentions_spec_digest(self) -> None:
        """Self-test output reports the SPEC digest hex so an operator
        can eyeball-confirm the regression anchor."""
        result = _run("", "--self-test")
        assert SPEC_DIGEST.hex() in result.stdout


class TestInteractiveDigest:
    def test_spec_vector_via_stdin(self) -> None:
        """Pipe SPEC seed / passphrase / top4-hex through stdin; the
        script must print the canonical 32-byte digest hex."""
        stdin = f"{SPEC_SEED}\n{SPEC_PASS}\n{SPEC_POW[:4].hex()}\n"
        result = _run(stdin)
        assert result.returncode == 0, (
            f"interactive run failed: stdout={result.stdout!r} stderr={result.stderr!r}"
        )
        assert SPEC_DIGEST.hex() in result.stdout

    def test_matches_in_repo_compute_digest(self) -> None:
        """End-to-end equivalence: the script's digest output must
        match :func:`mordred_hermes.keyvault.digest.compute_digest` for
        a non-SPEC input (proves the algorithm copy is faithful, not
        just memorised for the SPEC vector)."""
        from mordred_hermes.keyvault import digest

        seed = "round-trip seed"
        passphrase = "round-trip pass"
        pow_bytes = bytes.fromhex("12345678" + "ab" * 28)
        expected_hex = digest.compute_digest(seed, passphrase, pow_bytes).hex()

        stdin = f"{seed}\n{passphrase}\n{pow_bytes[:4].hex()}\n"
        result = _run(stdin)
        assert result.returncode == 0
        assert expected_hex in result.stdout

    def test_seed_normalization_matches_canonical(self) -> None:
        """Seed phrase normalization is NFKD + strip Cf + casefold +
        whitespace-collapse (api._normalize_seed_phrase). Feeding a
        mixed-case seed with a zero-width joiner and double spaces must
        produce the same digest as the clean SPEC vector."""
        from mordred_hermes.keyvault import digest

        # The canonical seed "test seed" with mixed case, ZWJ injected,
        # and double-space — all of which must be normalised away.
        noisy_seed = "Test‍  Seed"
        expected_hex = digest.compute_digest(SPEC_SEED, SPEC_PASS, SPEC_POW).hex()

        stdin = f"{noisy_seed}\n{SPEC_PASS}\n{SPEC_POW[:4].hex()}\n"
        result = _run(stdin)
        assert result.returncode == 0
        assert expected_hex in result.stdout, (
            "noisy seed should normalise to the canonical SPEC digest; "
            f"got stdout={result.stdout!r}"
        )

    def test_passphrase_preserves_case_and_invisibles(self) -> None:
        """Passphrase normalization is NFKD only — case and Cf chars
        are entropy and must NOT collapse. A passphrase that differs
        from canonical only in case must produce a *different* digest."""
        wrong_case_pass = SPEC_PASS.upper()

        stdin = f"{SPEC_SEED}\n{wrong_case_pass}\n{SPEC_POW[:4].hex()}\n"
        result = _run(stdin)
        assert result.returncode == 0
        assert SPEC_DIGEST.hex() not in result.stdout, (
            "uppercase passphrase must not produce the canonical digest "
            "(NFKD-only normalisation preserves case)"
        )


class TestInputValidation:
    def test_invalid_top4_hex_exits_nonzero(self) -> None:
        """Non-hex top4 input is a fatal error."""
        stdin = f"{SPEC_SEED}\n{SPEC_PASS}\nNOT_HEX\n"
        result = _run(stdin)
        assert result.returncode != 0

    def test_short_top4_hex_exits_nonzero(self) -> None:
        """top4 must be exactly 4 bytes = 8 hex chars."""
        stdin = f"{SPEC_SEED}\n{SPEC_PASS}\ndead\n"  # 2 bytes only
        result = _run(stdin)
        assert result.returncode != 0


class TestOfflinePortability:
    def test_script_has_no_mordred_imports(self) -> None:
        """The script must be runnable on an air-gapped machine that
        only has ``python3`` + ``blake3`` — it must not import any
        ``mordred_hermes`` module. Static check on the source."""
        source = _SCRIPT.read_text(encoding="utf-8")
        assert "mordred_hermes" not in source, (
            "scripts/keyvault_offline_digest.py must not depend on the "
            "mordred_hermes package — it has to run on a stripped-down "
            "offline device with only stdlib + blake3 available"
        )

    def test_script_has_no_third_party_imports_beyond_blake3(self) -> None:
        """Allow-list: stdlib + ``blake3`` only. If a future change
        pulls in ``cryptography``, ``argon2``, ``mordred_hermes``, …
        the operator-prep instructions in setup.md break silently."""
        source = _SCRIPT.read_text(encoding="utf-8")
        # Forbidden third-party tokens that have appeared in adjacent
        # keyvault modules. Not exhaustive — defence in depth.
        for forbidden in ("cryptography", "argon2", "pyobjc"):
            assert forbidden not in source, (
                f"scripts/keyvault_offline_digest.py imports/references "
                f"'{forbidden}' — that breaks the offline-portable invariant"
            )


@pytest.mark.skipif(not _SCRIPT.exists(), reason="script not yet implemented (RED)")
class TestScriptExists:
    """Sanity guard so the absence of the script reports as one clean
    skipped class rather than every test above erroring on FileNotFound."""

    def test_script_file_present(self) -> None:
        assert _SCRIPT.is_file()
