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
        assert result.returncode == 0, f"--self-test failed: stdout={result.stdout!r} stderr={result.stderr!r}"

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
        assert result.returncode == 0, f"interactive run failed: stdout={result.stdout!r} stderr={result.stderr!r}"
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
            f"noisy seed should normalise to the canonical SPEC digest; got stdout={result.stdout!r}"
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
            "uppercase passphrase must not produce the canonical digest (NFKD-only normalisation preserves case)"
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
    def _import_statements(self) -> list[str]:
        """Parse the script and return every ``import …`` / ``from … import …``
        statement as source text. Docstring cross-references that mention
        a package name do not count — only actual imports.
        """
        import ast

        tree = ast.parse(_SCRIPT.read_text(encoding="utf-8"))
        out: list[str] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                out.extend(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                # ImportFrom.module can be None for "from . import x"; guard it.
                out.append(node.module or "")
        return out

    def test_script_imports_no_mordred_hermes_module(self) -> None:
        """The script must be runnable on an air-gapped machine that
        only has ``python3`` + ``blake3`` — it must not *import* any
        ``mordred_hermes`` module. Docstring cross-references are fine
        (and useful: drift warning), so this checks AST imports only.
        """
        imports = self._import_statements()
        offenders = [m for m in imports if m.startswith("mordred_hermes")]
        assert not offenders, (
            f"scripts/keyvault_offline_digest.py imports {offenders!r} — "
            "must not depend on the mordred_hermes package (offline portability)"
        )

    def test_script_imports_no_other_third_party_beyond_blake3(self) -> None:
        """Allow-list: stdlib + ``blake3`` only. If a future change
        pulls in ``cryptography``, ``argon2``, …, the operator-prep
        instructions in setup.md break silently."""
        imports = self._import_statements()
        # Forbidden third-party top-level packages that have appeared in
        # adjacent keyvault modules. Match on the leading dotted segment.
        forbidden = {"cryptography", "argon2", "pyobjc", "mordred_hermes"}
        offenders = [m for m in imports if m.split(".", 1)[0] in forbidden]
        assert not offenders, (
            f"scripts/keyvault_offline_digest.py imports {offenders!r} — breaks the stdlib + blake3 invariant"
        )


class TestBlake3Bootstrap:
    """When ``blake3`` is absent the script must guide the operator instead
    of dumping a bare ``ModuleNotFoundError``: on a dev checkout it re-execs
    under the bundled venv so the command ``keyvault init`` prints
    (``python3 scripts/keyvault_offline_digest.py``) just works; on an
    air-gapped device it falls through to an install hint.

    These are static source checks (same philosophy as
    :class:`TestOfflinePortability`): the test environment always has
    blake3, so the ImportError branch can't be exercised at runtime here.
    """

    def _source(self) -> str:
        return _SCRIPT.read_text(encoding="utf-8")

    def test_import_error_is_handled(self) -> None:
        assert "except ImportError" in self._source()

    def test_reexec_under_bundled_venv_with_loop_guard(self) -> None:
        src = self._source()
        assert "os.execv" in src
        assert ".venv" in src and "mordred-hermes" in src
        assert "_KV_OFFLINE_REEXEC" in src  # guards against an infinite re-exec loop

    def test_install_hint_mentions_both_paths(self) -> None:
        src = self._source()
        assert "pip install blake3" in src  # bare offline device
        assert "mordred-hermes/.venv/bin/python" in src  # this dev checkout

    def test_reexec_uses_only_stdlib(self) -> None:
        """The bootstrap must not pull in a third-party package — the
        offline-portability invariant (stdlib + blake3) still holds."""
        import ast

        tree = ast.parse(self._source())
        modules: list[str] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                modules.extend(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                modules.append(node.module or "")
        third_party = [m for m in modules if m.split(".", 1)[0] not in {*sys.stdlib_module_names, "blake3"}]
        assert not third_party, f"bootstrap introduced non-stdlib import(s): {third_party!r}"


@pytest.mark.skipif(not _SCRIPT.exists(), reason="script not yet implemented (RED)")
class TestScriptExists:
    """Sanity guard so the absence of the script reports as one clean
    skipped class rather than every test above erroring on FileNotFound."""

    def test_script_file_present(self) -> None:
        assert _SCRIPT.is_file()
