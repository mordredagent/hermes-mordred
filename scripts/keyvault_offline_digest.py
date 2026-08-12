#!/usr/bin/env python3
"""keyvault_offline_digest.py — operator-facing tool for ``keyvault init``.

During ``hermes-mordred keyvault init`` the operator must independently
recompute the 32-byte verification digest on an *air-gapped second
device* and re-enter it on the primary machine. This script does that
computation. It is **deliberately decoupled** from the ``mordred_hermes``
package so it can be carried to a stripped-down offline machine that
only has ``python3`` + ``blake3`` installed.

The canonical algorithm is frozen in
``docs/dev/SPEC.md §Key generation and verification digest``::

    H               := BLAKE3 (32-byte digest mode)
    seed_hash       := H(SeedPhrase as UTF-8 bytes)
    pass_hash       := H(Passphrase as UTF-8 bytes)
    top4            := PoW_bytes[0:4]
    masked_pass[0:4]  := pass_hash[0:4] XOR top4
    masked_pass[4:32] := pass_hash[4:32]
    digest          := H(seed_hash || masked_pass)        # 32 bytes

Unicode normalization rules (copied verbatim from
``mordred-hermes/src/mordred_hermes/keyvault/api.py``):

* Seed phrase: NFKD + strip Cf-category chars + casefold +
  whitespace-collapse. Seed words come from the BIP39 list (lowercase
  ASCII, single-space separated) so mixed case, NBSP, and clipboard ZWSP
  injection must fold away.
* Passphrase: NFKD only. Case is significant, whitespace is preserved,
  Cf chars are entropy — collapsing any of them would conflate distinct
  passphrase choices.

Operator preparation (see ``docs/dev/setup.md``):

    1. On a second device that has internet: ``pip install blake3``
    2. Copy this file to the second device (USB / QR / printed-and-typed).
    3. Take the second device offline (Wi-Fi off, etc.).
    4. ``python3 keyvault_offline_digest.py``
    5. Transcribe the printed digest back to the primary machine.

Self-test::

    python3 keyvault_offline_digest.py --self-test

Validates the SPEC fixed vector (``"test seed"`` / ``"test pass"`` /
``deadbeef…``) → digest
``25c17b1e1b249dd278f6de52e6e0dddf855fe9943177c99c5428fc1c321b5c93``.
"""

from __future__ import annotations

import argparse
import contextlib
import getpass
import os
import sys
import unicodedata
from pathlib import Path

try:
    from blake3 import blake3
except ImportError as err:  # pragma: no cover - only reached when blake3 is absent
    # blake3 is missing in THIS interpreter. `keyvault init` tells the
    # operator to run `python3 scripts/keyvault_offline_digest.py`; on a dev
    # checkout the system python3 usually lacks blake3, so make that command
    # "just work" by re-executing under the bundled mordred-hermes venv,
    # which always has blake3. The operator then never needs the venv path.
    #
    # The _KV_OFFLINE_REEXEC env guard prevents an infinite loop if the venv
    # python ALSO lacks blake3. On a stripped-down air-gapped device the venv
    # path does not exist, so we skip the re-exec and fall through to the
    # install hint below (the script stays portable — see SPEC offline tool).
    _venv_python = Path(__file__).resolve().parents[1] / ".venv" / "bin" / "python"
    _script = str(Path(__file__).resolve())
    if not os.environ.get("_KV_OFFLINE_REEXEC") and _venv_python.exists():
        os.environ["_KV_OFFLINE_REEXEC"] = "1"
        sys.stderr.write(
            f"note: blake3 not found in this Python; re-running under the bundled venv ({_venv_python}).\n"
        )
        with contextlib.suppress(OSError):
            os.execv(str(_venv_python), [str(_venv_python), _script, *sys.argv[1:]])
        # if execv raised OSError, fall through to the install hint below
    sys.stderr.write(
        "\n"
        "error: the 'blake3' package is required but is not installed in the\n"
        "Python you ran this with.\n"
        "\n"
        "Easiest fix on this checkout — from the repo root, use the bundled\n"
        "venv that already has blake3 (this is what `keyvault init` expects):\n"
        "\n"
        "    .venv/bin/python scripts/keyvault_offline_digest.py\n"
        "\n"
        "On a stripped-down OFFLINE device (the air-gapped second device),\n"
        "install blake3 first, then re-run:\n"
        "\n"
        "    python3 -m pip install blake3\n"
        "    python3 keyvault_offline_digest.py\n"
        "\n"
    )
    raise SystemExit(1) from err

# SPEC fixed vector. Must match
# mordred-hermes/tests/test_keyvault_digest.py:SPEC_*. If the canonical
# algorithm ever changes (SPEC update), both pins move together.
_SPEC_SEED = "test seed"
_SPEC_PASS = "test pass"
_SPEC_POW_TOP4 = bytes.fromhex("deadbeef")
_SPEC_DIGEST_HEX = "25c17b1e1b249dd278f6de52e6e0dddf855fe9943177c99c5428fc1c321b5c93"


def _normalize_seed_phrase(s: str) -> str:
    """NFKD + strip Cf chars + casefold + collapse whitespace.

    Copied verbatim from ``mordred_hermes.keyvault.api._normalize_seed_phrase``.
    DO NOT diverge from the upstream implementation — drift here means
    the operator's computed digest will silently disagree with the
    primary machine's expected digest, and init will reject.
    """
    decomposed = unicodedata.normalize("NFKD", s)
    stripped = "".join(ch for ch in decomposed if unicodedata.category(ch) != "Cf")
    return " ".join(stripped.casefold().split())


def _normalize_passphrase(s: str) -> str:
    """NFKD only — preserves case, whitespace, and Cf chars.

    Copied verbatim from ``mordred_hermes.keyvault.api._normalize_passphrase``.
    Same drift warning as ``_normalize_seed_phrase``.
    """
    return unicodedata.normalize("NFKD", s)


def compute_digest(seed_phrase: str, passphrase: str, top4: bytes) -> bytes:
    """Compute the 32-byte verification digest from already-normalized inputs.

    ``top4`` MUST be exactly 4 bytes (``PoW_bytes[:4]``); the script
    rejects other lengths in :func:`_read_top4`. Inputs are encoded as
    UTF-8 as-is — the caller is responsible for normalization
    (see :func:`_normalize_seed_phrase` / :func:`_normalize_passphrase`).
    """
    if len(top4) != 4:
        raise ValueError(f"top4 must be exactly 4 bytes, got {len(top4)}")
    seed_hash = blake3(seed_phrase.encode("utf-8")).digest()
    pass_hash = blake3(passphrase.encode("utf-8")).digest()
    # No zip(strict=) or other 3.10+-only syntax here: this file must keep
    # running on stock system pythons (3.8/3.9) on the air-gapped second
    # device, and both operands are provably 4 bytes (digest slice + the
    # length check above).
    masked_pass = bytes(pass_hash[i] ^ top4[i] for i in range(4)) + pass_hash[4:]
    return blake3(seed_hash + masked_pass).digest()


def _read_top4(raw: str) -> bytes:
    """Parse ``top4(PoW)`` hex (8 chars → 4 bytes). Raises ValueError
    on any non-hex char or wrong length."""
    cleaned = raw.strip()
    try:
        top4 = bytes.fromhex(cleaned)
    except ValueError as exc:
        raise ValueError(f"top4(PoW) is not valid hex: {exc}") from None
    if len(top4) != 4:
        raise ValueError(f"top4(PoW) must be exactly 4 bytes = 8 hex chars; got {len(top4)} bytes")
    return top4


def _self_test() -> int:
    """Recompute the SPEC fixed vector and compare to the pinned digest.

    Returns 0 on match, 1 on mismatch. The pinned digest is printed
    either way so the operator can eyeball-check it against a trusted
    reference (e.g. SPEC.md or a printed copy).
    """
    actual = compute_digest(_SPEC_SEED, _SPEC_PASS, _SPEC_POW_TOP4)
    actual_hex = actual.hex()
    print(f"SPEC fixed vector digest: {_SPEC_DIGEST_HEX}")
    print(f"Computed digest:          {actual_hex}")
    if actual_hex == _SPEC_DIGEST_HEX:
        print("OK - algorithm matches SPEC.")
        return 0
    print(
        "MISMATCH - algorithm has drifted from SPEC. Do NOT trust this script.",
        file=sys.stderr,
    )
    return 1


def _interactive_compute() -> int:
    """Prompt for seed / passphrase / top4 and print the digest hex.

    Reads from stdin so the script is testable via subprocess pipes;
    the passphrase prompt routes through :func:`getpass.getpass` which
    falls back to plain stdin (with a stderr warning) when stdin is not
    a TTY. That fallback is desirable on the second device too if the
    operator pipes inputs from a file for any reason.
    """
    print("────────────────────────────────────────────────────────────", file=sys.stderr)
    print("  Mordred keyvault — offline verification digest", file=sys.stderr)
    print("────────────────────────────────────────────────────────────", file=sys.stderr)
    print(
        "  Transcribe THREE values shown on the primary device (the one",
        file=sys.stderr,
    )
    print("  running `keyvault init`). Nothing is written to disk.", file=sys.stderr)
    print(file=sys.stderr)

    print("  [1/3] Seed Phrase", file=sys.stderr)
    print(
        "        Format : 24 BIP39 words on ONE line, separated by spaces.",
        file=sys.stderr,
    )
    print("        Example: abandon ability able about ... actual", file=sys.stderr)
    print("        Note   : case and extra spaces are normalized.", file=sys.stderr)
    raw_seed = input("        > ")
    print(file=sys.stderr)

    print("  [2/3] Passphrase", file=sys.stderr)
    print("        Format : the exact passphrase you typed during init.", file=sys.stderr)
    print(
        "        Note   : input is HIDDEN (no echo). Case and whitespace matter.",
        file=sys.stderr,
    )
    raw_pass = getpass.getpass("        > ")
    print(file=sys.stderr)

    print("  [3/3] top4(PoW) hex", file=sys.stderr)
    print(
        "        Format : EXACTLY 8 hex characters (4 bytes). No '0x' prefix.",
        file=sys.stderr,
    )
    print(
        "        Source : the `[3] top4(PoW) hex → XXXXXXXX` line in the",
        file=sys.stderr,
    )
    print(
        "                 primary banner shown just before the 24 words.",
        file=sys.stderr,
    )
    print("        Example: 00000a4e", file=sys.stderr)
    raw_top4 = input("        > ")

    try:
        top4 = _read_top4(raw_top4)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    seed = _normalize_seed_phrase(raw_seed)
    passphrase = _normalize_passphrase(raw_pass)
    digest = compute_digest(seed, passphrase, top4)

    # Best-effort drop of the raw strings. CPython cannot zero an
    # immutable str in place — this only shortens the exposure window,
    # it does not scrub the bytes. The operator's threat model is
    # "primary machine air-gapped" + "second device air-gapped";
    # in-process memory hygiene is a third-tier mitigation.
    del raw_seed, raw_pass, raw_top4, seed, passphrase

    print()
    print(f"verification digest: {digest.hex()}")
    print()
    print(
        "Re-enter this hex on the primary device at the `Verification digest from your offline device (hex)` prompt.",
        file=sys.stderr,
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="keyvault_offline_digest.py",
        description=(
            "Compute the Mordred keyvault verification digest on an air-gapped second device during `keyvault init`."
        ),
    )
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="Validate the SPEC fixed vector and exit (no prompts).",
    )
    args = parser.parse_args(argv)

    if args.self_test:
        return _self_test()
    return _interactive_compute()


if __name__ == "__main__":
    raise SystemExit(main())
