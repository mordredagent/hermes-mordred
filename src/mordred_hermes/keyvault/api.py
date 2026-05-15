"""mordred_hermes.keyvault.api — public Python API surface.

Phase 4 PR4 step-A landed the split-normalization helpers and the
``verify_digest`` wrapper. Subsequent steps build on this:

- step-B (storage helpers + file-safety)
- step-C (MREN envelope + encrypt / decrypt with purpose binding)
- step-D (prepare_generate / confirm_generate / generate / export_backup /
  import_backup + SeedDisplayHandle)

Authoritative contract lives in ``mordred-docs/mordred/SPEC.md``
§"PR4 API contract & MREN envelope wire format". Codex pre-implementation
review (3 BLOCKER + 5 HIGH) drove the split normalization in this
module: applying ``casefold`` and whitespace-collapse uniformly to the
passphrase weakens entropy, so the two normalizers diverge intentionally.
"""

from __future__ import annotations

import unicodedata

from .digest import VerificationDigestMismatch
from .digest import verify_digest as _digest_verify

__all__ = [
    "VerificationDigestMismatch",
    "verify_digest",
]


def _normalize_seed_phrase(s: str) -> str:
    """Normalize a seed phrase: NFKD + casefold + collapse runs of whitespace.

    BIP39 word-list tolerance — the canonical word list is lowercase ASCII
    and word-separated by a single ASCII space; mixed case and runs of
    whitespace (incl. compatibility-decomposed NBSP / ideographic space)
    are operator-typo noise and are folded away.
    """
    return " ".join(unicodedata.normalize("NFKD", s).casefold().split())


def _normalize_passphrase(s: str) -> str:
    """Normalize a passphrase: NFKD only.

    BIP39 reference behavior (no casefold, no whitespace collapse). Case is
    significant; whitespace is preserved. Casefold would conflate distinct
    Unicode strings into the same entropy; whitespace collapse would drop
    information. See codex review HIGH #1.
    """
    return unicodedata.normalize("NFKD", s)


def verify_digest(
    seed_phrase: str,
    passphrase: str,
    pow_bytes: bytes,
    *,
    expected: bytes,
) -> None:
    """Verify the verification digest with split normalization applied.

    Inputs are normalized at this layer before reaching ``compute_digest``.
    The length-confusion guard (Codex review #6) is inherited from
    :func:`mordred_hermes.keyvault.digest.verify_digest`: any ``expected`` of
    length != 32 raises :exc:`VerificationDigestMismatch` (which is re-
    exported from this module for caller convenience).
    """
    _digest_verify(
        _normalize_seed_phrase(seed_phrase),
        _normalize_passphrase(passphrase),
        pow_bytes,
        expected=expected,
    )
