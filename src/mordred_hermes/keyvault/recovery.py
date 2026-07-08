"""mordred_keyvault.recovery — verify-before-decrypt backup restore.

Cross-machine recovery path for backup blobs produced by
:mod:`mordred_hermes.keyvault.backup`. The core safety property
(Codex review #4): when a recomputed digest disagrees with the blob's
embedded verification digest, NO key material is derived and NO
ciphertext is decrypted — the secret is never materialized in memory.

Order of operations inside :func:`import_backup`:

    1. Length-confusion guard on ``recomputed_digest`` (Codex #6) —
       reject != 32 bytes with :class:`RecoveryDigestMismatch` before
       any work.
    2. ``backup.parse_header(blob)`` — structural validation only.
       Raises :class:`mordred_hermes.keyvault.backup.BackupCorrupt`
       on malformed blobs; that exception is NOT remapped to
       :class:`RecoveryDigestMismatch` (callers must distinguish
       "user typed wrong passphrase" / "corrupt file" / "wrong
       transcription" — each maps to a different UX).
    3. Constant-time compare between ``recomputed_digest`` and
       ``parsed.verification_digest``. On mismatch: emit audit (if
       sink supplied) THEN raise :class:`RecoveryDigestMismatch`.
    4. Only on match: ``backup.decrypt_body(parsed, passphrase)``.
       Argon2id KDF runs here. :class:`cryptography.exceptions.InvalidTag`
       (wrong passphrase / header tamper / ciphertext tamper)
       propagates as-is.

Audit sink contract (Codex review #9): a ``Callable[[dict], None]``
that receives a single dict shaped like POLICY.md §Audit entry shape
(``event`` / ``decision`` / ``reason`` / event-specific extras).
The ``ts`` field is added by the upstream Writer, not here.
"""

from __future__ import annotations

from hmac import compare_digest as _compare_digest

from . import backup
from ._audit_emit import chain_and_raise, emit_capture
from .digest import VerificationDigestMismatch
from .wrap import AuditSink

_DIGEST_LEN = 32


class RecoveryDigestMismatch(VerificationDigestMismatch):
    """Raised when the backup blob's embedded verification digest does
    not match the caller-supplied recomputed digest.

    Subclasses :class:`mordred_hermes.keyvault.digest.VerificationDigestMismatch`
    so consumers catching the digest-layer exception catch the
    recovery-layer variant automatically — they represent the same
    user-facing concept (mis-transcription).
    """


def _emit_mismatch(audit_sink: AuditSink | None, *, blob_version: int) -> Exception | None:
    """Best-effort emit of the ``keyvault.recovery_digest_mismatch``
    audit entry. Returns the sink's exception (if any, as an
    :class:`Exception` instance) so the caller can chain it as
    ``__context__`` on the primary :class:`RecoveryDigestMismatch`
    (code-reviewer HIGH-1). The capture / chaining policy — why the sink
    exception must not escape, and why ``except Exception`` rather than
    ``BaseException`` — lives in :mod:`._audit_emit`.
    """
    return emit_capture(
        audit_sink,
        {
            "event": "keyvault.import_backup",
            "decision": "block",
            "reason": "keyvault.recovery_digest_mismatch",
            "blob_version": blob_version,
        },
    )


def import_backup(
    blob: bytes,
    passphrase: str,
    *,
    recomputed_digest: bytes,
    audit_sink: AuditSink | None = None,
) -> bytes:
    """Decrypt a backup blob iff ``recomputed_digest`` matches the
    embedded verification digest.

    Raises :class:`RecoveryDigestMismatch` on mismatch (before any
    KDF / AES work). If ``audit_sink`` itself raises while emitting
    the mismatch entry, the sink exception is chained as
    ``__context__`` so it remains diagnosable without masking the
    primary RecoveryDigestMismatch (code-reviewer HIGH-1).

    Raises :class:`mordred_hermes.keyvault.backup.BackupCorrupt` for
    structurally invalid blobs. Raises
    :class:`cryptography.exceptions.InvalidTag` on wrong passphrase or
    AAD tamper. Returns the original secret bytes on success.
    """
    # 1. Length-confusion guard (Codex review #6).
    if len(recomputed_digest) != _DIGEST_LEN:
        # We do NOT know the blob version yet (parse_header has not
        # run), so emit with version=0 sentinel — POLICY.md entry #17
        # Fields documents this as "pre-parse rejection".
        sink_exc = _emit_mismatch(audit_sink, blob_version=0)
        chain_and_raise(
            RecoveryDigestMismatch(f"recomputed_digest must be {_DIGEST_LEN} bytes, got {len(recomputed_digest)}"),
            sink_exc,
        )

    # 2. Structural validation (no KDF, no AES).
    parsed = backup.parse_header(blob)

    # 3. Verify-before-decrypt (Codex review #4). Constant-time compare.
    if not _compare_digest(parsed.verification_digest, recomputed_digest):
        sink_exc = _emit_mismatch(audit_sink, blob_version=parsed.version)
        chain_and_raise(
            RecoveryDigestMismatch(
                "verification digest mismatch — backup blob does not match "
                "the (seed, passphrase, PoW) transcription provided"
            ),
            sink_exc,
        )

    # 4. Only on match: run the KDF + AES-GCM decryption. InvalidTag
    # propagates to the caller.
    return backup.decrypt_body(parsed, passphrase)
