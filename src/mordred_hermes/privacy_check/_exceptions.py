"""Strict-policy refusal exceptions for ``mordred_privacy_check``.

Hermes wraps plugin callbacks in ``except Exception`` and continues after
ordinary plugin failures.  An integrity-policy refusal must escape that
wrapper, so it inherits directly from :class:`BaseException`.

The refusal is deliberately not a :class:`SystemExit`: policy enforcement is
not an ordinary CLI/process exit, and cleanup code that catches
``SystemExit`` must not accidentally consume it.
"""

from __future__ import annotations

from typing import Literal

# Closed Windows audit-writer refusal vocabulary (C7b). Sticky reasons keep a
# constructed writer refused for the rest of the process; see
# ``privacy_check._windows_audit``.
AuditRefusalReason = Literal[
    "audit-uncertain",
    "audit-unsafe",
    "audit-unavailable",
    "policy-pending",
    "custody-broken",
    "custody-pending",
    "custody-retained",
    "native-key-missing",
    "native-unavailable",
    "retained-ciphertext",
    "history-unrecognized",
    "audit-role-enrolled",
    "entry-rejected",
    "custody-nesting",
    "audit-invalid",
    "interrupted",
]


class MordredIntegrityRefused(BaseException):
    """Strict mode detected a disabled mandatory Mordred sibling plugin."""


class AuditWriterRefused(RuntimeError):
    """Windows audit custody or storage refused the audit writer (fail closed).

    Deliberately an ordinary :class:`Exception`: every Windows caller already
    converts audit-factory failures into its own hard refusal (privacy hooks
    into a tool block or :class:`MordredIntegrityRefused`, llm_guard's
    ``guarded_audit_factory`` and network registration into theirs). A bare
    ``BaseException`` here would bypass those classified conversions.
    """

    def __init__(self, reason: AuditRefusalReason, detail: str = "") -> None:
        message = f"Windows audit writer refused: {reason}"
        super().__init__(f"{message} ({detail})" if detail else message)
        self.reason: AuditRefusalReason = reason


class AuditEntryRejected(ValueError):
    """A Windows audit entry was oversized or unserializable; nothing was written.

    A :class:`ValueError` like the POSIX writers' oversize refusal, but
    distinguishable from invariant/validation ``ValueError`` s raised by the
    checked storage layers.
    """
