"""Strict-policy refusal exceptions for ``mordred_privacy_check``.

Hermes wraps plugin callbacks in ``except Exception`` and continues after
ordinary plugin failures.  An integrity-policy refusal must escape that
wrapper, so it inherits directly from :class:`BaseException`.

The refusal is deliberately not a :class:`SystemExit`: policy enforcement is
not an ordinary CLI/process exit, and cleanup code that catches
``SystemExit`` must not accidentally consume it.
"""

from __future__ import annotations


class MordredIntegrityRefused(BaseException):
    """Strict mode detected a disabled mandatory Mordred sibling plugin."""
