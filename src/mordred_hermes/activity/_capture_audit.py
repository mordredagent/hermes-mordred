"""``activity.capture_refused``: one audit entry per process and refusal code.

The receiver (recording) and the recall tools (reading) share the dedupe, so
a gate that keeps refusing does not flood the audit log. Entries carry the
refusal code and, for recording, the peer id; never batch or event content.
The audit write can never break the caller (same wrapping as
``dbcrypt._hooks._audit``).
"""

from __future__ import annotations

import contextlib
import logging
import threading
from typing import Final

from .._audit_support import safe_audit_append

__all__ = ["audit_capture_refused"]

_LOG = logging.getLogger(__name__)
#: Refusal codes come from small fixed sets; the cap only bounds a misbehaving caller.
_MAX_CODES: Final = 32
_EMITTED: set[str] = set()
_LOCK = threading.Lock()


def _first_time(code: str) -> bool:
    with _LOCK:
        if code in _EMITTED or len(_EMITTED) >= _MAX_CODES:
            return False
        _EMITTED.add(code)
        return True


def audit_capture_refused(code: str, *, peer_id: str | None = None) -> None:
    """Audit the first refusal of ``code`` in this process; later ones are silent."""
    if not _first_time(code):
        return
    entry: dict[str, str] = {
        "event": "activity_capture",
        "decision": "refuse",
        "reason": "activity.capture_refused",
        "code": code,
    }
    if peer_id is not None:
        entry["peer_id"] = peer_id
    with contextlib.suppress(Exception):
        from ..privacy_check import _runtime

        safe_audit_append(_runtime.ensure_state().audit, entry, logger=_LOG)
