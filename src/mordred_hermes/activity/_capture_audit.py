"""Activity audit entries, each emitted once per process and code.

- ``activity.capture_refused``: the receiver refused a batch because collection
  is disabled or the store refused it;
- ``activity.history_unavailable``: a Hermes-side history surface (navigation
  block, turn-start context, lookup tool) could not read the store and went on
  without history;
- ``activity.capture_suspended``: recording Hermes's own browser calls
  (:mod:`.capture_hermes`) was suspended for one Hermes session after repeated
  slow appends. Unlike the two codes above it is emitted once per suspended
  session (a session is suspended at most once per process), capped per
  process.

The dedupe keeps a gate that keeps refusing from flooding the audit log.
Entries carry the refusal code and, for capture, the peer id when known; never
batch, event or history content. The audit write can never break the caller
(same wrapping as ``dbcrypt._hooks._audit``).
"""

from __future__ import annotations

import contextlib
import logging
import threading
from typing import Final

from .._audit_support import safe_audit_append

__all__ = ["audit_capture_refused", "audit_capture_suspended", "audit_history_unavailable"]

_LOG = logging.getLogger(__name__)
#: Refusal codes come from small fixed sets; the cap only bounds a misbehaving caller.
_MAX_CODES: Final = 32
_EMITTED: set[str] = set()
_HISTORY_EMITTED: set[str] = set()
#: Suspension entries this process has written (one per suspended session, at most ``_MAX_CODES``).
_SUSPENDED: list[int] = [0]
_LOCK = threading.Lock()


def _first_time(code: str, emitted: set[str]) -> bool:
    with _LOCK:
        if code in emitted or len(emitted) >= _MAX_CODES:
            return False
        emitted.add(code)
        return True


def _append(entry: dict[str, str]) -> None:
    with contextlib.suppress(Exception):
        from ..privacy_check import _runtime

        safe_audit_append(_runtime.ensure_state().audit, entry, logger=_LOG)


def audit_capture_refused(code: str, *, peer_id: str | None = None) -> None:
    """Audit the first refusal of ``code`` in this process; later ones are silent."""
    if not _first_time(code, _EMITTED):
        return
    entry: dict[str, str] = {
        "event": "activity_capture",
        "decision": "refuse",
        "reason": "activity.capture_refused",
        "code": code,
    }
    if peer_id is not None:
        entry["peer_id"] = peer_id
    _append(entry)


def audit_history_unavailable(code: str) -> None:
    """Audit the first time a history surface went on without the store for ``code``; later ones are silent."""
    if not _first_time(code, _HISTORY_EMITTED):
        return
    _append(
        {
            "event": "activity_history",
            "decision": "refuse",
            "reason": "activity.history_unavailable",
            "code": code,
        }
    )


def audit_capture_suspended(code: str, *, peer_id: str) -> None:
    """Audit that capture of Hermes's browser calls was suspended for one session (``code`` says why)."""
    with _LOCK:
        if _SUSPENDED[0] >= _MAX_CODES:
            return
        _SUSPENDED[0] += 1
    _append(
        {
            "event": "activity_capture",
            "decision": "refuse",
            "reason": "activity.capture_suspended",
            "code": code,
            "peer_id": peer_id,
        }
    )
