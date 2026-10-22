"""Explicit user corrections, recorded as raw events.

:func:`record_correction` stores what the user said was wrong as a
``user_correction`` / ``human`` / ``correction`` event of an existing episode,
linked to the attempt it refers to (``hermes-mordred activity correct``).
Nothing is derived from it: the correction is part of the raw history like any
other event, and corrections the operator sends are stored the same way by the
receiver.
"""

from __future__ import annotations

import time
import uuid
from typing import Any, Final

from ._gate import ActivityRefused, refusal
from .contracts import DEFAULT_EXCLUDED_SITES, EventRejected, NormalizedEvent, normalize_event
from .store import ActivityStore

__all__ = ["CORRECTION_PEER", "record_correction"]

CORRECTION_PEER: Final = "hermes-cli"


def _refuse(code: str) -> ActivityRefused:
    return ActivityRefused(refusal(code))


def record_correction(
    store: ActivityStore,
    *,
    episode_id: str,
    text: str,
    attempt_id: str | None = None,
    hermes_session_id: str | None = None,
    excluded_sites: frozenset[str] = DEFAULT_EXCLUDED_SITES,
) -> NormalizedEvent:
    """Append one correction event to ``episode_id``; refuses an unknown episode or a foreign attempt."""
    if not isinstance(text, str) or not text.strip():
        raise _refuse("invalid_field")
    if store.episode(episode_id) is None:
        raise _refuse("episode_unknown")
    attempt_events: list[NormalizedEvent] = []
    if attempt_id is not None:
        attempt_events = [e for e in store.events_for_episode(episode_id) if e.attempt_id == attempt_id]
        if not attempt_events:
            raise _refuse("attempt_unknown")
    located = next((e for e in attempt_events if e.site is not None), None)
    raw: dict[str, Any] = {
        "event_id": str(uuid.uuid4()),
        "seq": time.time_ns(),
        "episode_id": episode_id,
        "attempt_id": attempt_id,
        "source": "user_correction",
        "actor": "human",
        "observed_at": time.time(),
        "phase": "correction",
        "action": {
            "op": "other",
            "site": located.site if located else None,
            "route": located.route if located else None,
        },
        "result": {"status": "unknown"},
        "quality": {"coverage": "selected_tab"},
        "session_ref": {"hermes_session_id": hermes_session_id},
        "text": text.strip(),
    }
    try:
        event = normalize_event(raw, excluded_sites=excluded_sites)
    except EventRejected as exc:
        raise _refuse(exc.code) from None
    producer = f"{CORRECTION_PEER}:{store.meta().store_generation}"
    store.append_batch(CORRECTION_PEER, producer, [event], foreign_episodes=True)
    return event
