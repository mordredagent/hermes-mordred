"""Explicit user corrections and the deterministic candidate lesson they imply.

:func:`record_correction` stores what the user said was wrong as a
``user_correction`` / ``human`` / ``correction`` event of an existing episode,
linked to the attempt it refers to. :func:`deterministic_candidate` turns one
such correction into a narrow candidate lesson without any model: the scope is
the attempt's site and route plus the episode's ``task_start`` text, the
guidance is the correction itself, and the evidence is the correction, the
attempt's intended/dispatched/observed events and the task boundary.

A candidate is never retrievable; it must be validated and adopted
(``lessons.py``) first.
"""

from __future__ import annotations

import sqlite3
import time
import uuid
from collections.abc import Sequence
from typing import Any, Final

from . import lessons
from ._gate import ActivityRefused, refusal
from .contracts import DEFAULT_EXCLUDED_SITES, EventRejected, NormalizedEvent, normalize_event, site_excluded
from .lessons import LessonRevision
from .store import ATTEMPT_PHASES, ActivityStore

__all__ = ["CORRECTION_PEER", "deterministic_candidate", "record_correction"]

CORRECTION_PEER: Final = "hermes-cli"
_DOES_NOT_APPLY: Final = (
    "Another site, account or page structure; whenever the user's current instruction says otherwise"
)
_CHECK_BEFORE_USE: Final = (
    "Confirm the site and the visible account indicator match this scope, and that the page still offers the "
    "referenced control"
)
_SUCCESS_MEASURE: Final = "The same step needs no repeated correction; the user confirms the outcome"


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
    store.append_batch(CORRECTION_PEER, f"{CORRECTION_PEER}:{store.meta().store_generation}", [event])
    return event


# --- deterministic candidate ---------------------------------------------------------------------


def _existing(conn: sqlite3.Connection, correction_event_id: str) -> tuple[str, int] | None:
    row = conn.execute(
        "SELECT l.lesson_id, max(l.revision) FROM activity_lessons l JOIN activity_lesson_evidence v "
        "ON v.lesson_id = l.lesson_id AND v.revision = l.revision "
        "WHERE v.event_id = ? AND l.origin = 'correction' GROUP BY l.lesson_id ORDER BY min(l.created_at) LIMIT 1",
        (correction_event_id,),
    ).fetchone()
    return None if row is None else (str(row[0]), int(row[1]))


def _episode_of(store: ActivityStore, event_id: str) -> str:
    with store.connection() as conn:
        row = conn.execute("SELECT episode_id FROM activity_events WHERE event_id = ?", (event_id,)).fetchone()
    if row is None:
        raise _refuse("evidence_unknown")
    return str(row[0])


def _attempt_events(events: Sequence[NormalizedEvent], correction: NormalizedEvent) -> list[NormalizedEvent]:
    """The referenced attempt, or the most recent ``intended`` attempt recorded before the correction."""
    attempt_id = correction.attempt_id
    if attempt_id is None:
        before = events[: events.index(correction)]
        attempt_id = next(
            (e.attempt_id for e in reversed(before) if e.phase == "intended" and e.attempt_id is not None), None
        )
    attempt = [e for e in events if attempt_id is not None and e.attempt_id == attempt_id and e.phase in ATTEMPT_PHASES]
    if not attempt:
        raise _refuse("attempt_unknown")
    return attempt


def _task_start(events: Sequence[NormalizedEvent], correction: NormalizedEvent) -> NormalizedEvent:
    """The latest task boundary observed before the correction, even when it was received after it."""
    starts = [e for e in events if e.op == "task_start" and e.text and e.observed_at <= correction.observed_at]
    if not starts:
        raise _refuse("task_unknown")
    return max(starts, key=lambda e: e.observed_at)


def _candidate_fields(
    attempt: Sequence[NormalizedEvent], boundary: NormalizedEvent, correction: NormalizedEvent
) -> dict[str, Any]:
    located = next((e for e in attempt if e.site is not None), None)
    if located is None or located.site is None:
        raise _refuse("scope_unknown")
    scope_task = (boundary.text or "").strip()[: lessons.MAX_TASK_CHARS]
    route = located.route
    return {
        "scope_site": located.site,
        "scope_route": route,
        "scope_task": scope_task,
        "applies_when": f"Operating {located.site}{route or ''} for a task like: {scope_task}",
        "does_not_apply": _DOES_NOT_APPLY,
        "check_before_use": _CHECK_BEFORE_USE,
        "guidance": correction.text,
        "success_measure": _SUCCESS_MEASURE,
    }


def deterministic_candidate(
    store: ActivityStore, correction_event_id: str, *, excluded_sites: frozenset[str] = DEFAULT_EXCLUDED_SITES
) -> LessonRevision:
    """The candidate lesson implied by one correction; a second call returns the same lesson."""
    episode_id = _episode_of(store, correction_event_id)
    events = store.events_for_episode(episode_id)
    correction = next(e for e in events if e.event_id == correction_event_id)
    if correction.phase != "correction" or not correction.text:
        raise _refuse("not_a_correction")
    attempt = _attempt_events(events, correction)
    boundary = _task_start(events, correction)
    evidence = [correction, *attempt, boundary]
    if any(site_excluded(e.site, excluded_sites) for e in evidence):
        raise _refuse("source_excluded")
    fields = _candidate_fields(attempt, boundary, correction)
    with store._transaction() as conn:
        found = _existing(conn, correction_event_id)
        if found is None:
            return lessons.create_candidate_in(
                conn,
                origin="correction",
                episode_id=episode_id,
                fields=fields,
                evidence_event_ids=[e.event_id for e in evidence],
                now=time.time(),
            )
    return lessons.get(store, *found)
