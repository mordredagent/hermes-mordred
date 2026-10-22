"""Lesson revisions: immutable revisions, explicit state transitions, digest-bound adoption.

A lesson revision is created as a ``candidate`` with pinned evidence and an
evidence digest. It is ``validated`` by a recorded independent method and
becomes ``admitted`` only through :func:`adopt`, which requires the operator
to confirm the exact evidence digest of that revision. Only admitted revisions
are ever retrievable by ordinary Hermes sessions (``retrieval.py``).

Changing a lesson never edits a revision in place: :func:`revise` copies a
revision into a new ``candidate`` revision, so a validation or adoption
always refers to the exact text it was given for. Adoption, suspension,
rejection and retirement are audited with identifiers and codes only.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import re
import sqlite3
import time
import uuid
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Final

from ._gate import ActivityRefused, refusal
from .contracts import DEFAULT_EXCLUDED_SITES, canonical_json, site_excluded
from .store import ActivityStore

__all__ = [
    "VALIDATION_METHODS",
    "EvidenceRow",
    "LessonRevision",
    "LessonState",
    "adopt",
    "create_candidate",
    "evidence",
    "get",
    "list_lessons",
    "reject",
    "retire",
    "revise",
    "suspend",
    "validate",
]

_LOG = logging.getLogger(__name__)


class LessonState:
    CANDIDATE: Final = "candidate"
    VALIDATED: Final = "validated"
    ADMITTED: Final = "admitted"
    SUSPENDED: Final = "suspended"
    REJECTED: Final = "rejected"
    RETIRED: Final = "retired"
    ALL: Final = frozenset({"candidate", "validated", "admitted", "suspended", "rejected", "retired"})


VALIDATION_METHODS: Final = frozenset({"fixture", "readonly_check", "user_confirmed"})
ORIGINS: Final = frozenset({"correction", "review"})

MAX_CONDITION_CHARS: Final = 1000
MAX_TASK_CHARS: Final = 300
MAX_ROUTE_CHARS: Final = 200
MAX_NOTE_CHARS: Final = 500
MIN_CONFIRMATION_CHARS: Final = 12

#: Fields :func:`revise` may change; scope_site never changes within one lesson.
REVISABLE_FIELDS: Final = frozenset(
    {"scope_route", "scope_task", "applies_when", "does_not_apply", "check_before_use", "guidance", "success_measure"}
)
_TEXT_LIMITS: Final[Mapping[str, int]] = {
    "scope_task": MAX_TASK_CHARS,
    "applies_when": MAX_CONDITION_CHARS,
    "does_not_apply": MAX_CONDITION_CHARS,
    "check_before_use": MAX_CONDITION_CHARS,
    "guidance": MAX_CONDITION_CHARS,
    "success_measure": MAX_CONDITION_CHARS,
}
_HOST_RE: Final = re.compile(r"^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?(?::[0-9]{1,5})?$")
_REASON_RE: Final = re.compile(r"^[a-z0-9][a-z0-9_-]{0,47}$")

_COLUMNS: Final = (
    "lesson_id, revision, state, origin, episode_id, scope_site, scope_route, scope_task, applies_when, "
    "does_not_apply, check_before_use, guidance, success_measure, evidence_digest, validation_method, "
    "validation_note, validated_at, adopted_at, adoption_digest, suspended_reason, created_at, superseded_by"
)

#: ``operation -> states it may start from``.
_TRANSITIONS: Final[Mapping[str, frozenset[str]]] = {
    "validate": frozenset({"candidate"}),
    "adopt": frozenset({"validated"}),
    "reject": frozenset({"candidate", "validated"}),
    "suspend": frozenset({"admitted", "validated"}),
    "retire": frozenset({"admitted", "suspended", "validated"}),
}


@dataclass(frozen=True)
class LessonRevision:
    lesson_id: str
    revision: int
    state: str
    origin: str
    episode_id: str | None
    scope_site: str | None
    scope_route: str | None
    scope_task: str | None
    applies_when: str | None
    does_not_apply: str | None
    check_before_use: str | None
    guidance: str | None
    success_measure: str | None
    evidence_digest: str | None
    validation_method: str | None
    validation_note: str | None
    validated_at: float | None
    adopted_at: float | None
    adoption_digest: str | None
    suspended_reason: str | None
    created_at: float
    superseded_by: str | None


@dataclass(frozen=True)
class EvidenceRow:
    """Identifiers and structure of one evidence event; never its ``target`` or ``text``."""

    event_id: str
    present: bool
    phase: str | None
    op: str | None
    site: str | None
    route: str | None


# --- validation helpers ------------------------------------------------------------------------


def _refuse(code: str) -> ActivityRefused:
    return ActivityRefused(refusal(code))


def _text(value: Any, limit: int) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > limit:
        raise _refuse("invalid_field")
    return value.strip()


def _site(value: Any) -> str:
    if not isinstance(value, str) or not _HOST_RE.fullmatch(value.strip().lower()):
        raise _refuse("invalid_field")
    return value.strip().lower()


def _route(value: Any) -> str | None:
    if value is None or value == "":
        return None
    if not isinstance(value, str) or not value.startswith("/") or len(value) > MAX_ROUTE_CHARS:
        raise _refuse("invalid_field")
    return value


def _checked_fields(fields: Mapping[str, Any]) -> dict[str, Any]:
    checked: dict[str, Any] = {name: _text(fields[name], limit) for name, limit in _TEXT_LIMITS.items()}
    checked["scope_site"] = _site(fields["scope_site"])
    checked["scope_route"] = _route(fields["scope_route"])
    return checked


def _reason(value: Any) -> str:
    if not isinstance(value, str) or not _REASON_RE.fullmatch(value):
        raise _refuse("invalid_reason")
    return value


def evidence_digest(pairs: Iterable[tuple[str, str]]) -> str:
    """sha256 over the canonical JSON of the sorted ``(event_id, content_digest)`` pairs."""
    ordered = sorted([event_id, digest] for event_id, digest in pairs)
    return hashlib.sha256(canonical_json(ordered).encode("ascii")).hexdigest()


def adoption_digest(lesson: LessonRevision, adopted_at: float) -> str:
    material = (
        f"{lesson.lesson_id}|{lesson.revision}|{lesson.scope_site}|{lesson.scope_route}|"
        f"{lesson.evidence_digest}|{adopted_at}"
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


# --- audit ---------------------------------------------------------------------------------------


def _audit(entry: Mapping[str, Any]) -> None:
    """Identifiers and codes only; an audit failure never undoes a committed transition."""
    try:
        from .._audit_support import safe_audit_append
        from ..privacy_check import _runtime

        safe_audit_append(_runtime.ensure_state().audit, entry, logger=_LOG)
    except Exception as exc:
        _LOG.warning("activity lesson audit unavailable (%s)", type(exc).__name__)


def _audit_state(lesson_id: str, revision: int, state: str, reason: str) -> None:
    _audit(
        {
            "event": "activity_lesson",
            "decision": state,
            "reason": "activity.lesson_suspended",
            "lesson_id": lesson_id,
            "revision": revision,
            "state": state,
            "code": reason,
        }
    )


# --- row access ----------------------------------------------------------------------------------


def _row_lesson(row: Sequence[Any]) -> LessonRevision:
    return LessonRevision(*row)


def _fetch(conn: sqlite3.Connection, lesson_id: str, revision: int | None) -> LessonRevision:
    if revision is None:
        row = conn.execute(
            f"SELECT {_COLUMNS} FROM activity_lessons WHERE lesson_id = ? ORDER BY revision DESC LIMIT 1",
            (lesson_id,),
        ).fetchone()
    else:
        row = conn.execute(
            f"SELECT {_COLUMNS} FROM activity_lessons WHERE lesson_id = ? AND revision = ?", (lesson_id, revision)
        ).fetchone()
    if row is None:
        raise _refuse("lesson_unknown")
    return _row_lesson(row)


def _evidence_rows(conn: sqlite3.Connection, lesson_id: str, revision: int) -> list[tuple[Any, ...]]:
    """``(event_id, content_digest|None, site|None, phase, op, route)`` per pinned evidence link."""
    return [
        tuple(row)
        for row in conn.execute(
            "SELECT v.event_id, e.content_digest, e.site, e.phase, e.op, e.route FROM activity_lesson_evidence v "
            "LEFT JOIN activity_events e ON e.event_id = v.event_id "
            "WHERE v.lesson_id = ? AND v.revision = ? ORDER BY e.receipt, v.event_id",
            (lesson_id, revision),
        )
    ]


def _insert(conn: sqlite3.Connection, lesson: LessonRevision) -> None:
    placeholders = ", ".join("?" * len(_COLUMNS.split(",")))
    conn.execute(
        f"INSERT INTO activity_lessons ({_COLUMNS}) VALUES ({placeholders})",
        tuple(getattr(lesson, name.strip()) for name in _COLUMNS.split(",")),
    )


def _transition(conn: sqlite3.Connection, operation: str, lesson_id: str, revision: int) -> LessonRevision:
    lesson = _fetch(conn, lesson_id, revision)
    if lesson.state not in _TRANSITIONS[operation]:
        raise _refuse("wrong_state")
    return lesson


# --- creation ------------------------------------------------------------------------------------


def create_candidate_in(
    conn: sqlite3.Connection,
    *,
    origin: str,
    episode_id: str,
    fields: Mapping[str, Any],
    evidence_event_ids: Sequence[str],
    now: float,
) -> LessonRevision:
    """:func:`create_candidate` inside a caller's open write transaction."""
    if origin not in ORIGINS:
        raise _refuse("invalid_field")
    checked = _checked_fields(fields)
    ids = list(dict.fromkeys(evidence_event_ids))
    if not ids:
        raise _refuse("evidence_unknown")
    found: dict[str, tuple[str, int]] = {}
    for event_id in ids:
        row = conn.execute(
            "SELECT content_digest, episode_revision FROM activity_events WHERE event_id = ? AND episode_id = ?",
            (event_id, episode_id),
        ).fetchone()
        if row is None:
            raise _refuse("evidence_unknown")
        found[event_id] = (str(row[0]), int(row[1]))
    lesson = LessonRevision(
        lesson_id=str(uuid.uuid4()),
        revision=1,
        state=LessonState.CANDIDATE,
        origin=origin,
        episode_id=episode_id,
        **checked,
        evidence_digest=evidence_digest((event_id, digest) for event_id, (digest, _) in found.items()),
        validation_method=None,
        validation_note=None,
        validated_at=None,
        adopted_at=None,
        adoption_digest=None,
        suspended_reason=None,
        created_at=now,
        superseded_by=None,
    )
    _insert(conn, lesson)
    conn.executemany(
        "INSERT INTO activity_lesson_evidence (lesson_id, revision, event_id, episode_revision, pinned) "
        "VALUES (?, ?, ?, ?, 1)",
        [(lesson.lesson_id, 1, event_id, episode_revision) for event_id, (_, episode_revision) in found.items()],
    )
    return lesson


def create_candidate(
    store: ActivityStore,
    *,
    origin: str,
    episode_id: str,
    scope_site: str,
    scope_route: str | None,
    scope_task: str,
    applies_when: str,
    does_not_apply: str,
    check_before_use: str,
    guidance: str,
    success_measure: str,
    evidence_event_ids: Sequence[str],
    now: float | None = None,
) -> LessonRevision:
    """Revision 1 of a new lesson, its evidence pinned, in one transaction."""
    fields = {
        "scope_site": scope_site,
        "scope_route": scope_route,
        "scope_task": scope_task,
        "applies_when": applies_when,
        "does_not_apply": does_not_apply,
        "check_before_use": check_before_use,
        "guidance": guidance,
        "success_measure": success_measure,
    }
    with store._transaction() as conn:
        return create_candidate_in(
            conn,
            origin=origin,
            episode_id=episode_id,
            fields=fields,
            evidence_event_ids=evidence_event_ids,
            now=time.time() if now is None else now,
        )


# --- readers -------------------------------------------------------------------------------------


def get(store: ActivityStore, lesson_id: str, revision: int | None = None) -> LessonRevision:
    """One revision (``None``: the latest); raises ``lesson_unknown``."""
    with store._transaction(write=False) as conn:
        return _fetch(conn, lesson_id, revision)


def list_lessons(
    store: ActivityStore, *, state: str | Iterable[str] | None = None, limit: int = 100
) -> list[LessonRevision]:
    states = (state,) if isinstance(state, str) else tuple(state or ())
    query = f"SELECT {_COLUMNS} FROM activity_lessons"
    params: tuple[Any, ...] = ()
    if states:
        query += f" WHERE state IN ({', '.join('?' * len(states))})"
        params = states
    with store._transaction(write=False) as conn:
        rows = conn.execute(query + " ORDER BY created_at DESC, lesson_id, revision LIMIT ?", (*params, max(0, limit)))
        return [_row_lesson(row) for row in rows.fetchall()]


def evidence(store: ActivityStore, lesson_id: str, revision: int) -> list[EvidenceRow]:
    with store._transaction(write=False) as conn:
        _fetch(conn, lesson_id, revision)
        rows = _evidence_rows(conn, lesson_id, revision)
    return [
        EvidenceRow(event_id=row[0], present=row[1] is not None, phase=row[3], op=row[4], site=row[2], route=row[5])
        for row in rows
    ]


# --- transitions ---------------------------------------------------------------------------------


def validate(
    store: ActivityStore,
    lesson_id: str,
    revision: int,
    *,
    method: str,
    note: str | None = None,
    now: float | None = None,
) -> LessonRevision:
    """``candidate`` → ``validated`` with the independent check that was performed."""
    if method not in VALIDATION_METHODS:
        raise _refuse("invalid_method")
    if note is not None and (not isinstance(note, str) or len(note) > MAX_NOTE_CHARS):
        raise _refuse("invalid_field")
    with store._transaction() as conn:
        _transition(conn, "validate", lesson_id, revision)
        conn.execute(
            "UPDATE activity_lessons SET state = 'validated', validation_method = ?, validation_note = ?, "
            "validated_at = ? WHERE lesson_id = ? AND revision = ?",
            (method, note, time.time() if now is None else now, lesson_id, revision),
        )
        return _fetch(conn, lesson_id, revision)


def _confirmed(confirmation: str, digest: str) -> bool:
    typed = confirmation.strip().lower().encode("utf-8")
    if not MIN_CONFIRMATION_CHARS <= len(typed) <= len(digest):
        return False
    return hmac.compare_digest(typed, digest[: len(typed)].encode("ascii"))


def _current_evidence_digest(conn: sqlite3.Connection, lesson: LessonRevision, excluded_sites: Iterable[str]) -> str:
    rows = _evidence_rows(conn, lesson.lesson_id, lesson.revision)
    if not rows or any(row[1] is None for row in rows):
        raise _refuse("evidence_changed")
    digest = evidence_digest((str(row[0]), str(row[1])) for row in rows)
    if lesson.evidence_digest is None or not hmac.compare_digest(digest, lesson.evidence_digest):
        raise _refuse("evidence_changed")
    sites = {lesson.scope_site, *(row[2] for row in rows)}
    if any(site_excluded(site, excluded_sites) for site in sites):
        raise _refuse("source_excluded")
    return digest


def adopt(
    store: ActivityStore,
    lesson_id: str,
    revision: int,
    *,
    confirmation: str,
    now: float,
    excluded_sites: frozenset[str] = DEFAULT_EXCLUDED_SITES,
) -> LessonRevision:
    """``validated`` → ``admitted`` after the operator confirmed this revision's evidence digest.

    The digest is recomputed from the evidence rows that exist now; a missing
    or changed event refuses. A previously admitted revision of the same lesson
    is retired and points at this one.
    """
    with store._transaction() as conn:
        lesson = _transition(conn, "adopt", lesson_id, revision)
        digest = _current_evidence_digest(conn, lesson, excluded_sites)
        if not isinstance(confirmation, str) or not _confirmed(confirmation, digest):
            raise _refuse("confirmation_mismatch")
        sealed = adoption_digest(lesson, now)
        conn.execute(
            "UPDATE activity_lessons SET state = 'admitted', adopted_at = ?, adoption_digest = ? "
            "WHERE lesson_id = ? AND revision = ?",
            (now, sealed, lesson_id, revision),
        )
        retired = [
            int(row[0])
            for row in conn.execute(
                "SELECT revision FROM activity_lessons WHERE lesson_id = ? AND revision != ? AND state = 'admitted'",
                (lesson_id, revision),
            )
        ]
        conn.executemany(
            "UPDATE activity_lessons SET state = 'retired', superseded_by = ? WHERE lesson_id = ? AND revision = ?",
            [(str(revision), lesson_id, old) for old in retired],
        )
        adopted = _fetch(conn, lesson_id, revision)
    _audit(
        {
            "event": "activity_lesson",
            "decision": "admitted",
            "reason": "activity.lesson_adopted",
            "lesson_id": lesson_id,
            "revision": revision,
            "adoption_digest": sealed,
        }
    )
    for old in retired:
        _audit_state(lesson_id, old, LessonState.RETIRED, "superseded")
    return adopted


def _set_state(store: ActivityStore, operation: str, lesson_id: str, revision: int, state: str, reason: str) -> None:
    code = _reason(reason)
    with store._transaction() as conn:
        _transition(conn, operation, lesson_id, revision)
        conn.execute(
            "UPDATE activity_lessons SET state = ?, suspended_reason = ? WHERE lesson_id = ? AND revision = ?",
            (state, code, lesson_id, revision),
        )
    _audit_state(lesson_id, revision, state, code)


def reject(store: ActivityStore, lesson_id: str, revision: int, *, reason: str) -> None:
    """``candidate``/``validated`` → ``rejected``; ``reason`` is a short code, not prose."""
    _set_state(store, "reject", lesson_id, revision, LessonState.REJECTED, reason)


def suspend(store: ActivityStore, lesson_id: str, revision: int, *, reason: str) -> None:
    """``admitted``/``validated`` → ``suspended``: retrieval (search and get) stops immediately."""
    _set_state(store, "suspend", lesson_id, revision, LessonState.SUSPENDED, reason)


def retire(store: ActivityStore, lesson_id: str, revision: int, *, reason: str = "retired") -> None:
    _set_state(store, "retire", lesson_id, revision, LessonState.RETIRED, reason)


def revise(
    store: ActivityStore, lesson_id: str, revision: int, *, now: float | None = None, **changes: Any
) -> LessonRevision:
    """Copy ``revision`` into a new ``candidate`` revision with ``changes``; the old one keeps its state."""
    unknown = set(changes) - REVISABLE_FIELDS
    if unknown or not changes:
        raise _refuse("invalid_field")
    with store._transaction() as conn:
        source = _fetch(conn, lesson_id, revision)
        merged = {name: getattr(source, name) for name in (*_TEXT_LIMITS, "scope_site", "scope_route")}
        merged.update(changes)
        checked = _checked_fields(merged)
        latest = _fetch(conn, lesson_id, None).revision
        lesson = LessonRevision(
            lesson_id=lesson_id,
            revision=latest + 1,
            state=LessonState.CANDIDATE,
            origin=source.origin,
            episode_id=source.episode_id,
            **checked,
            evidence_digest=source.evidence_digest,
            validation_method=None,
            validation_note=None,
            validated_at=None,
            adopted_at=None,
            adoption_digest=None,
            suspended_reason=None,
            created_at=time.time() if now is None else now,
            superseded_by=None,
        )
        _insert(conn, lesson)
        conn.execute(
            "INSERT INTO activity_lesson_evidence (lesson_id, revision, event_id, episode_revision, pinned) "
            "SELECT lesson_id, ?, event_id, episode_revision, pinned FROM activity_lesson_evidence "
            "WHERE lesson_id = ? AND revision = ?",
            (lesson.revision, lesson_id, revision),
        )
        return lesson
