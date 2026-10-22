"""Lesson revisions: validation, digest-bound adoption, supersession, suspension, revision."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from mordred_hermes.activity import lessons
from mordred_hermes.activity._gate import ActivityRefused
from mordred_hermes.activity.contracts import DEFAULT_EXCLUDED_SITES
from tests._activity_lesson_helpers import admitted, corrected_candidate, make_store, rows, seed_episode


@pytest.fixture(autouse=True)
def audit(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    monkeypatch.setattr(lessons, "_audit", lambda entry: entries.append(dict(entry)))
    return entries


def _refused(call: Any) -> str:
    with pytest.raises(ActivityRefused) as caught:
        call()
    return caught.value.code


def test_candidate_validated_admitted_flow(tmp_path: Path, audit: list[dict[str, Any]]) -> None:
    store = make_store(tmp_path)
    _, _, candidate = corrected_candidate(store)

    validated = lessons.validate(store, candidate.lesson_id, 1, method="user_confirmed", note="checked live")
    assert (validated.state, validated.validation_method, validated.validation_note) == (
        "validated",
        "user_confirmed",
        "checked live",
    )
    assert validated.evidence_digest is not None
    adopted = lessons.adopt(
        store, candidate.lesson_id, 1, confirmation=validated.evidence_digest[:12].upper(), now=1234.5
    )

    assert adopted.state == "admitted"
    assert adopted.adopted_at == 1234.5
    assert adopted.adoption_digest == lessons.adoption_digest(validated, 1234.5)
    assert audit == [
        {
            "event": "activity_lesson",
            "decision": "admitted",
            "reason": "activity.lesson_adopted",
            "lesson_id": candidate.lesson_id,
            "revision": 1,
            "adoption_digest": adopted.adoption_digest,
        }
    ]


def test_evidence_digest_covers_the_pinned_events(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    _, _, candidate = corrected_candidate(store)
    pairs = rows(
        store,
        "SELECT e.event_id, e.content_digest FROM activity_lesson_evidence v JOIN activity_events e "
        "ON e.event_id = v.event_id WHERE v.lesson_id = ?",
        candidate.lesson_id,
    )

    assert candidate.evidence_digest == lessons.evidence_digest(pairs)


def test_create_candidate_refuses_evidence_from_another_episode(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    one = seed_episode(store)
    other = seed_episode(store, episode="ep-2", seq0=10)

    code = _refused(
        lambda: lessons.create_candidate(
            store,
            origin="correction",
            episode_id=one.episode_id,
            scope_site="app.example.com",
            scope_route="/reports",
            scope_task="t",
            applies_when="a",
            does_not_apply="d",
            check_before_use="c",
            guidance="g",
            success_measure="s",
            evidence_event_ids=[one.task_start.event_id, other.task_start.event_id],
        )
    )

    assert code == "evidence_unknown"
    assert rows(store, "SELECT count(*) FROM activity_lessons") == [(0,)]


def test_text_fields_are_bounded(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    one = seed_episode(store)
    base: dict[str, Any] = {
        "origin": "correction",
        "episode_id": one.episode_id,
        "scope_site": "app.example.com",
        "scope_route": "/reports",
        "scope_task": "t",
        "applies_when": "a",
        "does_not_apply": "d",
        "check_before_use": "c",
        "guidance": "g",
        "success_measure": "s",
        "evidence_event_ids": [one.task_start.event_id],
    }
    for change in (
        {"guidance": "x" * 1001},
        {"scope_task": "x" * 301},
        {"scope_route": "/" + "x" * 200},
        {"scope_site": "https://app.example.com/path"},
    ):
        assert _refused(lambda change=change: lessons.create_candidate(store, **{**base, **change})) == "invalid_field"


def test_adopt_refuses_wrong_state_and_wrong_confirmation(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    _, _, candidate = corrected_candidate(store)
    digest = candidate.evidence_digest
    assert digest is not None

    assert _refused(lambda: lessons.adopt(store, candidate.lesson_id, 1, confirmation=digest, now=1.0)) == (
        "wrong_state"
    )
    lessons.validate(store, candidate.lesson_id, 1, method="fixture")
    for wrong in (digest[:11], "0" * 12 if not digest.startswith("0" * 12) else "f" * 12, digest + "00"):
        assert _refused(
            lambda wrong=wrong: lessons.adopt(store, candidate.lesson_id, 1, confirmation=wrong, now=1.0)
        ) == ("confirmation_mismatch")
    assert lessons.get(store, candidate.lesson_id, 1).state == "validated"


def test_adopt_refuses_missing_or_changed_evidence(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    _, correction, candidate = corrected_candidate(store)
    lessons.validate(store, candidate.lesson_id, 1, method="fixture")
    digest = candidate.evidence_digest
    assert digest is not None
    with store.connection() as conn:
        conn.execute(
            "UPDATE activity_events SET content_digest = 'tampered' WHERE event_id = ?", (correction.event_id,)
        )

    assert _refused(lambda: lessons.adopt(store, candidate.lesson_id, 1, confirmation=digest, now=1.0)) == (
        "evidence_changed"
    )

    with store.connection() as conn:
        conn.execute("DELETE FROM activity_events WHERE event_id = ?", (correction.event_id,))
    assert _refused(lambda: lessons.adopt(store, candidate.lesson_id, 1, confirmation=digest, now=1.0)) == (
        "evidence_changed"
    )


def test_adopt_refuses_a_site_excluded_since_capture(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    _, _, candidate = corrected_candidate(store)
    lessons.validate(store, candidate.lesson_id, 1, method="fixture")
    digest = candidate.evidence_digest
    assert digest is not None

    code = _refused(
        lambda: lessons.adopt(
            store,
            candidate.lesson_id,
            1,
            confirmation=digest,
            now=1.0,
            excluded_sites=DEFAULT_EXCLUDED_SITES | {"example.com"},
        )
    )

    assert code == "source_excluded"


def test_revision_supersedes_and_retires_the_admitted_one(tmp_path: Path, audit: list[dict[str, Any]]) -> None:
    store = make_store(tmp_path)
    _, _, candidate = corrected_candidate(store)
    admitted(store, candidate)

    revised = lessons.revise(store, candidate.lesson_id, 1, guidance="Pick Finance in the switcher first")
    assert (revised.revision, revised.state, revised.guidance) == (2, "candidate", "Pick Finance in the switcher first")
    assert revised.evidence_digest == candidate.evidence_digest
    assert lessons.get(store, candidate.lesson_id, 1).state == "admitted"
    assert len(lessons.evidence(store, candidate.lesson_id, 2)) == len(lessons.evidence(store, candidate.lesson_id, 1))

    admitted(store, revised, now=6000.0)

    old = lessons.get(store, candidate.lesson_id, 1)
    assert (old.state, old.superseded_by) == ("retired", "2")
    assert lessons.get(store, candidate.lesson_id).state == "admitted"
    assert audit[-1]["reason"] == "activity.lesson_suspended"
    assert (audit[-1]["revision"], audit[-1]["state"], audit[-1]["code"]) == (1, "retired", "superseded")


def test_revise_rejects_unknown_fields(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    _, _, candidate = corrected_candidate(store)

    assert _refused(lambda: lessons.revise(store, candidate.lesson_id, 1, scope_site="evil.example")) == (
        "invalid_field"
    )
    assert _refused(lambda: lessons.revise(store, candidate.lesson_id, 1, state="admitted")) == "invalid_field"


def test_suspend_reject_and_audit_codes(tmp_path: Path, audit: list[dict[str, Any]]) -> None:
    store = make_store(tmp_path)
    _, _, first = corrected_candidate(store)
    _, _, second = corrected_candidate(store, episode="ep-2", seq0=20)
    admitted(store, first)
    audit.clear()

    lessons.suspend(store, first.lesson_id, 1, reason="user_contradicted")
    lessons.reject(store, second.lesson_id, 1, reason="scope_too_wide")

    assert lessons.get(store, first.lesson_id, 1).state == "suspended"
    assert lessons.get(store, second.lesson_id, 1).state == "rejected"
    assert [(e["lesson_id"], e["state"], e["code"]) for e in audit] == [
        (first.lesson_id, "suspended", "user_contradicted"),
        (second.lesson_id, "rejected", "scope_too_wide"),
    ]
    assert _refused(lambda: lessons.suspend(store, second.lesson_id, 1, reason="x")) == "wrong_state"
    assert _refused(lambda: lessons.reject(store, first.lesson_id, 1, reason="Free text reason")) == "invalid_reason"


def test_list_lessons_by_state(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    _, _, first = corrected_candidate(store)
    _, _, second = corrected_candidate(store, episode="ep-2", seq0=20)
    admitted(store, first)

    assert [lesson.lesson_id for lesson in lessons.list_lessons(store, state="admitted")] == [first.lesson_id]
    assert [lesson.lesson_id for lesson in lessons.list_lessons(store, state="candidate")] == [second.lesson_id]
    assert len(lessons.list_lessons(store)) == 2
    assert _refused(lambda: lessons.get(store, "missing")) == "lesson_unknown"
