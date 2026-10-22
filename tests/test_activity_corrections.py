"""Explicit corrections and their deterministic candidate lessons."""

from __future__ import annotations

from pathlib import Path

import pytest

from mordred_hermes.activity import corrections, lessons
from mordred_hermes.activity._gate import ActivityRefused
from mordred_hermes.activity.contracts import DEFAULT_EXCLUDED_SITES
from tests._activity_lesson_helpers import (
    CORRECTION_TEXT,
    TASK_TEXT,
    corrected_candidate,
    make_store,
    rows,
    seed_episode,
)


def test_correction_is_a_human_correction_event_linked_to_the_attempt(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    seeded = seed_episode(store)

    event = corrections.record_correction(
        store, episode_id=seeded.episode_id, text=CORRECTION_TEXT, attempt_id=seeded.attempt_id
    )

    stored = store.events_for_episode(seeded.episode_id)[-1]
    assert stored.event_id == event.event_id
    assert (stored.source, stored.actor, stored.phase) == ("user_correction", "human", "correction")
    assert stored.attempt_id == seeded.attempt_id
    assert stored.text == CORRECTION_TEXT
    assert store.episode(seeded.episode_id).has_correction is True
    generation = store.meta().store_generation
    assert rows(store, "SELECT peer_id, producer_id FROM activity_events WHERE event_id = ?", event.event_id) == [
        ("hermes-cli", f"hermes-cli:{generation}")
    ]


def test_correction_refuses_unknown_episode_and_foreign_attempt(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    seeded = seed_episode(store)
    other = seed_episode(store, episode="ep-2", seq0=10)

    with pytest.raises(ActivityRefused) as unknown:
        corrections.record_correction(store, episode_id="ep-missing", text="x")
    with pytest.raises(ActivityRefused) as foreign:
        corrections.record_correction(store, episode_id=seeded.episode_id, text="x", attempt_id=other.attempt_id)

    assert unknown.value.code == "episode_unknown"
    assert foreign.value.code == "attempt_unknown"


def test_deterministic_candidate_content(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    seeded, correction, lesson = corrected_candidate(store)

    assert (lesson.revision, lesson.state, lesson.origin) == (1, "candidate", "correction")
    assert (lesson.scope_site, lesson.scope_route, lesson.scope_task) == ("app.example.com", "/reports", TASK_TEXT)
    assert lesson.applies_when == f"Operating app.example.com/reports for a task like: {TASK_TEXT}"
    assert lesson.does_not_apply == (
        "Another site, account or page structure; whenever the user's current instruction says otherwise"
    )
    assert lesson.check_before_use == (
        "Confirm the site and the visible account indicator match this scope, and that the page still offers "
        "the referenced control"
    )
    assert lesson.guidance == CORRECTION_TEXT
    assert lesson.success_measure == "The same step needs no repeated correction; the user confirms the outcome"
    evidence = {row.event_id for row in lessons.evidence(store, lesson.lesson_id, 1)}
    assert evidence == {correction.event_id, seeded.task_start.event_id, *(e.event_id for e in seeded.attempt)}
    assert rows(store, "SELECT DISTINCT pinned FROM activity_lesson_evidence") == [(1,)]


def test_deterministic_candidate_is_idempotent(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    _seeded, correction, first = corrected_candidate(store)

    again = corrections.deterministic_candidate(store, correction.event_id)

    assert (again.lesson_id, again.revision) == (first.lesson_id, first.revision)
    assert rows(store, "SELECT count(*) FROM activity_lessons") == [(1,)]


def test_without_attempt_the_latest_intended_attempt_before_the_correction_is_used(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    seeded = seed_episode(store)

    correction = corrections.record_correction(store, episode_id=seeded.episode_id, text=CORRECTION_TEXT)
    lesson = corrections.deterministic_candidate(store, correction.event_id)

    linked = {row.event_id for row in lessons.evidence(store, lesson.lesson_id, 1)}
    assert {e.event_id for e in seeded.attempt} <= linked


def test_candidate_refuses_non_correction_and_newly_excluded_site(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    seeded = seed_episode(store)
    correction = corrections.record_correction(
        store, episode_id=seeded.episode_id, text=CORRECTION_TEXT, attempt_id=seeded.attempt_id
    )

    with pytest.raises(ActivityRefused) as not_correction:
        corrections.deterministic_candidate(store, seeded.attempt[0].event_id)
    with pytest.raises(ActivityRefused) as excluded:
        corrections.deterministic_candidate(
            store, correction.event_id, excluded_sites=DEFAULT_EXCLUDED_SITES | {"example.com"}
        )

    assert not_correction.value.code == "not_a_correction"
    assert excluded.value.code == "source_excluded"
    assert rows(store, "SELECT count(*) FROM activity_lessons") == [(0,)]
