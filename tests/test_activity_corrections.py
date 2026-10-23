"""Explicit corrections are recorded as raw events; nothing is derived from them."""

from __future__ import annotations

from pathlib import Path

import pytest

from mordred_hermes.activity import _schema, corrections
from mordred_hermes.activity._gate import ActivityRefused
from tests._activity_episode_helpers import CORRECTION_TEXT, make_store, rows, seed_episode


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


def test_a_correction_is_only_a_raw_event(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    seeded = seed_episode(store)
    before = store.status().counts

    event = corrections.record_correction(store, episode_id=seeded.episode_id, text=f"  {CORRECTION_TEXT}  ")

    assert event.attempt_id is None
    assert event.text == CORRECTION_TEXT
    assert store.status().counts == {**before, "activity_events": before["activity_events"] + 1}
    tables = {row[0] for row in rows(store, "SELECT name FROM sqlite_master WHERE type = 'table'")}
    assert tables == {*_schema.TABLES, "sqlite_sequence"}
    episode = store.episode(seeded.episode_id)
    assert episode is not None and (episode.revision, episode.event_count) == (2, 5)


def test_correction_refuses_empty_text(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    seeded = seed_episode(store)

    with pytest.raises(ActivityRefused) as caught:
        corrections.record_correction(store, episode_id=seeded.episode_id, text="   ")

    assert caught.value.code == "invalid_field"
    assert rows(store, "SELECT count(*) FROM activity_events WHERE phase = 'correction'") == [(0,)]
