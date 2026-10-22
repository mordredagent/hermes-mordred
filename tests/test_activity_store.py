"""Behaviour contract of the activity store (plain SQLite through the explicit opener seam)."""

from __future__ import annotations

import dataclasses
import hashlib
import json
import os
import sqlite3
import time
import uuid
from pathlib import Path
from typing import Any

import pytest

from mordred_hermes.activity import _schema
from mordred_hermes.activity._gate import ActivityRefused
from mordred_hermes.activity.contracts import (
    DEFAULT_EXCLUDED_SITES,
    NormalizedEvent,
    canonical_digest,
    canonical_json,
    normalize_event,
)
from mordred_hermes.activity.corrections import CORRECTION_PEER
from mordred_hermes.activity.store import SUPPORTED_SCHEMA_VERSION, ActivityStore, BatchConflict

PEER = "operator:peer-a"
PEER_B = "operator:peer-b"
PRODUCER = "prod-1"


def plain_opener(path: Path) -> sqlite3.Connection:
    return sqlite3.connect(path)


def make_store(home: Path) -> ActivityStore:
    store = ActivityStore(home / "mordred.db", plain_opener)
    store.initialize(home)
    return store


def event(seq: int, episode: str = "ep-1", **overrides: Any) -> NormalizedEvent:
    raw: dict[str, Any] = {
        "event_id": overrides.pop("event_id", str(uuid.uuid4())),
        "seq": seq,
        "episode_id": episode,
        "source": "operator",
        "actor": "agent",
        "observed_at": 1000.0 + seq,
        "phase": "dispatched",
        "action": {"op": "click", "target": "Reports", "site": "example.com", "route": "/r"},
        "result": {"status": "unknown"},
        "quality": {"coverage": "selected_tab"},
        "session_ref": {"run_id": "run-1"},
    }
    raw.update(overrides)
    return normalize_event(raw, excluded_sites=DEFAULT_EXCLUDED_SITES)


def rows(store: ActivityStore, sql: str, *params: Any) -> list[tuple[Any, ...]]:
    with store.connection() as conn:
        return [tuple(row) for row in conn.execute(sql, params)]


def test_append_is_idempotent_for_identical_replays(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    batch = [event(1), event(2)]

    first = store.append_batch(PEER, PRODUCER, batch)
    replay = store.append_batch(PEER, PRODUCER, batch)

    assert (first.accepted, first.duplicates, first.episode_revisions) == (2, 0, {"ep-1": 1})
    assert (replay.accepted, replay.duplicates, replay.episode_revisions) == (0, 2, {"ep-1": 1})
    assert rows(store, "SELECT count(*) FROM activity_events") == [(2,)]


def test_conflicting_replay_leaves_the_whole_batch_unwritten(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    original = event(1)
    store.append_batch(PEER, PRODUCER, [original])
    changed = event(1, event_id=original.event_id, action={"op": "click", "target": "Changed", "site": "example.com"})

    with pytest.raises(BatchConflict) as caught:
        store.append_batch(PEER, PRODUCER, [event(5, episode="ep-2"), changed])

    assert caught.value.code == "conflict"
    assert rows(store, "SELECT count(*) FROM activity_events") == [(1,)]
    assert store.episode("ep-2") is None
    assert [e.target for e in store.events_for_episode("ep-1")] == ["Reports"]


def test_another_peer_cannot_claim_an_existing_event_id(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    original = event(1)
    store.append_batch(PEER, PRODUCER, [original])
    with pytest.raises(BatchConflict):
        store.append_batch("operator:peer-b", PRODUCER, [original])


def test_another_peer_cannot_append_to_an_episode_it_did_not_start(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    own = [event(1), event(2)]
    store.append_batch(PEER, PRODUCER, own)
    before = store.episode("ep-1")

    with pytest.raises(BatchConflict) as caught:
        store.append_batch(PEER_B, PRODUCER, [event(1, episode="ep-b"), event(2, phase="correction", text="x")])

    assert caught.value.code == "conflict"
    assert rows(store, "SELECT count(*) FROM activity_events") == [(2,)]
    assert store.episode("ep-b") is None
    assert store.episode("ep-1") == before
    replay = store.append_batch(PEER, PRODUCER, own)
    assert (replay.accepted, replay.duplicates, replay.episode_revisions) == (0, 2, {"ep-1": 1})
    assert store.append_batch(PEER, PRODUCER, [event(3)]).episode_revisions == {"ep-1": 2}


def test_another_peer_may_start_its_own_episode(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    store.append_batch(PEER, PRODUCER, [event(1)])

    result = store.append_batch(PEER_B, PRODUCER, [event(1, episode="ep-b")])

    assert (result.accepted, result.duplicates, result.episode_revisions) == (1, 0, {"ep-b": 1})
    assert rows(store, "SELECT DISTINCT peer_id FROM activity_events WHERE episode_id = 'ep-b'") == [(PEER_B,)]


def test_a_local_correction_does_not_take_over_the_peers_episode(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    store.append_batch(PEER, PRODUCER, [event(1)])
    fix = event(1, phase="correction", source="user_correction", actor="human", text="use the switcher")

    store.append_batch(CORRECTION_PEER, "cli", [fix], foreign_episodes=True)

    assert store.append_batch(PEER, PRODUCER, [event(2)]).episode_revisions == {"ep-1": 3}
    with pytest.raises(BatchConflict):
        store.append_batch(PEER_B, PRODUCER, [event(1)])
    with pytest.raises(BatchConflict):
        store.append_batch(CORRECTION_PEER, "cli", [event(2, phase="correction", text="again")])


def test_a_reused_producer_sequence_is_a_conflict(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    store.append_batch(PEER, PRODUCER, [event(1)])
    with pytest.raises(BatchConflict):
        store.append_batch(PEER, PRODUCER, [event(1)])
    # A restarted producer (new producer id) may start its sequence again.
    assert store.append_batch(PEER, "prod-2", [event(1)]).accepted == 1


def test_episode_revision_advances_only_on_new_events(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    first = event(1)
    store.append_batch(PEER, PRODUCER, [first])
    assert store.append_batch(PEER, PRODUCER, [first]).episode_revisions == {"ep-1": 1}

    mixed = store.append_batch(PEER, PRODUCER, [first, event(2)])

    assert mixed.episode_revisions == {"ep-1": 2}
    record = store.episode("ep-1")
    assert record is not None
    assert (record.revision, record.reviewed_revision, record.event_count) == (2, 0, 2)
    assert [e.seq for e in store.events_for_episode("ep-1", revision=1)] == [1]
    assert [e.seq for e in store.events_for_episode("ep-1")] == [1, 2]


def test_episode_scope_tracks_outcome_coverage_and_corrections(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    store.append_batch(
        PEER,
        PRODUCER,
        [
            event(1, result={"status": "claimed_success"}),
            event(2, phase="observed", quality={"coverage": "gap"}),
        ],
    )
    store.append_batch(
        PEER,
        PRODUCER,
        [
            event(3, phase="boundary", action={"op": "task_end"}, result={"status": "claimed_failure"}),
            event(4, phase="correction", action={"op": "other"}, text="use the account switcher first"),
            event(5, phase="observed", result={"status": "claimed_success"}),
        ],
    )

    record = store.episode("ep-1")
    assert record is not None
    assert record.site == "example.com"
    assert record.run_id == "run-1"
    assert record.observed_outcome == "claimed_failure"  # observed events do not count as outcome
    assert record.coverage == "gap"
    assert record.has_correction is True
    assert (record.started_at, record.last_event_at) == (1001.0, 1005.0)


def test_committed_events_survive_reopen(tmp_path: Path) -> None:
    stored = event(1)
    make_store(tmp_path).append_batch(PEER, PRODUCER, [stored])

    reopened = ActivityStore(tmp_path / "mordred.db", plain_opener)
    reopened.initialize(tmp_path)

    assert reopened.events_for_episode("ep-1") == [stored]


def test_store_bound_to_another_home_is_refused(tmp_path: Path) -> None:
    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()
    store = ActivityStore(tmp_path / "mordred.db", plain_opener)
    store.initialize(tmp_path / "a")

    with pytest.raises(ActivityRefused) as caught:
        ActivityStore(tmp_path / "mordred.db", plain_opener).initialize(tmp_path / "b")
    assert caught.value.code == "profile_mismatch"


def test_newer_schema_is_refused_not_recreated(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    with store.connection() as conn:
        conn.execute("UPDATE activity_meta SET value = '99' WHERE key = 'schema_version'")

    with pytest.raises(ActivityRefused) as caught:
        store.initialize(tmp_path)
    assert caught.value.code == "schema_newer"
    assert rows(store, "SELECT value FROM activity_meta WHERE key = 'schema_version'") == [("99",)]


def test_backup_restore_round_trip_preserves_rows_and_bumps_generation(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    kept = [event(1), event(2, episode="ep-2", session_ref={"hermes_session_id": "sess-1"})]
    store.append_batch(PEER, PRODUCER, kept)
    with store.connection() as conn:
        conn.executemany(
            "INSERT INTO activity_review_jobs (job_id, episode_id, input_revision, reviewer_version, state, "
            "lease_owner, lease_expires_at, created_at, updated_at) VALUES (?, 'ep-1', ?, 'v1', ?, 'w', 9e9, 0, 0)",
            [("job-leased", 1, "leased"), ("job-calling", 2, "calling"), ("job-done", 3, "completed")],
        )
        conn.execute(
            "INSERT INTO activity_review_attempts (attempt_id, job_id, request_id, state, started_at) "
            "VALUES ('att-1', 'job-calling', 'req-1', 'submitted', 0)"
        )
    before = store.meta()
    backup = tmp_path / "backups" / "snapshot.db"
    backup.parent.mkdir()
    store.backup(backup)
    assert backup.stat().st_mode & 0o777 == 0o600
    store.append_batch(PEER, PRODUCER, [event(3)])

    after = store.restore(backup)

    assert after.store_generation != before.store_generation
    assert after.profile_home == before.profile_home
    assert store.events_for_episode("ep-1") + store.events_for_episode("ep-2") == kept
    states = dict(rows(store, "SELECT job_id, state FROM activity_review_jobs"))
    assert states == {"job-leased": "pending", "job-calling": "uncertain", "job-done": "completed"}
    assert rows(store, "SELECT lease_owner FROM activity_review_jobs WHERE job_id = 'job-leased'") == [(None,)]
    assert rows(store, "SELECT state FROM activity_review_attempts") == [("uncertain",)]
    episode = store.episode("ep-2")
    assert episode is not None and episode.session_ref_state == "unavailable"


def test_backup_never_overwrites_an_existing_file(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    existing = tmp_path / "existing.db"
    existing.write_bytes(b"keep")
    with pytest.raises(ActivityRefused) as caught:
        store.backup(existing)
    assert caught.value.code == "destination_exists"
    assert existing.read_bytes() == b"keep"


def test_restore_refuses_a_newer_schema(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    store.append_batch(PEER, PRODUCER, [event(1)])
    newer = tmp_path / "newer.db"
    store.backup(newer)
    with sqlite3.connect(newer) as conn:
        conn.execute(
            "UPDATE activity_meta SET value = ? WHERE key = 'schema_version'", (str(SUPPORTED_SCHEMA_VERSION + 1),)
        )
    conn.close()
    store.append_batch(PEER, PRODUCER, [event(2)])
    generation = store.meta().store_generation

    with pytest.raises(ActivityRefused) as caught:
        store.restore(newer)

    assert caught.value.code == "schema_newer"
    assert store.meta().store_generation == generation
    assert len(store.events_for_episode("ep-1")) == 2


def _lesson(conn: sqlite3.Connection, lesson_id: str, state: str, created_at: float, evidence: list[str]) -> None:
    conn.execute(
        "INSERT INTO activity_lessons (lesson_id, revision, state, origin, created_at) "
        "VALUES (?, 1, ?, 'correction', ?)",
        (lesson_id, state, created_at),
    )
    conn.executemany(
        "INSERT INTO activity_lesson_evidence (lesson_id, revision, event_id, pinned) VALUES (?, 1, ?, ?)",
        [(lesson_id, event_id, int(state == "admitted")) for event_id in evidence],
    )


def test_retention_keeps_pinned_evidence_and_suspends_orphaned_lessons(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    pinned, unpinned, recent, candidate_evidence = event(1), event(2), event(3, episode="ep-new"), event(4)
    store.append_batch(PEER, PRODUCER, [pinned, unpinned, recent, candidate_evidence])
    now = time.time()
    old = now - 100 * 86400
    with store.connection() as conn:
        conn.execute("UPDATE activity_events SET received_at = ? WHERE episode_id = 'ep-1'", (old,))
        _lesson(conn, "kept", "admitted", old, [pinned.event_id])
        _lesson(conn, "orphan", "admitted", old, ["event-that-is-gone"])
        _lesson(conn, "stale-candidate", "candidate", old, [candidate_evidence.event_id])
        _lesson(conn, "fresh-candidate", "candidate", now, [])

    report = store.apply_retention(now, raw_days=30, candidate_days=90)

    remaining = {row[0] for row in rows(store, "SELECT event_id FROM activity_events")}
    assert remaining == {pinned.event_id, recent.event_id}
    lessons = dict(rows(store, "SELECT lesson_id, state FROM activity_lessons"))
    assert lessons == {"kept": "admitted", "orphan": "suspended", "fresh-candidate": "candidate"}
    assert rows(store, "SELECT suspended_reason FROM activity_lessons WHERE lesson_id = 'orphan'") == [
        ("evidence_missing",)
    ]
    assert (report.events_deleted, report.candidates_deleted, report.lessons_suspended) == (2, 1, 1)
    assert report.complete is True


def test_raw_retention_zero_keeps_events_and_episodes_but_still_expires_candidates(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    kept, candidate_evidence = event(1), event(2)
    store.append_batch(PEER, PRODUCER, [kept, candidate_evidence])
    now = time.time()
    ancient = now - 10_000 * 86400
    with store.connection() as conn:
        conn.execute("UPDATE activity_events SET received_at = ?", (ancient,))
        _lesson(conn, "stale-candidate", "candidate", ancient, [candidate_evidence.event_id])
        _lesson(conn, "orphan", "admitted", ancient, ["event-that-is-gone"])

    planned = store.plan_retention(now, raw_days=0, candidate_days=90)
    applied = store.apply_retention(now, raw_days=0, candidate_days=90)

    assert planned == applied
    assert (applied.events_deleted, applied.episodes_deleted) == (0, 0)
    assert (applied.candidates_deleted, applied.lessons_suspended, applied.complete) == (1, 1, True)
    assert {row[0] for row in rows(store, "SELECT event_id FROM activity_events")} == {
        kept.event_id,
        candidate_evidence.event_id,
    }
    assert store.episode("ep-1") is not None
    assert dict(rows(store, "SELECT lesson_id, state FROM activity_lessons")) == {"orphan": "suspended"}


def test_retention_is_bounded_per_pass(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    store.append_batch(PEER, PRODUCER, [event(seq) for seq in range(1, 6)])
    with store.connection() as conn:
        conn.execute("UPDATE activity_events SET received_at = 0")

    first = store.apply_retention(time.time(), raw_days=30, candidate_days=90, limit=3)

    assert (first.events_deleted, first.complete) == (3, False)
    assert rows(store, "SELECT count(*) FROM activity_events") == [(2,)]


def test_status_reports_counts_and_states_only(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    store.append_batch(PEER, PRODUCER, [event(1, phase="correction", text="SECRET correction text")])

    status = store.status()

    assert status.schema_version == SUPPORTED_SCHEMA_VERSION == 2
    assert status.counts["activity_events"] == 1
    assert status.counts["activity_episodes"] == 1
    assert status.unreviewed_episodes == 1
    assert "SECRET" not in repr(status)


def test_a_busy_store_is_refused_without_retrying(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    holder = sqlite3.connect(tmp_path / "mordred.db", isolation_level=None)
    holder.execute("BEGIN IMMEDIATE")
    try:
        with pytest.raises(ActivityRefused) as caught:
            store.append_batch(PEER, PRODUCER, [event(1)])
    finally:
        holder.rollback()
        holder.close()
    assert caught.value.code == "busy"


def test_a_full_disk_is_reported_as_such(tmp_path: Path) -> None:
    def full(_path: Path) -> sqlite3.Connection:
        raise sqlite3.OperationalError("database or disk is full")

    with pytest.raises(ActivityRefused) as caught:
        ActivityStore(tmp_path / "mordred.db", full).status()
    assert caught.value.code == "disk_full"


@pytest.mark.parametrize(
    ("message", "expected"),
    [
        ("database disk image is malformed", "store_unavailable"),
        ("database or disk is full", "disk_full"),
    ],
)
def test_a_corrupt_store_is_not_reported_as_a_full_disk(tmp_path: Path, message: str, expected: str) -> None:
    def failing(_path: Path) -> sqlite3.Connection:
        raise sqlite3.DatabaseError(message)

    with pytest.raises(ActivityRefused) as caught:
        ActivityStore(tmp_path / "mordred.db", failing).status()
    assert caught.value.code == expected


# --- post-task corrections join the attempt's episode ----------------------------------------------


def operator_task(attempt_id: str = "att-1", episode: str = "ep-task") -> list[NormalizedEvent]:
    """What the operator collector emits for one finished task: boundary, attempt, boundary."""
    return [
        event(
            1,
            episode,
            phase="boundary",
            actor="human",
            action={"op": "task_start", "site": "example.com"},
            text="Export the monthly report",
        ),
        event(2, episode, phase="intended", attempt_id=attempt_id),
        event(3, episode, phase="dispatched", attempt_id=attempt_id),
        event(4, episode, phase="boundary", action={"op": "task_end"}, result={"status": "claimed_success"}),
    ]


def post_task_correction(seq: int = 5, attempt_id: str = "att-1", episode: str = "ep-fresh") -> NormalizedEvent:
    # The collector closes its episode at task end, so the correction opens a fresh one.
    return event(
        seq,
        episode,
        phase="correction",
        actor="human",
        attempt_id=attempt_id,
        action={"op": "other"},
        text="Pick the Finance workspace first",
    )


def test_a_post_task_correction_joins_its_attempts_episode(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    store.append_batch(PEER, PRODUCER, operator_task())
    before = store.episode("ep-task")
    assert before is not None and before.has_correction is False
    fix = post_task_correction()

    result = store.append_batch(PEER, PRODUCER, [fix])
    replay = store.append_batch(PEER, PRODUCER, [fix])

    assert rows(store, "SELECT episode_id FROM activity_events WHERE event_id = ?", fix.event_id) == [("ep-task",)]
    assert store.episode("ep-fresh") is None
    after = store.episode("ep-task")
    assert after is not None
    assert (after.has_correction, after.revision, after.event_count) == (True, before.revision + 1, 5)
    assert (result.accepted, result.duplicates) == (1, 0)
    assert (replay.accepted, replay.duplicates) == (0, 1)
    [stored] = [e for e in store.events_for_episode("ep-task") if e.event_id == fix.event_id]
    assert stored.content_digest != fix.content_digest
    assert stored.content_digest == canonical_digest(stored)


def test_a_correction_and_its_attempt_in_one_batch_are_rehomed_and_replay_cleanly(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    sent = [*operator_task(), post_task_correction()]

    first = store.append_batch(PEER, PRODUCER, sent)
    replay = store.append_batch(PEER, PRODUCER, sent)

    assert rows(store, "SELECT DISTINCT episode_id FROM activity_events") == [("ep-task",)]
    assert store.episode("ep-fresh") is None
    record = store.episode("ep-task")
    assert record is not None and record.has_correction is True
    assert (first.accepted, first.duplicates) == (5, 0)
    assert (replay.accepted, replay.duplicates) == (0, len(sent))


def test_a_correction_for_an_unknown_attempt_keeps_its_own_episode(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    store.append_batch(PEER, PRODUCER, operator_task())
    fix = post_task_correction(attempt_id="att-missing")

    store.append_batch(PEER, PRODUCER, [fix])

    assert rows(store, "SELECT episode_id, content_digest FROM activity_events WHERE event_id = ?", fix.event_id) == [
        ("ep-fresh", fix.content_digest)
    ]
    record = store.episode("ep-fresh")
    assert record is not None and record.has_correction is True


def test_a_correction_never_joins_another_peers_attempt(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    store.append_batch(PEER_B, PRODUCER, operator_task())
    before = store.episode("ep-task")
    fix = post_task_correction()

    store.append_batch(PEER, PRODUCER, [fix])

    assert store.episode("ep-fresh") is not None
    assert store.episode("ep-task") == before
    assert rows(store, "SELECT episode_id, peer_id FROM activity_events WHERE event_id = ?", fix.event_id) == [
        ("ep-fresh", PEER)
    ]
    assert rows(store, "SELECT DISTINCT peer_id FROM activity_events WHERE episode_id = 'ep-task'") == [(PEER_B,)]


def test_a_correction_cannot_follow_its_own_batch_into_another_peers_episode(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    store.append_batch(PEER_B, PRODUCER, operator_task())
    before = store.episode("ep-task")
    claimed = event(6, "ep-task", phase="intended", attempt_id="att-2")

    with pytest.raises(BatchConflict):
        store.append_batch(PEER, PRODUCER, [claimed, post_task_correction(seq=7, attempt_id="att-2")])

    assert store.episode("ep-task") == before
    assert store.episode("ep-fresh") is None
    assert rows(store, "SELECT DISTINCT peer_id FROM activity_events") == [(PEER_B,)]


def test_a_correction_stored_before_its_attempt_replays_as_a_duplicate(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    fix = post_task_correction(seq=10)
    store.append_batch(PEER, PRODUCER, [fix])  # its attempt was not stored yet
    store.append_batch(PEER, PRODUCER, operator_task())

    replay = store.append_batch(PEER, PRODUCER, [fix])

    assert (replay.accepted, replay.duplicates) == (0, 1)
    assert rows(store, "SELECT episode_id FROM activity_events WHERE event_id = ?", fix.event_id) == [("ep-fresh",)]


# --- schema v2: query and page fields, upgrade from v1 ---------------------------------------------

#: The ``activity_events`` columns schema v2 added.
_V2_EVENT_COLUMNS = ("query TEXT,", "page_title TEXT,", "page_text TEXT,")
_V2_FIELDS = frozenset({"query", "page_title", "page_text", "content_digest"})


def v1_statements() -> list[str]:
    """The schema-v1 DDL: today's statements without the columns v2 added."""
    statements = [
        "\n".join(line for line in statement.splitlines() if line.strip() not in _V2_EVENT_COLUMNS)
        for statement in _schema.STATEMENTS
    ]
    pairs = zip(_schema.STATEMENTS, statements, strict=True)
    removed = sum(len(new.splitlines()) - len(old.splitlines()) for new, old in pairs)
    assert removed == len(_V2_EVENT_COLUMNS)
    return statements


def v1_digest(item: NormalizedEvent) -> str:
    """``content_digest`` as the schema-v1 receiver computed it (before the three fields existed)."""
    fields = {key: value for key, value in dataclasses.asdict(item).items() if key not in _V2_FIELDS}
    return hashlib.sha256(canonical_json(fields).encode("ascii")).hexdigest()


def make_v1_store(path: Path, home: Path, *events: NormalizedEvent) -> None:
    """A store as the schema-v1 receiver left it, holding ``events`` under ``PEER`` / ``PRODUCER``."""
    names = [f.name for f in dataclasses.fields(NormalizedEvent) if f.name not in _V2_FIELDS]
    columns = ", ".join("producer_seq" if name == "seq" else name for name in names)
    conn = sqlite3.connect(path)
    try:
        for statement in v1_statements():
            conn.execute(statement)
        meta = [("schema_version", "1"), ("profile_home", os.path.realpath(home)), ("store_generation", "ab" * 16)]
        conn.executemany("INSERT INTO activity_meta (key, value) VALUES (?, ?)", meta)
        for item in events:
            values = dataclasses.asdict(item)
            values.update(
                result_evidence=json.dumps(list(item.result_evidence)),
                exclusions=json.dumps(list(item.exclusions)),
                truncated=int(item.truncated),
            )
            conn.execute(
                f"INSERT INTO activity_events (peer_id, producer_id, trust, permitted_use, received_at, "
                f"episode_revision, {columns}, content_digest) VALUES ({', '.join('?' * (len(names) + 7))})",
                (PEER, PRODUCER, "paired_peer", "learning", time.time(), 1, *map(values.get, names), v1_digest(item)),
            )
            conn.execute(
                "INSERT OR IGNORE INTO activity_episodes (episode_id, revision, started_at, last_event_at, coverage, "
                "event_count, created_at, updated_at) VALUES (?, 1, ?, ?, ?, 1, 0, 0)",
                (item.episode_id, item.observed_at, item.observed_at, item.coverage),
            )
        conn.commit()
    finally:
        conn.close()


def event_columns(store: ActivityStore) -> set[str]:
    return {str(row[1]) for row in rows(store, "PRAGMA table_info(activity_events)")}


def test_a_v1_store_is_upgraded_in_place_and_its_rows_still_verify(tmp_path: Path) -> None:
    old = event(1)
    make_v1_store(tmp_path / "mordred.db", tmp_path, old)
    store = ActivityStore(tmp_path / "mordred.db", plain_opener)

    meta = store.initialize(tmp_path)

    assert meta.schema_version == store.meta().schema_version == SUPPORTED_SCHEMA_VERSION == 2
    assert {"query", "page_title", "page_text"} <= event_columns(store)
    [stored] = store.events_for_episode("ep-1")
    assert stored == old
    [(digest,)] = rows(store, "SELECT content_digest FROM activity_events")
    assert canonical_digest(stored) == digest == v1_digest(old)
    replay = store.append_batch(PEER, PRODUCER, [old])
    assert (replay.accepted, replay.duplicates) == (0, 1)
    fresh = event(2, page_title="Reports", page_text="Totals for May")
    assert store.append_batch(PEER, PRODUCER, [fresh]).accepted == 1
    assert store.events_for_episode("ep-1") == [old, fresh]
    # Opening an upgraded store again changes nothing.
    assert store.initialize(tmp_path) == meta


def test_a_v1_store_bound_to_another_home_is_refused_before_any_upgrade(tmp_path: Path) -> None:
    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()
    make_v1_store(tmp_path / "mordred.db", tmp_path / "a", event(1))
    store = ActivityStore(tmp_path / "mordred.db", plain_opener)

    with pytest.raises(ActivityRefused) as caught:
        store.initialize(tmp_path / "b")

    assert caught.value.code == "profile_mismatch"
    assert rows(store, "SELECT value FROM activity_meta WHERE key = 'schema_version'") == [("1",)]
    assert "query" not in event_columns(store)


def test_restoring_a_v1_backup_upgrades_the_store(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    old = event(1)
    make_v1_store(tmp_path / "v1-backup.db", tmp_path, old)

    meta = store.restore(tmp_path / "v1-backup.db")

    assert meta.schema_version == SUPPORTED_SCHEMA_VERSION
    assert store.events_for_episode("ep-1") == [old]
    assert store.append_batch(PEER, PRODUCER, [event(2, page_text="Totals")]).accepted == 1


def test_query_and_page_fields_round_trip(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    sent = event(
        1,
        action={"op": "navigate", "site": "example.com", "route": "/r?view=list&token=s1#totals"},
        page_title="Monthly reports",
        page_text="Totals for May",
    )

    store.append_batch(PEER, PRODUCER, [sent])

    [stored] = store.events_for_episode("ep-1")
    assert stored == sent
    assert (stored.route, stored.query) == ("/r", "?view=list&token=redacted#totals")
    assert (stored.page_title, stored.page_text) == ("Monthly reports", "Totals for May")
    assert stored.content_digest == canonical_digest(stored)
    assert store.append_batch(PEER, PRODUCER, [sent]).duplicates == 1
