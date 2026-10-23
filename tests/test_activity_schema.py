"""Schema v3 of ``mordred.db``: upgrades from v1 and v2 and the dropped lesson-pipeline tables.

A new v3 store and a v1 or v2 store upgraded to v3 must end with the same
tables, columns and indexes, and every event row stored before the upgrade
must still verify against its digest.
"""

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
from mordred_hermes.activity.store import SUPPORTED_SCHEMA_VERSION, ActivityStore
from tests._activity_schema_history import LESSON_TABLES, V2_STATEMENTS, v1_statements

PEER = "operator:peer-a"
PRODUCER = "prod-1"
#: Columns of ``NormalizedEvent`` that schema v2 added (and that the v1 digest did not cover).
_V2_FIELDS = frozenset({"query", "page_title", "page_text", "content_digest"})


def plain_opener(path: Path) -> sqlite3.Connection:
    return sqlite3.connect(path)


def make_store(home: Path) -> ActivityStore:
    store = ActivityStore(home / "mordred.db", plain_opener)
    store.initialize(home)
    return store


def event(seq: int, episode: str = "ep-1", **overrides: Any) -> NormalizedEvent:
    raw: dict[str, Any] = {
        "event_id": str(uuid.uuid4()),
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


def v1_digest(item: NormalizedEvent) -> str:
    """``content_digest`` as the schema-v1 receiver computed it (before the three fields existed)."""
    fields = {key: value for key, value in dataclasses.asdict(item).items() if key not in _V2_FIELDS}
    return hashlib.sha256(canonical_json(fields).encode("ascii")).hexdigest()


def _seed_lesson_pipeline(conn: sqlite3.Connection, event_id: str) -> None:
    """One row in every table of the removed lesson pipeline, linked like the old code linked them."""
    conn.execute(
        "INSERT INTO activity_review_jobs (job_id, episode_id, input_revision, reviewer_version, state, "
        "created_at, updated_at) VALUES ('job-1', 'ep-1', 1, 'v1', 'leased', 0, 0)"
    )
    conn.execute(
        "INSERT INTO activity_review_attempts (attempt_id, job_id, request_id, state, started_at) "
        "VALUES ('att-1', 'job-1', 'req-1', 'submitted', 0)"
    )
    conn.execute(
        "INSERT INTO activity_lessons (lesson_id, revision, state, origin, episode_id, guidance, created_at) "
        "VALUES ('lesson-1', 1, 'admitted', 'correction', 'ep-1', 'Select Finance first', 0)"
    )
    conn.execute(
        "INSERT INTO activity_lesson_evidence (lesson_id, revision, event_id, pinned) VALUES ('lesson-1', 1, ?, 1)",
        (event_id,),
    )
    conn.execute(
        "INSERT INTO activity_uses (use_id, lesson_id, revision, retrieved_at) VALUES ('use-1', 'lesson-1', 1, 0)"
    )
    conn.execute("INSERT INTO activity_budget (window_start, window_end) VALUES (0, 86400)")


def make_old_store(path: Path, home: Path, version: int, *events: NormalizedEvent) -> None:
    """A store as the schema-``version`` receiver left it, with lesson-pipeline rows when it has events."""
    assert version in (1, 2)
    excluded = _V2_FIELDS if version == 1 else frozenset({"content_digest"})
    names = [f.name for f in dataclasses.fields(NormalizedEvent) if f.name not in excluded]
    columns = ", ".join("producer_seq" if name == "seq" else name for name in names)
    conn = sqlite3.connect(path)
    try:
        for statement in v1_statements() if version == 1 else V2_STATEMENTS:
            conn.execute(statement)
        meta = [
            ("schema_version", str(version)),
            ("profile_home", os.path.realpath(home)),
            ("store_generation", "ab" * 16),
        ]
        conn.executemany("INSERT INTO activity_meta (key, value) VALUES (?, ?)", meta)
        for item in events:
            values = dataclasses.asdict(item)
            values.update(
                result_evidence=json.dumps(list(item.result_evidence)),
                exclusions=json.dumps(list(item.exclusions)),
                truncated=int(item.truncated),
            )
            digest = v1_digest(item) if version == 1 else canonical_digest(item)
            conn.execute(
                f"INSERT INTO activity_events (peer_id, producer_id, trust, permitted_use, received_at, "
                f"episode_revision, {columns}, content_digest) VALUES ({', '.join('?' * (len(names) + 7))})",
                (PEER, PRODUCER, "paired_peer", "learning", time.time(), 1, *map(values.get, names), digest),
            )
            conn.execute(
                "INSERT OR IGNORE INTO activity_episodes (episode_id, revision, started_at, last_event_at, coverage, "
                "event_count, created_at, updated_at) VALUES (?, 1, ?, ?, ?, 1, 0, 0)",
                (item.episode_id, item.observed_at, item.observed_at, item.coverage),
            )
        if events:
            _seed_lesson_pipeline(conn, events[0].event_id)
        conn.commit()
    finally:
        conn.close()


def schema_shape(store: ActivityStore) -> dict[str, Any]:
    """Tables with their columns, and indexes with their columns, from ``sqlite_master`` and the pragmas.

    Column order is not compared: v2 appended ``query``/``page_title``/``page_text`` to an upgraded
    ``activity_events`` after ``content_digest``, and every reader and writer names its columns. The
    ``CREATE`` text is compared for every other object (it carries the ``CHECK`` constraints).
    """
    shape: dict[str, Any] = {}
    with store.connection() as conn:
        objects = conn.execute("SELECT type, name, tbl_name, sql FROM sqlite_master ORDER BY type, name").fetchall()
        for kind, name, table, sql in objects:
            entry: dict[str, Any] = {"table": table}
            if kind == "table":
                info = conn.execute(f"PRAGMA table_xinfo({name})").fetchall()
                entry["columns"] = {row[1]: (row[2], row[3], row[4], row[5], row[6]) for row in info}
            else:
                entry["columns"] = [row[2] for row in conn.execute(f"PRAGMA index_info({name})")]
                unique = {row[1]: row[2] for row in conn.execute(f"PRAGMA index_list({table})")}
                entry["unique"] = unique[name]
            if name != "activity_events":
                entry["sql"] = sql
            shape[f"{kind}:{name}"] = entry
    return shape


def table_names(store: ActivityStore) -> set[str]:
    return {row[0] for row in rows(store, "SELECT name FROM sqlite_master WHERE type = 'table'")}


def test_a_new_store_holds_only_the_history_tables(tmp_path: Path) -> None:
    store = make_store(tmp_path)

    assert store.meta().schema_version == SUPPORTED_SCHEMA_VERSION == _schema.SCHEMA_VERSION == 3
    assert table_names(store) == {*_schema.TABLES, "sqlite_sequence"}
    assert not table_names(store) & set(LESSON_TABLES)


def test_migration_2_drops_exactly_the_lesson_pipeline_tables() -> None:
    assert set(_schema.DROPPED_TABLES) == set(LESSON_TABLES)
    assert not set(_schema.TABLES) & set(LESSON_TABLES)
    assert {f"DROP TABLE IF EXISTS {name}" for name in LESSON_TABLES} <= set(_schema.MIGRATIONS[2])
    created = {statement.split()[2] for statement in V2_STATEMENTS if statement.startswith("CREATE INDEX")} - {
        statement.split()[2] for statement in _schema.STATEMENTS if statement.startswith("CREATE INDEX")
    }
    assert created == set(_schema.DROPPED_INDEXES)


@pytest.mark.parametrize("version", [1, 2])
def test_an_older_store_upgrades_to_the_same_schema_as_a_new_one(tmp_path: Path, version: int) -> None:
    (tmp_path / "new").mkdir()
    (tmp_path / "old").mkdir()
    fresh = make_store(tmp_path / "new")
    kept = [event(1), event(2, page_title="Reports", page_text="Totals") if version == 2 else event(2)]
    make_old_store(tmp_path / "old" / "mordred.db", tmp_path / "old", version, *kept)
    assert table_names(ActivityStore(tmp_path / "old" / "mordred.db", plain_opener)) >= set(LESSON_TABLES)
    upgraded = ActivityStore(tmp_path / "old" / "mordred.db", plain_opener)

    meta = upgraded.initialize(tmp_path / "old")

    assert meta.schema_version == upgraded.meta().schema_version == SUPPORTED_SCHEMA_VERSION
    assert schema_shape(upgraded) == schema_shape(fresh)
    assert store_rows_verify(upgraded) == len(kept)
    assert upgraded.events_for_episode("ep-1") == kept
    assert upgraded.status().counts == {"activity_events": 2, "activity_episodes": 1}
    replay = upgraded.append_batch(PEER, PRODUCER, kept)
    assert (replay.accepted, replay.duplicates) == (0, 2)
    # Opening an upgraded store again changes nothing.
    assert upgraded.initialize(tmp_path / "old") == meta


def store_rows_verify(store: ActivityStore) -> int:
    """Every stored event's digest matches its content (the v1 digest for rows a v1 receiver wrote)."""
    stored = store.events_for_episode("ep-1")
    digests = [row[0] for row in rows(store, "SELECT content_digest FROM activity_events ORDER BY receipt")]
    assert len(stored) == len(digests)
    for item, digest in zip(stored, digests, strict=True):
        assert item.content_digest == digest
        assert digest in (canonical_digest(item), v1_digest(item))
    return len(stored)


def test_a_v1_store_is_upgraded_in_place_and_its_rows_still_verify(tmp_path: Path) -> None:
    old = event(1)
    make_old_store(tmp_path / "mordred.db", tmp_path, 1, old)
    store = ActivityStore(tmp_path / "mordred.db", plain_opener)

    meta = store.initialize(tmp_path)

    assert meta.schema_version == store.meta().schema_version == SUPPORTED_SCHEMA_VERSION
    [stored] = store.events_for_episode("ep-1")
    assert stored == old
    [(digest,)] = rows(store, "SELECT content_digest FROM activity_events")
    assert canonical_digest(stored) == digest == v1_digest(old)
    fresh = event(2, page_title="Reports", page_text="Totals for May")
    assert store.append_batch(PEER, PRODUCER, [fresh]).accepted == 1
    assert store.events_for_episode("ep-1") == [old, fresh]


def test_an_older_store_bound_to_another_home_is_refused_before_any_upgrade(tmp_path: Path) -> None:
    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()
    make_old_store(tmp_path / "mordred.db", tmp_path / "a", 1, event(1))
    store = ActivityStore(tmp_path / "mordred.db", plain_opener)

    with pytest.raises(ActivityRefused) as caught:
        store.initialize(tmp_path / "b")

    assert caught.value.code == "profile_mismatch"
    assert rows(store, "SELECT value FROM activity_meta WHERE key = 'schema_version'") == [("1",)]
    assert "query" not in {str(row[1]) for row in rows(store, "PRAGMA table_info(activity_events)")}
    assert table_names(store) >= set(LESSON_TABLES)


@pytest.mark.parametrize("version", [1, 2])
def test_restoring_an_older_backup_upgrades_the_store(tmp_path: Path, version: int) -> None:
    store = make_store(tmp_path)
    reference = schema_shape(store)
    old = event(1)
    make_old_store(tmp_path / "old-backup.db", tmp_path, version, old)

    meta = store.restore(tmp_path / "old-backup.db")

    assert meta.schema_version == SUPPORTED_SCHEMA_VERSION
    assert schema_shape(store) == reference
    assert store.events_for_episode("ep-1") == [old]
    assert store.append_batch(PEER, PRODUCER, [event(2, page_text="Totals")]).accepted == 1
