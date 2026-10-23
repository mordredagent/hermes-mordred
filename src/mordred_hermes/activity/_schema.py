"""Schema v3 of ``mordred.db`` (all activity tables live in this one encrypted file).

:data:`STATEMENTS` create a new store at the current version;
:data:`MIGRATIONS` upgrades an older store in place, one version per step,
inside the transaction that opens it:

- v2 added the nullable ``query``, ``page_title`` and ``page_text`` columns to
  ``activity_events`` (the capture policy that keeps everything but secrets);
- v3 dropped the tables of the removed lesson pipeline (review jobs and
  attempts, lessons and their evidence, recall uses, the review budget;
  2026-10-22). ``activity_episodes.reviewed_revision`` stays as a dormant
  column (always ``0``) in new stores too, so a new store and an upgraded one
  have the same tables, columns and indexes without ``ALTER TABLE DROP COLUMN``.
  Columns that v2 added to an upgraded store sit after ``content_digest``;
  every reader and writer names its columns.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Final

SCHEMA_VERSION: Final = 3

TABLES: Final = (
    "activity_meta",
    "activity_events",
    "activity_episodes",
)

#: Tables of the lesson pipeline that schema v3 dropped, children before their parents.
DROPPED_TABLES: Final = (
    "activity_review_attempts",
    "activity_review_jobs",
    "activity_lesson_evidence",
    "activity_lessons",
    "activity_uses",
    "activity_budget",
)
#: Their explicit indexes (``DROP TABLE`` removes them too; listed so the step reads complete).
DROPPED_INDEXES: Final = (
    "activity_review_attempts_job",
    "activity_lessons_state",
    "activity_lesson_evidence_event",
    "activity_uses_lesson",
)

STATEMENTS: Final = (
    """
    CREATE TABLE activity_meta (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE activity_events (
        receipt INTEGER PRIMARY KEY AUTOINCREMENT,
        event_id TEXT NOT NULL,
        peer_id TEXT NOT NULL,
        producer_id TEXT NOT NULL,
        producer_seq INTEGER NOT NULL,
        trust TEXT NOT NULL,
        permitted_use TEXT NOT NULL,
        received_at REAL NOT NULL,
        episode_id TEXT NOT NULL,
        episode_revision INTEGER NOT NULL,
        attempt_id TEXT,
        parent_attempt_id TEXT,
        source TEXT NOT NULL,
        actor TEXT NOT NULL,
        observed_at REAL NOT NULL,
        phase TEXT NOT NULL,
        op TEXT NOT NULL,
        target TEXT,
        site TEXT,
        route TEXT,
        args_json TEXT NOT NULL,
        result_status TEXT NOT NULL,
        result_method TEXT,
        result_evidence TEXT NOT NULL,
        coverage TEXT NOT NULL,
        exclusions TEXT NOT NULL,
        truncated INTEGER NOT NULL,
        page_sig_before TEXT,
        page_sig_after TEXT,
        hermes_session_id TEXT,
        turn_id TEXT,
        run_id TEXT,
        text TEXT,
        query TEXT,
        page_title TEXT,
        page_text TEXT,
        content_digest TEXT NOT NULL
    )
    """,
    "CREATE UNIQUE INDEX activity_events_event_id ON activity_events (event_id)",
    "CREATE UNIQUE INDEX activity_events_producer_seq ON activity_events (peer_id, producer_id, producer_seq)",
    "CREATE INDEX activity_events_episode ON activity_events (episode_id, episode_revision)",
    "CREATE INDEX activity_events_received ON activity_events (received_at)",
    """
    CREATE TABLE activity_episodes (
        episode_id TEXT PRIMARY KEY,
        revision INTEGER NOT NULL,
        reviewed_revision INTEGER NOT NULL DEFAULT 0,
        site TEXT,
        run_id TEXT,
        hermes_session_id TEXT,
        session_ref_state TEXT NOT NULL DEFAULT 'bound' CHECK (session_ref_state IN ('bound', 'unavailable')),
        started_at REAL NOT NULL,
        last_event_at REAL NOT NULL,
        observed_outcome TEXT NOT NULL DEFAULT 'unknown',
        coverage TEXT NOT NULL,
        has_correction INTEGER NOT NULL DEFAULT 0,
        event_count INTEGER NOT NULL DEFAULT 0,
        created_at REAL NOT NULL,
        updated_at REAL NOT NULL
    )
    """,
    "CREATE INDEX activity_episodes_last_event ON activity_episodes (last_event_at)",
)

#: ``MIGRATIONS[n]`` upgrades a store from schema ``n`` to ``n + 1``.
MIGRATIONS: Final[Mapping[int, tuple[str, ...]]] = {
    1: (
        "ALTER TABLE activity_events ADD COLUMN query TEXT",
        "ALTER TABLE activity_events ADD COLUMN page_title TEXT",
        "ALTER TABLE activity_events ADD COLUMN page_text TEXT",
    ),
    2: (
        *(f"DROP INDEX IF EXISTS {name}" for name in DROPPED_INDEXES),
        *(f"DROP TABLE IF EXISTS {name}" for name in DROPPED_TABLES),
    ),
}
