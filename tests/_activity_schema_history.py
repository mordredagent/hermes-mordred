"""The historical schema-v2 DDL of ``mordred.db``, frozen for upgrade tests.

Schema v3 dropped the lesson-pipeline tables (2026-10-22), so the production
statements can no longer describe what a v1 or v2 store held. These are the
v2 ``STATEMENTS`` exactly as shipped on the branch before the removal; the
v1 DDL is the same without the three ``activity_events`` columns v2 added.
Never edit them to follow the current schema.
"""

from __future__ import annotations

from typing import Final

#: The ``activity_events`` column definitions schema v2 added (v1 lacked them).
V2_EVENT_COLUMNS: Final = ("query TEXT,", "page_title TEXT,", "page_text TEXT,")
#: Tables of the removed lesson pipeline, present in v1 and v2 stores.
LESSON_TABLES: Final = (
    "activity_review_jobs",
    "activity_review_attempts",
    "activity_lessons",
    "activity_lesson_evidence",
    "activity_uses",
    "activity_budget",
)

V2_STATEMENTS: Final = (
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
    """
    CREATE TABLE activity_review_jobs (
        job_id TEXT PRIMARY KEY,
        episode_id TEXT NOT NULL,
        input_revision INTEGER NOT NULL,
        reviewer_version TEXT NOT NULL,
        state TEXT NOT NULL CHECK (state IN
            ('pending', 'leased', 'calling', 'completed', 'deferred', 'failed', 'uncertain')),
        lease_owner TEXT,
        lease_expires_at REAL,
        snapshot_digest TEXT,
        created_at REAL NOT NULL,
        updated_at REAL NOT NULL,
        failure_code TEXT,
        UNIQUE (episode_id, input_revision, reviewer_version)
    )
    """,
    """
    CREATE TABLE activity_review_attempts (
        attempt_id TEXT PRIMARY KEY,
        job_id TEXT NOT NULL REFERENCES activity_review_jobs (job_id),
        request_id TEXT NOT NULL UNIQUE,
        provider TEXT,
        model TEXT,
        reserved_input_tokens INTEGER NOT NULL DEFAULT 0,
        reserved_output_tokens INTEGER NOT NULL DEFAULT 0,
        reserved_cost_usd REAL NOT NULL DEFAULT 0,
        usage_input_tokens INTEGER,
        usage_output_tokens INTEGER,
        cost_usd_estimate REAL,
        state TEXT NOT NULL CHECK (state IN ('reserved', 'submitted', 'completed', 'failed', 'uncertain')),
        failure_code TEXT,
        started_at REAL NOT NULL,
        finished_at REAL
    )
    """,
    "CREATE INDEX activity_review_attempts_job ON activity_review_attempts (job_id)",
    """
    CREATE TABLE activity_lessons (
        lesson_id TEXT NOT NULL,
        revision INTEGER NOT NULL,
        state TEXT NOT NULL CHECK (state IN
            ('candidate', 'validated', 'admitted', 'suspended', 'rejected', 'retired')),
        origin TEXT NOT NULL CHECK (origin IN ('correction', 'review')),
        episode_id TEXT,
        scope_site TEXT,
        scope_route TEXT,
        scope_task TEXT,
        applies_when TEXT,
        does_not_apply TEXT,
        check_before_use TEXT,
        guidance TEXT,
        success_measure TEXT,
        evidence_digest TEXT,
        validation_method TEXT,
        validation_note TEXT,
        validated_at REAL,
        adopted_at REAL,
        adoption_digest TEXT,
        suspended_reason TEXT,
        created_at REAL NOT NULL,
        superseded_by TEXT,
        PRIMARY KEY (lesson_id, revision)
    )
    """,
    "CREATE INDEX activity_lessons_state ON activity_lessons (state, scope_site)",
    """
    CREATE TABLE activity_lesson_evidence (
        lesson_id TEXT NOT NULL,
        revision INTEGER NOT NULL,
        event_id TEXT NOT NULL,
        episode_revision INTEGER,
        pinned INTEGER NOT NULL DEFAULT 0,
        PRIMARY KEY (lesson_id, revision, event_id),
        FOREIGN KEY (lesson_id, revision) REFERENCES activity_lessons (lesson_id, revision)
    )
    """,
    "CREATE INDEX activity_lesson_evidence_event ON activity_lesson_evidence (event_id)",
    """
    CREATE TABLE activity_uses (
        use_id TEXT PRIMARY KEY,
        lesson_id TEXT NOT NULL,
        revision INTEGER NOT NULL,
        hermes_session_id TEXT,
        task_ref TEXT,
        retrieved_at REAL NOT NULL,
        applied INTEGER,
        outcome TEXT,
        outcome_at REAL
    )
    """,
    "CREATE INDEX activity_uses_lesson ON activity_uses (lesson_id, revision)",
    """
    CREATE TABLE activity_budget (
        window_start REAL PRIMARY KEY,
        window_end REAL NOT NULL,
        reserved_cost_usd REAL NOT NULL DEFAULT 0,
        used_cost_usd REAL NOT NULL DEFAULT 0,
        attempts INTEGER NOT NULL DEFAULT 0
    )
    """,
)


def v1_statements() -> list[str]:
    """The schema-v1 DDL: the v2 statements without the columns v2 added."""
    statements = [
        "\n".join(line for line in statement.splitlines() if line.strip() not in V2_EVENT_COLUMNS)
        for statement in V2_STATEMENTS
    ]
    removed = sum(
        len(new.splitlines()) - len(old.splitlines()) for new, old in zip(V2_STATEMENTS, statements, strict=True)
    )
    assert removed == len(V2_EVENT_COLUMNS)
    return statements
