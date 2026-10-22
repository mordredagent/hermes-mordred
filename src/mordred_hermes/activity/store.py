"""``ActivityStore``: schema v2, idempotent event append, episodes, status, backup/restore, retention.

The store never decides whether it may exist: :func:`._gate.open_store` runs
the protection gate and hands this class an opener that only returns keyed
connections. Tests construct it directly with a plain-SQLite opener on a
temporary directory; that constructor argument is the only test seam.

Every public method opens one short connection, runs one transaction and
closes it. ``busy_timeout`` is 2 s and the host's journal mode is left alone.
SQLite failures become :class:`._gate.ActivityRefused` with ``busy``,
``disk_full`` or ``store_unavailable``; nothing is retried here and no
exception text carries event content.

Opening (:meth:`ActivityStore.initialize`) and restoring upgrade an older
schema in place through :data:`._schema.MIGRATIONS`; a newer one is refused.
"""

from __future__ import annotations

import contextlib
import json
import os
import secrets
import sqlite3
import sys
import time
from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Final

from . import _schema
from ._gate import ActivityRefused, Refusal, refusal
from .contracts import COVERAGE_RANK, NormalizedEvent, canonical_digest

__all__ = [
    "ATTEMPT_PHASES",
    "BUSY_TIMEOUT_S",
    "SUPPORTED_SCHEMA_VERSION",
    "ActivityStore",
    "AppendResult",
    "BatchConflict",
    "EpisodeRecord",
    "RetentionReport",
    "StoreMeta",
    "StoreStatus",
]

SUPPORTED_SCHEMA_VERSION: Final = _schema.SCHEMA_VERSION
BUSY_TIMEOUT_S: Final = 2.0
_DAY: Final = 86400.0
#: Phases that make up one attempt; ``intended`` first, as the attempt's canonical event.
ATTEMPT_PHASES: Final = ("intended", "dispatched", "observed")
#: Lesson states whose evidence ordinary retention ages out with the lesson itself.
_UNADOPTED_STATES: Final = ("candidate", "rejected")
#: Lesson states that depend on pinned evidence and are suspended without it.
_DEPENDENT_STATES: Final = ("validated", "admitted")

Opener = Callable[[Path], sqlite3.Connection]
CopyCheck = Callable[[Path], Refusal | None]


class BatchConflict(ActivityRefused):
    """An ``event_id`` (or producer sequence) already stored with different content, or an episode
    another peer owns; nothing was written."""

    def __init__(self) -> None:
        super().__init__(refusal("conflict"))


@dataclass(frozen=True)
class AppendResult:
    accepted: int
    duplicates: int
    episode_revisions: dict[str, int]


@dataclass(frozen=True)
class StoreMeta:
    schema_version: int
    profile_home: str
    store_generation: str


@dataclass(frozen=True)
class EpisodeRecord:
    episode_id: str
    revision: int
    reviewed_revision: int
    site: str | None
    run_id: str | None
    hermes_session_id: str | None
    session_ref_state: str
    started_at: float
    last_event_at: float
    observed_outcome: str
    coverage: str
    has_correction: bool
    event_count: int


@dataclass(frozen=True)
class StoreStatus:
    """Identifiers and counts only."""

    schema_version: int
    store_generation: str
    counts: dict[str, int]
    job_states: dict[str, int]
    attempt_states: dict[str, int]
    lesson_states: dict[str, int]
    unreviewed_episodes: int


@dataclass(frozen=True)
class RetentionReport:
    events_deleted: int
    candidates_deleted: int
    lessons_suspended: int
    episodes_deleted: int
    #: ``False`` when a step hit its per-pass limit; run another pass.
    complete: bool


_EVENT_COLUMNS: Final = (
    "event_id, producer_seq, episode_id, attempt_id, parent_attempt_id, source, actor, observed_at, phase, op, "
    "target, site, route, args_json, result_status, result_method, result_evidence, coverage, exclusions, "
    "truncated, page_sig_before, page_sig_after, hermes_session_id, turn_id, run_id, text, query, page_title, "
    "page_text, content_digest"
)
_EPISODE_COLUMNS: Final = (
    "episode_id, revision, reviewed_revision, site, run_id, hermes_session_id, session_ref_state, started_at, "
    "last_event_at, observed_outcome, coverage, has_correction, event_count"
)


def _db_errors() -> tuple[type[BaseException], ...]:
    """The stdlib's and, once installed, the SQLCipher replacement's error base classes."""
    current = sys.modules.get("sqlite3", sqlite3)
    return (sqlite3.Error, getattr(current, "Error", sqlite3.Error))


def _classify(exc: BaseException) -> Refusal:
    text = str(exc).lower()
    if "locked" in text or "busy" in text:
        return refusal("busy")
    if "full" in text:
        return refusal("disk_full")
    return refusal("store_unavailable")


@contextlib.contextmanager
def _refusing() -> Iterator[None]:
    try:
        yield
    except _db_errors() as exc:
        raise ActivityRefused(_classify(exc)) from None


def _event_from_row(row: Sequence[Any]) -> NormalizedEvent:
    values = list(row)
    values[16] = tuple(json.loads(values[16]))  # result_evidence
    values[18] = tuple(json.loads(values[18]))  # exclusions
    values[19] = bool(values[19])  # truncated
    return NormalizedEvent(*values)


def _outcome(events: Sequence[NormalizedEvent]) -> str | None:
    """Latest non-unknown result of a task-boundary or dispatch event in this group."""
    outcome = None
    for event in events:
        relevant = event.phase in ("boundary", "dispatched") or event.op == "task_end"
        if relevant and event.result_status != "unknown":
            outcome = event.result_status
    return outcome


def _attempt_episode(conn: sqlite3.Connection, peer_id: str, attempt_id: str) -> str | None:
    """The episode holding ``peer_id``'s attempt ``attempt_id``; another peer's attempt never counts."""
    row = conn.execute(
        "SELECT episode_id FROM activity_events WHERE peer_id = ? AND attempt_id = ? AND phase IN (?, ?, ?) "
        "ORDER BY phase = 'intended' DESC, receipt LIMIT 1",
        (peer_id, attempt_id, *ATTEMPT_PHASES),
    ).fetchone()
    return None if row is None else str(row[0])


def _worst_coverage(coverages: Sequence[str]) -> str:
    return max(coverages, key=lambda coverage: COVERAGE_RANK[coverage])


def _first(values: Sequence[str | None]) -> str | None:
    return next((value for value in values if value is not None), None)


class ActivityStore:
    def __init__(
        self,
        path: Path,
        opener: Opener,
        *,
        copy_opener: Opener | None = None,
        verify_copy: CopyCheck | None = None,
    ) -> None:
        self.path = path
        self._opener = opener
        # Backups live outside the store; production opens them through the
        # process sqlite3 (the shim encrypts a new destination with the store's key).
        self._copy_opener = copy_opener or opener
        self._verify_copy = verify_copy

    # --- connections ------------------------------------------------------------------------

    @contextlib.contextmanager
    def connection(self) -> Iterator[sqlite3.Connection]:
        """One short connection; SQLite failures become content-free refusals."""
        with _refusing():
            conn = self._opener(self.path)
            try:
                conn.isolation_level = None  # explicit BEGIN / COMMIT below
                conn.execute(f"PRAGMA busy_timeout = {int(BUSY_TIMEOUT_S * 1000)}")
                yield conn
            finally:
                conn.close()

    @contextlib.contextmanager
    def _transaction(self, *, write: bool = True) -> Iterator[sqlite3.Connection]:
        with self.connection() as conn:
            conn.execute("BEGIN IMMEDIATE" if write else "BEGIN")
            try:
                yield conn
            except BaseException:
                if conn.in_transaction:
                    conn.rollback()
                raise
            conn.execute("COMMIT")

    # --- schema and binding -----------------------------------------------------------------

    @staticmethod
    def _read_meta(conn: sqlite3.Connection) -> dict[str, str] | None:
        exists = conn.execute("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'activity_meta'").fetchone()
        if exists is None:
            return None
        return {str(key): str(value) for key, value in conn.execute("SELECT key, value FROM activity_meta")}

    def initialize(self, profile_home: Path) -> StoreMeta:
        """Create the schema bound to ``profile_home``, or verify an existing store's version and binding.

        An older schema bound to ``profile_home`` is upgraded in the same transaction.
        """
        bound = os.path.realpath(profile_home)
        with self._transaction() as conn:
            meta = self._read_meta(conn)
            if meta is None:
                for statement in _schema.STATEMENTS:
                    conn.execute(statement)
                meta = {
                    "schema_version": str(SUPPORTED_SCHEMA_VERSION),
                    "profile_home": bound,
                    "store_generation": secrets.token_hex(16),
                }
                conn.executemany("INSERT INTO activity_meta (key, value) VALUES (?, ?)", sorted(meta.items()))
            checked = self._checked_meta(meta)
            if checked.profile_home != bound:
                raise ActivityRefused(refusal("profile_mismatch"))
            return self._upgraded(conn, checked)

    @staticmethod
    def _upgraded(conn: sqlite3.Connection, meta: StoreMeta) -> StoreMeta:
        """Run :data:`._schema.MIGRATIONS` from ``meta.schema_version`` up to the supported version."""
        steps = range(meta.schema_version, SUPPORTED_SCHEMA_VERSION)
        if not steps:
            return meta
        if any(step not in _schema.MIGRATIONS for step in steps):
            raise ActivityRefused(refusal("store_unavailable"))
        for step in steps:
            for statement in _schema.MIGRATIONS[step]:
                conn.execute(statement)
        conn.execute(
            "UPDATE activity_meta SET value = ? WHERE key = 'schema_version'", (str(SUPPORTED_SCHEMA_VERSION),)
        )
        return replace(meta, schema_version=SUPPORTED_SCHEMA_VERSION)

    @staticmethod
    def _checked_meta(meta: dict[str, str] | None) -> StoreMeta:
        if meta is None or not meta.get("schema_version", "").isdigit():
            raise ActivityRefused(refusal("store_unavailable"))
        version = int(meta["schema_version"])
        if version > SUPPORTED_SCHEMA_VERSION:
            # A newer Mordred wrote this store; never recreate or downgrade it.
            raise ActivityRefused(refusal("schema_newer"))
        return StoreMeta(version, meta.get("profile_home", ""), meta.get("store_generation", ""))

    def meta(self) -> StoreMeta:
        with self._transaction(write=False) as conn:
            return self._checked_meta(self._read_meta(conn))

    # --- append -----------------------------------------------------------------------------

    def append_batch(
        self,
        peer_id: str,
        producer_id: str,
        events: Sequence[NormalizedEvent],
        *,
        trust: str = "paired_peer",
        permitted_use: str = "learning",
        foreign_episodes: bool = False,
    ) -> AppendResult:
        """Append new events in one transaction; replays are duplicates, changed replays a conflict.

        An episode belongs to the peer that first wrote to it; new events naming another peer's episode
        are a conflict. Only the local ``activity correct`` command passes ``foreign_episodes=True`` to
        add a correction to an episode a peer wrote; paired peers never do.
        """
        now = time.time()
        with self._transaction() as conn:
            # Re-homing must precede the replay check: it is a pure function of batch and store, so a resent
            # batch re-homes identically and stays a duplicate instead of a conflict.
            events = self._rehome_corrections(conn, peer_id, events)
            fresh = self._fresh_events(conn, peer_id, producer_id, events)
            if not foreign_episodes:
                self._check_episode_owners(conn, peer_id, fresh)
            revisions: dict[str, int] = {}
            for episode_id in dict.fromkeys(event.episode_id for event in fresh):
                group = [event for event in fresh if event.episode_id == episode_id]
                revision = self._advance_episode(conn, episode_id, group, now)
                self._insert_events(conn, group, revision, (peer_id, producer_id, trust, permitted_use, now))
                revisions[episode_id] = revision
            for episode_id in dict.fromkeys(event.episode_id for event in events):
                if episode_id not in revisions:
                    row = conn.execute(
                        "SELECT revision FROM activity_episodes WHERE episode_id = ?", (episode_id,)
                    ).fetchone()
                    revisions[episode_id] = int(row[0]) if row else 0
        return AppendResult(len(fresh), len(events) - len(fresh), revisions)

    @classmethod
    def _rehome_corrections(
        cls, conn: sqlite3.Connection, peer_id: str, events: Sequence[NormalizedEvent]
    ) -> list[NormalizedEvent]:
        """Corrections moved into the episode of the attempt they reference.

        The operator closes its episode when a task ends, so a correction typed afterwards arrives in a fresh
        episode while its ``attempt_id`` still names the finished task's attempt; left there, the correction has
        no attempt or task context to learn from.
        """
        homes: dict[str, str] = {}
        for phase in ATTEMPT_PHASES:
            for event in events:
                if event.phase == phase and event.attempt_id is not None:
                    homes.setdefault(event.attempt_id, event.episode_id)
        return [cls._rehomed(conn, peer_id, event, homes) for event in events]

    @staticmethod
    def _rehomed(
        conn: sqlite3.Connection, peer_id: str, event: NormalizedEvent, homes: dict[str, str]
    ) -> NormalizedEvent:
        if event.phase != "correction" or event.attempt_id is None:
            return event
        home = homes.get(event.attempt_id) or _attempt_episode(conn, peer_id, event.attempt_id)
        if home is None or home == event.episode_id:
            return event
        stored = conn.execute("SELECT episode_id FROM activity_events WHERE event_id = ?", (event.event_id,)).fetchone()
        if stored is not None and stored[0] == event.episode_id:
            # Stored before its attempt arrived: a replay must keep matching the stored row.
            return event
        moved = replace(event, episode_id=home)
        return replace(moved, content_digest=canonical_digest(moved))

    @staticmethod
    def _fresh_events(
        conn: sqlite3.Connection, peer_id: str, producer_id: str, events: Sequence[NormalizedEvent]
    ) -> list[NormalizedEvent]:
        """Events not stored yet; raises :class:`BatchConflict` before anything is written."""
        fresh: list[NormalizedEvent] = []
        in_batch: dict[str, str] = {}
        for event in events:
            if event.event_id in in_batch:
                if in_batch[event.event_id] != event.content_digest:
                    raise BatchConflict()
                continue
            in_batch[event.event_id] = event.content_digest
            stored = conn.execute(
                "SELECT content_digest, peer_id FROM activity_events WHERE event_id = ?", (event.event_id,)
            ).fetchone()
            if stored is not None:
                # Same id from another peer is a forgery attempt, not a replay.
                if tuple(stored) != (event.content_digest, peer_id):
                    raise BatchConflict()
                continue
            reused_seq = conn.execute(
                "SELECT 1 FROM activity_events WHERE peer_id = ? AND producer_id = ? AND producer_seq = ?",
                (peer_id, producer_id, event.seq),
            ).fetchone()
            if reused_seq is not None:
                raise BatchConflict()
            fresh.append(event)
        return fresh

    @staticmethod
    def _check_episode_owners(conn: sqlite3.Connection, peer_id: str, fresh: Sequence[NormalizedEvent]) -> None:
        """An episode belongs to the peer that first wrote to it; raises :class:`BatchConflict` otherwise."""
        for episode_id in dict.fromkeys(event.episode_id for event in fresh):
            owner = conn.execute(
                "SELECT peer_id FROM activity_events WHERE episode_id = ? ORDER BY episode_revision, receipt LIMIT 1",
                (episode_id,),
            ).fetchone()
            if owner is not None and owner[0] != peer_id:
                raise BatchConflict()

    @staticmethod
    def _advance_episode(
        conn: sqlite3.Connection, episode_id: str, group: Sequence[NormalizedEvent], now: float
    ) -> int:
        started = min(event.observed_at for event in group)
        last = max(event.observed_at for event in group)
        outcome = _outcome(group)
        correction = int(any(event.phase == "correction" for event in group))
        row = conn.execute(
            "SELECT revision, coverage FROM activity_episodes WHERE episode_id = ?", (episode_id,)
        ).fetchone()
        if row is None:
            conn.execute(
                "INSERT INTO activity_episodes (episode_id, revision, site, run_id, hermes_session_id, started_at, "
                "last_event_at, observed_outcome, coverage, has_correction, event_count, created_at, updated_at) "
                "VALUES (?, 1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    episode_id,
                    _first([event.site for event in group]),
                    _first([event.run_id for event in group]),
                    _first([event.hermes_session_id for event in group]),
                    started,
                    last,
                    outcome or "unknown",
                    _worst_coverage([event.coverage for event in group]),
                    correction,
                    len(group),
                    now,
                    now,
                ),
            )
            return 1
        conn.execute(
            "UPDATE activity_episodes SET revision = revision + 1, site = COALESCE(site, ?), "
            "run_id = COALESCE(run_id, ?), hermes_session_id = COALESCE(hermes_session_id, ?), "
            "started_at = MIN(started_at, ?), last_event_at = MAX(last_event_at, ?), "
            "observed_outcome = COALESCE(?, observed_outcome), coverage = ?, "
            "has_correction = MAX(has_correction, ?), event_count = event_count + ?, updated_at = ? "
            "WHERE episode_id = ?",
            (
                _first([event.site for event in group]),
                _first([event.run_id for event in group]),
                _first([event.hermes_session_id for event in group]),
                started,
                last,
                outcome,
                _worst_coverage([row[1], *(event.coverage for event in group)]),
                correction,
                len(group),
                now,
                episode_id,
            ),
        )
        return int(row[0]) + 1

    @staticmethod
    def _insert_events(
        conn: sqlite3.Connection,
        group: Sequence[NormalizedEvent],
        revision: int,
        origin: tuple[str, str, str, str, float],
    ) -> None:
        rows = [
            (
                *origin,
                revision,
                event.event_id,
                event.seq,
                event.episode_id,
                event.attempt_id,
                event.parent_attempt_id,
                event.source,
                event.actor,
                event.observed_at,
                event.phase,
                event.op,
                event.target,
                event.site,
                event.route,
                event.args_json,
                event.result_status,
                event.result_method,
                json.dumps(list(event.result_evidence)),
                event.coverage,
                json.dumps(list(event.exclusions)),
                int(event.truncated),
                event.page_sig_before,
                event.page_sig_after,
                event.hermes_session_id,
                event.turn_id,
                event.run_id,
                event.text,
                event.query,
                event.page_title,
                event.page_text,
                event.content_digest,
            )
            for event in group
        ]
        placeholders = ", ".join("?" * len(rows[0]))
        conn.executemany(
            f"INSERT INTO activity_events (peer_id, producer_id, trust, permitted_use, received_at, "
            f"episode_revision, {_EVENT_COLUMNS}) VALUES ({placeholders})",
            rows,
        )

    # --- readers ----------------------------------------------------------------------------

    def episode(self, episode_id: str) -> EpisodeRecord | None:
        with self._transaction(write=False) as conn:
            row = conn.execute(
                f"SELECT {_EPISODE_COLUMNS} FROM activity_episodes WHERE episode_id = ?", (episode_id,)
            ).fetchone()
        return None if row is None else self._episode_from_row(row)

    def list_episodes(self, limit: int = 50) -> list[EpisodeRecord]:
        with self._transaction(write=False) as conn:
            rows = conn.execute(
                f"SELECT {_EPISODE_COLUMNS} FROM activity_episodes ORDER BY last_event_at DESC LIMIT ?",
                (max(0, limit),),
            ).fetchall()
        return [self._episode_from_row(row) for row in rows]

    @staticmethod
    def _episode_from_row(row: Sequence[Any]) -> EpisodeRecord:
        values = list(row)
        values[11] = bool(values[11])
        return EpisodeRecord(*values)

    def events_for_episode(self, episode_id: str, *, revision: int | None = None) -> list[NormalizedEvent]:
        """Internal reader (CLI counts, reviewer, tests) — never exposed to Hermes tools.

        With ``revision``, only events that existed at that episode revision (a frozen review input).
        """
        query = f"SELECT {_EVENT_COLUMNS} FROM activity_events WHERE episode_id = ?"
        params: tuple[Any, ...] = (episode_id,)
        if revision is not None:
            query += " AND episode_revision <= ?"
            params = (episode_id, revision)
        with self._transaction(write=False) as conn:
            rows = conn.execute(query + " ORDER BY receipt", params).fetchall()
        return [_event_from_row(row) for row in rows]

    def status(self) -> StoreStatus:
        with self._transaction(write=False) as conn:
            meta = self._checked_meta(self._read_meta(conn))
            counts = {
                table: int(conn.execute(f"SELECT count(*) FROM {table}").fetchone()[0])
                for table in _schema.TABLES
                if table != "activity_meta"
            }
            unreviewed = conn.execute(
                "SELECT count(*) FROM activity_episodes WHERE reviewed_revision < revision"
            ).fetchone()[0]
            return StoreStatus(
                schema_version=meta.schema_version,
                store_generation=meta.store_generation,
                counts=counts,
                job_states=self._state_counts(conn, "activity_review_jobs"),
                attempt_states=self._state_counts(conn, "activity_review_attempts"),
                lesson_states=self._state_counts(conn, "activity_lessons"),
                unreviewed_episodes=int(unreviewed),
            )

    @staticmethod
    def _state_counts(conn: sqlite3.Connection, table: str) -> dict[str, int]:
        rows = conn.execute(f"SELECT state, count(*) FROM {table} GROUP BY state ORDER BY state")
        return {str(state): int(count) for state, count in rows}

    # --- backup and restore -----------------------------------------------------------------

    def _check_copy(self, path: Path) -> None:
        found = self._verify_copy(path) if self._verify_copy is not None else None
        if found is not None:
            raise ActivityRefused(found)

    def backup(self, dest: Path) -> None:
        """A consistent snapshot (SQLite backup API, WAL included) to a new ``0600`` file."""
        try:
            fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        except FileExistsError:
            raise ActivityRefused(refusal("destination_exists")) from None
        os.close(fd)
        try:
            with _refusing(), contextlib.closing(self._copy_opener(dest)) as target, self.connection() as source:
                source.backup(target)
            self._check_copy(dest)
        except BaseException:
            dest.unlink(missing_ok=True)
            raise

    def restore(self, src: Path) -> StoreMeta:
        """Replace this store's content with ``src``; leases reset, uncertain work classified.

        The store stays bound to its current profile home and gets a new
        generation. No review job, model call or browser action is started.
        """
        if not src.is_file():
            raise ActivityRefused(refusal("store_unavailable"))
        self._check_copy(src)
        bound = self.meta().profile_home
        with _refusing(), contextlib.closing(self._copy_opener(src)) as source:
            self._checked_meta(self._read_meta(source))
            with self.connection() as target:
                source.backup(target)
        with self._transaction() as conn:
            self._after_restore(conn, bound)
            return self._upgraded(conn, self._checked_meta(self._read_meta(conn)))

    @staticmethod
    def _after_restore(conn: sqlite3.Connection, bound: str) -> None:
        now = time.time()
        conn.executemany(
            "INSERT OR REPLACE INTO activity_meta (key, value) VALUES (?, ?)",
            [("profile_home", bound), ("store_generation", secrets.token_hex(16))],
        )
        conn.execute(
            "UPDATE activity_review_jobs SET state = 'pending', lease_owner = NULL, lease_expires_at = NULL, "
            "updated_at = ? WHERE state = 'leased'",
            (now,),
        )
        # A request that may have reached the provider is never resubmitted automatically.
        conn.execute(
            "UPDATE activity_review_jobs SET state = 'uncertain', lease_owner = NULL, lease_expires_at = NULL, "
            "updated_at = ? WHERE state = 'calling'",
            (now,),
        )
        conn.execute(
            "UPDATE activity_review_attempts SET state = 'uncertain', finished_at = ? WHERE state = 'submitted'",
            (now,),
        )
        conn.execute(
            "UPDATE activity_review_attempts SET state = 'failed', failure_code = 'restore_reset', finished_at = ? "
            "WHERE state = 'reserved'",
            (now,),
        )
        # Session references may point at conversations a state recovery replaced; never rebind them.
        conn.execute(
            "UPDATE activity_episodes SET session_ref_state = 'unavailable' WHERE hermes_session_id IS NOT NULL"
        )

    # --- retention --------------------------------------------------------------------------

    def apply_retention(self, now: float, *, raw_days: int, candidate_days: int, limit: int = 500) -> RetentionReport:
        """One bounded pass: expire unadopted candidates, age out unpinned raw events, suspend orphaned lessons.

        ``raw_days`` of ``0`` keeps raw events and episodes forever; candidates still expire.
        """
        events = episodes = 0
        with self._transaction() as conn:
            candidates = self._expire_candidates(conn, now - candidate_days * _DAY, limit)
            if raw_days > 0:
                events = conn.execute(
                    "DELETE FROM activity_events WHERE receipt IN (SELECT e.receipt FROM activity_events e "
                    "WHERE e.received_at < ? AND NOT EXISTS "
                    "(SELECT 1 FROM activity_lesson_evidence v WHERE v.event_id = e.event_id) LIMIT ?)",
                    (now - raw_days * _DAY, limit),
                ).rowcount
            suspended = self._suspend_orphaned(conn, limit)
            if raw_days > 0:
                episodes = conn.execute(
                    "DELETE FROM activity_episodes WHERE episode_id IN (SELECT p.episode_id FROM activity_episodes p "
                    "WHERE NOT EXISTS (SELECT 1 FROM activity_events e WHERE e.episode_id = p.episode_id) "
                    "AND NOT EXISTS (SELECT 1 FROM activity_lessons l WHERE l.episode_id = p.episode_id) LIMIT ?)",
                    (limit,),
                ).rowcount
        counts = (candidates, events, suspended, episodes)
        return RetentionReport(events, candidates, suspended, episodes, complete=all(c < limit for c in counts))

    def plan_retention(self, now: float, *, raw_days: int, candidate_days: int, limit: int = 500) -> RetentionReport:
        """What one :meth:`apply_retention` pass would change, from read-only queries; nothing is deleted.

        Evidence links of candidates expiring in the same pass no longer pin their events. Counts
        are capped at ``limit`` per step, like the pass itself; ``raw_days`` of ``0`` plans no event
        or episode deletion.
        """
        unadopted = ", ".join(f"'{state}'" for state in _UNADOPTED_STATES)
        expiring = f"(l.state IN ({unadopted}) AND l.created_at < :candidate_cutoff)"
        # An event survives the pass when it is recent or still pinned by a non-expiring evidence link.
        survives = (
            "(e.received_at >= :raw_cutoff OR EXISTS (SELECT 1 FROM activity_lesson_evidence v "
            "LEFT JOIN activity_lessons l ON l.lesson_id = v.lesson_id AND l.revision = v.revision "
            f"WHERE v.event_id = e.event_id AND NOT (l.lesson_id IS NOT NULL AND {expiring})))"
        )
        params = {"candidate_cutoff": now - candidate_days * _DAY, "raw_cutoff": now - raw_days * _DAY, "limit": limit}
        queries = (
            f"SELECT 1 FROM activity_lessons l WHERE {expiring} LIMIT :limit",
            f"SELECT 1 FROM activity_events e WHERE NOT {survives} LIMIT :limit",
            "SELECT 1 FROM activity_episodes p WHERE NOT EXISTS (SELECT 1 FROM activity_events e "
            f"WHERE e.episode_id = p.episode_id AND {survives}) AND NOT EXISTS (SELECT 1 FROM activity_lessons l "
            f"WHERE l.episode_id = p.episode_id AND NOT {expiring}) LIMIT :limit",
        )
        if raw_days <= 0:  # raw events and episodes are kept forever; only candidates expire
            queries = (queries[0], "", "")
        with self._transaction(write=False) as conn:
            candidates, events, episodes = (len(conn.execute(q, params).fetchall()) if q else 0 for q in queries)
            # Pinned evidence of a dependent lesson always survives, so only already-missing events orphan it.
            suspended = len(self._orphaned(conn, limit))
        counts = (candidates, events, suspended, episodes)
        return RetentionReport(events, candidates, suspended, episodes, complete=all(c < limit for c in counts))

    @staticmethod
    def _expire_candidates(conn: sqlite3.Connection, cutoff: float, limit: int) -> int:
        marks = ", ".join("?" * len(_UNADOPTED_STATES))
        expired = conn.execute(
            f"SELECT lesson_id, revision FROM activity_lessons WHERE state IN ({marks}) AND created_at < ? LIMIT ?",
            (*_UNADOPTED_STATES, cutoff, limit),
        ).fetchall()
        conn.executemany("DELETE FROM activity_lesson_evidence WHERE lesson_id = ? AND revision = ?", expired)
        conn.executemany("DELETE FROM activity_lessons WHERE lesson_id = ? AND revision = ?", expired)
        return len(expired)

    @staticmethod
    def _orphaned(conn: sqlite3.Connection, limit: int) -> list[Any]:
        marks = ", ".join("?" * len(_DEPENDENT_STATES))
        return conn.execute(
            f"SELECT DISTINCT l.lesson_id, l.revision FROM activity_lessons l JOIN activity_lesson_evidence v "
            f"ON v.lesson_id = l.lesson_id AND v.revision = l.revision WHERE v.pinned = 1 "
            f"AND l.state IN ({marks}) AND NOT EXISTS "
            f"(SELECT 1 FROM activity_events e WHERE e.event_id = v.event_id) LIMIT ?",
            (*_DEPENDENT_STATES, limit),
        ).fetchall()

    @classmethod
    def _suspend_orphaned(cls, conn: sqlite3.Connection, limit: int) -> int:
        orphaned = cls._orphaned(conn, limit)
        conn.executemany(
            "UPDATE activity_lessons SET state = 'suspended', suspended_reason = 'evidence_missing' "
            "WHERE lesson_id = ? AND revision = ?",
            orphaned,
        )
        return len(orphaned)
