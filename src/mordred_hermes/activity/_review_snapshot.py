"""Frozen review input (bounded snapshot) and code-only eligibility over durable episodes."""

from __future__ import annotations

import contextlib
import hashlib
import json
import sqlite3
from collections import Counter
from collections.abc import Iterator
from dataclasses import dataclass
from typing import TYPE_CHECKING, Final

from ._review_output import REVIEW_INSTRUCTIONS
from .config import ActivityConfig
from .contracts import TEXT_PHASES, NormalizedEvent, site_excluded

if TYPE_CHECKING:
    from .store import ActivityStore

#: Most recent episodes examined per eligibility pass (bounded code-only work).
_SCAN_LIMIT: Final = 200
_REPEAT_THRESHOLD: Final = 3
_SUCCESS: Final = frozenset({"claimed_success", "verified_success"})


@contextlib.contextmanager
def transaction(store: ActivityStore, *, write: bool = True) -> Iterator[sqlite3.Connection]:
    """One short transaction on a fresh store connection (the store's own discipline)."""
    with store.connection() as conn:
        conn.execute("BEGIN IMMEDIATE" if write else "BEGIN")
        try:
            yield conn
        except BaseException:
            if conn.in_transaction:
                conn.rollback()
            raise
        conn.execute("COMMIT")


# --------------------------------------------------------------------------- #
# Snapshot
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class Snapshot:
    text: str
    event_ids: frozenset[str]
    sites: frozenset[str]
    digest: str
    omitted: int = 0


def _event_line(event: NormalizedEvent) -> str:
    exclusions = ",".join(event.exclusions) or "-"
    line = (
        f"{event.event_id} {event.seq} {event.phase} {event.op} {event.actor} {event.site or '-'} "
        f"{json.dumps(event.route) if event.route else '-'} {event.result_status} {exclusions}"
    )
    if event.phase in TEXT_PHASES and event.text:
        # JSON quoting keeps a newline inside free text from forging another record line.
        line += f" text={json.dumps(event.text, ensure_ascii=False)}"
    return line


def build_snapshot(
    store: ActivityStore,
    episode_id: str,
    revision: int,
    *,
    max_input_tokens: int = ActivityConfig.review_max_input_tokens,
    excluded_sites: frozenset[str] = frozenset(),
) -> Snapshot:
    """The frozen review input: one line per event up to ``revision``, oldest dropped first to fit."""
    events = [
        event
        for event in store.events_for_episode(episode_id, revision=revision)
        if not site_excluded(event.site, excluded_sites)
    ]
    header = f"episode {episode_id} revision {revision}"
    budget = max(0, max_input_tokens * 4 - len(REVIEW_INSTRUCTIONS) - len(header) - 64)
    lines = [_event_line(event) for event in events]
    total = sum(len(line) + 1 for line in lines)
    start = 0
    while start < len(lines) and total > budget:
        total -= len(lines[start]) + 1
        start += 1
    kept = events[start:]
    body = [header]
    if start:
        body.append(f"[... {start} earlier events omitted]")
    body.extend(lines[start:])
    text = "\n".join(body)
    return Snapshot(
        text=text,
        event_ids=frozenset(event.event_id for event in kept),
        sites=frozenset(event.site for event in kept if event.site),
        digest=hashlib.sha256(text.encode("utf-8")).hexdigest(),
        omitted=start,
    )


# --------------------------------------------------------------------------- #
# Eligibility
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class Eligible:
    episode_id: str
    revision: int
    #: correction | failure_recovery | repeated_procedure
    signal: str


Signature = tuple[str | None, tuple[tuple[str, str | None], ...]]


def _completed_signatures(conn: sqlite3.Connection) -> dict[str, Signature]:
    """``site`` + ordered dispatched ``(op, route)`` of recently completed episodes."""
    marks = ", ".join("?" * len(_SUCCESS))
    rows = conn.execute(
        "SELECT e.episode_id, p.site, e.op, e.route FROM activity_events e "
        "JOIN activity_episodes p ON p.episode_id = e.episode_id "
        f"WHERE e.phase = 'dispatched' AND p.episode_id IN (SELECT episode_id FROM activity_episodes "
        f"WHERE observed_outcome IN ({marks}) ORDER BY last_event_at DESC LIMIT ?) ORDER BY e.receipt",
        (*sorted(_SUCCESS), _SCAN_LIMIT),
    ).fetchall()
    steps: dict[str, tuple[str | None, list[tuple[str, str | None]]]] = {}
    for episode_id, site, op, route in rows:
        steps.setdefault(str(episode_id), (site, []))[1].append((str(op), route))
    return {episode_id: (site, tuple(seq)) for episode_id, (site, seq) in steps.items()}


def _failure_recovered(conn: sqlite3.Connection, episode_id: str, revision: int) -> bool:
    rows = conn.execute(
        "SELECT op, route, result_status FROM activity_events WHERE episode_id = ? AND episode_revision <= ? "
        "ORDER BY receipt",
        (episode_id, revision),
    ).fetchall()
    failed: set[tuple[str, str | None]] = set()
    for op, route, status in rows:
        if status == "verified_failure":
            failed.add((op, route))
        elif status in _SUCCESS and (op, route) in failed:
            return True
    return False


def eligible_episodes(store: ActivityStore, config: ActivityConfig, now: float) -> list[Eligible]:
    """Unreviewed revisions with a meaningful signal, oldest activity first. Code only."""
    del now  # elapsed time is never a signal
    with transaction(store, write=False) as conn:
        rows = conn.execute(
            "SELECT episode_id, revision, has_correction, site FROM activity_episodes "
            "WHERE revision > reviewed_revision ORDER BY last_event_at DESC LIMIT ?",
            (_SCAN_LIMIT,),
        ).fetchall()
        signatures = _completed_signatures(conn)
        repeated = Counter(sig for sig in signatures.values() if sig[1])
        found: list[Eligible] = []
        for episode_id, revision, has_correction, site in reversed(rows):
            if site_excluded(site, config.excluded_sites):
                continue
            signature = signatures.get(episode_id)
            if has_correction:
                signal = "correction"
            elif _failure_recovered(conn, episode_id, int(revision)):
                signal = "failure_recovery"
            elif signature is not None and signature[1] and repeated[signature] >= _REPEAT_THRESHOLD:
                signal = "repeated_procedure"
            else:
                continue
            found.append(Eligible(str(episode_id), int(revision), signal))
    return found
