"""Read paths over the import store, and the one write (dismiss).

Lexical ranking goes through :meth:`ImportStore.search`; hydration is raw SQL
over the ``import_*`` tables. Raw SQL is deliberate: it keeps the reader
independent of the record dataclasses, so a source this build has no enum
member for still renders instead of raising.
"""

from __future__ import annotations

import contextlib
import sqlite3
import time
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any, Protocol

from . import fusion
from .cards import Card, build_card, conflict_summary, mark_conflicts, terms_of
from .derive import Derived, derive

#: Parts pulled from the store per derived query before grouping by conversation.
_SCAN_LIMIT = 80
#: Parts shown per conversation.
_PER_CONVERSATION = 2
#: Dismissed conversations stay hidden for this long.
_SUPPRESS_DAYS = 7

_HYDRATE_SQL = """
SELECT p.part_uid, p.text, p.author_name, p.author_owner_class, p.source_uid,
       m.conv_uid, m.sent_at, m.message_id, c.source, c.title
FROM import_parts p
JOIN import_messages m ON m.source_uid = p.source_uid
JOIN import_conversations c ON c.conv_uid = m.conv_uid
JOIN import_runs r ON r.run_id = m.run_id
WHERE r.state = 'committed' AND p.part_uid IN ({marks})
"""

_ANCHOR_SQL = """
SELECT m.conv_uid
FROM import_parts p
JOIN import_messages m ON m.source_uid = p.source_uid
JOIN import_runs r ON r.run_id = m.run_id
WHERE r.state = 'committed' AND p.part_uid = ?
"""

_OPEN_SQL = """
SELECT p.part_uid, p.text, p.author_name, p.author_owner_class, m.sent_at, m.message_id
FROM import_parts p
JOIN import_messages m ON m.source_uid = p.source_uid
JOIN import_runs r ON r.run_id = m.run_id
WHERE r.state = 'committed' AND m.conv_uid = ?
ORDER BY (m.sent_at IS NULL), m.sent_at, m.message_id, p.ordinal
"""

# Not part of the import schema (``imports._schema``): it holds no message
# data, only which conversation ids the user hid and until when, and the
# import store never reads it.
_SUPPRESSION_TABLE = """
CREATE TABLE IF NOT EXISTS recall_suppression (
    subject_kind TEXT NOT NULL,
    subject_id   TEXT NOT NULL,
    reason       TEXT NOT NULL,
    until        INTEGER,
    created_at   INTEGER NOT NULL,
    PRIMARY KEY (subject_kind, subject_id)
)
"""

_SUPPRESSED_SQL = """
SELECT subject_id FROM recall_suppression
WHERE subject_kind = 'conv' AND (until IS NULL OR until > ?)
"""


class _Hit(Protocol):
    @property
    def part_uid(self) -> str: ...
    @property
    def rank(self) -> float: ...


class RecallStore(Protocol):
    """The slice of :class:`~mordred_hermes.imports.store.ImportStore` recall uses."""

    def connection(self) -> contextlib.AbstractContextManager[sqlite3.Connection]: ...

    def search(self, query: str | None, *, limit: int = 20) -> Sequence[_Hit]: ...


@dataclass(frozen=True)
class SearchResult:
    cards: list[Card]
    confidence: str
    conflict_note: str
    took_ms: int
    derived: Derived

    def as_dict(self, query: str) -> dict[str, Any]:
        return {
            "query": query,
            "derived": self.derived.as_dict(),
            "confidence": self.confidence,
            "conflict_note": self.conflict_note,
            "took_ms": self.took_ms,
            "cards": [card.as_dict() for card in self.cards],
        }


class RecallIndex:
    def __init__(self, store: RecallStore) -> None:
        self.store = store

    # -- search -----------------------------------------------------------

    def search(self, text: str, *, limit: int = 8, now: float | None = None) -> SearchResult:
        started = time.monotonic()
        now = time.time() if now is None else now
        derived = derive(text)
        if not derived.queries:
            return SearchResult([], "none", "", 0, derived)

        terms = list(derived.keywords) or terms_of(derived.summary)[:8]
        hits = self._multi_hits(derived.queries)
        parts = self._hydrate([hit.part_uid for hit in hits])
        suppressed = self._suppressed(now)

        scored: list[tuple[float, dict[str, float], dict[str, Any]]] = []
        for hit in hits:
            part = parts.get(hit.part_uid)
            if part is None or part["conv_uid"] in suppressed:
                continue
            value, components = fusion.score(
                rank=hit.rank,
                terms=terms,
                text=part["text"],
                sent_at=part["sent_at"],
                source=part["source"],
                now=now,
            )
            scored.append((value, components, part))
        scored.sort(key=lambda item: fusion.rank_key(item[0], item[2]["sent_at"], item[2]["part_uid"]))

        cards: list[Card] = []
        per_conv: dict[str, int] = {}
        conv_scores: dict[str, float] = {}
        for value, components, part in scored:
            conv = part["conv_uid"]
            if per_conv.get(conv, 0) >= _PER_CONVERSATION:
                continue
            if conv not in per_conv and len(per_conv) >= limit:
                continue
            per_conv[conv] = per_conv.get(conv, 0) + 1
            conv_scores.setdefault(conv, value)
            cards.append(build_card(part=part, terms=terms, score=value, components=components))

        ordered = fusion.sort_cards(mark_conflicts(cards))
        return SearchResult(
            cards=ordered,
            confidence=fusion.confidence(list(conv_scores.values()), distinct_conversations=len(conv_scores)),
            conflict_note=conflict_summary(ordered),
            took_ms=int((time.monotonic() - started) * 1000),
            derived=derived,
        )

    def _multi_hits(self, queries: Sequence[str]) -> list[_Hit]:
        """One search per derived keyword; a part keeps its best (lowest) rank."""
        best: dict[str, _Hit] = {}
        for query in queries:
            for hit in self.store.search(query, limit=_SCAN_LIMIT):
                previous = best.get(hit.part_uid)
                if previous is None or hit.rank < previous.rank:
                    best[hit.part_uid] = hit
        return sorted(best.values(), key=lambda hit: hit.rank)

    # -- open -------------------------------------------------------------

    def open(self, part_uid: str, *, before: int = 2, after: int = 2) -> list[dict[str, Any]]:
        """The parts around ``part_uid`` in its conversation; ``[]`` when it is unknown."""
        with self.store.connection() as conn:
            anchor = conn.execute(_ANCHOR_SQL, (part_uid,)).fetchone()
            if anchor is None:
                return []
            rows = conn.execute(_OPEN_SQL, (anchor[0],)).fetchall()
        index = next((i for i, row in enumerate(rows) if row[0] == part_uid), None)
        if index is None:
            return []
        window = rows[max(0, index - max(0, before)) : index + max(0, after) + 1]
        return [
            {
                "part_uid": row[0],
                "text": row[1],
                "author": row[2],
                "owner_class": row[3],
                "sent_at": row[4],
                "message_id": row[5],
                "anchor": row[0] == part_uid,
            }
            for row in window
        ]

    # -- suppression ------------------------------------------------------

    def dismiss(self, conv_uid: str, *, now: float | None = None) -> None:
        now = time.time() if now is None else now
        until = int(now + _SUPPRESS_DAYS * 86400)
        with self.store.connection() as conn:
            conn.execute(_SUPPRESSION_TABLE)
            conn.execute(
                "INSERT INTO recall_suppression (subject_kind, subject_id, reason, until, created_at) "
                "VALUES ('conv', ?, 'dismissed', ?, ?) "
                "ON CONFLICT(subject_kind, subject_id) DO UPDATE SET until = excluded.until, "
                "reason = excluded.reason, created_at = excluded.created_at",
                (conv_uid, until, int(now)),
            )

    def _suppressed(self, now: float) -> set[str]:
        with self.store.connection() as conn:
            exists = conn.execute(
                "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'recall_suppression'"
            ).fetchone()
            if exists is None:
                return set()
            return {str(row[0]) for row in conn.execute(_SUPPRESSED_SQL, (int(now),))}

    # -- hydration --------------------------------------------------------

    def _hydrate(self, part_uids: Sequence[str]) -> dict[str, dict[str, Any]]:
        if not part_uids:
            return {}
        marks = ",".join("?" for _ in part_uids)
        with self.store.connection() as conn:
            rows = conn.execute(_HYDRATE_SQL.format(marks=marks), list(part_uids)).fetchall()
        return {
            row[0]: {
                "part_uid": row[0],
                "text": row[1] or "",
                "author": row[2],
                "owner_class": row[3],
                "source_uid": row[4],
                "conv_uid": row[5],
                "sent_at": row[6] if isinstance(row[6], int) else None,
                "message_id": row[7],
                "source": row[8],
                "title": row[9],
            }
            for row in rows
        }
