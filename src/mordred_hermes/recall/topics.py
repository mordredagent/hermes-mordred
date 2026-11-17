"""Events and topics built when the import store changes, stored in mordred.db, searched by term.

Nothing here runs a model or groups anything per search. :func:`build` reads
every committed part (Telegram left out, :data:`.events.EXCLUDED_SOURCES`) and
writes, in one transaction:

* **episodes** (:func:`.events.episodes_of`) and which part belongs to which;
* **events**, the level a chat contains: episodes grouped by content
  (average linkage over their noun vectors, divided by a time penalty), so a
  chat holds several events and one event may span chats;
* **topics**, the level a chat belongs to: events grouped again, with a
  floor for events of the same thread (the same chat, or a resumed session)
  that decays over :data:`THREAD_DAYS`, so the chats of one piece of work
  meet in one topic, then cut where a local model says the events do not
  share a pursuit (:func:`_split`: a general-assistant chat holds many);
* the **term index**: for every index term (:mod:`..imports.analysis`) and
  every event and topic holding it, its BM25 relevance with the events (and
  the topics) as documents;
* each event's and topic's **importance**: engaged minutes, days and chats.

Headlines are written separately by :func:`fill_lines` (a local model, see
:mod:`.headlines`) and cached by a digest of their material in
``recall_lines``, which a rebuild keeps: after an import only new or changed
events and episodes need the model. :class:`TopicsUpdater` rebuilds when the
committed runs change and then fills missing lines, so both stay current.

A search (:class:`TopicIndex`) only reads: the term index gives the events
holding every query term and their relevance, the stored importance and the
end date give the rest of the score, and the hits of the part index anchor
each branch at a match.

Rebuilding is complete rather than incremental (the dev store, 15k parts:
see the build's ``timings``); the model work is what is incremental.
"""

from __future__ import annotations

import hashlib
import heapq
import json
import logging
import math
import sqlite3
import threading
import time
from collections import Counter, defaultdict
from collections.abc import Callable, Collection, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Final

from ..imports import analysis
from .events import (
    EXCLUDED_SOURCES,
    MAX_USER_MESSAGES,
    ONGOING_SECONDS,
    USER_MESSAGE_CHARS,
    Branch,
    Episode,
    Event,
    EventResult,
    Part,
    Threads,
    Vector,
    analyse,
    clean,
    date,
    episodes_of,
    excerpt,
    gap,
    set_dwell,
    vector,
)

_log = logging.getLogger(__name__)

#: Raise when the built rows or the line material change shape, so every row is rebuilt.
BUILD_VERSION: Final = "3"
#: Raise only when a stored line no longer fits its item: it is part of every line's key.
_DIGEST_VERSION: Final = "2"
#: Events: episodes merge while their average similarity is above this.
EVENT_SIMILARITY: Final = 0.2
#: Topics: events merge while their average similarity is above this.
TOPIC_SIMILARITY: Final = 0.12
#: Time distance (s) that divides a similarity by e.
_TIME_TAU: Final = 21 * 86400
#: Events of one thread start a topic at this similarity, decaying over THREAD_DAYS.
_THREAD_FLOOR: Final = 0.5
THREAD_DAYS: Final = 14
#: Terms in a vector: an episode's, and an event's when topics are grouped.
_EVENT_VECTOR_TERMS: Final = 60
#: A term in more than this share of the episodes is left out of the pairing (its weight is tiny anyway).
_COMMON_SHARE: Final = 0.3
#: BM25 parameters.
_K1: Final = 1.2
_B: Final = 0.75
_RECENCY_TAU: Final = 30 * 86400
_KEYWORDS: Final = 10
_MAX_BRANCHES: Final = 4
#: A page selection finds the events holding at least this share of its nouns' weight ...
MIN_COVERAGE: Final = 0.35
#: ... or at least two of its rare nouns: held by this many events or fewer.
_RARE_EVENTS: Final = 3
#: A selection's rarest shared nouns whose parts anchor the branches.
_SELECTION_ANCHORS: Final = 3
#: The first answer shows only the events scoring at least this share of the best
#: one; the rest are left to the recommender (:mod:`.recommend`), which explains them.
CONFIDENT_SHARE: Final = 0.4
#: Events shown under one topic.
_EVENTS_PER_TOPIC: Final = 3
_HIT_LIMIT: Final = 500
_MAX_WORDS: Final = 8
_TITLES: Final = 6
#: A membership question lists the focus event and up to this many events on each side (by start).
_PICK_WINDOW: Final = 6
#: A listed event: its keywords, and its user message's characters.
_PICK_KEYWORDS: Final = 5
_PICK_MESSAGE_CHARS: Final = 80

_PARTS_SQL = """
SELECT p.id, p.part_uid, p.text, p.author_owner_class, m.sent_at, m.conv_uid, c.source, c.title
FROM import_parts p
JOIN import_messages m ON m.source_uid = p.source_uid
JOIN import_conversations c ON c.conv_uid = m.conv_uid
JOIN import_runs r ON r.run_id = m.run_id
WHERE r.state = 'committed' AND m.sent_at IS NOT NULL
ORDER BY m.conv_uid, m.sent_at, m.message_id, p.ordinal
"""

_FINGERPRINT_SQL = """
SELECT (SELECT count(*) FROM import_runs WHERE state = 'committed'),
       (SELECT max(finished_at) FROM import_runs WHERE state = 'committed'),
       (SELECT count(*) FROM import_parts)
"""

# Not part of the import schema: derived rows only, rebuilt from the import tables.
_SCHEMA: Final = (
    "CREATE TABLE IF NOT EXISTS recall_build (key TEXT PRIMARY KEY, value TEXT NOT NULL)",
    """CREATE TABLE IF NOT EXISTS recall_episodes (
        episode_id INTEGER PRIMARY KEY, conv_uid TEXT NOT NULL, thread TEXT NOT NULL, source TEXT NOT NULL,
        title TEXT, start INTEGER NOT NULL, end INTEGER NOT NULL, parts INTEGER NOT NULL, minutes REAL NOT NULL,
        event_id INTEGER NOT NULL, digest TEXT NOT NULL, material TEXT NOT NULL)""",
    "CREATE INDEX IF NOT EXISTS recall_episodes_event ON recall_episodes (event_id)",
    "CREATE INDEX IF NOT EXISTS recall_episodes_thread ON recall_episodes (thread)",
    """CREATE TABLE IF NOT EXISTS recall_part_episode (
        part_id INTEGER PRIMARY KEY, episode_id INTEGER NOT NULL)""",
    """CREATE TABLE IF NOT EXISTS recall_groups (
        group_id INTEGER PRIMARY KEY, level TEXT NOT NULL CHECK (level IN ('event', 'topic')),
        parent_id INTEGER, start INTEGER NOT NULL, end INTEGER NOT NULL, minutes REAL NOT NULL,
        days INTEGER NOT NULL, chats INTEGER NOT NULL, sources TEXT NOT NULL, keywords TEXT NOT NULL,
        importance REAL NOT NULL, children INTEGER NOT NULL, digest TEXT NOT NULL, material TEXT NOT NULL)""",
    "CREATE INDEX IF NOT EXISTS recall_groups_parent ON recall_groups (parent_id)",
    """CREATE TABLE IF NOT EXISTS recall_group_terms (
        term TEXT NOT NULL, group_id INTEGER NOT NULL, score REAL NOT NULL,
        PRIMARY KEY (term, group_id)) WITHOUT ROWID""",
    """CREATE TABLE IF NOT EXISTS recall_lines (
        digest TEXT PRIMARY KEY, kind TEXT NOT NULL, text TEXT, model TEXT NOT NULL, created_at INTEGER NOT NULL)""",
)
_DERIVED: Final = ("recall_episodes", "recall_part_episode", "recall_groups", "recall_group_terms")


def ensure_schema(conn: sqlite3.Connection) -> None:
    for statement in _SCHEMA:
        conn.execute(statement)


def _has_schema(conn: sqlite3.Connection) -> bool:
    row = conn.execute("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'recall_build'").fetchone()
    return row is not None


def fingerprint(store: Any) -> str:
    """What a build depends on: the committed runs and the part count."""
    with store.connection() as conn:
        runs, finished, parts = conn.execute(_FINGERPRINT_SQL).fetchone()
    return f"{BUILD_VERSION}:{runs}:{finished}:{parts}"


def built_fingerprint(store: Any) -> str | None:
    with store.connection() as conn:
        if not _has_schema(conn):
            return None
        row = conn.execute("SELECT value FROM recall_build WHERE key = 'fingerprint'").fetchone()
    return str(row[0]) if row else None


def _digest(kind: str, members: Iterable[str]) -> str:
    """A line's cache key: what the item is made of, not its derived material.

    An episode is its parts (uid and text), a group its episodes' digests. The
    material (keywords, chosen replies) follows the store-wide term weights and
    shifts with every import; keyed by it, one new chat would re-ask every line.
    """
    body = "\0".join(sorted(members))
    return hashlib.sha256(f"{_DIGEST_VERSION}\0{kind}\0{body}".encode()).hexdigest()


def _episode_digest(ep: Episode) -> str:
    return _digest("episode", (f"{p.uid}\0{hashlib.sha256(p.text.encode()).hexdigest()}" for p in ep.parts))


# -- grouping ------------------------------------------------------------------------


def _pairs(vectors: Sequence[Vector]) -> dict[tuple[int, int], float]:
    """Dot products of every pair of unit vectors sharing a term, through term postings."""
    postings: dict[str, list[tuple[int, float]]] = defaultdict(list)
    for index, vec in enumerate(vectors):
        for term, value in vec.items():
            postings[term].append((index, value))
    limit = max(2, int(len(vectors) * _COMMON_SHARE))
    dots: dict[tuple[int, int], float] = defaultdict(float)
    for posting in postings.values():
        if len(posting) > limit:
            continue
        for x in range(len(posting)):
            i, vi = posting[x]
            for y in range(x + 1, len(posting)):
                j, vj = posting[y]
                dots[(i, j) if i < j else (j, i)] += vi * vj
    return dots


def average_linkage(count: int, sims: Mapping[tuple[int, int], float], threshold: float) -> list[list[int]]:
    """Groups of ``range(count)`` merged while their average pairwise similarity exceeds ``threshold``.

    Sparse: an absent pair has similarity 0. Lance-Williams updates and a
    lazy heap keep it near O(pairs log pairs) instead of cubic.
    """
    members = {i: [i] for i in range(count)}
    near: dict[int, dict[int, float]] = defaultdict(dict)
    heap: list[tuple[float, int, int]] = []
    for (i, j), value in sims.items():
        if value <= 0:
            continue
        near[i][j] = near[j][i] = value
        if value > threshold:
            heap.append((-value, i, j))
    heapq.heapify(heap)
    while heap:
        negative, i, j = heapq.heappop(heap)
        if i not in members or j not in members or near[i].get(j) != -negative:
            continue  # stale: one side merged since this entry was pushed
        size_i, size_j = len(members[i]), len(members[j])
        for k in (set(near[i]) | set(near[j])) - {i, j}:
            value = (size_i * near[i].get(k, 0.0) + size_j * near[j].get(k, 0.0)) / (size_i + size_j)
            near[k].pop(j, None)
            near[i][k] = near[k][i] = value
            if value > threshold:
                heapq.heappush(heap, (-value, min(i, k), max(i, k)))
        near[i].pop(j, None)
        near.pop(j, None)
        members[i] += members.pop(j)
    return list(members.values())


# -- build ---------------------------------------------------------------------------


@dataclass
class _Group:
    episodes: list[Episode]
    level: str
    children: list[_Group] = field(default_factory=list)
    group_id: int = 0
    parent_id: int | None = None

    @property
    def parts(self) -> list[Part]:
        return [part for ep in self.episodes for part in ep.parts]


@dataclass
class BuildResult:
    parts: int
    episodes: int
    events: int
    topics: int
    term_rows: int
    fingerprint: str
    timings: dict[str, int]
    #: Membership questions still to ask, and candidate topics waiting for their events' headlines.
    pick_jobs: list[PickJob] = field(default_factory=list)
    waiting: int = 0

    def as_dict(self) -> dict[str, Any]:
        return {
            "parts": self.parts,
            "episodes": self.episodes,
            "events": self.events,
            "topics": self.topics,
            "term_rows": self.term_rows,
            "fingerprint": self.fingerprint,
            "timings": self.timings,
            "pick_jobs": len(self.pick_jobs),
            "waiting": self.waiting,
        }


def _load(store: Any) -> list[Part]:
    with store.connection() as conn:
        rows = conn.execute(_PARTS_SQL).fetchall()
    parts = []
    for pid, uid, text, owner_class, sent, conv, source, title in rows:
        if source in EXCLUDED_SOURCES or not isinstance(sent, int):
            continue
        parts.append(Part(int(pid), uid, text or "", owner_class == "account_owner", sent, conv, source, title))
    return parts


def _confident(events: list[Event]) -> list[Event]:
    """``events`` best first, without those far below the best (:data:`CONFIDENT_SHARE`)."""
    events.sort(key=lambda event: -event.score)
    if not events:
        return events
    floor = CONFIDENT_SHARE * events[0].score
    return [event for event in events if event.score >= floor]


def _idf(found: int, total: int) -> float:
    """BM25's inverse document frequency: rare words weigh more, and it never goes negative."""
    return math.log(1 + (total - found + 0.5) / (found + 0.5))


def _bm25(groups: Sequence[_Group]) -> list[tuple[str, int, float]]:
    """``(term, group_id, score)`` for every term of every group, the groups as BM25 documents."""
    tfs: list[Counter[str]] = []
    for group in groups:
        tf: Counter[str] = Counter()
        for part in group.parts:
            tf.update(part.counts)
        tfs.append(tf)
    if not tfs:
        return []
    lengths = [sum(tf.values()) for tf in tfs]
    average = (sum(lengths) / len(lengths)) or 1.0
    df: Counter[str] = Counter(term for tf in tfs for term in tf)
    total = len(tfs)
    rows = []
    for group, tf, length in zip(groups, tfs, lengths, strict=True):
        norm = _K1 * (1 - _B + _B * length / average)
        for term, n in tf.items():
            idf = _idf(df[term], total)
            rows.append((term, group.group_id, idf * n * (_K1 + 1) / (n + norm)))
    return rows


def _stats(group: _Group, threads: Threads) -> dict[str, Any]:
    parts = group.parts
    chats = {threads.root(ep.conv): ep.parts[0].source for ep in group.episodes}
    minutes = sum(ep.minutes for ep in group.episodes)
    days = len({date(part.sent) for part in parts})
    return {
        "start": min(ep.start for ep in group.episodes),
        "end": max(ep.end for ep in group.episodes),
        "minutes": minutes,
        "days": days,
        "chats": len(chats),
        "sources": dict(Counter(chats.values()).most_common()),
        # Unchanged from the weekly-topic prototype: engaged time x spread over days x chats.
        "importance": math.log1p(minutes) * math.log1p(days) * math.log1p(len(chats)),
    }


def _user_messages(parts: Iterable[Part]) -> list[str]:
    said = [clean(part.text) for part in parts if part.owner]
    return [text[:USER_MESSAGE_CHARS] for text in said if len(text) >= 10][:MAX_USER_MESSAGES]


def _spread_messages(episodes: Iterable[Episode]) -> list[str]:
    """One user message per episode, the biggest episodes first, so one long episode cannot fill them all."""
    said = []
    for ep in sorted(episodes, key=lambda ep: -len(ep.parts)):
        said += _user_messages(ep.parts)[:1]
    return said[:MAX_USER_MESSAGES]


def _episode_material(ep: Episode) -> dict[str, Any]:
    """What a model may read to say what happened in one episode."""
    # The agent's replies that carry most of the episode's own weighted nouns.
    ranked = sorted((p for p in ep.parts if not p.owner), key=lambda p: -sum(ep.vector.get(t, 0.0) for t in p.terms))
    return {
        "source": ep.parts[0].source,
        "title": ep.parts[0].title,
        "from": date(ep.start),
        "to": date(ep.end),
        "user_messages": _user_messages(ep.parts),
        "replies": [clean(p.text)[:160] for p in ranked[:2] if clean(p.text)],
    }


def _group_material(group: _Group, keywords: list[str], stats: Mapping[str, Any]) -> dict[str, Any]:
    titles = list(dict.fromkeys(ep.parts[0].title for ep in group.episodes if ep.parts[0].title))[:_TITLES]
    return {
        "from": date(stats["start"]),
        "to": date(stats["end"]),
        "sources": stats["sources"],
        "keywords": keywords,
        "chat_titles": titles,
        "user_messages": _spread_messages(group.episodes),
    }


def _keywords(group: _Group, weight: Mapping[str, float], written: Mapping[str, Counter[str]]) -> list[str]:
    keys = vector(group.parts, weight, _KEYWORDS)
    return [written[term].most_common(1)[0][0] if term in written else term for term in keys]


def _events_of(episodes: Sequence[Episode]) -> list[_Group]:
    """Episodes grouped by content, divided by their distance in time (the level a chat contains)."""
    sims = {
        (i, j): value * math.exp(-gap(episodes[i], episodes[j]) / _TIME_TAU)
        for (i, j), value in _pairs([ep.vector for ep in episodes]).items()
    }
    groups = average_linkage(len(episodes), sims, EVENT_SIMILARITY)
    return [_Group([episodes[i] for i in sorted(g)], "event") for g in groups]


def _topics_of(events: Sequence[_Group], weight: Mapping[str, float], threads: Threads) -> list[_Group]:
    """Events grouped again, the events of one thread held together (the level a chat belongs to)."""
    spans = [(min(ep.start for ep in e.episodes), max(ep.end for ep in e.episodes)) for e in events]

    def distance(i: int, j: int) -> int:
        return max(0, max(spans[i][0], spans[j][0]) - min(spans[i][1], spans[j][1]))

    vectors = [vector(event.parts, weight, _EVENT_VECTOR_TERMS) for event in events]
    sims = {(i, j): value * math.exp(-distance(i, j) / _TIME_TAU) for (i, j), value in _pairs(vectors).items()}
    by_thread: dict[str, list[int]] = defaultdict(list)
    for index, event in enumerate(events):
        for root in {threads.root(ep.conv) for ep in event.episodes}:
            by_thread[root].append(index)
    for members in by_thread.values():
        for x, i in enumerate(members):
            for j in members[x + 1 :]:
                key = (i, j) if i < j else (j, i)
                floor = _THREAD_FLOOR * math.exp(-distance(i, j) / (THREAD_DAYS * 86400))
                sims[key] = max(sims.get(key, 0.0), floor)
    return [
        _Group([ep for i in sorted(g) for ep in events[i].episodes], "topic", children=[events[i] for i in sorted(g)])
        for g in average_linkage(len(events), sims, TOPIC_SIMILARITY)
    ]


@dataclass(frozen=True)
class PickJob:
    """One membership question: which listed events share the focus event's pursuit."""

    digest: str
    items: list[dict[str, Any]]
    focus: int
    listed: list[str]  # the listed events' digests, in list order


def _start(group: _Group) -> int:
    return min(ep.start for ep in group.episodes)


def _split(
    candidates: Sequence[_Group],
    digest_of: Callable[[_Group], str],
    item_of: Callable[[_Group], dict[str, Any]],
    stored: Mapping[str, str],
) -> tuple[list[_Group], list[PickJob], int]:
    """Candidate topics cut where their events do not share a pursuit, by the stored membership answers.

    The same-thread floor holds a chat's events together, which is wrong for a
    chat that asks about anything (a general assistant). Each event of a
    candidate is shown with its neighbours and the model names the ones in its
    pursuit; two events stay linked only when each names the other, and the
    linked events form the topics. A candidate is kept whole until every one of
    its answers is stored (and its events' headlines with them, which the list
    shows). Returns the topics, the questions still to ask, and the candidates
    waiting for headlines.
    """
    topics: list[_Group] = []
    jobs: list[PickJob] = []
    waiting = 0
    for candidate in candidates:
        events = sorted(candidate.children, key=_start)
        if len(events) < 2:
            topics.append(candidate)
            continue
        keys = [digest_of(event) for event in events]
        if any(key not in stored for key in keys):
            waiting += 1
            topics.append(candidate)
            continue
        named: dict[int, set[int]] = {}
        for k in range(len(events)):
            window = range(max(0, k - _PICK_WINDOW), min(len(events), k + _PICK_WINDOW + 1))
            # The list order is part of the question, so it is part of the key.
            digest = _digest("pick", (f"{i - k}:{keys[i]}" for i in window))
            answer = stored.get(digest)
            if answer is None:
                jobs.append(
                    PickJob(digest, [item_of(events[i]) for i in window], k - window.start, [keys[i] for i in window])
                )
                continue
            named[k] = {keys.index(d) for d in json.loads(answer) if d in keys}
        if len(named) < len(events):
            topics.append(candidate)
            continue
        for component in _components(
            len(events), {(k, j) for k, others in named.items() for j in others if k in named[j]}
        ):
            members = [events[k] for k in component]
            topics.append(_Group([ep for e in members for ep in e.episodes], "topic", children=members))
    return topics, jobs, waiting


def _components(count: int, edges: Iterable[tuple[int, int]]) -> list[list[int]]:
    """Connected components of ``range(count)``, each sorted, in order of their first member."""
    near: dict[int, set[int]] = defaultdict(set)
    for a, b in edges:
        near[a].add(b)
        near[b].add(a)
    seen: set[int] = set()
    out = []
    for start in range(count):
        if start in seen:
            continue
        stack, component = [start], []
        seen.add(start)
        while stack:
            node = stack.pop()
            component.append(node)
            for other in near[node] - seen:
                seen.add(other)
                stack.append(other)
        out.append(sorted(component))
    return out


def build(store: Any, *, now: float | None = None) -> BuildResult:
    """Rebuild every stored episode, event, topic and term row from the committed import tables."""
    started = time.monotonic()
    stamp = fingerprint(store)
    parts = _load(store)
    loaded = time.monotonic()
    written: dict[str, Counter[str]] = {}
    for part in parts:
        part.terms, part.counts = analyse(part.text, written)
    df: Counter[str] = Counter(term for part in parts for term in part.terms)
    total = len(parts) or 1
    weight = {term: math.log(total / n) for term, n in df.items() if n >= 2}
    analysed = time.monotonic()

    by_conv: dict[str, list[Part]] = defaultdict(list)
    for part in parts:
        by_conv[part.conv].append(part)
    episodes: list[Episode] = []
    for items in by_conv.values():
        set_dwell(items)
        episodes.extend(episodes_of(items, weight))
    threads = Threads(parts)

    events = _events_of(episodes)
    digests = {id(ep): _episode_digest(ep) for ep in episodes}

    def digest_of(group: _Group) -> str:
        return _digest(group.level, (digests[id(ep)] for ep in group.episodes))

    stored = _stored_lines(store)

    def item_of(event: _Group) -> dict[str, Any]:
        said = _spread_messages(event.episodes)[:1]
        return {
            "見出し": stored.get(digest_of(event)),
            "キーワード": _keywords(event, weight, written)[:_PICK_KEYWORDS],
            "本人の発言": [text[:_PICK_MESSAGE_CHARS] for text in said],
        }

    topics, pick_jobs, waiting = _split(_topics_of(events, weight, threads), digest_of, item_of, stored)
    grouped = time.monotonic()

    next_id = 1
    for topic in topics:
        topic.group_id, next_id = next_id, next_id + 1
        for event in topic.children:
            event.group_id, next_id = next_id, next_id + 1
            event.parent_id = topic.group_id
    term_rows = _bm25(events) + _bm25(topics)
    _write(
        store, stamp, episodes, events, topics, term_rows, threads, weight, written, digests, len(pick_jobs) + waiting
    )
    done = time.monotonic()
    return BuildResult(
        parts=len(parts),
        episodes=len(episodes),
        events=len(events),
        topics=len(topics),
        term_rows=len(term_rows),
        fingerprint=stamp,
        timings={
            "load_ms": int((loaded - started) * 1000),
            "analyse_ms": int((analysed - loaded) * 1000),
            "group_ms": int((grouped - analysed) * 1000),
            "write_ms": int((done - grouped) * 1000),
        },
        pick_jobs=pick_jobs,
        waiting=waiting,
    )


def _stored_lines(store: Any) -> dict[str, str]:
    with store.connection() as conn:
        if not _has_schema(conn):
            return {}
        return {str(d): str(t) for d, t in conn.execute("SELECT digest, text FROM recall_lines WHERE text IS NOT NULL")}


def _write(
    store: Any,
    stamp: str,
    episodes: Sequence[Episode],
    events: Sequence[_Group],
    topics: Sequence[_Group],
    term_rows: Sequence[tuple[str, int, float]],
    threads: Threads,
    weight: Mapping[str, float],
    written: Mapping[str, Counter[str]],
    digests: Mapping[int, str],
    pending: int,
) -> None:
    event_of = {id(ep): event.group_id for event in events for ep in event.episodes}
    with store.connection() as conn:
        ensure_schema(conn)
        # Derived personal text: overwritten rows are scrubbed from the file too.
        conn.execute("PRAGMA secure_delete = ON")
        conn.execute("BEGIN IMMEDIATE")
        try:
            for table in _DERIVED:
                conn.execute(f"DELETE FROM {table}")  # noqa: S608 - fixed table names
            for episode_id, ep in enumerate(episodes, start=1):
                material = _episode_material(ep)
                conn.execute(
                    "INSERT INTO recall_episodes VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        episode_id,
                        ep.conv,
                        threads.root(ep.conv),
                        ep.parts[0].source,
                        ep.parts[0].title,
                        ep.start,
                        ep.end,
                        len(ep.parts),
                        ep.minutes,
                        event_of[id(ep)],
                        digests[id(ep)],
                        json.dumps(material, ensure_ascii=False),
                    ),
                )
                conn.executemany(
                    "INSERT INTO recall_part_episode VALUES (?, ?)", [(part.id, episode_id) for part in ep.parts]
                )
            for group in [*topics, *events]:
                stats = _stats(group, threads)
                keywords = _keywords(group, weight, written)
                material = _group_material(group, keywords, stats)
                conn.execute(
                    "INSERT INTO recall_groups VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        group.group_id,
                        group.level,
                        group.parent_id,
                        stats["start"],
                        stats["end"],
                        stats["minutes"],
                        stats["days"],
                        stats["chats"],
                        json.dumps(stats["sources"]),
                        json.dumps(keywords, ensure_ascii=False),
                        stats["importance"],
                        len(group.children),
                        _digest(group.level, (digests[id(ep)] for ep in group.episodes)),
                        json.dumps(material, ensure_ascii=False),
                    ),
                )
            conn.executemany("INSERT INTO recall_group_terms VALUES (?, ?, ?)", term_rows)
            conn.executemany(
                "INSERT OR REPLACE INTO recall_build VALUES (?, ?)",
                [("fingerprint", stamp), ("built_at", str(int(time.time()))), ("pending_picks", str(pending))],
            )
            conn.execute("COMMIT")
        except BaseException:
            if conn.in_transaction:
                conn.rollback()
            raise


# -- lines (headlines and branch lines, by a local model) -----------------------------


@dataclass(frozen=True)
class LineJob:
    digest: str
    kind: str  # 'event' | 'topic' | 'episode'
    material: dict[str, Any]


_LINE_KINDS: Final = ("event", "topic", "episode")


def missing_lines(store: Any, *, limit: int = 64, kinds: Sequence[str] = _LINE_KINDS) -> list[LineJob]:
    """Material without a stored line, the most recent first (what a person searches for first)."""
    marks = ",".join("?" for _ in kinds)
    with store.connection() as conn:
        if not _has_schema(conn):
            return []
        rows = conn.execute(
            f"""
            SELECT digest, kind, material FROM (
                SELECT g.digest, g.level AS kind, g.material, g.end FROM recall_groups g
                UNION ALL
                SELECT e.digest, 'episode', e.material, e.end FROM recall_episodes e
            ) WHERE digest NOT IN (SELECT digest FROM recall_lines) AND kind IN ({marks})
            GROUP BY digest ORDER BY max(end) DESC LIMIT ?
            """,  # noqa: S608 - only placeholders and fixed identifiers are interpolated; values are bound
            (*kinds, limit),
        ).fetchall()
    return [LineJob(str(d), str(k), json.loads(m)) for d, k, m in rows]


def store_lines(store: Any, answers: Iterable[tuple[LineJob, str | None]], model: str) -> int:
    """Keep the model's answers; a failed one (``None``) is not stored, so it is asked again later."""
    kept = [(job.digest, job.kind, text, model, int(time.time())) for job, text in answers if text]
    if not kept:
        return 0
    with store.connection() as conn:
        ensure_schema(conn)
        conn.execute("BEGIN IMMEDIATE")
        conn.executemany("INSERT OR REPLACE INTO recall_lines VALUES (?, ?, ?, ?, ?)", kept)
        conn.execute("COMMIT")
    return len(kept)


def _unanswered(writer: Any, digests: Iterable[str], failed: set[str] | None) -> None:
    """Note the material a reachable model gave no usable answer for (a model that was not reachable notes nothing)."""
    if failed is not None and getattr(writer, "reachable", True):
        failed.update(digests)


def fill_lines(
    store: Any,
    writer: Any,
    *,
    batch: int = 16,
    budget_s: float | None = None,
    kinds: Sequence[str] = _LINE_KINDS,
    skip: Collection[str] = (),
    failed: set[str] | None = None,
) -> int:
    """Ask the model for every missing line, a batch at a time; the number written.

    Material in ``skip`` is not asked; material the model answered without a
    usable line is added to ``failed`` (the caller decides when to ask again).
    """
    written = 0
    started = time.monotonic()
    passed: set[str] = set(skip)
    while budget_s is None or time.monotonic() - started < budget_s:
        jobs = [job for job in missing_lines(store, limit=batch + len(passed), kinds=kinds) if job.digest not in passed]
        jobs = jobs[:batch]
        if not jobs:
            break
        answers = writer.lines([(job.kind, job.material) for job in jobs])
        stored = store_lines(store, zip(jobs, answers, strict=True), writer.target.model)
        written += stored
        missed = [job.digest for job, text in zip(jobs, answers, strict=True) if not text]
        _unanswered(writer, missed, failed)
        passed.update(missed)
        if stored == 0:
            break  # the model answers nothing: try again on the next pass
    return written


def fill_picks(
    store: Any,
    writer: Any,
    jobs: Sequence[PickJob],
    *,
    batch: int = 16,
    budget_s: float | None = None,
    skip: Collection[str] = (),
    failed: set[str] | None = None,
) -> int:
    """Ask the membership questions, a batch at a time; the number of answers stored.

    An answer is stored as the digests of the events it names, so it reads the
    same whatever list position the events have in a later build.
    """
    written = 0
    started = time.monotonic()
    jobs = [job for job in jobs if job.digest not in skip]
    for offset in range(0, len(jobs), batch):
        if budget_s is not None and time.monotonic() - started >= budget_s:
            break
        chunk = jobs[offset : offset + batch]
        answers = writer.picks([(job.items, job.focus) for job in chunk])
        kept = [
            (job.digest, "pick", json.dumps([job.listed[i] for i in named]), writer.target.model, int(time.time()))
            for job, named in zip(chunk, answers, strict=True)
            if named is not None
        ]
        _unanswered(writer, [job.digest for job, named in zip(chunk, answers, strict=True) if named is None], failed)
        if not kept:
            break  # the model answers nothing: try again on the next pass
        with store.connection() as conn:
            conn.execute("BEGIN IMMEDIATE")
            conn.executemany("INSERT OR REPLACE INTO recall_lines VALUES (?, ?, ?, ?, ?)", kept)
            conn.execute("COMMIT")
        written += len(kept)
    return written


def pending_picks(store: Any) -> int:
    """Membership questions (and candidates waiting for headlines) left by the stored build."""
    with store.connection() as conn:
        if not _has_schema(conn):
            return 0
        row = conn.execute("SELECT value FROM recall_build WHERE key = 'pending_picks'").fetchone()
    return int(row[0]) if row else 0


def line_counts(store: Any) -> dict[str, int]:
    with store.connection() as conn:
        if not _has_schema(conn):
            return {}
        rows = conn.execute(
            """
            SELECT kind, count(*), sum(digest IN (SELECT digest FROM recall_lines)) FROM (
                SELECT digest, level AS kind FROM recall_groups UNION ALL SELECT digest, 'episode' FROM recall_episodes
            ) GROUP BY kind
            """
        ).fetchall()
    counts: dict[str, int] = {}
    for kind, total, done in rows:
        counts[f"{kind}s"] = int(total)
        counts[f"{kind}s_with_lines"] = int(done or 0)
    counts["picks_pending"] = pending_picks(store)
    return counts


# -- search --------------------------------------------------------------------------


class TopicIndex:
    """Events for typed words, read from the stored build (no grouping, no model)."""

    def __init__(self, store: Any) -> None:
        self.store = store

    def built(self) -> bool:
        return built_fingerprint(self.store) is not None

    def events(
        self, text: str, *, limit: int = 5, now: float | None = None, suppressed: Iterable[str] = ()
    ) -> EventResult:
        started = time.monotonic()
        now = time.time() if now is None else now
        words = list(dict.fromkeys(text.split()))[:_MAX_WORDS]
        query = " ".join(words)
        terms = list(dict.fromkeys(token.term for word in words for token in analysis.tokens(word)))
        if not terms:
            return EventResult(query, [], 0, 0, 0)
        hidden = set(suppressed)
        hits = [hit for hit in self.store.search(query, limit=_HIT_LIMIT) if hit.conv_uid not in hidden]
        with self.store.connection() as conn:
            relevance = self._relevance(conn, terms)
            part_hits = self._hit_episodes(conn, [hit.part_uid for hit in hits])
            looked = time.monotonic()
            events = _confident(self._events(conn, relevance, part_hits, hidden, words, now))
            cards = self._topic_cards(conn, events, limit, now)
        done = time.monotonic()
        return EventResult(
            query,
            events[:limit],
            topics=cards,
            hits=len(hits),
            episodes=len({ep for ep, _uid, _owner in part_hits}),
            took_ms=int((done - started) * 1000),
            timings={"lookup_ms": int((looked - started) * 1000), "assemble_ms": int((done - looked) * 1000)},
        )

    @staticmethod
    def _topic_cards(conn: sqlite3.Connection, events: Sequence[Event], limit: int, now: float) -> list[dict[str, Any]]:
        """The ``limit`` best topics, each with its best events (``events`` is sorted best first)."""
        order: list[int] = []
        members: dict[int, list[Event]] = defaultdict(list)
        for event in events:
            key = event.topic["id"] if event.topic else -id(event)
            if key not in members:
                order.append(key)
            members[key].append(event)
        cards = []
        for key in order[:limit]:
            group = members[key]
            card: dict[str, Any] = {
                "id": key if key > 0 else None,
                "headline": group[0].topic["headline"] if group[0].topic else None,
                "events_total": group[0].topic["events"] if group[0].topic else 1,
                "events": [event.as_dict() for event in group[:_EVENTS_PER_TOPIC]],
                "matched_events": len(group),
            }
            row = conn.execute(
                "SELECT start, end, sources, keywords, minutes, days FROM recall_groups WHERE group_id = ?", (key,)
            ).fetchone()
            if row is not None:
                start, end, sources, keywords, minutes, days = row
                card |= {
                    "start": int(start),
                    "end": int(end),
                    "ongoing": now - end < ONGOING_SECONDS,
                    "sources": json.loads(sources),
                    "keywords": json.loads(keywords),
                    "minutes": round(minutes),
                    "days": int(days),
                }
            cards.append(card)
        return cards

    def selection_events(
        self, words: Sequence[str], *, limit: int = 5, now: float | None = None, suppressed: Iterable[str] = ()
    ) -> EventResult:
        """Events for a page selection's nouns (:func:`.derive.selection_words`), ranked by what they share.

        Each noun weighs by its rarity over the stored events (BM25's IDF; a noun
        no event holds weighs the most), and an event covers the weight of the
        nouns it holds over the weight of them all. Events under
        :data:`MIN_COVERAGE` are left out unless they share two rare nouns with
        the selection (a name and a term only they mention): a selection about
        something never discussed shares only common words with the store
        (時間, 午後) and finds nothing. The rest rank by their BM25 over the nouns they hold
        (no recency or importance: the question is what was said about this).
        The query reported is those nouns, the rarest first.
        """
        started = time.monotonic()
        now = time.time() if now is None else now
        hidden = set(suppressed)
        analysed = [
            (word, terms)
            for word in dict.fromkeys(words)
            if (terms := list(dict.fromkeys(token.term for token in analysis.tokens(word))))
        ]
        with self.store.connection() as conn:
            total = int(conn.execute("SELECT count(*) FROM recall_groups WHERE level = 'event'").fetchone()[0])
            holders = {word: self._relevance(conn, terms) for word, terms in analysed}
        weight = {word: _idf(len(held), total) for word, held in holders.items()}
        whole = sum(weight.values())
        covered: dict[int, float] = defaultdict(float)
        relevance: dict[int, float] = defaultdict(float)
        rare: Counter[int] = Counter()
        for word, held in holders.items():
            for event_id, score in held.items():
                covered[event_id] += weight[word]
                relevance[event_id] += score
                rare[event_id] += len(held) <= _RARE_EVENTS
        kept = {
            event_id: relevance[event_id]
            for event_id in covered
            if covered[event_id] >= MIN_COVERAGE * whole or rare[event_id] >= 2
        }
        # The score is known here, so only the events the topic cards can show are assembled.
        kept = dict(heapq.nlargest(limit * _EVENTS_PER_TOPIC, kept.items(), key=lambda item: item[1]))
        shared = sorted(
            (word for word, held in holders.items() if not kept.keys().isdisjoint(held)), key=lambda w: -weight[w]
        )[:_MAX_WORDS]
        hits = [
            hit
            for word in (shared[:_SELECTION_ANCHORS] if kept else [])
            for hit in self.store.search(word, limit=_HIT_LIMIT)
            if hit.conv_uid not in hidden
        ]
        with self.store.connection() as conn:
            part_hits = self._hit_episodes(conn, list(dict.fromkeys(hit.part_uid for hit in hits)))
            if kept:
                marks = ",".join("?" for _ in kept)
                inside = {
                    int(row[0])
                    for row in conn.execute(
                        f"SELECT episode_id FROM recall_episodes WHERE event_id IN ({marks})",  # noqa: S608 - only placeholders and fixed identifiers are interpolated; values are bound
                        list(kept),
                    )
                }
                part_hits = [hit for hit in part_hits if hit[0] in inside]
            else:
                part_hits = []
            looked = time.monotonic()
            events = _confident(self._events(conn, kept, part_hits, hidden, shared, now, selection=True))
            cards = self._topic_cards(conn, events, limit, now)
        done = time.monotonic()
        return EventResult(
            " ".join(shared),
            events[:limit],
            topics=cards,
            hits=len(part_hits),
            episodes=len({ep for ep, _uid, _owner in part_hits}),
            took_ms=int((done - started) * 1000),
            timings={"lookup_ms": int((looked - started) * 1000), "assemble_ms": int((done - looked) * 1000)},
        )

    @staticmethod
    def _relevance(conn: sqlite3.Connection, terms: Sequence[str]) -> dict[int, float]:
        """BM25 per event holding every term (summed over the terms)."""
        marks = ",".join("?" for _ in terms)
        rows = conn.execute(
            f"""
            SELECT t.group_id, sum(t.score), count(*) FROM recall_group_terms t
            JOIN recall_groups g ON g.group_id = t.group_id
            WHERE g.level = 'event' AND t.term IN ({marks}) GROUP BY t.group_id
            """,  # noqa: S608 - only placeholders and fixed identifiers are interpolated; values are bound
            list(terms),
        ).fetchall()
        return {int(gid): float(score) for gid, score, matched in rows if matched == len(terms)}

    @staticmethod
    def _hit_episodes(conn: sqlite3.Connection, part_uids: Sequence[str]) -> list[tuple[int, str, bool]]:
        if not part_uids:
            return []
        out: list[tuple[int, str, bool]] = []
        for start in range(0, len(part_uids), 500):
            chunk = list(part_uids[start : start + 500])
            marks = ",".join("?" for _ in chunk)
            out += [
                (int(ep), str(uid), owner == "account_owner")
                for ep, uid, owner in conn.execute(
                    f"""
                    SELECT pe.episode_id, p.part_uid, p.author_owner_class FROM import_parts p
                    JOIN recall_part_episode pe ON pe.part_id = p.id WHERE p.part_uid IN ({marks})
                    """,  # noqa: S608 - only placeholders and fixed identifiers are interpolated; values are bound
                    chunk,
                )
            ]
        return out

    def _events(
        self,
        conn: sqlite3.Connection,
        relevance: Mapping[int, float],
        part_hits: Sequence[tuple[int, str, bool]],
        hidden: set[str],
        words: Sequence[str],
        now: float,
        *,
        selection: bool = False,
    ) -> list[Event]:
        """The events of ``relevance`` and every event a hit falls in.

        For a ``selection`` only those of ``relevance``, scored by it alone.
        """
        hits_by_episode: dict[int, list[tuple[str, bool]]] = defaultdict(list)
        for ep, uid, owner in part_hits:
            hits_by_episode[ep].append((uid, owner))
        candidates = set(relevance)
        if hits_by_episode and not selection:
            marks = ",".join("?" for _ in hits_by_episode)
            candidates |= {
                int(row[0])
                for row in conn.execute(
                    f"SELECT DISTINCT event_id FROM recall_episodes WHERE episode_id IN ({marks})",  # noqa: S608 - only placeholders and fixed identifiers are interpolated; values are bound
                    list(hits_by_episode),
                )
            }
        lines = {
            str(d): str(t) for d, t in conn.execute("SELECT digest, text FROM recall_lines WHERE text IS NOT NULL")
        }
        events: list[Event] = []
        for event_id in candidates:
            row = conn.execute(
                "SELECT parent_id, start, end, minutes, days, sources, keywords, importance, digest "
                "FROM recall_groups WHERE group_id = ?",
                (event_id,),
            ).fetchone()
            if row is None:
                continue
            parent_id, start, end, minutes, days, sources, keywords, importance, digest = row
            episodes = conn.execute(
                "SELECT episode_id, conv_uid, source, title, start, end, digest FROM recall_episodes "
                "WHERE event_id = ? ORDER BY start",
                (event_id,),
            ).fetchall()
            shown = [ep for ep in episodes if ep[1] not in hidden]
            found = [hit for ep in shown for hit in hits_by_episode.get(int(ep[0]), [])]
            # The event's terms may all sit in the chats the user hid: with none of
            # its hits left, the rest of the event is not what was searched for.
            if not shown or (len(shown) < len(episodes) and not found):
                continue
            episodes = shown
            lexical = relevance.get(event_id, 0.0) + math.log1p(len(found))
            rel = lexical * (1.5 if any(owner for _uid, owner in found) else 1.0)
            recency = math.exp(-max(0.0, now - end) / _RECENCY_TAU)
            # A selection asks what was said about this, so only the match counts there.
            score = relevance.get(event_id, 0.0) if selection else rel * (1 + importance / 10) * (0.5 + recency)
            topic = None
            if parent_id is not None:
                parent = conn.execute(
                    "SELECT digest, children FROM recall_groups WHERE group_id = ?", (parent_id,)
                ).fetchone()
                if parent is not None:
                    topic = {"id": int(parent_id), "headline": lines.get(str(parent[0])), "events": int(parent[1])}
            events.append(
                Event(
                    ongoing=now - end < ONGOING_SECONDS,
                    start=int(start),
                    end=int(end),
                    sources=json.loads(sources),
                    minutes=round(minutes),
                    days=int(days),
                    keywords=json.loads(keywords),
                    branches=self._branches(conn, episodes, hits_by_episode, lines, words),
                    score=score,
                    components={"relevance": rel, "importance": float(importance), "recency": recency},
                    headline=lines.get(str(digest)),
                    topic=topic,
                )
            )
        return events

    @staticmethod
    def _branches(
        conn: sqlite3.Connection,
        episodes: Sequence[tuple[Any, ...]],
        hits_by_episode: Mapping[int, list[tuple[str, bool]]],
        lines: Mapping[str, str],
        words: Sequence[str],
    ) -> list[Branch]:
        """One branch per episode: those with hits (most first); without any, the most recent."""
        ranked = sorted(episodes, key=lambda ep: (-len(hits_by_episode.get(int(ep[0]), [])), -int(ep[5])))
        with_hits = [ep for ep in ranked if hits_by_episode.get(int(ep[0]))]
        ranked = with_hits or ranked[:2]
        branches = []
        for episode_id, conv, source, title, start, end, digest in ranked[:_MAX_BRANCHES]:
            hits = hits_by_episode.get(int(episode_id), [])
            if hits:
                anchor = hits[0][0]
            else:
                row = conn.execute(
                    "SELECT p.part_uid FROM recall_part_episode pe JOIN import_parts p ON p.id = pe.part_id "
                    "WHERE pe.episode_id = ? ORDER BY pe.part_id LIMIT 1",
                    (episode_id,),
                ).fetchone()
                anchor = str(row[0]) if row else ""
            text_row = conn.execute("SELECT text FROM import_parts WHERE part_uid = ?", (anchor,)).fetchone()
            # How many topics the whole chat (its thread) runs through: one that asks about anything shows it.
            chat_topics = conn.execute(
                "SELECT count(DISTINCT g.parent_id) FROM recall_episodes e "
                "JOIN recall_groups g ON g.group_id = e.event_id "
                "WHERE e.thread = (SELECT thread FROM recall_episodes WHERE episode_id = ?)",
                (episode_id,),
            ).fetchone()[0]
            branches.append(
                Branch(
                    source=str(source),
                    title=title,
                    conv_uid=str(conv),
                    start=int(start),
                    end=int(end),
                    hits=len(hits),
                    anchor_part_uid=anchor,
                    excerpts=[excerpt(str(text_row[0] or ""), words)] if text_row else [],
                    user_messages=[],
                    summary=lines.get(str(digest)),
                    chat_topics=int(chat_topics or 1),
                )
            )
        folders = places(conn, [(branch.source, branch.conv_uid) for branch in branches])
        for branch in branches:
            branch.folder = folders.get(branch.conv_uid)
        return branches


def places(conn: sqlite3.Connection, chats: Sequence[tuple[str, str]]) -> dict[str, str]:
    """``{conv_uid: folder}`` for the local sessions (``(source, conv_uid)``) whose working folder was recorded."""
    from ..imports.local._model import place_key

    keys = {place_key(source, conv): conv for source, conv in chats}
    if not keys:
        return {}
    marks = ",".join("?" for _ in keys)
    rows = conn.execute(f"SELECT key, value FROM import_meta WHERE key IN ({marks})", list(keys)).fetchall()  # noqa: S608 - only placeholders and fixed identifiers are interpolated; values are bound
    return {keys[str(key)]: str(value) for key, value in rows}


# -- keeping it current --------------------------------------------------------------


#: A line or membership question the model answered unusably is asked again after this.
RETRY_UNANSWERED_S: Final = 6 * 3600.0


class TopicsUpdater:
    """Rebuilds when the committed import runs change, then fills missing lines; one background thread."""

    def __init__(
        self,
        opener: Callable[[], Any],
        writer: Any = None,
        *,
        interval_s: float = 60.0,
        on_error: Callable[[str], None] | None = None,
    ) -> None:
        self._opener = opener
        self._writer = writer
        self._interval = interval_s
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._on_error = on_error or (lambda code: _log.info("recall topics: %s", code))
        self.last_build: BuildResult | None = None
        # Material the model answered without a usable line, by when: not asked again for RETRY_UNANSWERED_S,
        # so a few lines it never manages do not keep a model server busy (and running) all day.
        self._unanswered: dict[str, float] = {}

    def start(self) -> None:
        if self._thread is None:
            self._thread = threading.Thread(target=self._run, name="recall-topics", daemon=True)
            self._thread.start()

    def stop(self) -> None:
        self._stop.set()

    def run_once(self) -> None:
        """One pass: rebuild if the import tables changed, then the model's work for a few minutes.

        Event and episode lines come first, since a membership question lists
        the events' headlines; then the questions, with a rebuild that applies
        their answers; then the topics' names, so a topic that the answers cut
        apart is named only once, after the cut.
        """
        store = self._opener()
        # After a restart the questions are known only to a build: make one if the stored build left some.
        unknown = self.last_build is None and self._writer is not None and pending_picks(store) > 0
        if built_fingerprint(store) != fingerprint(store) or unknown:
            self._rebuild(store)
        if self._writer is None:
            return
        budget = self._interval * 5
        now = time.monotonic()
        self._unanswered = {d: at for d, at in self._unanswered.items() if now - at < RETRY_UNANSWERED_S}
        skip = set(self._unanswered)
        failed: set[str] = set()
        try:
            self._model_work(store, budget, skip, failed)
        finally:
            self._unanswered.update(dict.fromkeys(failed, time.monotonic()))

    def _model_work(self, store: Any, budget: float, skip: set[str], failed: set[str]) -> None:
        written = fill_lines(
            store, self._writer, budget_s=budget, kinds=("event", "episode"), skip=skip | failed, failed=failed
        )
        if written:
            _log.info("recall topics: %d lines written", written)
            if self.last_build is not None and self.last_build.waiting:
                self._rebuild(store)
        if self.last_build is not None and self.last_build.pick_jobs:
            answered = fill_picks(
                store, self._writer, self.last_build.pick_jobs, budget_s=budget, skip=skip | failed, failed=failed
            )
            if answered:
                _log.info("recall topics: %d membership answers", answered)
                self._rebuild(store)
        named = fill_lines(store, self._writer, budget_s=budget, skip=skip | failed, failed=failed)
        if named:
            _log.info("recall topics: %d lines written", named)

    def _rebuild(self, store: Any) -> None:
        self.last_build = build(store)
        _log.info("recall topics rebuilt: %s", json.dumps(self.last_build.as_dict()))

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                self.run_once()
            except Exception as exc:  # keep the thread alive; the store may be locked or unkeyed for now
                self._on_error(type(exc).__name__)
            self._idle()
            self._stop.wait(self._interval)
        if self._writer is not None and hasattr(self._writer, "close"):
            self._writer.close()

    def _idle(self) -> None:
        """A model server Hermes started for this work is stopped once it has been unused for a while."""
        if self._writer is not None and hasattr(self._writer, "idle"):
            try:
                self._writer.idle()
            except Exception as exc:
                self._on_error(type(exc).__name__)
