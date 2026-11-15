"""Building blocks for recall events: parts, episodes, threads, and the event shapes.

:mod:`.topics` builds the stored events and topics from these when the import
store changes; nothing here runs per search. The pieces:

* **Episodes.** A conversation is cut into episodes: a pause longer than
  :data:`EPISODE_GAP` always cuts, and inside a stretch a topic shift cuts too
  (TextTiling over weighted noun vectors, :func:`tiles`).
* **Threads.** A resumed or forked Claude Code session replays the earlier
  history into a new conversation; conversations sharing at least
  :data:`THREAD_SHARED` identical messages are one chat when counting
  (:class:`Threads`).
* **Vectors.** An episode (or an event) is a vector of noun weights
  (:func:`vector`): inverse document frequency over every stored part, so
  words that appear everywhere (確認, ファイル) carry little weight, and the
  owner's own messages count twice.

Telegram is left out: its text may only go to Venice or the model the
Telegram settings choose, and events are summarised by a local model
(:mod:`.headlines`).
"""

from __future__ import annotations

import datetime as dt
import hashlib
import itertools
import math
import re
from collections import Counter, defaultdict
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Final

from ..imports import analysis

#: Sources whose text never enters an event (see the module docstring).
EXCLUDED_SOURCES: Final = frozenset({"telegram"})
#: A pause this long (seconds) always starts a new episode.
EPISODE_GAP: Final = 3 * 3600
#: TextTiling block size (parts), required depth, and the shortest episode it may cut off.
_TILE: Final = 6
_TILE_DEPTH: Final = 0.35
_MIN_EPISODE: Final = 8
#: Engaged time a message holds: until the next message of its conversation, capped; the last one gets a little.
_DWELL_CAP: Final = 10 * 60
_LAST_DWELL: Final = 2 * 60
#: Terms kept per episode vector.
_VECTOR_TERMS: Final = 40
#: Identical messages two conversations must share to count as one chat.
THREAD_SHARED: Final = 10
#: An event whose last activity is this recent is still going on.
ONGOING_SECONDS: Final = 7 * 86400
#: Kept for a model to read: user messages per episode and their length; excerpt width around a match.
MAX_USER_MESSAGES: Final = 4
USER_MESSAGE_CHARS: Final = 220
EXCERPT_CHARS: Final = 70

# Removed before analysis and from every excerpt: code, URLs, paths, hashes.
_NOISE: Final = re.compile(
    r"```.*?```|`[^`\n]*`|https?://\S+|(?:~|\.{1,2})?/[\w.@%+-]+(?:/[\w.@%+-]+)+|\b[0-9a-f]{7,64}\b", re.S
)
# Never shown or sent to a model: pairing codes, API-key shapes, long opaque tokens.
_SECRET: Final = re.compile(r"MORT-[A-Z0-9-]+|\b(?:sk|pk|ghp|xox[bp])[-_][A-Za-z0-9_-]{8,}|[A-Za-z0-9_+/=-]{32,}")
_WORD: Final = re.compile(r"[\w・ー]+")
_DIGIT: Final = re.compile(r"\d")
_SHORT_LATIN: Final = re.compile(r"[A-Za-z]{1,2}")
_SPACE: Final = re.compile(r"\s+")

Vector = dict[str, float]


def _visible(text: str) -> str:
    """``text`` without code, URLs, paths, hashes and secret-shaped tokens (offsets not kept)."""
    return _SECRET.sub(" ", _NOISE.sub(" ", text))


def clean(text: str) -> str:
    """:func:`_visible` on one line, a removed secret shown as an ellipsis."""
    return _SPACE.sub(" ", _SECRET.sub("…", _NOISE.sub(" ", text))).strip()


@dataclass
class Part:
    id: int
    uid: str
    text: str
    owner: bool
    sent: int
    conv: str
    source: str
    title: str | None
    #: Noun terms (vectors) and every index term with its count (the term index).
    terms: frozenset[str] = frozenset()
    counts: Counter[str] = field(default_factory=Counter)
    dwell: float = 0.0


@dataclass
class Episode:
    conv: str
    parts: list[Part]
    vector: Vector

    @property
    def start(self) -> int:
        return self.parts[0].sent

    @property
    def end(self) -> int:
        return self.parts[-1].sent

    @property
    def minutes(self) -> float:
        return sum(part.dwell for part in self.parts)


@dataclass
class Branch:
    """One stretch of one chat inside an event."""

    source: str
    title: str | None
    conv_uid: str
    start: int
    end: int
    hits: int
    anchor_part_uid: str
    excerpts: list[str]
    user_messages: list[str]
    summary: str | None = None
    #: Topics the whole chat runs through; more than one marks a chat that mixes subjects.
    chat_topics: int = 1
    #: The folder a local session worked in (Claude Code, Codex), when the import recorded it.
    folder: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "title": self.title,
            "conv_uid": self.conv_uid,
            "start": self.start,
            "end": self.end,
            "hits": self.hits,
            "anchor_part_uid": self.anchor_part_uid,
            "excerpt": self.excerpts[0] if self.excerpts else "",
            "summary": self.summary,
            "chat_topics": self.chat_topics,
            "folder": self.folder,
        }


@dataclass
class Event:
    ongoing: bool
    start: int
    end: int
    #: Chats per source, a resumed session counted once.
    sources: dict[str, int]
    minutes: int
    days: int
    keywords: list[str]
    branches: list[Branch]
    score: float
    components: dict[str, float]
    headline: str | None = None
    #: The stored topic this event belongs to: ``{"id", "headline", "events"}``.
    topic: dict[str, Any] | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "headline": self.headline,
            "ongoing": self.ongoing,
            "start": self.start,
            "end": self.end,
            "sources": self.sources,
            "minutes": self.minutes,
            "days": self.days,
            "keywords": self.keywords,
            "score": round(self.score, 4),
            "components": {key: round(value, 4) for key, value in self.components.items()},
            "topic": self.topic,
            "branches": [branch.as_dict() for branch in self.branches],
        }


@dataclass
class EventResult:
    query: str
    events: list[Event]
    hits: int
    episodes: int
    took_ms: int
    timings: dict[str, int] = field(default_factory=dict)
    #: The events grouped under their stored topics, best first (see :mod:`.topics`).
    topics: list[dict[str, Any]] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "query": self.query,
            "hits": self.hits,
            "episodes": self.episodes,
            "took_ms": self.took_ms,
            "timings": self.timings,
            "events": [event.as_dict() for event in self.events],
            "topics": self.topics,
        }


def date(ts: int) -> str:
    return dt.datetime.fromtimestamp(ts).date().isoformat()


def nouns(text: str) -> frozenset[str]:
    """The noun terms of ``text`` that can carry a topic: no numbers, pronouns, symbols or 1-2 letter words."""
    return analyse(text)[0]


def cos(a: Vector, b: Vector) -> float:
    if len(a) > len(b):
        a, b = b, a
    return sum(value * b.get(term, 0.0) for term, value in a.items())


def normalised(vector: Vector) -> Vector:
    norm = math.sqrt(sum(value * value for value in vector.values())) or 1.0
    return {term: value / norm for term, value in vector.items()}


def gap(a: Episode, b: Episode) -> int:
    return max(0, max(a.start, b.start) - min(a.end, b.end))


class Threads:
    """Union-find over conversations that share copied messages."""

    def __init__(self, parts: Iterable[Part]) -> None:
        copies: dict[tuple[str, int, str], set[str]] = defaultdict(set)
        convs: set[str] = set()
        for part in parts:
            convs.add(part.conv)
            digest = hashlib.sha256(part.text.encode()).hexdigest()
            copies[(part.source, part.sent, digest)].add(part.conv)
        self._parent = {conv: conv for conv in convs}
        shared: Counter[tuple[str, str]] = Counter()
        for holders in copies.values():
            first, *rest = sorted(holders)
            for other in rest:
                shared[first, other] += 1
        for (a, b), count in shared.items():
            if count >= THREAD_SHARED:
                self._parent[self.root(a)] = self.root(b)

    def root(self, conv: str) -> str:
        while self._parent[conv] != conv:
            self._parent[conv] = self._parent[self._parent[conv]]
            conv = self._parent[conv]
        return conv


def analyse(text: str, written: dict[str, Counter[str]] | None = None) -> tuple[frozenset[str], Counter[str]]:
    """``text``'s topic nouns (:func:`nouns`) and every index term with its count, from one analysis.

    ``written``, when given, collects how each noun term was written (for keywords).
    """
    text = _visible(text)
    kept: set[str] = set()
    counts: Counter[str] = Counter()
    for token in analysis.tokens(text):
        counts[token.term] += 1
        if token.pos != "名詞" or token.sub in ("数詞", "代名詞"):
            continue
        surface = text[token.start : token.end]
        if (
            len(surface) < 2
            or _DIGIT.search(surface)
            or not _WORD.fullmatch(surface)
            or _SHORT_LATIN.fullmatch(surface)
        ):
            continue
        kept.add(token.term)
        if written is not None:
            written.setdefault(token.term, Counter())[surface] += 1
    return frozenset(kept), counts


def set_dwell(parts: Sequence[Part]) -> None:
    """Engaged minutes per part of one conversation (in time order): until the next one, capped."""
    for here, after in zip(parts, [*parts[1:], None], strict=True):
        here.dwell = (min(_DWELL_CAP, after.sent - here.sent) if after else _LAST_DWELL) / 60


def vector(parts: Sequence[Part], weight: Mapping[str, float], top: int | None = _VECTOR_TERMS) -> Vector:
    """The parts' nouns weighted by ``weight`` x log(1 + count), the owner's counted twice; unit length."""
    counts: Counter[str] = Counter()
    for part in parts:
        for term in part.terms:
            if term in weight:
                counts[term] += 2 if part.owner else 1
    weighted = {term: weight[term] * math.log1p(n) for term, n in counts.items()}
    if top is not None:
        weighted = dict(sorted(weighted.items(), key=lambda item: -item[1])[:top])
    return normalised(weighted)


def episodes_of(parts: Sequence[Part], weight: Mapping[str, float]) -> list[Episode]:
    """One conversation's parts (in time order) cut into episodes."""
    if not parts:
        return []
    stretches: list[list[Part]] = [[parts[0]]]
    for prev, part in itertools.pairwise(parts):
        if part.sent - prev.sent > EPISODE_GAP:
            stretches.append([])
        stretches[-1].append(part)
    return [Episode(parts[0].conv, cut, vector(cut, weight)) for stretch in stretches for cut in tiles(stretch, weight)]


def tiles(stretch: list[Part], weight: Mapping[str, float]) -> list[list[Part]]:
    """``stretch`` cut where the blocks on both sides of a gap share few weighted terms (TextTiling)."""
    if len(stretch) < 2 * _MIN_EPISODE:
        return [stretch]
    sims = [
        cos(vector(stretch[max(0, g - _TILE) : g], weight, None), vector(stretch[g : g + _TILE], weight, None))
        for g in range(1, len(stretch))
    ]
    cuts = [0]
    for g in range(1, len(stretch)):
        here = sims[g - 1]
        depth = (max(sims[max(0, g - 1 - _TILE) : g]) - here) + (max(sims[g - 1 : g - 1 + _TILE]) - here)
        if depth >= _TILE_DEPTH and g - cuts[-1] >= _MIN_EPISODE and len(stretch) - g >= _MIN_EPISODE:
            cuts.append(g)
    cuts.append(len(stretch))
    return [stretch[a:b] for a, b in itertools.pairwise(cuts)]


def surface(parts: Sequence[Part], term: str) -> str:
    """The most common written form of ``term`` in ``parts`` (the term itself is stemmed or normalised)."""
    seen: Counter[str] = Counter()
    for part in parts:
        if term in part.terms:
            text = _visible(part.text)
            seen.update(text[t.start : t.end] for t in analysis.tokens(text) if t.term == term)
            if sum(seen.values()) >= 5:
                break
    return seen.most_common(1)[0][0] if seen else term


def excerpt(text: str, words: Sequence[str]) -> str:
    """``text`` around its first match of ``words``, cleaned."""
    text = clean(text)
    spans = analysis.spans(text, words)
    if not spans:
        return text[: 2 * EXCERPT_CHARS]
    start, end = spans[0]
    return text[max(0, start - EXCERPT_CHARS) : end + EXCERPT_CHARS]
