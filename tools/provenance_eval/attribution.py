"""Who an answer says said something: speaker labels, sentence mentions, categories.

Free-text rule (SPEC): a token counts as attributed to the asked person
unless its sentence names the true author; a sentence that names exactly one
other person attributes the token to that person; a name shared by several
people, or several people named without the true author, is *ambiguous* and
fails. "Unknown sender"-style wording is an abstention for that token.
Matching is on NFKC + casefold text; Latin names match on word boundaries and
whitespace inside a name is optional (``田中太郎`` = ``田中 太郎``).
"""

from __future__ import annotations

import re
from collections import defaultdict
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Final

from .tokens import normalize
from .truth import Truth

__all__ = [
    "AMBIGUOUS",
    "NEUTRAL",
    "UNKNOWN",
    "UNRESOLVED",
    "Category",
    "Mentions",
    "Resolver",
    "attribute",
    "categorize",
]

UNKNOWN: Final = "?unknown"  # the answer says the author is unknown
NEUTRAL: Final = "?neutral"  # no one is named and no one was asked about
AMBIGUOUS: Final = "?ambiguous"
UNRESOLVED: Final = "?unresolved"  # a speaker label that names no known person

_OWNER_CUES: Final = ("account owner", "アカウント所有者", "you", "yourself", "あなた", "ご自身")
_UNKNOWN_CUES: Final = (
    "unknown sender",
    "不明な送信者",
    "unknown",
    "不明",
    "not known",
    "unidentified",
    "誰が書いたか分かりません",
)
_SUFFIXES: Final = (" (contact)", " (連絡先)", "(contact)", "(連絡先)")


class Category(StrEnum):
    CORRECT = "correct"
    ABSTAINED = "abstained"
    CRITICAL = "critical_swap"  # owner <-> anyone else
    SAME_NAME = "same_name_merge"
    OTHER_OTHER = "other_other"
    AMBIGUOUS = "ambiguous"

    @property
    def misattributed(self) -> bool:
        return self in (Category.CRITICAL, Category.SAME_NAME, Category.OTHER_OTHER, Category.AMBIGUOUS)


@dataclass(frozen=True)
class Mentions:
    people: frozenset[str]
    ambiguous: tuple[frozenset[str], ...]
    unknown: bool

    @property
    def empty(self) -> bool:
        return not self.people and not self.ambiguous and not self.unknown


@dataclass(frozen=True)
class _Pattern:
    regex: re.Pattern[str]
    people: frozenset[str]  # empty: an "unknown author" cue
    size: int


def _fold(text: str) -> str:
    return " ".join(normalize(text).casefold().split())


def _regex(phrase: str) -> re.Pattern[str]:
    body = r"\s*".join(re.escape(word) for word in phrase.split())
    head = r"(?<![a-z0-9])" if phrase[:1].isascii() and phrase[:1].isalnum() else ""
    tail = r"(?![a-z0-9])" if phrase[-1:].isascii() and phrase[-1:].isalnum() else ""
    return re.compile(head + body + tail)


class Resolver:
    """Maps names, addresses, owner cues and rendered labels to people for one thread."""

    def __init__(self, truth: Truth, thread_id: str, labels: Mapping[str, str | None] | None = None) -> None:
        local = set(truth.thread(thread_id).participants) | {truth.owner_id}
        by_phrase: dict[str, set[str]] = defaultdict(set)
        for person in truth.people:
            for phrase in (*person.names, *person.short_names, *person.addresses):
                by_phrase[_fold(phrase)].add(person.person_id)
        table: dict[str, frozenset[str]] = {
            phrase: frozenset((people & local) or people) for phrase, people in by_phrase.items()
        }
        table.update({_fold(cue): frozenset({truth.owner_id}) for cue in _OWNER_CUES})
        table.update({_fold(cue): frozenset() for cue in _UNKNOWN_CUES})
        self._exact: dict[str, str | None] = {}
        for label, labelled in (labels or {}).items():
            folded = _fold(label)
            table[folded] = frozenset({labelled}) if labelled else frozenset()
            self._exact[folded] = labelled
        self._patterns = sorted(
            (_Pattern(_regex(phrase), people, len(phrase)) for phrase, people in table.items() if phrase),
            key=lambda item: -item.size,
        )

    def ordered(self, text: str) -> list[tuple[int, frozenset[str]]]:
        """Non-overlapping mentions (longest phrase first), in text order."""
        folded = _fold(text)
        taken = [False] * len(folded)
        found: list[tuple[int, frozenset[str]]] = []
        for pattern in self._patterns:
            for match in pattern.regex.finditer(folded):
                start, end = match.span()
                if start == end or any(taken[start:end]):
                    continue
                taken[start:end] = [True] * (end - start)
                found.append((start, pattern.people))
        return sorted(found, key=lambda item: item[0])

    def mentions(self, text: str) -> Mentions:
        people: set[str] = set()
        ambiguous: list[frozenset[str]] = []
        unknown = False
        for _start, group in self.ordered(text):
            if not group:
                unknown = True
            elif len(group) == 1:
                people |= group
            else:
                ambiguous.append(group)
        return Mentions(frozenset(people), tuple(ambiguous), unknown)

    def first(self, text: str) -> str | None:
        """The first person (or ``UNKNOWN`` / ``AMBIGUOUS``) named in ``text``; ``None`` if nobody."""
        for _start, group in self.ordered(text):
            if not group:
                return UNKNOWN
            return next(iter(group)) if len(group) == 1 else AMBIGUOUS
        return None

    def resolve_label(self, label: str) -> str:
        """A structured claim's speaker string as a person id or a sentinel."""
        folded = _fold(label)
        for suffix in _SUFFIXES:
            folded = folded.removesuffix(suffix).strip()
        if folded in self._exact:
            person = self._exact[folded]
            return person if person is not None else UNKNOWN
        found = self.mentions(label)
        if len(found.people) == 1 and not found.ambiguous:
            return next(iter(found.people))
        if found.people or found.ambiguous:
            return AMBIGUOUS
        return UNKNOWN if found.unknown else UNRESOLVED


def attribute(mentions: Mentions, true_author: str, target: str | None, *, knowable: bool) -> str:
    """The free-text sentence rule (see the module docstring)."""
    if true_author in mentions.people:
        return true_author
    if any(true_author in group for group in mentions.ambiguous):
        return AMBIGUOUS
    if mentions.unknown and not knowable:
        return UNKNOWN
    if len(mentions.people) == 1 and not mentions.ambiguous:
        return next(iter(mentions.people))
    if mentions.people or mentions.ambiguous:
        return AMBIGUOUS
    if mentions.unknown:
        return UNKNOWN
    return target if target is not None else NEUTRAL


def _has_namesake(truth: Truth, person_id: str) -> bool:
    names = set(truth.person(person_id).names)
    return any(set(other.names) & names for other in truth.people if other.person_id != person_id)


def categorize(attributed: str, true_author: str, truth: Truth) -> Category:
    if attributed == true_author:
        return Category.CORRECT
    if attributed in (UNKNOWN, NEUTRAL):
        return Category.ABSTAINED
    if attributed in (AMBIGUOUS, UNRESOLVED):
        return Category.SAME_NAME if _has_namesake(truth, true_author) else Category.AMBIGUOUS
    if truth.is_owner(attributed) != truth.is_owner(true_author):
        return Category.CRITICAL
    if set(truth.person(attributed).names) & set(truth.person(true_author).names):
        return Category.SAME_NAME
    return Category.OTHER_OTHER
