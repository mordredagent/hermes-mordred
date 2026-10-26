"""Evidence cards: excerpt, highlight spans, kind, and why-this-appeared.

Cards are built ONLY from stored rows. No model text is ever inserted into a
card; the excerpt is a substring of the stored part, and the highlight spans
index into that substring.
"""

from __future__ import annotations

import dataclasses
import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

#: Excerpt window around the first matching term.
_BEFORE = 40
_AFTER = 160

_KIND_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("decision", re.compile(r"決定|固定|合意|決め(?:た|る|ます)|にしよう|decided|agreed|we will use", re.I)),
    ("change", re.compile(r"変更|前倒し|延期|修正し|差し替え|moved|changed|pushed", re.I)),
    ("deadline", re.compile(r"締め?切り|期限|までに|必着|due\b|deadline", re.I)),
    ("code", re.compile(r"```|traceback|Error:|verify\(|inputs|関数|リポジトリ", re.I)),
    ("link", re.compile(r"https?://", re.I)),
)

_DAY_RE = re.compile(r"(\d{1,2})\s*日")
_URL_RE = re.compile(r"https?://[^\s)>\]]+")


@dataclass(frozen=True)
class Card:
    part_uid: str
    conv_uid: str
    source: str
    title: str
    author: str
    owner_class: str
    sent_at: int | None
    message_id: str
    kind: str
    excerpt: str
    spans: tuple[tuple[int, int], ...]
    why: str
    score: float
    components: dict[str, float] = field(default_factory=dict)
    days: tuple[str, ...] = ()
    conflict: bool = False

    def as_dict(self) -> dict[str, Any]:
        return {
            # `uid` is what the browser extension keys on; `part_uid` is kept for
            # the existing /open contract.
            "uid": self.part_uid,
            "part_uid": self.part_uid,
            "conv_uid": self.conv_uid,
            "source": self.source,
            "title": self.title,
            "author": self.author,
            "owner_class": self.owner_class,
            "sent_at": self.sent_at,
            "message_id": self.message_id,
            "kind": self.kind,
            "excerpt": self.excerpt,
            "spans": [list(span) for span in self.spans],
            "why": self.why,
            "score": round(self.score, 4),
            "components": {k: round(v, 4) for k, v in self.components.items()},
            "days": list(self.days),
            "conflict": self.conflict,
        }


def terms_of(query: str) -> list[str]:
    """Whitespace terms, longest first, deduplicated; the whole query counts as one term."""
    raw = [t for t in re.split(r"\s+", query.strip()) if t]
    seen: list[str] = []
    for term in sorted(raw, key=len, reverse=True):
        if term not in seen:
            seen.append(term)
    if len(raw) > 1 and query.strip() not in seen:
        seen.append(query.strip())
    return seen


def detect_kind(text: str) -> str:
    for kind, pattern in _KIND_PATTERNS:
        if pattern.search(text):
            return kind
    return "statement"


def _matches(text: str, terms: Sequence[str]) -> list[tuple[int, int]]:
    """Case-insensitive, non-overlapping spans; the longest term wins an overlap."""
    found: list[tuple[int, int]] = []
    for term in terms:
        if not term:
            continue
        for match in re.finditer(re.escape(term), text, re.IGNORECASE):
            found.append((match.start(), match.end()))
    found.sort(key=lambda span: (span[0], -(span[1] - span[0])))
    kept: list[tuple[int, int]] = []
    for start, end in found:
        if kept and start < kept[-1][1]:
            continue
        kept.append((start, end))
        if len(kept) >= 12:
            break
    return kept


def excerpt(text: str, terms: Sequence[str]) -> tuple[str, tuple[tuple[int, int], ...]]:
    """A window around the first match, and spans relative to that window."""
    whole = _matches(text, terms)
    anchor = whole[0][0] if whole else 0
    start = max(0, anchor - _BEFORE)
    end = min(len(text), start + _BEFORE + _AFTER)
    start = max(0, min(start, max(0, len(text) - (end - start))))
    fragment = text[start:end]
    prefix = "…" if start > 0 else ""
    suffix = "…" if end < len(text) else ""
    shown = prefix + fragment + suffix
    shift = start - len(prefix)
    spans = tuple((a - shift, b - shift) for a, b in whole if a >= start and b <= end)
    return shown, spans


def _int_or_none(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def days_in(text: str) -> tuple[str, ...]:
    """Day-of-month mentions, normalised, deduplicated, in order of appearance."""
    found: list[str] = []
    for match in _DAY_RE.finditer(text):
        value = f"{int(match.group(1))}日"
        if value not in found:
            found.append(value)
    return tuple(found)


def build_card(*, part: Mapping[str, Any], terms: Sequence[str], score: float, components: dict[str, float]) -> Card:
    text = str(part["text"])
    shown, spans = excerpt(text, terms)
    hits = [term for term in terms if re.search(re.escape(term), text, re.IGNORECASE)]
    why = f"「{'」「'.join(hits)}」を含む発言" if hits else "語彙スコア上位"
    return Card(
        part_uid=str(part["part_uid"]),
        conv_uid=str(part["conv_uid"]),
        source=str(part["source"]),
        title=str(part.get("title") or ""),
        author=str(part.get("author") or ""),
        owner_class=str(part.get("owner_class") or ""),
        sent_at=_int_or_none(part.get("sent_at")),
        message_id=str(part.get("message_id") or ""),
        kind=detect_kind(text),
        excerpt=shown,
        spans=spans,
        why=why,
        score=score,
        components=components,
        days=days_in(text),
    )


def mark_conflicts(cards: Iterable[Card]) -> list[Card]:
    """Flag cards whose day-of-month mentions disagree across sources.

    A cheap, honest signal: it never claims the dates mean the same thing, only
    that different numbers appear for the same query.
    """
    cards = list(cards)
    per_source: dict[str, set[str]] = {}
    for card in cards:
        per_source.setdefault(card.source, set()).update(card.days)
    all_days = {day for days in per_source.values() for day in days}
    if len(per_source) < 2 or len(all_days) < 2:
        return cards
    flagged = []
    for card in cards:
        if card.days:
            flagged.append(_replace(card, conflict=True))
        else:
            flagged.append(card)
    return flagged


def _replace(card: Card, *, conflict: bool) -> Card:
    return dataclasses.replace(card, conflict=conflict)


def conflict_summary(cards: Iterable[Card]) -> str:
    """A one-line note naming the days that disagree, or an empty string."""
    by_source: dict[str, set[str]] = {}
    for card in cards:
        if card.days:
            by_source.setdefault(card.source, set()).update(card.days)
    if len(by_source) < 2:
        return ""
    flat = sorted({day for days in by_source.values() for day in days}, key=lambda d: int(d[:-1]))
    if len(flat) < 2:
        return ""
    parts = [f"{source}={','.join(sorted(days, key=lambda d: int(d[:-1])))}" for source, days in by_source.items()]
    return "日付が一致しません: " + " / ".join(parts)
