"""Scoring and confidence.

One transparent linear combination, not a learned ranker. Every component is
returned with the card so the UI can explain why something appeared, and so a
weight change is measurable against the golden set.
"""

from __future__ import annotations

import math
import re
from collections.abc import Iterable, Mapping, Sequence
from typing import Protocol, TypeVar

#: How much a source is trusted when two hits are otherwise equal.
SOURCE_WEIGHT: dict[str, float] = {
    "mail": 1.0,
    "telegram": 1.0,
    "codex": 0.9,
    "claude_code": 0.9,
    "activity": 0.7,
}

#: Weights sum to 1.0.
WEIGHTS = {
    "lexical": 0.40,
    "coverage": 0.20,
    "assertion": 0.20,
    "recency": 0.10,
    "source": 0.10,
}

#: bm25 ranks are negative; this scale maps a strong match to 1.0.
_BM25_SCALE = 4.0
#: Days for the recency component to halve.
_HALF_LIFE_DAYS = 180.0


def lexical_component(rank: float) -> float:
    """Positive, bounded: a LIKE-path hit (rank 0.0) contributes nothing here."""
    return max(0.0, min(1.0, -float(rank) / _BM25_SCALE))


def coverage_component(terms: Sequence[str], text: str) -> float:
    """Fraction of query terms present, case-insensitively (DEPLOY_KEY matches deploy)."""
    if not terms:
        return 0.0
    folded = text.casefold()
    return sum(1 for term in terms if term.casefold() in folded) / len(terms)


def recency_component(sent_at: int | None, now: float) -> float:
    if not sent_at:
        return 0.0
    age_days = max(0.0, (now - sent_at) / 86400.0)
    return math.pow(0.5, age_days / _HALF_LIFE_DAYS)


_QUESTION_RE = re.compile("[?\uff1f]|(?:いつ|何日|どこ|だれ|誰|教えて|ですか|ますか)\\s*$")


def assertion_component(text: str) -> float:
    """1.0 for a statement, 0.0 for a question.

    Recall is asked to surface what was decided or said, and a question
    ("締め切りはいつ?") is usually the search target's *context*, not its
    answer. Only the opening is inspected, so a statement that quotes a
    question later in the same part is not penalised.
    """
    opening = text.strip()[:60]
    return 0.0 if _QUESTION_RE.search(opening) else 1.0


def score(
    *,
    rank: float,
    terms: Sequence[str],
    text: str,
    sent_at: int | None,
    source: str,
    now: float,
) -> tuple[float, dict[str, float]]:
    components = {
        "lexical": lexical_component(rank),
        "coverage": coverage_component(terms, text),
        "assertion": assertion_component(text),
        "recency": recency_component(sent_at, now),
        "source": SOURCE_WEIGHT.get(source, 0.8),
    }
    total = sum(WEIGHTS[name] * value for name, value in components.items())
    return total, components


def confidence(scores: Sequence[float], *, distinct_conversations: int) -> str:
    """`high` only when the top card is both strong and ahead of the rest.

    Silence is a feature: a weak or flat result set returns `none`, and the UI
    says so instead of showing a doubtful card.
    """
    if not scores or distinct_conversations == 0:
        return "none"
    top = scores[0]
    margin = top - scores[1] if len(scores) > 1 else top
    if top >= 0.52 and margin >= 0.06:
        return "high"
    if top >= 0.34:
        return "low"
    return "none"


def rank_key(score_value: float, sent_at: int | None, part_uid: str) -> tuple[float, int, str]:
    return (-score_value, -(sent_at or 0), part_uid)


class _Ranked(Protocol):
    @property
    def score(self) -> float: ...
    @property
    def sent_at(self) -> int | None: ...
    @property
    def part_uid(self) -> str: ...


_R = TypeVar("_R", bound=_Ranked)


def sort_cards(cards: Iterable[_R]) -> list[_R]:
    return sorted(cards, key=lambda c: rank_key(c.score, c.sent_at, c.part_uid))


def explain(components: Mapping[str, float], source: str) -> str:
    """Human-readable component breakdown, for the card's tooltip."""
    return (
        f"lexical={components['lexical']:.2f} coverage={components['coverage']:.2f} "
        f"recency={components['recency']:.2f} source={source}"
    )
