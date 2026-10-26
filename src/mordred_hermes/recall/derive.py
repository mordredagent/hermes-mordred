"""Turn a long selection into something worth searching.

A page selection is usually a paragraph, and a paragraph is a bad query: the
service's search ANDs its terms, so a whole sentence matches nothing. This
module derives a short summary for display and a handful of keywords for the
search, without an LLM.

It is deliberately extractive and deterministic:

* keywords are runs of kanji, katakana, latin words, and numbers with a unit,
  scored by frequency and length, minus a stop list;
* the summary is the sentence with the highest keyword density;
* the queries are the keywords (never the summary — a sentence would AND to
  zero hits).

An LLM may replace this later; the interface (`Derived`) stays the same.
"""

from __future__ import annotations

import math
import re
import unicodedata
from dataclasses import dataclass
from typing import Any

#: The selection is cut here before anything else.
MAX_SELECTION = 1000
#: How many keywords are searched.
MAX_QUERIES = 5
#: Display cap for the summary.
MAX_SUMMARY = 160

_KANJI = re.compile(r"[\u4e00-\u9fff]{2,}")
_KATAKANA = re.compile(r"[\u30a1-\u30fa\u30fc]{2,}")
_LATIN = re.compile(r"[A-Za-z][A-Za-z0-9_+.-]{2,}")
_NUMBER_UNIT = re.compile(r"\d{1,4}(?:日|月|年|円|%|時|分|人|件|回|位)")
_SENTENCE_SPLIT = re.compile("(?<=[。\uff0e.!?\uff01\uff1f])|\n+")

#: Words that carry no recall value on their own.
_STOP = {
    "これ",
    "それ",
    "あれ",
    "ここ",
    "そこ",
    "どこ",
    "ため",
    "よう",
    "こと",
    "もの",
    "です",
    "ます",
    "して",
    "した",
    "する",
    "ある",
    "いる",
    "なる",
    "から",
    "まで",
    "より",
    "について",
    "として",
    "という",
    "場合",
    "内容",
    "確認",
    "以上",
    "以下",
    "the",
    "and",
    "for",
    "that",
    "this",
    "with",
    "from",
    "have",
    "will",
    "your",
    "you",
    "are",
    "was",
    "were",
    "but",
    "not",
    "can",
    "all",
    "any",
    "how",
    "what",
}


@dataclass(frozen=True)
class Derived:
    summary: str
    keywords: tuple[str, ...] = ()
    queries: tuple[str, ...] = ()
    chars: int = 0
    truncated: bool = False
    source: str = "heuristic"

    def as_dict(self) -> dict[str, Any]:
        return {
            "summary": self.summary,
            "keywords": list(self.keywords),
            "queries": list(self.queries),
            "chars": self.chars,
            "truncated": self.truncated,
            "source": self.source,
        }


def normalize(text: str) -> str:
    value = unicodedata.normalize("NFKC", text or "")
    return re.sub(r"[ \t\u3000]+", " ", value).strip()


def _candidates(text: str) -> list[str]:
    found: list[str] = []
    for pattern in (_KANJI, _KATAKANA, _LATIN, _NUMBER_UNIT):
        found.extend(match.group(0) for match in pattern.finditer(text))
    return found


def keywords_of(text: str, *, limit: int = MAX_QUERIES) -> list[str]:
    counts: dict[str, int] = {}
    for word in _candidates(text):
        key = word.casefold()
        if key in _STOP or len(word) < 2:
            continue
        counts[word] = counts.get(word, 0) + 1
    scored = sorted(
        counts.items(),
        key=lambda item: (-(item[1] * (1 + math.log(len(item[0])))), -len(item[0]), item[0]),
    )
    kept: list[str] = []
    for word, _count in scored:
        if any(word in longer or longer in word for longer in kept):
            continue
        kept.append(word)
        if len(kept) >= limit:
            break
    return kept


def _sentences(text: str) -> list[str]:
    return [part.strip() for part in _SENTENCE_SPLIT.split(text) if part.strip()]


def summarize(text: str, keywords: list[str], *, limit: int = MAX_SUMMARY) -> str:
    sentences = _sentences(text)
    if not sentences:
        return text[:limit]
    if len(sentences) == 1:
        return sentences[0][:limit]
    # Count distinct keywords, not their characters: a long loanword alone should
    # not beat a sentence that carries two of the things being asked about.
    best = max(
        sentences,
        key=lambda sentence: (
            sum(1 for word in keywords if word in sentence),
            -sentences.index(sentence),
        ),
    )
    return best[:limit]


def derive(text: str, *, max_selection: int = MAX_SELECTION) -> Derived:
    cleaned = normalize(text)
    truncated = len(cleaned) > max_selection
    body = cleaned[:max_selection]
    if not body:
        return Derived(summary="", chars=0)

    keywords = keywords_of(body)
    summary = summarize(body, keywords)

    queries: list[str] = []
    for word in keywords:
        if len(word) >= 2 and word not in queries:
            queries.append(word)
    if not queries:
        # Nothing word-like: fall back to a short prefix so the search still runs.
        fallback = body[:60].strip()
        if fallback:
            queries.append(fallback)

    return Derived(
        summary=summary,
        keywords=tuple(keywords),
        queries=tuple(queries[:MAX_QUERIES]),
        chars=len(cleaned),
        truncated=truncated,
    )
