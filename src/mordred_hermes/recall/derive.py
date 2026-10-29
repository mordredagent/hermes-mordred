"""Turn a long selection into something worth searching.

A page selection is usually a paragraph, and a paragraph is a bad query: the
service's search ANDs its terms, so a whole sentence matches nothing. This
module derives a short summary for display and a handful of keywords for the
search, without an LLM.

It is deliberately extractive and deterministic:

* keywords come from the same morphological analysis as the search index
  (:mod:`mordred_hermes.imports.analysis`), so a keyword is always made of whole
  index terms: a run of adjacent nouns (with their prefixes and suffixes) is one
  compound keyword (経費精算, 暗号化, 15日), a content verb or adjective is a
  keyword of its own, and pronouns, particles, light verbs (する, ある) and a
  stop list are dropped; keywords are scored by frequency and length;
* the summary is the sentence with the highest keyword density;
* the queries are the keywords (never the summary — a sentence would AND to
  zero hits).

An LLM may replace this later; the interface (`Derived`) stays the same.
"""

from __future__ import annotations

import math
import re
import unicodedata
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from ..imports import analysis

#: The selection is cut here before anything else.
MAX_SELECTION = 1000
#: How many keywords are searched.
MAX_QUERIES = 5
#: Display cap for the summary.
MAX_SUMMARY = 160

#: Counters that close a number expression (15日, 3万円, 50%).
_COUNTERS = frozenset(
    {
        "日",
        "月",
        "年",
        "円",
        "時",
        "分",
        "秒",
        "人",
        "件",
        "回",
        "位",
        "週",
        "歳",
        "個",
        "枚",
        "台",
        "本",
        "冊",
        "万",
        "億",
        "千",
        "%",
        "割",
    }
)
#: Honorific and plural suffixes left off a name (田中さん -> 田中).
_HONORIFICS = frozenset({"さん", "様", "氏", "君", "ちゃん", "殿", "達", "等"})
#: Candidates whose corpus frequency is looked up (the rest cannot win).
_RARITY_POOL = 20
#: Parts of speech that join a compound keyword when adjacent.
_NOUNISH = frozenset({"名詞", "接頭辞", "接尾辞", "形状詞"})
#: Parts of speech that are a keyword on their own (weighted below a noun).
_PREDICATES = frozenset({"動詞", "形容詞"})
_PREDICATE_WEIGHT = 0.6
#: Verbs that carry no meaning of their own (normalised forms): する, いる, ある, なる, できる, ...
_LIGHT_VERBS = frozenset(
    {"為る", "居る", "有る", "成る", "出来る", "言う", "思う", "付く", "行く", "来る", "見る", "呉れる"}
)
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
    "use",
    "used",
    "using",
    "into",
    "about",
    "also",
    "just",
    "than",
    "then",
    "there",
    "their",
    "they",
    "them",
    "these",
    "those",
    "which",
    "while",
    "would",
    "could",
    "should",
    "been",
    "being",
    "does",
    "its",
    "our",
    "out",
    "his",
    "her",
    "she",
    "him",
    "who",
    "when",
    "where",
    "why",
    "here",
    "only",
    "very",
    "more",
    "some",
    "such",
    "each",
    "other",
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


def _is_number(token: analysis.Token) -> bool:
    return token.sub == "数詞"


def _closes_number(token: analysis.Token) -> bool:
    return _is_number(token) or token.pos == "接尾辞" or token.term in _COUNTERS


def _breaks_run(run: list[analysis.Token], token: analysis.Token) -> bool:
    """Whether ``token`` starts a new keyword instead of extending ``run``."""
    if not run:
        return False
    if run[-1].end != token.start:  # a particle, a symbol or a space sat between them
        return True
    if _is_number(token) and not _is_number(run[-1]):
        return True  # a number starts its own expression (毎月 | 20日)
    return any(_is_number(t) for t in run) and not _closes_number(token)  # 31日 | 必着


def _keyword(text: str, run: list[analysis.Token]) -> str | None:
    """A compound keyword from adjacent noun-like tokens; ``None`` when it is not worth searching."""
    while run and run[0].pos == "接尾辞":
        run = run[1:]
    while run and (run[-1].pos == "接頭辞" or run[-1].term in _HONORIFICS):
        run = run[:-1]
    if not run:
        return None
    word = text[run[0].start : run[-1].end]
    if word.casefold() in _STOP or word.isdigit():
        return None
    return word if len(word) >= 2 else None  # one letter, kanji or kana alone is too common


def _candidates(text: str) -> list[tuple[str, float]]:
    """``(keyword, weight)`` in reading order: compound nouns, then content verbs and adjectives."""
    found: list[tuple[str, float]] = []
    run: list[analysis.Token] = []

    def flush() -> None:
        word = _keyword(text, run)
        if word is not None:
            found.append((word, 1.0))
        run.clear()

    for token in analysis.tokens(text):
        if token.pos in _NOUNISH and token.term not in _STOP:
            if _breaks_run(run, token):
                flush()
            run.append(token)
            continue
        flush()
        if token.pos in _PREDICATES and token.term not in _LIGHT_VERBS and token.end - token.start >= 2:
            found.append((text[token.start : token.end], _PREDICATE_WEIGHT))
    flush()
    return found


#: ``words -> ({word: parts containing it}, parts in all)``, e.g. :meth:`ImportStore.document_frequencies`.
Frequencies = Callable[[Sequence[str]], tuple[Mapping[str, int], int]]


def _idf(found: int, total: int) -> float:
    """BM25's inverse document frequency: rare words weigh more, and it never goes negative."""
    return math.log(1 + (total - found + 0.5) / (found + 0.5))


def keywords_of(text: str, *, limit: int = MAX_QUERIES, frequencies: Frequencies | None = None) -> list[str]:
    """The ``limit`` best keywords of ``text``.

    Without ``frequencies`` a keyword scores by how often it occurs, times a
    length bonus. With them it scores by occurrence times IDF over the
    searched corpus, and a keyword the corpus does not contain is dropped (it
    can recall nothing).
    """
    counts: dict[str, float] = {}
    for word, weight in _candidates(text):
        counts[word] = counts.get(word, 0.0) + weight
    scored = sorted(
        counts.items(),
        key=lambda item: (-(item[1] * (1 + math.log(len(item[0])))), -len(item[0]), item[0]),
    )
    if frequencies is not None:
        pool = scored[:_RARITY_POOL]
        found, total = frequencies([word for word, _weight in pool])
        weighted = [(word, weight * _idf(found.get(word, 0), total)) for word, weight in pool if found.get(word, 0)]
        scored = sorted(weighted, key=lambda item: (-item[1], -len(item[0]), item[0]))
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


def derive(text: str, *, max_selection: int = MAX_SELECTION, frequencies: Frequencies | None = None) -> Derived:
    cleaned = normalize(text)
    truncated = len(cleaned) > max_selection
    body = cleaned[:max_selection]
    if not body:
        return Derived(summary="", chars=0)

    keywords = keywords_of(body, frequencies=frequencies)
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
