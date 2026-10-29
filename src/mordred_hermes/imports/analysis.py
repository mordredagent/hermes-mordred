"""Text analysis for the import search index: morphemes, not character n-grams.

Japanese has no word separators, so the index needs a morphological analyser
to find the words. :func:`tokens` runs Sudachi (split mode A, the shortest
units, so a compound such as 経費精算 is indexed as 経費 + 精算 and a search for
either part finds it) and keeps one *term* per content morpheme:

* Japanese and other non-Latin morphemes use Sudachi's normalised form, so
  spelling variants meet (〆切 and 締め切り, 打合せ and 打ち合わせ) and inflected
  verbs meet their dictionary form (延ばした -> 延ばす);
* Latin words use their own spelling, case-folded and stemmed (Snowball
  English): Sudachi would otherwise normalise them to katakana (Venice ->
  ベニス), and stemming lets private / privately and pair / pairing meet;
* particles, auxiliary verbs, punctuation, symbols and whitespace are dropped.

Every term keeps the character span of the morpheme it came from, so a hit can
be highlighted exactly where the index matched it.

The index and every query go through this one module: a term only matches
the same term, never part of a longer word (``AI`` does not match
``pairing``). The FTS5 table stores the terms separated by single spaces and
splits on whitespace only (:data:`FTS_TOKENIZER`), so SQLite never tokenises
the text a second time.
"""

from __future__ import annotations

import re
import threading
import unicodedata
from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from functools import cache, lru_cache
from typing import Any, Final

#: FTS5 tokenizer for the term column: whitespace separates terms, nothing else does.
FTS_TOKENIZER: Final = "unicode61 remove_diacritics 0 categories 'L* N* Co M* P* S*'"

#: Sudachi refuses input over 49149 bytes; 12000 characters stay under it even at 4 bytes each.
_CHUNK_CHARS: Final = 12000
#: Coarse parts of speech that carry no search value on their own.
_SKIP_POS: Final = frozenset({"助詞", "助動詞", "補助記号", "記号", "空白"})
_LATIN: Final = re.compile(r"[A-Za-z][A-Za-z0-9]*")
_SPACE: Final = re.compile(r"\s+")

# Sudachi's tokenizer and the Snowball stemmer keep per-call state; one lock
# serialises them (analysis runs at millions of characters per second).
_lock = threading.Lock()


class AnalyzerUnavailable(RuntimeError):
    """Sudachi or its dictionary is not installed."""


@dataclass(frozen=True)
class Token:
    term: str
    start: int
    end: int
    #: Sudachi's coarse part of speech (名詞, 動詞, 接尾辞, ...) and its first subdivision (数詞, 固有名詞, ...).
    pos: str = ""
    sub: str = ""


@cache
def _engines() -> tuple[Any, Any, Any]:
    try:
        import snowballstemmer
        from sudachipy import Dictionary, SplitMode
    except ImportError as exc:  # a broken install, not a data condition
        raise AnalyzerUnavailable(str(exc)) from None
    tokenizer = Dictionary(dict="core").tokenizer(SplitMode.A)
    return tokenizer, snowballstemmer.stemmer("english"), SplitMode.A


def _chunks(text: str) -> Iterator[tuple[int, str]]:
    """``(offset, piece)`` pieces under Sudachi's input limit, cut at a line break or space when possible."""
    start = 0
    while start < len(text):
        end = min(len(text), start + _CHUNK_CHARS)
        if end < len(text):
            cut = max(text.rfind("\n", start, end), text.rfind(" ", start, end))
            if cut > start:
                end = cut + 1
        yield start, text[start:end]
        start = end


@lru_cache(maxsize=65536)
def _stem(word: str) -> str:
    """Snowball is pure Python; words repeat, so each is stemmed once (called under :data:`_lock`)."""
    return str(_engines()[1].stemWord(word))


def _term(surface: str, normalized: str) -> str:
    plain = unicodedata.normalize("NFKC", surface)
    if _LATIN.fullmatch(plain):
        return _stem(plain.casefold())
    return _SPACE.sub("", unicodedata.normalize("NFKC", normalized)).casefold()


def tokens(text: str) -> list[Token]:
    """The content terms of ``text`` with their character spans, in reading order."""
    if not text:
        return []
    tokenizer, _stemmer, mode = _engines()
    found: list[Token] = []
    with _lock:
        for offset, piece in _chunks(text):
            for morpheme in tokenizer.tokenize(piece, mode):
                pos, sub = morpheme.part_of_speech()[:2]
                if pos in _SKIP_POS:
                    continue
                term = _term(morpheme.surface(), morpheme.normalized_form())
                if term:
                    found.append(Token(term, offset + morpheme.begin(), offset + morpheme.end(), pos, sub))
    return found


def index_text(text: str) -> str:
    """What the FTS5 term column stores for ``text``."""
    return " ".join(token.term for token in tokens(text))


def phrase(word: str) -> str | None:
    """``word``'s terms as one FTS5 phrase literal, or ``None`` when it has no content term.

    A phrase matches its terms adjacent and in order, so a compound the
    analyser splits (経費精算) still matches only itself, not its parts apart.
    The literal is quoted: a term can never become an FTS5 operator.
    """
    terms = [token.term for token in tokens(word)]
    if not terms:
        return None
    return '"' + " ".join(terms).replace('"', '""') + '"'


def match_query(words: Sequence[str]) -> str | None:
    """An FTS5 query matching every word (AND of phrases); ``None`` when no word has a content term."""
    phrases = [found for found in (phrase(word) for word in words) if found is not None]
    return " AND ".join(phrases) if phrases else None


@lru_cache(maxsize=1024)
def _sequence(word: str) -> tuple[str, ...]:
    return tuple(token.term for token in tokens(word))


def _occurrences(found: Sequence[Token], sequence: tuple[str, ...]) -> Iterator[tuple[int, int]]:
    """Where ``sequence`` occurs as consecutive terms of ``found``: what its FTS5 phrase matches."""
    size = len(sequence)
    for i in range(len(found) - size + 1):
        if all(found[i + k].term == sequence[k] for k in range(size)):
            yield found[i].start, found[i + size - 1].end


def spans(text: str, words: Sequence[str]) -> list[tuple[int, int]]:
    """Character spans in ``text`` where a word of ``words`` matches as its index phrase would, in order."""
    sequences = {_sequence(word) for word in words} - {()}
    if not sequences:
        return []
    found = tokens(text)
    return sorted({span for sequence in sequences for span in _occurrences(found, sequence)})


def matched(text: str, words: Sequence[str]) -> list[str]:
    """The words of ``words`` whose index phrase matches ``text``."""
    found = tokens(text)
    kept: list[str] = []
    for word in words:
        sequence = _sequence(word)
        if sequence and any(True for _span in _occurrences(found, sequence)):
            kept.append(word)
    return kept
