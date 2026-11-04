"""Validate a model's citations against the request's evidence set.

Security contract:

- An evidence id counts only if it is a member of the selection that was sent
  for THIS request. Ids the answer cites but the selection lacks are reported
  as ``unverified_ids``; they never produce a card.
- A quoted span (``「…」``, ``『…』``, ``“…”`` or ``"…"`` longer than 12
  characters) attached to a cited id in the same sentence must be an exact
  substring of that part's stored text after NFKC normalisation of both sides;
  otherwise it is listed in ``unsupported_quotes``.
- Cards are built ONLY from stored data (:class:`RenderedPartRef`). The single
  piece of model text a card may carry is a quote span that matched the stored
  text. A model-written speaker, date or chat name never reaches a card.
- Run this on the de-aliased answer. Correct citations do not prove that the
  model's summary is semantically correct.
"""

from __future__ import annotations

import re
import unicodedata
from bisect import bisect_right
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Final

from .aliases import neutralize
from .records import OwnerClass, PartKind, ProvenanceQuality
from .render import RenderedPartRef

__all__ = [
    "EVIDENCE_ID_RE",
    "EXCERPT_CHARS",
    "MIN_QUOTE_CHARS",
    "EvidenceCard",
    "EvidenceReport",
    "RenderedPartRef",
    "validate",
]

#: Telegram ``tg:<dialog>:<msg>`` and mail ``mail:<account>:<msgid | h:hex>``
#: ids with a ``#a`` / ``#q<n>`` / ``#f<n>`` part suffix. Mail message ids use
#: the percent-encoded alphabet of :func:`~.records.normalize_message_id`, so
#: surrounding punctuation in an answer is never swallowed into an id.
EVIDENCE_ID_RE: Final = re.compile(
    r"(?<![0-9A-Za-z_])"
    r"(?:tg:-?\d{1,19}:\d{1,19}"
    r"|mail:[A-Za-z0-9][A-Za-z0-9._-]{0,63}:(?:h:[0-9a-f]{32}|(?:[A-Za-z0-9_.~@+=$!/-]|%[0-9A-F]{2})+))"
    r"#(?:a|q\d{1,4}|f\d{1,4})"
    r"(?![0-9A-Za-z_])"
)
MIN_QUOTE_CHARS: Final = 12  # quotes must be LONGER than this to be checked
EXCERPT_CHARS: Final = 160

_QUOTE_RES: Final = (
    re.compile(r"「([^「」\n]*)」"),
    re.compile(r"『([^『』\n]*)』"),
    re.compile(r"“([^“”\n]*)”"),
    re.compile(r'"([^"\n]*)"'),
)
# Sentence ends: ideographic full stop, fullwidth . ! ? (as escapes), ASCII ! ?, newline, ". ".
_TERMINATOR_RE: Final = re.compile("[。\uff0e\uff01\uff1f!?\n]|\\.(?=\\s|$)")
_LEADING_FILLER_RE: Final = re.compile("[\\s(\uff08\\[【]*")


@dataclass(frozen=True, kw_only=True)
class EvidenceCard:
    """A source card rendered from stored data only."""

    evidence_id: str
    speaker: str
    speaker_class: OwnerClass
    part_kind: PartKind
    chat: str
    sent_at: int | None
    original_sent_at: int | None
    excerpt: str
    quote_verified: bool
    quote: str | None  # the matched span (NFKC), only when quote_verified
    provenance_quality: ProvenanceQuality


@dataclass(frozen=True)
class EvidenceReport:
    cards: tuple[EvidenceCard, ...]
    unverified_ids: tuple[str, ...]
    unsupported_quotes: tuple[str, ...]


@dataclass(frozen=True)
class _Span:
    start: int
    end: int
    value: str


def _nfkc(text: str) -> str:
    return unicodedata.normalize("NFKC", text)


def _quotes(answer: str) -> list[_Span]:
    found = [_Span(m.start(), m.end(), m.group(1)) for regex in _QUOTE_RES for m in regex.finditer(answer)]
    return sorted(found, key=lambda span: span.start)


class _Sentences:
    """Sentence membership with quotes and ids masked, so their punctuation never splits."""

    def __init__(self, answer: str, masked: Sequence[_Span]) -> None:
        chars = list(answer)
        for span in masked:
            chars[span.start : span.end] = "x" * (span.end - span.start)
        self._text = "".join(chars)
        self._ends = [m.end() for m in _TERMINATOR_RE.finditer(self._text)]

    def of(self, pos: int) -> int:
        return bisect_right(self._ends, pos)

    def of_id(self, span: _Span) -> set[int]:
        """An id right after a terminator also cites the sentence it trails: ``「…」。(id)``."""
        index = self.of(span.start)
        sentences = {index}
        if index and _LEADING_FILLER_RE.fullmatch(self._text, self._ends[index - 1], span.start):
            sentences.add(index - 1)
        return sentences


def _nearest_id(quote: _Span, ids: Sequence[_Span], sentences: _Sentences) -> str | None:
    """The cited id closest to the quote within its sentence; ties go to the following id."""
    sentence = sentences.of(quote.start)
    best: tuple[int, int, str] | None = None
    for span in ids:
        if sentence not in sentences.of_id(span):
            continue
        if span.start >= quote.end:
            rank = (span.start - quote.end, 0, span.value)
        elif span.end <= quote.start:
            rank = (quote.start - span.end, 1, span.value)
        else:
            continue  # an id inside the quote does not attribute it
        if best is None or rank[:2] < best[:2]:
            best = rank
    return None if best is None else best[2]


def _quote_matches(stored: str, quote: str) -> bool:
    return any(quote in _nfkc(candidate) for candidate in (stored, neutralize(stored)))


def _card(ref: RenderedPartRef, verdicts: Sequence[tuple[bool, str]]) -> EvidenceCard:
    verified = bool(verdicts) and all(ok for ok, _quote in verdicts)
    return EvidenceCard(
        evidence_id=ref.evidence_id,
        speaker=ref.speaker,
        speaker_class=ref.speaker_class,
        part_kind=ref.part_kind,
        chat=ref.chat,
        sent_at=ref.sent_at,
        original_sent_at=ref.original_sent_at,
        excerpt=ref.text[:EXCERPT_CHARS],
        quote_verified=verified,
        quote=verdicts[0][1] if verified else None,
        provenance_quality=ref.provenance_quality,
    )


def validate(answer: str, selection: Mapping[str, RenderedPartRef]) -> EvidenceReport:
    """Check cited ids and attached quotes; build cards from ``selection`` only."""
    ids = [_Span(m.start(), m.end(), m.group(0)) for m in EVIDENCE_ID_RE.finditer(answer)]
    quotes = _quotes(answer)
    sentences = _Sentences(answer, [*quotes, *ids])
    verdicts: dict[str, list[tuple[bool, str]]] = {}
    unsupported: list[str] = []
    for quote in quotes:
        normalized = _nfkc(quote.value).strip()
        if len(normalized) <= MIN_QUOTE_CHARS:
            continue
        evidence_id = _nearest_id(quote, ids, sentences)
        if evidence_id is None:
            continue
        ref = selection.get(evidence_id)
        ok = ref is not None and _quote_matches(ref.text, normalized)
        verdicts.setdefault(evidence_id, []).append((ok, normalized))
        if not ok:
            unsupported.append(quote.value)
    cited = list(dict.fromkeys(span.value for span in ids))
    return EvidenceReport(
        cards=tuple(_card(selection[eid], verdicts.get(eid, ())) for eid in cited if eid in selection),
        unverified_ids=tuple(eid for eid in cited if eid not in selection),
        unsupported_quotes=tuple(dict.fromkeys(unsupported)),
    )
