"""Split a mail body into authored, quoted and forwarded segments.

A line state machine (no model, no network). At every nesting level it reads:

- **Forward banners** (Gmail en/ja, Thunderbird en/ja, Outlook ``-----Original
  Message-----``, Apple ``Begin forwarded message:``) followed by a header
  block (``From``/``Date``/``Subject`` and the Japanese sender, date and
  subject labels). Everything after the block is a *forwarded* segment
  attributed to the block's sender, with the block's date as original date.
- **Outlook reply header blocks** (an underscore rule or a blank line, then
  ``From``+``Sent``/``Date``+``To``/``Subject`` or the Japanese labels):
  everything after the block is a *quoted* segment attributed to it.
- **Attribution lines** directly followed by quoted lines: ``On … wrote:``
  (also wrapped over two or three lines), the Gmail Japanese
  date-time-name-address-colon form, the Japanese "wrote" suffix and the Apple
  Japanese form. The attribution applies to the following quote blocks at the
  same level (inline replies keep it).
- **Quote prefixes** ``>`` and the full-width greater-than sign (U+FF1E) per
  depth. Inline replies between quote blocks stay with the surrounding level's
  text.

Limits: nesting depth :data:`MAX_DEPTH` and at most :data:`MAX_PARTS` parts per
message (authored text counts as one part; overflow quotes are merged into one
quote with no attribution). A line that merely *looks like* a rendered head
line (``[Mail …] speaker: …``) is ordinary text; nothing here parses it.

Segments carry *claims* only (:class:`Attribution`); deciding a part's author
is :mod:`.normalize`'s job (an own address claimed in a quote is not proof).
"""

from __future__ import annotations

import re
from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Final

from ..records import PartKind
from ._dates import parse_loose_date
from ._text import clean_line, strip_blank_edges

__all__ = [
    "MAX_DEPTH",
    "MAX_PARTS",
    "Attribution",
    "Segment",
    "SegmentResult",
    "parse_claimed_sender",
    "segment_body",
]

MAX_DEPTH: Final = 8
MAX_PARTS: Final = 64
_MAX_HEADER_LINES: Final = 24
_MAX_BLANK_GAP: Final = 2

_QUOTE_RE: Final = re.compile(r"^[ \t]{0,3}((?:[>\uff1e][ \t]?)+)")
_STRIP_ONE_RE: Final = re.compile(r"^[ \t]{0,3}[>\uff1e][ \t]?")
_FORWARD_BANNERS: Final = (
    (re.compile(r"-{2,}\s*(?:forwarded message|original message)\s*-{2,}", re.IGNORECASE), "en"),
    (re.compile(r"begin forwarded message\s*:", re.IGNORECASE), "en"),
    (re.compile(r"-{2,}\s*(?:転送されたメッセージ|転送メッセージ|元のメッセージ)\s*-{2,}"), "ja"),
    (re.compile(r"転送されたメッセージ\s*[:\uff1a]"), "ja"),
)
_UNDERSCORE_RULE_RE: Final = re.compile(r"_{8,}")
_HEADER_LABELS: Final = {
    "from": ("from", "en"),
    "sent": ("date", "en"),
    "date": ("date", "en"),
    "to": ("to", "en"),
    "cc": ("to", "en"),
    "subject": ("subject", "en"),
    "reply-to": ("reply_to", "en"),
    "差出人": ("from", "ja"),
    "送信者": ("from", "ja"),
    "送信日時": ("date", "ja"),
    "日付": ("date", "ja"),
    "宛先": ("to", "ja"),
    "件名": ("subject", "ja"),
}
_HEADER_RE: Final = re.compile(
    r"^[ \t]*\*?(?P<label>From|Sent|Date|To|Cc|Subject|Reply-To|差出人|送信者|送信日時|日付|宛先|件名)\*?"
    r"[ \t]*[:\uff1a][ \t]*(?P<value>.*)$",
    re.IGNORECASE,
)
_ANGLE_ADDR_RE: Final = re.compile(r"<\s*([^<>\s]+@[^<>\s]+?)\s*>")
_MAILTO_RE: Final = re.compile(r"\[\s*mailto:([^\]\s]+@[^\]\s]+)\s*\]", re.IGNORECASE)
_BARE_ADDR_RE: Final = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_TIME_TOKEN_RE: Final = re.compile(
    r"\d{1,2}:\d{2}(?::\d{2})?(?:\s*[AaPp]\.?[Mm]\.?(?![A-Za-z]))?(?:\s*(?:GMT|UTC)\s*[+-]\d{1,4})?"
)
_ON_WROTE_RE: Final = re.compile(r"On\s+(?P<body>.+?)\s*wrote\s*[:\uff1a]")
_GMAIL_JA_RE: Final = re.compile(
    r"(?P<date>\d{4}年\d{1,2}月\d{1,2}日(?:\s*[(\uff08][^)\uff09]{1,3}[)\uff09])?\s*\d{1,2}:\d{2})\s+(?P<who>.+?<[^<>]+@[^<>]+>)\s*[:\uff1a]"
)
_JA_WROTE_RE: Final = re.compile(r"(?P<who>.+?)\s*さんは書きました\s*[:\uff1a]?")
_JA_APPLE_RE: Final = re.compile(r"(?P<date>.+?\d{1,2}:\d{2})\s*[、,]\s*(?P<who>.+?)\s*のメール\s*[:\uff1a]")
_DATE_FIRST_RE: Final = re.compile(r"(?P<date>.+?\d{1,2}:\d{2})\s*[、,]\s*(?P<rest>.+)")


@dataclass(frozen=True, kw_only=True)
class Attribution:
    """What the text *claims* about a quoted/forwarded span's author (never proof)."""

    address: str | None
    name: str
    sent_at: int | None
    source: str  # attribution | forward_header | header_block | rfc822
    locale: str  # en | ja | neutral
    message_id: str | None = None


@dataclass(frozen=True, kw_only=True)
class Segment:
    kind: PartKind
    text: str
    depth: int
    attribution: Attribution | None


@dataclass(frozen=True)
class SegmentResult:
    segments: tuple[Segment, ...]
    markers: Counter[str]
    part_limit: bool = False
    depth_limit: bool = False


def quote_depth(line: str) -> int:
    match = _QUOTE_RE.match(line)
    return 0 if match is None else sum(char in ">\uff1e" for char in match.group(1))


def _fullwidth_prefix(line: str) -> bool:
    """True when this level's quote marker (the first one) is the full-width sign."""
    return line.lstrip(" \t").startswith("\uff1e")


def _strip_one(line: str) -> str:
    return _STRIP_ONE_RE.sub("", line, count=1)


def _blank(line: str) -> bool:
    return not line.strip()


def _skip_blank(lines: Sequence[str], index: int, limit: int = _MAX_BLANK_GAP) -> int:
    skipped = 0
    while index < len(lines) and _blank(lines[index]) and skipped < limit:
        index += 1
        skipped += 1
    return index


def parse_claimed_sender(text: str) -> tuple[str, str | None]:
    """``Name <addr>`` / ``Name [mailto:addr]`` / bare address → (name, lowercased address)."""
    for pattern in (_ANGLE_ADDR_RE, _MAILTO_RE):
        matches = list(pattern.finditer(text))
        if matches:
            last = matches[-1]
            name = text[: last.start()] + text[last.end() :]
            return clean_line(name.strip(" \t\"',、")), last.group(1).lower()
    bare = _BARE_ADDR_RE.search(text)
    if bare is not None:
        name = text[: bare.start()] + text[bare.end() :]
        return clean_line(name.strip(" \t\"',、")), bare.group(0).lower()
    return clean_line(text.strip(" \t\"',、")), None


def _split_date_who(body: str) -> tuple[str, str]:
    """``<date> <name> <addr>`` or ``<date>, <name>`` → (date text, who text)."""
    angle = list(_ANGLE_ADDR_RE.finditer(body))
    head = body[: angle[-1].start()] if angle else body
    times = list(_TIME_TOKEN_RE.finditer(head))
    if times:
        cut = times[-1].end()
        return body[:cut], body[cut:].lstrip(" ,、")
    if "," in head:
        date, _sep, _name = head.rpartition(",")
        return date, body[len(date) + 1 :].strip()
    return "", body


def _attribution(who: str, date_text: str, locale: str, tz: int | None) -> Attribution | None:
    name, address = parse_claimed_sender(who)
    if not name and not address:
        return None
    sent_at = parse_loose_date(date_text, tz) if date_text else None
    return Attribution(address=address, name=name, sent_at=sent_at, source="attribution", locale=locale)


def match_attribution(text: str, tz: int | None) -> Attribution | None:
    """Recognise one (joined) attribution line; ``None`` when it is not one."""
    value = text.strip()
    if (match := _ON_WROTE_RE.fullmatch(value)) is not None:
        date_text, who = _split_date_who(match.group("body"))
        return _attribution(who, date_text, "en", tz)
    if (match := _GMAIL_JA_RE.fullmatch(value)) is not None:
        return _attribution(match.group("who"), match.group("date"), "ja", tz)
    if (match := _JA_APPLE_RE.fullmatch(value)) is not None:
        return _attribution(match.group("who"), match.group("date"), "ja", tz)
    if (match := _JA_WROTE_RE.fullmatch(value)) is not None:
        who = match.group("who")
        dated = _DATE_FIRST_RE.fullmatch(who)
        if dated is not None:
            return _attribution(dated.group("rest"), dated.group("date"), "ja", tz)
        return _attribution(who, "", "ja", tz)
    return None


def _wrap_candidate(line: str) -> bool:
    stripped = line.lstrip()
    return stripped.startswith("On ") or stripped[:1].isdigit() or ("<" in line and ">" not in line.rsplit("<", 1)[1])


def _forward_banner(line: str) -> str | None:
    stripped = line.strip()
    for pattern, locale in _FORWARD_BANNERS:
        if pattern.fullmatch(stripped):
            return locale
    return None


@dataclass
class _Headers:
    fields: dict[str, str] = field(default_factory=dict)
    locale: str = "en"
    end: int = 0


def _continues(line: str, key: str) -> bool:
    """A wrapped header value: indented, or the rest of a wrapped address list."""
    return line[:1] in {" ", "\t"} or (key == "to" and ("@" in line or line.rstrip().endswith((",", ";"))))


def _header_lines(lines: Sequence[str], start: int) -> _Headers:
    found = _Headers(end=start)
    last: str | None = None
    index = start
    while index < len(lines) and index - start < _MAX_HEADER_LINES and not _blank(lines[index]):
        match = _HEADER_RE.match(lines[index])
        if match is not None:
            key, locale = _HEADER_LABELS[match.group("label").lower()]
            found.fields.setdefault(key, match.group("value").strip())
            found.locale = "ja" if locale == "ja" else found.locale
            last = key
        elif last is not None and _continues(lines[index], last):
            found.fields[last] = f"{found.fields[last]} {lines[index].strip()}"
        else:
            break
        index += 1
    found.end = index
    return found


def _header_attribution(headers: _Headers, source: str, locale: str, tz: int | None) -> Attribution | None:
    name, address = parse_claimed_sender(headers.fields.get("from", ""))
    if not name and not address:
        return None
    sent_at = parse_loose_date(headers.fields.get("date", ""), tz)
    return Attribution(address=address, name=name, sent_at=sent_at, source=source, locale=locale)


class _Segmenter:
    def __init__(self, tz: int | None) -> None:
        self.tz = tz
        self.segments: list[Segment] = []
        self.markers: Counter[str] = Counter()
        self.non_authored = 0
        self.overflow: list[str] = []
        self.overflow_depth = 0
        self.depth_limit = False

    # -- output -------------------------------------------------------------

    def emit(self, kind: PartKind, attribution: Attribution | None, depth: int, lines: Sequence[str]) -> None:
        text = "\n".join(strip_blank_edges(list(lines)))
        if not text.strip():
            return
        if kind is PartKind.AUTHORED:
            self.segments.append(Segment(kind=kind, text=text, depth=depth, attribution=attribution))
            return
        if self.non_authored >= MAX_PARTS - 2:
            self.overflow.append(text)
            self.overflow_depth = self.overflow_depth or depth
            return
        self.non_authored += 1
        self.segments.append(Segment(kind=kind, text=text, depth=depth, attribution=attribution))

    def result(self) -> SegmentResult:
        segments = list(self.segments)
        if self.overflow:
            overflow = Segment(
                kind=PartKind.QUOTED, text="\n".join(self.overflow), depth=self.overflow_depth, attribution=None
            )
            segments.append(overflow)
        return SegmentResult(tuple(segments), self.markers, bool(self.overflow), self.depth_limit)

    # -- structure ------------------------------------------------------------

    def nest(self, lines: Sequence[str], depth: int, kind: PartKind, attribution: Attribution | None) -> None:
        if depth + 1 > MAX_DEPTH:
            self.depth_limit = True
            self.emit(kind, attribution, depth, lines)
            return
        self.walk(lines, depth + 1, kind, attribution)

    def quote_block(self, lines: Sequence[str], depth: int, attribution: Attribution | None) -> None:
        fullwidth = any(_fullwidth_prefix(line) for line in lines)
        self.markers[f"quote_prefix:{'ja' if fullwidth else 'neutral'}"] += 1
        if depth + 1 > MAX_DEPTH:
            self.depth_limit = True
            self.emit(PartKind.QUOTED, attribution, depth, lines)
            return
        self.walk([_strip_one(line) for line in lines], depth + 1, PartKind.QUOTED, attribution)

    def forward_at(self, lines: Sequence[str], index: int) -> tuple[Attribution | None, int] | None:
        locale = _forward_banner(lines[index])
        if locale is None:
            return None
        headers = _header_lines(lines, _skip_blank(lines, index + 1))
        locale = "ja" if headers.locale == "ja" else locale
        self.markers[f"forward_banner:{locale}"] += 1
        attribution = _header_attribution(headers, "forward_header", locale, self.tz)
        return attribution, _skip_blank(lines, headers.end, len(lines))

    def header_block_at(self, lines: Sequence[str], index: int) -> tuple[Attribution | None, int] | None:
        line = lines[index]
        rule = _UNDERSCORE_RULE_RE.fullmatch(line.strip()) is not None
        if not rule and (_HEADER_RE.match(line) is None or (index > 0 and not _blank(lines[index - 1]))):
            return None
        headers = _header_lines(lines, index + 1 if rule else index)
        fields = headers.fields
        if not ("from" in fields and "date" in fields and ("to" in fields or "subject" in fields)):
            return None
        self.markers[f"header_block:{headers.locale}"] += 1
        attribution = _header_attribution(headers, "header_block", headers.locale, self.tz)
        return attribution, _skip_blank(lines, headers.end, len(lines))

    def attribution_at(self, lines: Sequence[str], index: int) -> tuple[Attribution, int] | None:
        for width in (1, 2, 3):
            chunk = lines[index : index + width]
            if len(chunk) < width or any(_blank(item) or quote_depth(item) for item in chunk):
                return None
            found = match_attribution(" ".join(item.strip() for item in chunk), self.tz)
            if found is not None:
                following = _skip_blank(lines, index + width)
                if following < len(lines) and quote_depth(lines[following]) > 0:
                    self.markers[f"attribution:{found.locale}"] += 1
                    return found, following
                return None
            if width == 1 and not _wrap_candidate(lines[index]):
                return None
        return None

    def walk(self, lines: Sequence[str], depth: int, kind: PartKind, attribution: Attribution | None) -> None:
        own: list[str] = []
        claimed: Attribution | None = None  # attribution for quote blocks at this level
        index = 0
        while index < len(lines):
            if quote_depth(lines[index]) > 0:
                end = _quote_end(lines, index)
                self.emit(kind, attribution, depth, own)
                own = []
                self.quote_block(lines[index:end], depth, claimed)
                index = end
                continue
            nested = self.forward_at(lines, index)
            nested_kind = PartKind.FORWARDED
            if nested is None:
                nested, nested_kind = self.header_block_at(lines, index), PartKind.QUOTED
            if nested is not None:
                self.emit(kind, attribution, depth, own)
                self.nest(lines[nested[1] :], depth, nested_kind, nested[0])
                return
            found = self.attribution_at(lines, index)
            if found is not None:
                claimed, index = found
                continue
            own.append(lines[index])
            index += 1
        self.emit(kind, attribution, depth, own)


def _quote_end(lines: Sequence[str], start: int) -> int:
    """End (exclusive) of the quote block at ``start``; blank lines inside the block are kept."""
    end = index = start
    while index < len(lines):
        if quote_depth(lines[index]) > 0:
            index += 1
            end = index
        elif _blank(lines[index]):
            index += 1
        else:
            break
    return end


def segment_body(
    text: str,
    *,
    tz_offset_minutes: int | None = None,
    base_kind: PartKind = PartKind.AUTHORED,
    base_attribution: Attribution | None = None,
    base_depth: int = 0,
) -> SegmentResult:
    """Segment ``text`` (already decoded, newline-normalised).

    ``base_kind``/``base_attribution`` describe the text's own level: the
    message's authored text, or an attached message forwarded as a whole.
    """
    segmenter = _Segmenter(tz_offset_minutes)
    segmenter.walk(text.split("\n"), base_depth, base_kind, base_attribution)
    return segmenter.result()
