"""Header decoding for the mail collector.

- RFC 2047 encoded words are decoded here (adjacent words of one charset are
  joined before decoding so a multibyte sequence split across words survives).
  ISO-2022-JP falls back to ``iso2022_jp_ext`` and then ``cp932``; every
  fallback is counted as ``charset_fallback``.
- Address lists are split with :func:`email.utils.getaddresses` on the *raw*
  value, so a decoded display name containing a comma cannot split an entry.
- An invalid or missing ``Date`` is ``None`` (never the import time).
- Message-IDs lose surrounding whitespace and ``<>``; only the domain part is
  lowercased.
- ``X-Gmail-Labels`` is split on commas outside double quotes and outside
  encoded words; each label is decoded.

Nothing here logs header values.
"""

from __future__ import annotations

import base64
import binascii
import email.utils
import re
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass
from email.message import Message
from typing import Final

from ._charset import decode_bytes, decode_raw_header
from ._dates import parse_header_date
from ._text import clean_line

__all__ = [
    "Address",
    "MailHeaders",
    "decode_words",
    "normalize_message_id",
    "parse_address_list",
    "parse_headers",
    "parse_labels",
    "split_message_ids",
]

_ENCODED_WORD_RE: Final = re.compile(r"=\?(?P<charset>[^?\s*]+)(?:\*[^?\s]*)?\?(?P<enc>[QqBb])\?(?P<data>[^?\s]*)\?=")
_FOLD_RE: Final = re.compile(r"\r?\n(?=[ \t])")
_ANGLE_ID_RE: Final = re.compile(r"<([^<>]*)>")
_THRID_RE: Final = re.compile(r"\d{1,32}")
_MAX_REFERENCES: Final = 50
_MAX_ADDRESSES: Final = 100
_MAX_LABELS: Final = 64
_MAX_ID_CHARS: Final = 512


@dataclass(frozen=True)
class Address:
    """One parsed mailbox: a decoded display name and a lowercased address."""

    name: str
    address: str


@dataclass(frozen=True, kw_only=True)
class MailHeaders:
    """The header facts the collector uses; values are decoded and single-line."""

    from_: tuple[Address, ...]
    to: tuple[Address, ...]
    cc: tuple[Address, ...]
    reply_to: tuple[Address, ...]
    x_original_from: tuple[Address, ...]
    subject: str
    date: int | None
    tz_offset_minutes: int | None
    message_id: str | None
    in_reply_to: tuple[str, ...]
    references: tuple[str, ...]
    labels: tuple[str, ...]
    gm_thread_id: str | None
    auto_submitted: str | None
    precedence: str | None
    list_id: str | None
    authentication_results: tuple[str, ...]
    #: Unfolded, undecoded ``Date``/``From``/``To``/``Subject`` (fallback-uid input).
    raw_identity: tuple[str, str, str, str]

    @property
    def sender(self) -> Address | None:
        return next((item for item in self.from_ if item.address), None)


def _unfold(value: str) -> str:
    return _FOLD_RE.sub("", value).strip()


def _word_bytes(match: re.Match[str]) -> bytes | None:
    data = match.group("data")
    try:
        if match.group("enc") in "Bb":
            return base64.b64decode(data + "=" * (-len(data) % 4), validate=True)
        return binascii.a2b_qp(data.encode("ascii", errors="replace"), header=True)
    except (binascii.Error, ValueError):
        return None


def _flush(out: list[str], pending: list[tuple[str, bytes]], stats: Counter[str]) -> None:
    if pending:
        charset = pending[0][0]
        out.append(decode_bytes(b"".join(data for _cs, data in pending), charset, stats))
        pending.clear()


def decode_words(value: str, stats: Counter[str]) -> str:
    """Decode RFC 2047 encoded words; whitespace between adjacent words is dropped."""
    value = decode_raw_header(_unfold(value), stats)
    out: list[str] = []
    pending: list[tuple[str, bytes]] = []
    position = 0
    for match in _ENCODED_WORD_RE.finditer(value):
        between = value[position : match.start()]
        adjacent = bool(pending) and not between.strip()
        data = _word_bytes(match)
        position = match.end()
        if data is None:
            stats["bad_encoded_word"] += 1
            _flush(out, pending, stats)
            out.append(between + match.group(0))
            continue
        charset = match.group("charset").lower()
        if not adjacent or pending[0][0] != charset:
            _flush(out, pending, stats)
            if not adjacent:
                out.append(between)
        pending.append((charset, data))
    _flush(out, pending, stats)
    out.append(value[position:])
    return "".join(out)


def _split_ids(value: str) -> list[str]:
    found = _ANGLE_ID_RE.findall(value)
    if found:
        return found
    bare = value.strip()
    return [bare] if bare and not any(char.isspace() for char in bare) else []


def normalize_message_id(value: str | None) -> str | None:
    """Strip whitespace and ``<>``; lowercase only the domain part. Empty → ``None``."""
    if not value:
        return None
    ids = _split_ids(value)
    if not ids:
        return None
    ident = "".join(ids[0].split())
    if not ident or len(ident) > _MAX_ID_CHARS:
        return None
    local, sep, domain = ident.rpartition("@")
    return f"{local}@{domain.lower()}" if sep and local else ident


def split_message_ids(value: str | None) -> tuple[str, ...]:
    """Every ``<id>`` in ``value`` normalised, first and last kept when there are many."""
    if not value:
        return ()
    ids = [norm for raw in _split_ids(value) if (norm := normalize_message_id(f"<{raw}>")) is not None]
    if len(ids) > _MAX_REFERENCES:
        ids = [ids[0], *ids[-(_MAX_REFERENCES - 1) :]]
    return tuple(ids)


def parse_address_list(values: Iterable[str], stats: Counter[str]) -> tuple[Address, ...]:
    """Split raw address headers, then decode each display name."""
    raw = [decode_raw_header(_unfold(value), stats) for value in values]
    result: list[Address] = []
    for name, addr in email.utils.getaddresses(raw):
        address = "".join(addr.split()).lower()
        if "@" not in address:
            address = ""
        display = clean_line(decode_words(name, stats))
        if address or display:
            result.append(Address(display, address))
        if len(result) >= _MAX_ADDRESSES:
            stats["address_limit"] += 1
            break
    return tuple(result)


def _label_tokens(value: str) -> list[str]:
    tokens: list[str] = []
    current: list[str] = []
    quoted = False
    i = 0
    while i < len(value):
        char = value[i]
        word = _ENCODED_WORD_RE.match(value, i) if char == "=" else None
        if word is not None:
            current.append(word.group(0))
            i = word.end()
            continue
        if char == '"':
            quoted = not quoted
        elif char == "," and not quoted:
            tokens.append("".join(current))
            current = []
        else:
            current.append(char)
        i += 1
    tokens.append("".join(current))
    return tokens


def parse_labels(value: str | None, stats: Counter[str]) -> tuple[str, ...]:
    """``X-Gmail-Labels`` → decoded labels (quoted commas and encoded words respected)."""
    if not value:
        return ()
    labels: list[str] = []
    for token in _label_tokens(decode_raw_header(_unfold(value), stats)):
        label = clean_line(decode_words(token.strip(), stats), max_chars=128)
        if label and label not in labels:
            labels.append(label)
        if len(labels) >= _MAX_LABELS:
            break
    return tuple(labels)


def _first(values: dict[str, list[str]], name: str) -> str | None:
    found = values.get(name)
    return _unfold(found[0]) if found else None


def _collect(msg: Message) -> dict[str, list[str]]:
    values: dict[str, list[str]] = {}
    for name, value in msg.raw_items():
        values.setdefault(name.strip().lower(), []).append(str(value))
    return values


def _thread_id(value: str | None) -> str | None:
    if value is None:
        return None
    value = value.strip()
    return value if _THRID_RE.fullmatch(value) else None


def _lower_token(value: str | None) -> str | None:
    return value.strip().lower() if value and value.strip() else None


def parse_headers(msg: Message, stats: Counter[str]) -> MailHeaders:
    """Decode the headers of ``msg`` (raw values from :meth:`Message.raw_items`)."""
    values = _collect(msg)
    date, offset = parse_header_date(decode_raw_header(_first(values, "date") or "", stats))
    subject = _first(values, "subject")
    return MailHeaders(
        from_=parse_address_list(values.get("from", []), stats),
        to=parse_address_list(values.get("to", []), stats),
        cc=parse_address_list(values.get("cc", []), stats),
        reply_to=parse_address_list(values.get("reply-to", []), stats),
        x_original_from=parse_address_list(values.get("x-original-from", []), stats),
        subject=clean_line(decode_words(subject, stats), max_chars=512) if subject else "",
        date=date,
        tz_offset_minutes=offset,
        message_id=normalize_message_id(_first(values, "message-id")),
        in_reply_to=split_message_ids(_first(values, "in-reply-to")),
        references=split_message_ids(_first(values, "references")),
        labels=parse_labels(_first(values, "x-gmail-labels"), stats),
        gm_thread_id=_thread_id(_first(values, "x-gm-thrid")),
        auto_submitted=_lower_token(_first(values, "auto-submitted")),
        precedence=_lower_token(_first(values, "precedence")),
        list_id=_first(values, "list-id"),
        authentication_results=tuple(_unfold(value) for value in values.get("authentication-results", [])),
        raw_identity=(
            _first(values, "date") or "",
            _first(values, "from") or "",
            _first(values, "to") or "",
            subject or "",
        ),
    )
