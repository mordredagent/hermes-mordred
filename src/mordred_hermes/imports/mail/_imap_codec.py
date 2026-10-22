"""Pure IMAP response parsing for the mail collector (no I/O, no logging).

- Modified UTF-7 (RFC 3501 5.1.3) for mailbox names and Gmail custom labels.
- A small tokenizer for parenthesized IMAP data (atoms, quoted strings,
  literals, ``NIL``) over the shapes :mod:`imaplib` returns: a FETCH or LIST
  response is a run of ``(line ending in {n}, literal)`` tuples closed by a
  trailing ``bytes`` line.
- :func:`fetch_records` turns a ``UID FETCH`` result into ``{item: value}``
  dicts; :func:`list_entries` parses ``LIST``; :func:`search_uids` parses
  ``UID SEARCH``; :func:`gmail_labels` maps ``X-GM-LABELS``.
- :class:`DrainedLiteral` stands in for a literal the client discarded unread
  (over the size limit, see :mod:`.imap`); it parses to a :class:`Literal`
  with ``drained=True`` and never to message bytes.
- :class:`SystemLabel` marks a Gmail system label recognised on the wire
  BEFORE any decoding; a custom label is a plain ``str`` even when its decoded
  text reads ``\\Sent``, so it can never pass for a system label.

Every failure is :class:`ImapProtocolError` (code ``imap_protocol``); no
exception carries response text.
"""

from __future__ import annotations

import base64
import binascii
import re
from collections.abc import Iterable, Iterator, Sequence
from dataclasses import dataclass
from typing import Final

__all__ = [
    "GMAIL_SYSTEM_LABELS",
    "DrainedLiteral",
    "ImapProtocolError",
    "ListEntry",
    "Literal",
    "SystemLabel",
    "decode_mutf7",
    "encode_mutf7",
    "fetch_records",
    "gmail_labels",
    "is_drained",
    "list_entries",
    "quote_mailbox",
    "search_uids",
    "system_label",
    "tokenize",
]

_LITERAL_TAIL_RE: Final = re.compile(rb"\{(\d{1,10})\}\Z")
_MAX_DEPTH: Final = 16
#: Custom labels kept per message (they never classify; system labels are always all inspected).
_MAX_CUSTOM_LABELS: Final = 64
_UNSAFE_NAME_CHARS: Final = frozenset(chr(code) for code in (*range(0x20), 0x7F))
_MAX_SEARCH_UIDS: Final = 1_000_000
_SPECIALS: Final = frozenset(b" ()")
#: Gmail system labels (``X-GM-LABELS``) in their canonical spelling, keyed by the case-folded form.
GMAIL_SYSTEM_LABELS: Final = {
    label.casefold(): label
    for label in ("\\Inbox", "\\Sent", "\\Draft", "\\Spam", "\\Trash", "\\Important", "\\Starred", "\\AllMail")
}


class ImapProtocolError(Exception):
    """The server's response did not have the expected shape (content-free)."""

    def __init__(self, code: str = "imap_protocol") -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True, slots=True)
class Literal:
    """A literal (``{n}`` followed by n bytes) inside a response; ``drained``: discarded unread."""

    data: bytes
    drained: bool = False

    def __repr__(self) -> str:
        return f"Literal(bytes={len(self.data)}, drained={self.drained})"


class DrainedLiteral(bytes):
    """What the guarded client returns for a literal it read and discarded (``size`` bytes, never kept)."""

    size: int

    def __new__(cls, size: int) -> DrainedLiteral:
        obj = super().__new__(cls, b"")
        obj.size = size
        return obj


def is_drained(value: Value) -> bool:
    """True for the parsed form of a :class:`DrainedLiteral`."""
    return isinstance(value, Literal) and value.drained


class SystemLabel(str):
    """A Gmail system label (``\\Sent``, ``\\Draft``, ...) in canonical spelling.

    Only :func:`system_label` creates one, from a label whose wire form IS a known
    system label; :func:`gmail_labels` never makes one out of a decoded custom label.
    """

    __slots__ = ()


def system_label(wire: str) -> SystemLabel | None:
    """The canonical :class:`SystemLabel` for an exact wire form (case-insensitive, no trimming), else ``None``."""
    canonical = GMAIL_SYSTEM_LABELS.get(wire.casefold())
    return None if canonical is None else SystemLabel(canonical)


# --- modified UTF-7 -------------------------------------------------------------------------------


def decode_mutf7(value: str) -> str:
    """Decode an IMAP modified UTF-7 name; ``&-`` is ``&``. Malformed input raises :class:`ImapProtocolError`."""
    out: list[str] = []
    i = 0
    while i < len(value):
        char = value[i]
        if char != "&":
            if not " " <= char <= "~":
                raise ImapProtocolError()
            out.append(char)
            i += 1
            continue
        end = value.find("-", i + 1)
        if end == -1:
            raise ImapProtocolError()
        chunk = value[i + 1 : end]
        if not chunk:
            out.append("&")
        else:
            data = chunk.replace(",", "/")
            try:
                raw = base64.b64decode(data + "=" * (-len(data) % 4), validate=True)
                out.append(raw.decode("utf-16-be"))
            except (binascii.Error, ValueError):
                raise ImapProtocolError() from None
        i = end + 1
    return "".join(out)


def encode_mutf7(value: str) -> str:
    """Encode a name as IMAP modified UTF-7."""
    out: list[str] = []
    pending: list[str] = []

    def flush() -> None:
        if pending:
            raw = "".join(pending).encode("utf-16-be")
            out.append("&" + base64.b64encode(raw).decode("ascii").rstrip("=").replace("/", ",") + "-")
            pending.clear()

    for char in value:
        if " " <= char <= "~":
            flush()
            out.append("&-" if char == "&" else char)
        else:
            pending.append(char)
    flush()
    return "".join(out)


def quote_mailbox(name: str) -> str:
    """A quoted IMAP string for an (already modified-UTF-7) mailbox name."""
    if not safe_mailbox_name(name):
        raise ImapProtocolError()
    return '"' + name.replace("\\", "\\\\").replace('"', '\\"') + '"'


# --- tokenizer ------------------------------------------------------------------------------------


Token = bytes | Literal | None  # an atom or quoted string, a literal, or the ``(``/``)`` markers below
_OPEN: Final = b"\x00("
_CLOSE: Final = b"\x00)"


def _atom_end(text: bytes, start: int) -> int:
    i = start
    while i < len(text) and text[i] not in _SPECIALS:
        if text[i] == ord("["):
            close = text.find(b"]", i)
            if close == -1:
                raise ImapProtocolError()
            i = close + 1
            continue
        i += 1
    return i


def _quoted(text: bytes, start: int) -> tuple[bytes, int]:
    out = bytearray()
    i = start + 1
    while i < len(text):
        byte = text[i]
        if byte == ord("\\") and i + 1 < len(text):
            out.append(text[i + 1])
            i += 2
            continue
        if byte == ord('"'):
            return bytes(out), i + 1
        out.append(byte)
        i += 1
    raise ImapProtocolError()


def _text_tokens(text: bytes) -> Iterator[Token]:
    i = 0
    while i < len(text):
        byte = text[i]
        if byte == ord(" "):
            i += 1
        elif byte == ord("("):
            yield _OPEN
            i += 1
        elif byte == ord(")"):
            yield _CLOSE
            i += 1
        elif byte == ord('"'):
            value, i = _quoted(text, i)
            yield b'"' + value
        else:
            end = _atom_end(text, i)
            atom = text[i:end]
            yield None if atom.upper() == b"NIL" else b"=" + atom
            i = end


def tokenize(record: Sequence[bytes | tuple[bytes, bytes]]) -> list[Token]:
    """Tokens of one response record; quoted strings are prefixed ``"`` and atoms ``=`` internally."""
    tokens: list[Token] = []
    for element in record:
        if isinstance(element, tuple):
            head, literal = element
            match = _LITERAL_TAIL_RE.search(head)
            drained = isinstance(literal, DrainedLiteral)
            size = literal.size if isinstance(literal, DrainedLiteral) else len(literal)
            if match is None or int(match.group(1)) != size:
                raise ImapProtocolError()
            tokens.extend(_text_tokens(head[: match.start()]))
            tokens.append(Literal(b"", drained=True) if drained else Literal(bytes(literal)))
        else:
            tokens.extend(_text_tokens(element))
    return tokens


Value = bytes | Literal | None | list["Value"]


def _parse(tokens: list[Token], start: int, depth: int) -> tuple[list[Value], int]:
    if depth > _MAX_DEPTH:
        raise ImapProtocolError()
    items: list[Value] = []
    i = start
    while i < len(tokens):
        token = tokens[i]
        if token == _OPEN:
            nested, i = _parse(tokens, i + 1, depth + 1)
            items.append(nested)
            continue
        if token == _CLOSE:
            if depth == 0:
                raise ImapProtocolError()
            return items, i + 1
        items.append(token[1:] if isinstance(token, bytes) else token)
        i += 1
    if depth != 0:
        raise ImapProtocolError()
    return items, i


def parse_values(record: Sequence[bytes | tuple[bytes, bytes]]) -> list[Value]:
    """One record as nested Python values (``bytes`` for atoms and strings, :class:`Literal`, ``None``)."""
    return _parse(tokenize(record), 0, 0)[0]


def records(data: Iterable[object]) -> Iterator[list[bytes | tuple[bytes, bytes]]]:
    """Group imaplib's untagged data into records: literal tuples closed by a ``bytes`` line."""
    current: list[bytes | tuple[bytes, bytes]] = []
    for element in data:
        if element is None:
            continue
        if isinstance(element, tuple):
            if len(element) != 2 or not all(isinstance(part, bytes) for part in element):
                raise ImapProtocolError()
            current.append((element[0], element[1]))
            continue
        if not isinstance(element, bytes):
            raise ImapProtocolError()
        current.append(element)
        yield current
        current = []
    if current:
        raise ImapProtocolError()  # a literal without its closing line


# --- FETCH, LIST, SEARCH --------------------------------------------------------------------------


def _text(value: Value) -> str:
    if isinstance(value, Literal):
        if value.drained:
            raise ImapProtocolError()
        value = value.data
    if not isinstance(value, bytes):
        raise ImapProtocolError()
    try:
        return value.decode("ascii")
    except UnicodeDecodeError:
        raise ImapProtocolError() from None


def fetch_records(data: Iterable[object]) -> list[dict[str, Value]]:
    """``UID FETCH`` data → one ``{ITEM: value}`` dict per message (item names upper-cased)."""
    result: list[dict[str, Value]] = []
    for record in records(data):
        values = parse_values(record)
        if len(values) != 2 or not isinstance(values[1], list) or len(values[1]) % 2:
            raise ImapProtocolError()
        items = values[1]
        result.append({_text(items[i]).upper(): items[i + 1] for i in range(0, len(items), 2)})
    return result


def number(value: Value) -> int:
    """A non-negative decimal atom."""
    text = _text(value)
    if not text.isdigit() or len(text) > 20:
        raise ImapProtocolError()
    return int(text)


def body_bytes(value: Value) -> bytes:
    """The ``BODY[]`` value: a literal (or, rarely, a quoted string); a drained literal is an error."""
    if isinstance(value, Literal):
        if value.drained:
            raise ImapProtocolError()
        return value.data
    if isinstance(value, bytes):
        return value
    raise ImapProtocolError()


def gmail_labels(value: Value) -> tuple[str, ...]:
    """``X-GM-LABELS`` → every system label (:class:`SystemLabel`), then decoded custom labels.

    A label is a system label only when its wire form (atom or quoted string, before
    any modified UTF-7 decoding and without trimming) is one of
    :data:`GMAIL_SYSTEM_LABELS`; ``" \\Sent "`` or ``&AFw-Sent`` stay custom labels.
    Every item is inspected, so a ``\\Draft`` is found at any position; at most
    :data:`_MAX_CUSTOM_LABELS` custom labels are kept (they never classify). A custom
    label that is not valid modified UTF-7 is kept in its wire form.
    """
    if not isinstance(value, list):
        raise ImapProtocolError()
    system: list[SystemLabel] = []
    custom: list[str] = []
    for item in value:
        if item is None:
            continue
        wire = _text(item)
        known = system_label(wire)
        if known is not None:
            if known not in system:
                system.append(known)
            continue
        if len(custom) >= _MAX_CUSTOM_LABELS:
            continue
        try:
            label = decode_mutf7(wire)
        except ImapProtocolError:
            label = wire
        if label and label not in custom:
            custom.append(label)
    return (*system, *custom)


@dataclass(frozen=True, slots=True)
class ListEntry:
    """One ``LIST`` row: attributes (case-folded), and the mailbox name as sent (modified UTF-7)."""

    attributes: frozenset[str]
    name: str

    @property
    def display(self) -> str:
        """The decoded name for the operator's terminal (the wire name when it is not valid modified UTF-7)."""
        try:
            return decode_mutf7(self.name)
        except ImapProtocolError:
            return self.name

    @property
    def selectable(self) -> bool:
        return not ({"\\noselect", "\\nonexistent"} & self.attributes)


def safe_mailbox_name(name: str) -> bool:
    """A mailbox name that can be sent as a quoted string: printable ASCII, no CR, LF or NUL."""
    return bool(name) and name.isascii() and not (_UNSAFE_NAME_CHARS & set(name))


def list_entries(data: Iterable[object]) -> list[ListEntry]:
    """``LIST`` data → entries; ``NIL``/``None`` rows and names with control characters are skipped."""
    entries: list[ListEntry] = []
    for record in records(data):
        values = parse_values(record)
        if len(values) != 3 or not isinstance(values[0], list):
            raise ImapProtocolError()
        attributes = frozenset(_text(item).casefold() for item in values[0] if item is not None)
        name = _text(values[2])
        if safe_mailbox_name(name):  # a name that could frame a command is never offered or sealed
            entries.append(ListEntry(attributes, name))
    return entries


def search_uids(data: Iterable[object]) -> list[int]:
    """``UID SEARCH`` data → the UIDs (every untagged SEARCH line, de-duplicated, ascending)."""
    found: set[int] = set()
    for element in data:
        if element is None:
            continue
        if not isinstance(element, bytes):
            raise ImapProtocolError()
        for token in element.split():
            if not token.isdigit() or len(token) > 10:
                raise ImapProtocolError()
            found.add(int(token))
            if len(found) > _MAX_SEARCH_UIDS:
                raise ImapProtocolError()
    return sorted(found)
