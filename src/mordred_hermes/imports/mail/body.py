"""Body text extraction: text/plain preferred, HTML converted without a browser.

- ``text/plain`` is preferred; an HTML-only message is converted by
  :class:`HtmlToText` (an :class:`html.parser.HTMLParser` subclass): script,
  style, head and title are dropped; ``<blockquote>`` and Outlook reply blocks
  (``div#divRplyFwdMsg`` and the border-top header div, after which Outlook
  puts the original message) become ``> `` prefixed lines; ``<br>``/``<p>``/
  ``<div>`` and other blocks become newlines. A ``div.gmail_quote`` is a
  container: its attribution or forward banner stays unprefixed so the
  segmenter can attribute it, and its ``blockquote`` supplies the prefix.
- Attachments are recorded by kind only (``image``, ``document``, ``rfc822``,
  ``other``), never by file name.
- A ``message/rfc822`` attachment becomes a forwarded message (attached
  messages nested up to depth 2; deeper ones are counted as attachments only).
- Body text is bounded before segmentation; part texts are capped later.
"""

from __future__ import annotations

import re
from collections import Counter
from collections.abc import Iterator
from dataclasses import dataclass
from email.message import Message
from html.parser import HTMLParser
from typing import Final

from ._charset import decode_bytes
from ._text import cap_utf8, clean_text
from .headers import MailHeaders, parse_headers

__all__ = ["MAX_BODY_BYTES", "MAX_RFC822_DEPTH", "BodyResult", "ForwardedMail", "HtmlToText", "extract_body"]

MAX_RFC822_DEPTH: Final = 2
#: Upper bound on body text handed to the segmenter (each part is capped at 64 KiB later).
MAX_BODY_BYTES: Final = 4 * 1024 * 1024
_SKIP_TAGS: Final = frozenset({"script", "style", "head", "title", "template", "noscript"})
_VOID_TAGS: Final = frozenset({"br", "hr", "img", "meta", "link", "input", "wbr", "area", "base", "col", "source"})
_BLOCK_TAGS: Final = frozenset(
    {
        *("p", "div", "li", "tr", "ul", "ol", "table", "pre", "section", "article", "header", "footer"),
        *("h1", "h2", "h3", "h4", "h5", "h6", "center", "blockquote", "dl", "dt", "dd", "td", "th", "hr"),
    }
)
_OUTLOOK_BORDER_RE: Final = re.compile(r"border-top\s*:\s*solid", re.IGNORECASE)
_HEADER_BLOCK: Final = -1  # stack marker: an Outlook reply header block (no depth change)
_DOCUMENT_TYPES: Final = frozenset(
    {
        "application/pdf",
        "application/msword",
        "application/rtf",
        "text/csv",
        "text/plain",
        "text/html",
        "text/calendar",
    }
)


@dataclass(frozen=True, kw_only=True)
class ForwardedMail:
    """An attached message: its claimed sender, date and body text."""

    headers: MailHeaders
    text: str
    depth: int


@dataclass(frozen=True, kw_only=True)
class BodyResult:
    text: str
    html_only: bool
    truncated: bool
    attachments: tuple[str, ...]  # kinds only
    forwarded: tuple[ForwardedMail, ...]


class HtmlToText(HTMLParser):
    """Convert mail HTML to plain lines with ``> `` quote prefixes."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.lines: list[str] = []
        self._buffer: list[str] = []
        self._stack: list[tuple[str, int, bool]] = []  # (tag, quote delta, skipped)
        self._depth = 0
        self._rest_quote = 0
        self._skip = 0
        self._pre = 0

    def _flush(self, *, blank_ok: bool = False) -> None:
        text = "".join(self._buffer)
        self._buffer = []
        text = text if self._pre else " ".join(text.split())
        depth = self._depth + self._rest_quote
        prefix = "> " * depth
        for line in text.split("\n") if self._pre else [text]:
            if line.strip():
                self.lines.append(f"{prefix}{line}" if depth else line)
            elif (blank_ok or self._pre) and self.lines and self.lines[-1].strip("> "):
                self.lines.append(prefix.rstrip())

    def _quote_delta(self, tag: str, attrs: dict[str, str]) -> int:
        if tag == "blockquote":
            return 1
        if tag == "div" and (
            attrs.get("id", "").lower() == "divrplyfwdmsg" or _OUTLOOK_BORDER_RE.search(attrs.get("style", ""))
        ):
            self._rest_quote += 1  # Outlook puts the original below this block, unwrapped
            return _HEADER_BLOCK
        return 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = {key.lower(): value or "" for key, value in attrs}
        if tag in _BLOCK_TAGS or tag == "br":
            self._flush(blank_ok=tag in {"br", "p"})
        if tag in _VOID_TAGS:
            return
        skipped = tag in _SKIP_TAGS
        delta = 0 if skipped else self._quote_delta(tag, values)
        self._skip += skipped
        self._depth += max(delta, 0)
        self._pre += tag == "pre"
        self._stack.append((tag, delta, skipped))

    def handle_endtag(self, tag: str) -> None:
        if tag in _VOID_TAGS or all(item[0] != tag for item in self._stack):
            return
        if tag in _BLOCK_TAGS:
            self._flush()
        while self._stack:
            name, delta, skipped = self._stack.pop()
            if delta == _HEADER_BLOCK:
                self._flush()
                self._buffer.append("")  # the header block ends with a blank line
                self._flush(blank_ok=True)
                delta = 0
            self._depth -= delta
            self._skip -= skipped
            self._pre -= name == "pre"
            if name == tag:
                break

    def handle_data(self, data: str) -> None:
        if not self._skip:
            self._buffer.append(data)

    def text(self) -> str:
        self.close()
        self._flush()
        return "\n".join(self.lines)


def html_to_text(html: str) -> str:
    parser = HtmlToText()
    parser.feed(html)
    return parser.text()


def _decoded(part: Message, stats: Counter[str]) -> str:
    payload = part.get_payload(decode=True)
    if not isinstance(payload, bytes):
        return ""
    return decode_bytes(payload, part.get_content_charset(), stats)


def _contains(part: Message, target: Message) -> bool:
    return any(item is target for item in part.walk())


def _attachment_leaves(part: Message, body: Message | None) -> Iterator[Message]:
    if part.get_content_maintype() == "multipart":
        if body is not None and part.get_content_type() == "multipart/alternative" and _contains(part, body):
            return
        payload = part.get_payload()
        for sub in payload if isinstance(payload, list) else []:
            if isinstance(sub, Message):
                yield from _attachment_leaves(sub, body)
        return
    if part is not body:
        yield part


def _kind(part: Message) -> str:
    ctype = part.get_content_type()
    if ctype == "message/rfc822":
        return "rfc822"
    if part.get_content_maintype() == "image":
        return "image"
    if ctype in _DOCUMENT_TYPES or ctype.startswith(("application/vnd.", "application/x-iwork")):
        return "document"
    return "other"


def _select_body(msg: Message) -> Message | None:
    get_body = getattr(msg, "get_body", None)
    if get_body is not None:
        found = get_body(preferencelist=("plain", "html"))
        return found if isinstance(found, Message) else None
    return msg if msg.get_content_maintype() == "text" else None


def _forwarded(part: Message, depth: int, stats: Counter[str]) -> list[ForwardedMail]:
    payload = part.get_payload()
    inner = payload[0] if isinstance(payload, list) and payload else None
    if not isinstance(inner, Message):
        return []
    result = extract_body(inner, stats, depth=depth)
    mail = ForwardedMail(headers=parse_headers(inner, stats), text=result.text, depth=depth)
    return [mail, *result.forwarded]


def extract_body(msg: Message, stats: Counter[str], *, depth: int = 0) -> BodyResult:
    """Body text, attachment kinds and attached messages of ``msg``."""
    body = _select_body(msg)
    html_only = body is not None and body.get_content_type() == "text/html"
    raw = "" if body is None else _decoded(body, stats)
    text = clean_text(html_to_text(raw) if html_only else raw)
    text, truncated = cap_utf8(text, MAX_BODY_BYTES)
    kinds: list[str] = []
    forwarded: list[ForwardedMail] = []
    for leaf in _attachment_leaves(msg, body):
        kind = _kind(leaf)
        kinds.append(kind)
        if kind == "rfc822" and depth < MAX_RFC822_DEPTH:
            forwarded.extend(_forwarded(leaf, depth + 1, stats))
    if depth == 0:  # walk() already descends into attached messages
        for item in msg.walk():
            for defect in item.defects:
                stats[f"defect:{type(defect).__name__}"] += 1
    return BodyResult(
        text=text, html_only=html_only, truncated=truncated, attachments=tuple(kinds), forwarded=tuple(forwarded)
    )
