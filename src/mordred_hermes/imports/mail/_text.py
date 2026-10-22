"""Small text helpers shared by the mail collector (no content is logged)."""

from __future__ import annotations

import re
import unicodedata
from typing import Final

#: Authored, quoted and forwarded part texts are capped at 64 KiB (UTF-8).
MAX_PART_BYTES: Final = 64 * 1024
_MAX_LINE_CHARS: Final = 256
# C0 controls except tab/newline, DEL and C1 controls.
_TEXT_CONTROL_RE: Final = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")
_WS_RE: Final = re.compile(r"\s+")


def clean_text(text: str) -> str:
    """Normalise newlines and replace control characters (ESC included) with U+FFFD."""
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    return _TEXT_CONTROL_RE.sub("�", text)


def clean_line(value: str | None, *, max_chars: int = _MAX_LINE_CHARS) -> str:
    """One bounded line: control/format characters dropped, whitespace collapsed."""
    if not value:
        return ""
    kept = [
        " " if unicodedata.category(char) in {"Cc", "Zl", "Zp"} else char
        for char in value
        if unicodedata.category(char) not in {"Cf", "Cs"}
    ]
    return " ".join("".join(kept).split())[:max_chars]


def cap_utf8(text: str, limit: int = MAX_PART_BYTES) -> tuple[str, bool]:
    """Cut ``text`` to at most ``limit`` UTF-8 bytes on a character boundary."""
    data = text.encode("utf-8")
    if len(data) <= limit:
        return text, False
    return data[:limit].decode("utf-8", errors="ignore"), True


def link_key(text: str) -> str:
    """Comparison form for quote linking: NFKC with all whitespace removed.

    Clients re-wrap quoted lines (a Japanese sentence split over two lines gains
    no space), so whitespace is ignored entirely; every other character counts.
    """
    return _WS_RE.sub("", unicodedata.normalize("NFKC", text))


def strip_blank_edges(lines: list[str]) -> list[str]:
    start, end = 0, len(lines)
    while start < end and not lines[start].strip():
        start += 1
    while end > start and not lines[end - 1].strip():
        end -= 1
    return lines[start:end]
