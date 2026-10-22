"""Read-only mail sources: streaming mbox splitter and ``.eml`` readers.

Security contract:

- Sources are opened read-only (``O_RDONLY``, never ``rb+``); a missing path is
  an error, never created. :mod:`mailbox` is deliberately not used because
  ``mailbox.mbox`` opens ``rb+`` and creates missing files.
- Only regular files are read: the path is checked with :func:`os.lstat` before
  opening (a symlink, FIFO, socket or device is refused) and the opened
  descriptor is checked again with :func:`os.fstat`.
- The mbox is streamed line by line; a message larger than
  :data:`MAX_MESSAGE_BYTES` is dropped while reading and counted as
  ``skipped_oversize``. No temporary files are written.
- Errors carry content-free codes only.
"""

from __future__ import annotations

import io
import os
import re
import stat
from collections import Counter
from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import IO, Final

__all__ = [
    "MAX_MESSAGE_BYTES",
    "EmlBytes",
    "EmlSource",
    "MailSource",
    "MboxBytes",
    "MboxSource",
    "RawMessage",
    "SourceError",
    "iter_raw",
    "split_mbox",
]

MAX_MESSAGE_BYTES: Final = 25 * 1024 * 1024
_CHUNK: Final = 1024 * 1024
# A full ``From_`` line: ``From <sender> <asctime date>`` (Takeout writes this form).
_FROM_LINE_RE: Final = re.compile(
    rb"From \S*\s+(?:[A-Z][a-z]{2}\s+){1,2}\d{1,2}\s+\d{1,2}:\d{2}(?::\d{2})?(?:\s+[+-]\d{4})?\s+\d{4}\s*"
)
_ESCAPED_FROM_RE: Final = re.compile(rb">+From ")


class SourceError(Exception):
    """A source could not be read. ``code`` is stable and content-free."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True, slots=True)
class RawMessage:
    """One message's raw bytes and its position within its source."""

    data: bytes
    origin_index: int


@dataclass(frozen=True)
class MboxSource:
    path: Path


@dataclass(frozen=True)
class EmlSource:
    """A single ``.eml`` file or a directory of ``.eml`` files (sorted by name, not recursive)."""

    path: Path


@dataclass(frozen=True)
class MboxBytes:
    """An in-memory mbox (for example the provenance evaluation generator's output)."""

    data: bytes


@dataclass(frozen=True)
class EmlBytes:
    """In-memory ``.eml`` messages."""

    messages: Sequence[bytes]


MailSource = MboxSource | EmlSource | MboxBytes | EmlBytes

_OPEN_FLAGS: Final = (
    os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0)
)


def _open_regular(path: Path) -> IO[bytes]:
    try:
        before = os.lstat(path)
    except FileNotFoundError:
        raise SourceError("not_found") from None
    except OSError:
        raise SourceError("read_error") from None
    if not stat.S_ISREG(before.st_mode):
        raise SourceError("not_regular_file")
    try:
        fd = os.open(path, _OPEN_FLAGS)
    except OSError:
        raise SourceError("read_error") from None
    try:
        after = os.fstat(fd)
        if not stat.S_ISREG(after.st_mode) or (after.st_dev, after.st_ino) != (before.st_dev, before.st_ino):
            raise SourceError("not_regular_file")
        return os.fdopen(fd, "rb")
    except BaseException:
        os.close(fd)
        raise


def _is_blank(line: bytes) -> bool:
    return line in {b"\n", b"\r\n", b"\r"}


def _is_separator(line: bytes, *, previous_blank: bool) -> bool:
    if not line.startswith(b"From "):
        return False
    return previous_blank or _FROM_LINE_RE.fullmatch(line.rstrip(b"\r\n")) is not None


def _unescape(line: bytes) -> bytes:
    return line[1:] if _ESCAPED_FROM_RE.match(line) else line


class _MboxSplitter:
    """Line-at-a-time ``From_`` splitter with an oversize guard."""

    def __init__(self, stats: Counter[str]) -> None:
        self.stats = stats
        self.lines: list[bytes] = []
        self.size = 0
        self.oversize = False
        self.started = False
        self.index = 0

    def feed(self, line: bytes) -> None:
        if self.oversize:
            return
        self.size += len(line)
        if self.size > MAX_MESSAGE_BYTES:
            self.oversize = True
            self.lines = []
            return
        self.lines.append(line)

    def finish(self) -> RawMessage | None:
        lines, oversize, started = self.lines, self.oversize, self.started
        self.lines, self.size, self.oversize, self.started = [], 0, False, True
        if oversize:
            self.stats["skipped_oversize"] += 1
            self.index += 1
            return None
        if lines and _is_blank(lines[-1]):
            lines.pop()  # the blank line that precedes the next From_ line
        if not started:
            if any(line.strip() for line in lines):
                self.stats["skipped_no_separator"] += 1
            return None
        message = RawMessage(b"".join(lines), self.index)
        self.index += 1
        return message


def _read_lines(handle: IO[bytes]) -> Iterator[tuple[bytes, bool]]:
    """Yield ``(chunk, at_line_start)``; very long lines arrive in bounded chunks."""
    at_start = True
    while chunk := handle.readline(_CHUNK):
        yield chunk, at_start
        at_start = chunk.endswith(b"\n")


def split_mbox(handle: IO[bytes], stats: Counter[str]) -> Iterator[RawMessage]:
    """Split an mbox stream; ``>From `` lines are unescaped (mboxo and mboxrd)."""
    splitter = _MboxSplitter(stats)
    previous_blank = True
    for chunk, at_start in _read_lines(handle):
        if at_start and _is_separator(chunk, previous_blank=previous_blank):
            message = splitter.finish()
            if message is not None:
                yield message
            previous_blank = False
            continue
        splitter.feed(_unescape(chunk) if at_start else chunk)
        previous_blank = at_start and _is_blank(chunk)
    message = splitter.finish()
    if message is not None:
        yield message


def _read_eml(path: Path, stats: Counter[str], index: int) -> RawMessage | None:
    with _open_regular(path) as handle:
        data = handle.read(MAX_MESSAGE_BYTES + 1)
    if len(data) > MAX_MESSAGE_BYTES:
        stats["skipped_oversize"] += 1
        return None
    return RawMessage(data, index)


def _eml_paths(path: Path, stats: Counter[str]) -> list[Path]:
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        raise SourceError("not_found") from None
    except OSError:
        raise SourceError("read_error") from None
    if stat.S_ISREG(info.st_mode):
        return [path]
    if not stat.S_ISDIR(info.st_mode):
        raise SourceError("not_regular_file")
    paths: list[Path] = []
    try:
        entries = sorted(os.scandir(path), key=lambda entry: entry.name)
    except OSError:
        raise SourceError("read_error") from None
    for entry in entries:
        if not entry.name.lower().endswith(".eml"):
            continue
        if entry.is_file(follow_symlinks=False):
            paths.append(Path(entry.path))
        else:
            stats["skipped_not_regular"] += 1
    return paths


def _iter_eml(path: Path, stats: Counter[str]) -> Iterator[RawMessage]:
    for index, item in enumerate(_eml_paths(path, stats)):
        try:
            message = _read_eml(item, stats, index)
        except SourceError as exc:
            stats[f"skipped_{exc.code}"] += 1
            continue
        if message is not None:
            yield message


def _iter_eml_bytes(messages: Sequence[bytes], stats: Counter[str]) -> Iterator[RawMessage]:
    for index, data in enumerate(messages):
        if len(data) > MAX_MESSAGE_BYTES:
            stats["skipped_oversize"] += 1
            continue
        yield RawMessage(bytes(data), index)


def iter_raw(source: MailSource, stats: Counter[str]) -> Iterator[RawMessage]:
    """Raw messages of ``source`` in source order. Raises :class:`SourceError` for an unreadable source."""
    if isinstance(source, MboxSource):
        with _open_regular(source.path) as handle:
            yield from split_mbox(handle, stats)
    elif isinstance(source, MboxBytes):
        yield from split_mbox(io.BytesIO(source.data), stats)
    elif isinstance(source, EmlSource):
        yield from _iter_eml(source.path, stats)
    else:
        yield from _iter_eml_bytes(source.messages, stats)
