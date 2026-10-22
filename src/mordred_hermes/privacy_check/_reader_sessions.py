"""Durable record of the sessions that are in reader mode.

A session enters reader mode the first time it reads imported private history
(see :data:`.egress.READER_TOOLS`). The in-process set in :mod:`.egress` dies
with the Hermes process, so the pre-tool hook also records the session here
*before* the first read is allowed: a restarted Hermes that resumes the same
session id stays restricted.

File: ``<home>/mordred/reader_sessions.json``::

    {"version": 1, "sessions": ["<sha256(session_id) hex>", ...]}

- Only SHA-256 digests of session ids are stored, never the ids themselves.
- At most :data:`MAX_ENTRIES` digests, oldest first, and none is ever
  evicted: dropping an old digest would silently lift the restriction from
  that session the next time it is resumed. When the record is full,
  :func:`record` raises ``ReaderRecordError("record_full")`` and the hook
  refuses every reader tool for a session not yet recorded
  (``egress.reader_unrecorded``) until the operator prunes the file (a
  pruning CLI is future work). Sessions already recorded keep working.
- A missing file reads as an empty record. The file lives in the operator's
  own Hermes home, which Mordred trusts like the rest of its configuration;
  deleting it is an operator action, and each affected session is recorded
  again (back in reader mode) at its next reader-tool call.
- Written through the checked private-storage helpers
  (:mod:`mordred_hermes._private_fs`) on every platform: a ``0700`` directory,
  a ``0600`` file, an atomic replace under the directory's private lock, and
  checked NTFS storage on Windows. Anything the helpers refuse raises
  :class:`ReaderRecordError`, so callers fail closed.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import re
import threading
from collections.abc import Iterator
from pathlib import Path
from typing import Final

from .._bounded_json import _BoundedJSONDecoder
from .._private_fs import (
    PrivateDirectory,
    PrivateFSError,
    open_optional_private_directory,
    open_private_directory,
)

_platform = os.name

DIR_NAME: Final = "mordred"
FILE_NAME: Final = "reader_sessions.json"
VERSION: Final = 1
MAX_ENTRIES: Final = 4096
#: A full record is 274,459 bytes as written (66 bytes per quoted digest plus a
#: comma, ~30 bytes of framing); 512 KiB leaves room for a hand-formatted file.
#: Anything larger was not written by us.
MAX_BYTES: Final = 512 * 1024
_DIGEST = re.compile(r"[0-9a-f]{64}")

#: ``record_path -> ((dev, ino, size, mtime_ns), digests)``
_cache: dict[Path, tuple[tuple[int, int, int, int], frozenset[str]]] = {}
_cache_lock = threading.Lock()


class ReaderRecordError(Exception):
    """The durable reader record could not be read or written.

    ``code`` is content-free (no paths, no session ids) so it can go to logs
    and to the model.
    """

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def digest(session_id: str) -> str:
    """The stored form of ``session_id``."""
    return hashlib.sha256(session_id.encode("utf-8", "surrogatepass")).hexdigest()


def record_path(home: Path) -> Path:
    """``<home>/mordred/reader_sessions.json`` with symlinks in ``home`` resolved.

    The checked storage helpers open every component without following links,
    so a home reached through a symlink (``/var`` on macOS, a linked
    ``~/.hermes``) is resolved first; the components are then re-checked.
    """
    return Path(home).resolve() / DIR_NAME / FILE_NAME


def record(home: Path, session_id: str) -> None:
    """Durably add ``session_id`` to the reader record; raise on any failure.

    A session already recorded is a no-op, also when the record is full. A
    new session in a full record raises ``ReaderRecordError("record_full")``;
    nothing is evicted.
    """
    if not session_id:
        raise ReaderRecordError("no_session")
    with _translated():
        entry = digest(session_id)
        path = record_path(home)
        with open_private_directory(path.parent, create=True) as directory, directory.transaction() as tx:
            try:
                current = _decode(tx.read_bytes(FILE_NAME, max_bytes=MAX_BYTES))
                exists = True
            except PrivateFSError as exc:
                if exc.reason != "missing":
                    raise
                current, exists = [], False
            if entry in current:
                return
            if len(current) >= MAX_ENTRIES:
                raise ReaderRecordError("record_full")
            data = _encode([*current, entry])
            if exists:
                tx.replace_bytes(FILE_NAME, data)
            else:
                tx.create_bytes(FILE_NAME, data)


def load(home: Path) -> tuple[str, ...]:
    """The recorded digests, oldest first; empty when there is no record."""
    with _translated():
        path = record_path(home)
        with _open_existing(path.parent) as directory:
            if directory is None:
                return ()
            try:
                return tuple(_decode(directory.read_bytes(FILE_NAME, max_bytes=MAX_BYTES)))
            except PrivateFSError as exc:
                if exc.reason == "missing":
                    return ()
                raise


def contains(home: Path, session_id: str) -> bool:
    """Whether ``session_id`` is recorded; the parsed file is cached by stat."""
    with _translated():
        path = record_path(home)
    before = _stamp(path)
    if before is None:
        return False
    with _cache_lock:
        cached = _cache.get(path)
    if cached is not None and cached[0] == before:
        return digest(session_id) in cached[1]
    digests = frozenset(load(home))
    if _stamp(path) == before:
        with _cache_lock:
            _cache[path] = (before, digests)
    return digest(session_id) in digests


def _stamp(path: Path) -> tuple[int, int, int, int] | None:
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise ReaderRecordError("stat_failed") from exc
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns)


@contextlib.contextmanager
def _open_existing(path: Path) -> Iterator[PrivateDirectory | None]:
    """The checked directory, or ``None`` when it does not exist."""
    if _platform == "nt":
        with open_optional_private_directory(path) as directory:
            yield directory
        return
    with contextlib.ExitStack() as stack:
        try:
            opened: PrivateDirectory | None = stack.enter_context(open_private_directory(path))
        except PrivateFSError as exc:
            if exc.reason != "missing":
                raise
            opened = None
        yield opened


@contextlib.contextmanager
def _translated() -> Iterator[None]:
    """Turn every storage or format failure into a content-free refusal."""
    try:
        yield
    except ReaderRecordError:
        raise
    except PrivateFSError as exc:
        raise ReaderRecordError(f"storage_{exc.reason}") from exc
    except ValueError as exc:  # bad JSON, bad UTF-8, too deep, wrong shape
        raise ReaderRecordError("corrupt") from exc
    except OSError as exc:
        raise ReaderRecordError("io") from exc
    except Exception as exc:
        raise ReaderRecordError("unexpected") from exc


def _encode(digests: list[str]) -> bytes:
    return json.dumps({"version": VERSION, "sessions": digests}, separators=(",", ":")).encode("ascii") + b"\n"


def _decode(data: bytes) -> list[str]:
    document = json.loads(data.decode("utf-8"), cls=_BoundedJSONDecoder)
    if not isinstance(document, dict) or set(document) != {"version", "sessions"}:
        raise ValueError("reader record has the wrong shape")
    version = document["version"]
    if type(version) is not int or version != VERSION:
        raise ReaderRecordError("unsupported_version")
    sessions = document["sessions"]
    if (
        not isinstance(sessions, list)
        or len(sessions) > MAX_ENTRIES
        or not all(isinstance(item, str) and _DIGEST.fullmatch(item) for item in sessions)
        or len(set(sessions)) != len(sessions)
    ):
        raise ValueError("reader record has the wrong shape")
    return list(sessions)
