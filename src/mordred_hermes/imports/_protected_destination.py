"""Export-source snapshots and policy-only activity destinations.

A returned Path is classification, never authority for a later open. Database
I/O belongs exclusively to guarded SQLCipher. Source reads are for export
files, use the actual checked handle and release a verified memory snapshot;
no database header is opened to guess whether it contains encrypted data.
"""

from __future__ import annotations

import contextlib
import io
import os
import stat
from collections.abc import Iterator
from pathlib import Path
from typing import BinaryIO

from ..activity._gate import ActivityRefused, refusal

_MAX_SOURCE = 64 * 1024 * 1024
_EXPORT_SUFFIXES = frozenset({".json", ".jsonl", ".ndjson", ".eml", ".mbox", ".zip", ".txt"})


def checked_store_destination(path: Path, *, home: Path) -> Path:
    """Classify the fixed store path without creating anything or securing later opens."""
    expected = home / "plugin-data" / "mordred" / "mordred.db"
    if not home.is_absolute() or ".." in home.parts or path != expected:
        raise ActivityRefused(refusal("profile_mismatch"))
    for parent in (*reversed(expected.parents), expected):
        try:
            info = parent.lstat()
        except FileNotFoundError:
            break
        directory = parent != expected
        valid = stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode) and info.st_nlink == 1
        if not valid or getattr(info, "st_file_attributes", 0) & 0x400:
            raise ActivityRefused(refusal("store_unavailable"))
    return expected


def _file_fact(info: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return info.st_dev, info.st_ino, info.st_mode, info.st_nlink, info.st_size, info.st_mtime_ns


def _source_file(info: os.stat_result) -> None:
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_nlink != 1
        or info.st_mode & 0o022
        or info.st_uid != os.getuid()
        or not 0 <= info.st_size <= _MAX_SOURCE
    ):
        raise ActivityRefused(refusal("store_unavailable"))


def _posix_source(path: Path) -> bytes:
    with contextlib.ExitStack() as stack:
        parents: list[tuple[Path, int, tuple[int, int]]] = []
        for parent in reversed(path.parents):
            descriptor = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
            stack.callback(os.close, descriptor)
            info = os.fstat(descriptor)
            parents.append((parent, descriptor, (info.st_dev, info.st_ino)))
        before = path.lstat()
        _source_file(before)  # in particular, refuse hardlinks before acquiring a raw file fd
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
        with os.fdopen(descriptor, "rb") as source:
            opened = os.fstat(source.fileno())
            _source_file(opened)
            if _file_fact(opened) != _file_fact(before):
                raise ActivityRefused(refusal("store_unavailable"))
            data = source.read(_MAX_SOURCE + 1)
            after = os.fstat(source.fileno())
            if len(data) != before.st_size or _file_fact(after) != _file_fact(before):
                raise ActivityRefused(refusal("store_unavailable"))
            if _file_fact(path.lstat()) != _file_fact(before):
                raise ActivityRefused(refusal("store_unavailable"))
            for parent, held, identity in parents:
                named, pinned = parent.lstat(), os.fstat(held)
                if (
                    not stat.S_ISDIR(named.st_mode)
                    or (named.st_dev, named.st_ino) != identity
                    or (pinned.st_dev, pinned.st_ino) != identity
                ):
                    raise ActivityRefused(refusal("store_unavailable"))
            return data


def _windows_source(path: Path) -> bytes:
    from .._private_fs._windows_paths import checked_directory_optional, windows_leaf
    from .._private_fs._windows_security import validate_confidential_file

    windows_leaf(path.name)
    with checked_directory_optional(path.parent, confidential=True) as parent:
        if parent is None:
            raise ActivityRefused(refusal("store_unavailable"))
        parent.check()
        api = parent.handle.api
        bound = parent.path.rstrip("\\") + "\\" + path.name
        # Share-read excludes write/delete through every alias until validation
        # and close. OPEN_REPARSE_POINT is provided by NativeAPI.open.
        with api.open(bound, share=1) as source:
            validate_confidential_file(source)
            before = api.metadata(source)
            if before.size > _MAX_SOURCE or api.final_path(source).casefold() != bound.casefold():
                raise ActivityRefused(refusal("store_unavailable"))
            data = api.read(source, before.size + 1)
            validate_confidential_file(source)
            if len(data) != before.size or api.metadata(source) != before:
                raise ActivityRefused(refusal("store_unavailable"))
            parent.check()
            return data


@contextlib.contextmanager
def checked_import_source(path: Path, *, home: Path) -> Iterator[BinaryIO]:
    """Yield a verified in-memory export snapshot; no path is reopened by the caller."""
    from ..dbcrypt._policy import looks_like_database_name

    # Source policy is separate from database destination policy. Never open a
    # protected DB (or its sidecars) as a raw export, including unknown suffixes.
    if (
        not home.is_absolute()
        or not path.is_absolute()
        or ".." in path.parts
        or looks_like_database_name(path.name)
        or path.suffix.casefold() not in _EXPORT_SUFFIXES
    ):
        raise ActivityRefused(refusal("store_unavailable"))
    try:
        data = _windows_source(path) if os.name == "nt" else _posix_source(path)
    except OSError:
        raise ActivityRefused(refusal("store_unavailable")) from None
    with io.BytesIO(data) as source:
        yield source
