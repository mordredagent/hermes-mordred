"""Export-source snapshots and policy-only activity destinations.

A returned Path is classification, never authority for a later open. Database
I/O belongs exclusively to guarded SQLCipher. Source reads are for export
files and use the actual checked handle: POSIX streams the file through an
isolated worker, while Windows reads the validated handle fully into memory
(no size cap); no database header is opened to guess whether it contains
encrypted data.
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import stat
import subprocess
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import IO, Any, BinaryIO

from ..activity._gate import ActivityRefused, refusal

_MAX_SOURCE = 64 * 1024 * 1024
_SIDECAR_SUFFIXES = ("-wal", "-shm", "-journal")
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


def _file_fact(info: os.stat_result) -> tuple[int, ...]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_uid,
        info.st_gid,
        info.st_nlink,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def _parent_fact(info: os.stat_result) -> tuple[int, ...]:
    if not stat.S_ISDIR(info.st_mode):
        raise ActivityRefused(refusal("store_unavailable"))
    return info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid


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
    # Metadata only in this PID: even a rejected source can alias a live DB,
    # and closing any raw fd for that inode would release our SQLite locks.
    before = path.lstat()
    _source_file(before)
    parents = [_parent_fact(parent.lstat()) for parent in reversed(path.parents)]
    executable = Path(sys.executable)
    if not executable.is_absolute():
        raise ActivityRefused(refusal("store_unavailable"))
    request = json.dumps(
        {
            "path": str(path),
            "limit": _MAX_SOURCE,
            "file": _file_fact(before),
            "parents": parents,
        }
    ).encode("utf-8")
    worker = Path(__file__).resolve().with_name("_posix_source.py")
    try:
        result = subprocess.run(
            [str(executable), "-I", "-S", str(worker)],
            input=request,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env={},
            close_fds=True,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired):
        raise ActivityRefused(refusal("store_unavailable")) from None
    if result.returncode != 0 or len(result.stdout) > _MAX_SOURCE or len(result.stdout) != before.st_size:
        raise ActivityRefused(refusal("store_unavailable"))
    if _file_fact(path.lstat()) != _file_fact(before):
        raise ActivityRefused(refusal("store_unavailable"))
    if [_parent_fact(parent.lstat()) for parent in reversed(path.parents)] != parents:
        raise ActivityRefused(refusal("store_unavailable"))
    return result.stdout


def _windows_source(path: Path, *, limit: int | None = _MAX_SOURCE) -> bytes:
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
            if (limit is not None and before.size > limit) or api.final_path(source).casefold() != bound.casefold():
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


class _CountingReader(io.RawIOBase):
    """Counts bytes pulled from the worker pipe so the exit check can compare with st_size."""

    def __init__(self, raw: IO[bytes]) -> None:
        super().__init__()
        self._raw = raw
        self.count = 0

    def readable(self) -> bool:
        return True

    def readinto(self, buffer: Any) -> int:
        got = self._raw.readinto(buffer) or 0  # type: ignore[attr-defined]
        self.count += got
        return got


def _refused() -> ActivityRefused:
    return ActivityRefused(refusal("store_unavailable"))


def _export_request(resolved: Path, before: os.stat_result) -> tuple[list[str], bytes]:
    executable = Path(sys.executable)
    if not executable.is_absolute():
        raise _refused()
    request = json.dumps({"path": str(resolved), "file": _file_fact(before), "stream": True}).encode("utf-8")
    worker = Path(__file__).resolve().with_name("_posix_source.py")
    return [str(executable), "-I", "-S", str(worker)], request


@contextlib.contextmanager
def _posix_export_stream(resolved: Path) -> Iterator[BinaryIO]:
    # Metadata only in this PID; the isolated worker is the sole opener.
    before = resolved.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_uid != os.getuid():
        raise _refused()
    argv, request = _export_request(resolved, before)
    try:
        proc = subprocess.Popen(
            argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env={}, close_fds=True
        )
    except OSError:
        raise _refused() from None
    assert proc.stdin is not None and proc.stdout is not None
    try:
        try:
            proc.stdin.write(request)
        finally:
            proc.stdin.close()
        counter = _CountingReader(proc.stdout)
        stream = io.BufferedReader(counter, buffer_size=1024 * 1024)
        # A refused worker exits before emitting anything: fail before the caller sees data.
        if before.st_size > 0 and not stream.peek(1):
            proc.wait()
            raise _refused()
        yield stream
        while stream.read(1024 * 1024):  # verify against the whole file even if the caller stopped early
            pass
        if proc.wait() != 0 or counter.count != before.st_size or _file_fact(resolved.lstat()) != _file_fact(before):
            raise _refused()
    except BaseException:
        with contextlib.suppress(OSError):
            proc.kill()
        raise
    finally:
        proc.stdout.close()
        proc.wait()


@contextlib.contextmanager
def checked_export_stream(path: Path) -> Iterator[BinaryIO]:
    """Yield a streaming, verified view of a mail export; the worker child is the only opener.

    Symlinked parents are resolved; the leaf must be a regular, single-link file owned by
    the caller. POSIX streams through the isolated worker with no size, suffix or mode-bit
    limit. Windows reads the validated handle fully into memory (no size cap) and keeps the
    confidential-parent-directory policy. Database-named files are refused. The caller must
    consume the stream inside the ``with`` block; completeness is verified at exit.
    """
    from ..dbcrypt._policy import looks_like_database_name

    if not path.is_absolute():
        raise _refused()
    resolved = Path(os.path.realpath(path.parent)) / path.name
    if looks_like_database_name(resolved.name) or resolved.name.lower().endswith(_SIDECAR_SUFFIXES):
        raise _refused()
    try:
        if os.name == "nt":
            with io.BytesIO(_windows_source(resolved, limit=None)) as source:
                yield source
            return
        with _posix_export_stream(resolved) as stream:
            yield stream
    except OSError:
        raise _refused() from None
