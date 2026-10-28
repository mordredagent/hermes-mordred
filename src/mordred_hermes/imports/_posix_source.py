"""Key-free stdlib snapshot worker, executed with Python -I -S and empty env.

Only this fresh process opens source file descriptors. Closing a rejected
hardlink to a live database therefore cannot release the importing PID's locks.
No package bootstrap, SQL, native custody, stdout diagnostics or spool is used.
"""

from __future__ import annotations

import contextlib
import json
import os
import stat
import sys
from collections.abc import Callable
from pathlib import Path

_MAX_SOURCE = 64 * 1024 * 1024
_MAX_REQUEST = 512 * 1024
_CHUNK = 1024 * 1024


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
        raise ValueError("unsafe source parent")
    return info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid


def _source_file(info: os.stat_result, limit: int | None) -> None:
    # limit=None is the streamed mail-export policy: no size or mode-bit limit.
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_nlink != 1
        or info.st_uid != os.getuid()
        or (limit is not None and (info.st_mode & 0o022 or not 0 <= info.st_size <= limit))
    ):
        raise ValueError("unsafe source")


def _read_source(path: Path, limit: int | None, expected_file: object, sink: Callable[[bytes], object]) -> None:
    """Read in chunks into ``sink``; the open, identity and regular-file checks precede any chunk."""
    if not isinstance(expected_file, list) or len(expected_file) != 9:
        raise ValueError("invalid source facts")
    before = path.lstat()
    _source_file(before, limit)
    if list(_file_fact(before)) != expected_file:
        raise ValueError("source handoff changed")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as source:
        opened = os.fstat(source.fileno())
        _source_file(opened, limit)
        if _file_fact(opened) != _file_fact(before):
            raise ValueError("source open changed")
        total = 0
        while chunk := source.read(_CHUNK):
            total += len(chunk)
            if total > before.st_size:
                raise ValueError("source grew")
            sink(chunk)
        if total != before.st_size or _file_fact(os.fstat(source.fileno())) != _file_fact(before):
            raise ValueError("source read changed")
        if _file_fact(path.lstat()) != _file_fact(before):
            raise ValueError("named source changed")


def _snapshot(path: Path, limit: int, expected_file: object, expected_parents: object) -> bytes:
    """Buffered snapshot: nothing reaches stdout before every final check passed."""
    if not path.is_absolute() or ".." in path.parts:
        raise ValueError("unsafe source path")
    if not isinstance(expected_parents, list) or len(expected_parents) != len(path.parents):
        raise ValueError("invalid source parents")
    with contextlib.ExitStack() as stack:
        parents: list[tuple[Path, int, tuple[int, ...]]] = []
        for parent, expected in zip(reversed(path.parents), expected_parents, strict=True):
            descriptor = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
            stack.callback(os.close, descriptor)
            actual = _parent_fact(os.fstat(descriptor))
            if list(actual) != expected:
                raise ValueError("source parent handoff changed")
            parents.append((parent, descriptor, actual))
        chunks: list[bytes] = []
        _read_source(path, limit, expected_file, chunks.append)
        for parent, held, expected in parents:
            if _parent_fact(parent.lstat()) != expected or _parent_fact(os.fstat(held)) != expected:
                raise ValueError("source parents changed")
    return b"".join(chunks)  # Every final check and owned-handle close precedes stdout.


def _stream(path: Path, expected_file: object) -> None:
    """Mail-export policy: stream chunks to stdout; the parent verifies count and exit status."""
    if not path.is_absolute() or ".." in path.parts:
        raise ValueError("unsafe source path")
    out = sys.stdout.buffer

    def emit(chunk: bytes) -> None:
        out.write(chunk)

    _read_source(path, None, expected_file, emit)
    out.flush()


def main() -> int:
    try:
        if os.name != "posix":
            return 1
        encoded = sys.stdin.buffer.read(_MAX_REQUEST + 1)
        if len(encoded) > _MAX_REQUEST:
            return 1
        request = json.loads(encoded)
        if isinstance(request, dict) and set(request) == {"path", "file", "stream"} and request["stream"] is True:
            _stream(Path(request["path"]), request["file"])
            return 0
        if not isinstance(request, dict) or set(request) != {"path", "limit", "file", "parents"}:
            return 1
        limit = request["limit"]
        if type(limit) is not int or not 0 < limit <= _MAX_SOURCE:
            return 1
        data = _snapshot(Path(request["path"]), limit, request["file"], request["parents"])
    except Exception:
        return 1  # Failure has empty stdout and no content-bearing diagnostics.
    view = memoryview(data)
    for start in range(0, len(view), _CHUNK):
        sys.stdout.buffer.write(view[start : start + _CHUNK])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
