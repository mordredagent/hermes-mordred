"""Generic atomic-file-I/O primitives shared by the wizard's writers.

Extracted from :mod:`.policy_writer` (which keeps the policy-specific
lock/transaction helpers built on top of these) to keep each module under
the size guideline. Nothing here knows about ``config.yaml`` / ``policy.json``
-- callers across the wizard package (``env_file_writer``,
``credentials_writer``, ``memory_cli``, ``openclaw_migration``, and
``policy_writer`` itself) use these for their own atomic writes.
"""

from __future__ import annotations

import contextlib
import errno
import os
import stat
import tempfile
from pathlib import Path

from ruamel.yaml import YAML

_O_CLOEXEC = getattr(os, "O_CLOEXEC", 0)
_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_O_NONBLOCK = getattr(os, "O_NONBLOCK", 0)

try:
    import fcntl
except ImportError:  # pragma: no cover - non-POSIX fallback
    fcntl = None  # type: ignore[assignment]


def _round_trip_yaml() -> YAML:
    """ruamel YAML instance configured for round-trip preservation.

    ``typ="rt"`` retains comments, key order, and anchors. Indent settings
    match the Hermes-shipped config style (2-space mapping, 4-space sequence,
    sequences offset 2 from their parent key) so the diff stays minimal
    when we touch unrelated nested keys.
    """
    yaml = YAML(typ="rt")
    yaml.indent(mapping=2, sequence=4, offset=2)
    yaml.preserve_quotes = True
    yaml.width = 4096  # don't wrap long values
    return yaml


def _fsync_durable(fd: int) -> None:
    """Flush an fd durably, using F_FULLFSYNC where macOS provides it."""
    full_fsync = getattr(fcntl, "F_FULLFSYNC", None)
    if full_fsync is not None:
        try:
            fcntl.fcntl(fd, full_fsync)
            return
        except OSError as exc:
            if exc.errno not in (errno.ENOTSUP, errno.EOPNOTSUPP, errno.EINVAL):
                raise
    os.fsync(fd)


def _fsync_parent(path: Path) -> None:
    if os.name != "posix":  # pragma: no cover - Windows directory-open semantics
        return
    fd = os.open(path.parent, os.O_RDONLY | _O_CLOEXEC)
    try:
        _fsync_durable(fd)
    finally:
        os.close(fd)


def _read_regular_text(path: Path) -> str | None:
    """Read an existing regular file without following or blocking on specials."""
    try:
        before = path.lstat()
    except FileNotFoundError:
        return None
    if not stat.S_ISREG(before.st_mode):
        raise OSError(errno.EINVAL, "configuration source must be a regular file", str(path))
    fd = os.open(path, os.O_RDONLY | _O_CLOEXEC | _O_NOFOLLOW | _O_NONBLOCK)
    try:
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode) or (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
            raise OSError(errno.EAGAIN, "configuration source changed while opening", str(path))
        chunks: list[bytes] = []
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            chunks.append(chunk)
        return b"".join(chunks).decode("utf-8")
    finally:
        os.close(fd)


def _ensure_real_directory(directory: Path) -> None:
    """Create or validate a directory without accepting a symlink endpoint."""
    try:
        metadata = directory.lstat()
    except FileNotFoundError:
        with contextlib.suppress(FileExistsError):
            directory.mkdir(mode=0o700, parents=True)
        metadata = directory.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise OSError(errno.ENOTDIR, "writer parent must be a real directory", str(directory))


def _atomic_write_text(path: Path, text: str, *, mode: int | None = None) -> None:
    """Write ``text`` to ``path`` via tmp + replace.

    Idempotent: if ``path`` already contains ``text`` byte-for-byte, no
    write happens (avoids touching mtime and triggering downstream watchers).

    The tmpfile is created via :func:`tempfile.mkstemp` (atomic
    ``O_CREAT|O_EXCL`` at mode 0o600 with a random suffix). This closes:

    - H3 (review 2026-05-14): for ``mode=0o600`` calls (policy.json,
      .env, credentials JSON) the secret content never lands on disk at
      umask-default — the file is 0o600 from the moment of creation.
    - M5: predictable ``<name>.tmp`` paths could collide under
      concurrent writers; the random suffix removes that.
    - M6: stale ``<name>.tmp`` from a prior crash no longer collides
      with subsequent writes.

    The final file mode after ``os.replace`` is the explicit ``mode``
    argument when provided; otherwise the tmpfile's 0o600 (tightest safe
    default — the parent directory is 0o700 so this doesn't restrict
    legitimate access).

    An existing file must be readable before it can be replaced. A read error
    may hide operator-managed fields or secrets; treating it as merely a failed
    idempotency comparison would allow a writable parent directory to turn a
    transient ACL/ownership problem into silent data loss.
    """
    try:
        path_metadata = path.lstat()
    except FileNotFoundError:
        path_metadata = None
    if path_metadata is not None and stat.S_ISREG(path_metadata.st_mode):
        # Read through a descriptor opened without following symlinks where the
        # platform supports it. O_NONBLOCK plus the post-open fstat also avoids
        # hanging if a regular path is raced into a FIFO between lstat/open.
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        existing_fd = os.open(path, flags)
        try:
            opened_metadata = os.fstat(existing_fd)
            same_object = (path_metadata.st_dev, path_metadata.st_ino) == (
                opened_metadata.st_dev,
                opened_metadata.st_ino,
            )
            if stat.S_ISREG(opened_metadata.st_mode) and same_object:
                with os.fdopen(os.dup(existing_fd), encoding="utf-8") as existing_file:
                    existing = existing_file.read()
                if existing == text:
                    if mode is None or stat.S_IMODE(opened_metadata.st_mode) == mode:
                        return  # no-op -- content and requested metadata match
                    fchmod = getattr(os, "fchmod", None)
                    if callable(fchmod):
                        fchmod(existing_fd, mode)
                        _fsync_durable(existing_fd)
                        return
                    # Windows may not expose fchmod. Fall through to the same
                    # private tmp + atomic replacement used for content changes.
        finally:
            os.close(existing_fd)
    # Symlinks and other non-regular entries are never opened for comparison:
    # following one could disclose another file, while reading a FIFO/device
    # can block forever. The atomic replace below safely replaces the directory
    # entry itself (or fails closed for an unreplaceable directory).

    parent = path.parent
    parent.mkdir(parents=True, exist_ok=True, mode=0o700)

    # mkstemp returns (fd, name). fd is opened O_RDWR|O_CREAT|O_EXCL at
    # mode 0o600 atomically -- no umask-default window. prefix/suffix
    # combine to keep the path adjacent to its target so os.replace stays
    # within the same filesystem (otherwise replace is non-atomic).
    fd, tmp_name = tempfile.mkstemp(dir=parent, prefix=path.name + ".", suffix=".tmp")
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)
            f.flush()
            _fsync_durable(f.fileno())
        if mode is not None and mode != 0o600:
            os.chmod(tmp, mode)
        os.replace(tmp, path)
        _fsync_parent(path)
    except BaseException:
        # Best-effort cleanup -- if replace already happened the unlink is
        # a no-op (the path no longer points at our tmpfile).
        with contextlib.suppress(FileNotFoundError):
            tmp.unlink()
        raise
