"""Atomic capture helpers for resealing live plaintext working files."""

from __future__ import annotations

import errno
import os
import stat
import tempfile
from pathlib import Path

from . import _storage

_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_O_CLOEXEC = getattr(os, "O_CLOEXEC", 0)
_O_NONBLOCK = getattr(os, "O_NONBLOCK", 0)
_O_DIRECTORY = getattr(os, "O_DIRECTORY", 0)
_PRIVATE_MODE = 0o600


def _sync_directory(directory: Path) -> None:
    """Durably commit directory-entry changes without following the directory."""
    if os.name != "posix":
        return
    fd = os.open(directory, os.O_RDONLY | _O_DIRECTORY | _O_NOFOLLOW | _O_CLOEXEC)
    try:
        _storage._fsync_durable(fd)
    finally:
        os.close(fd)


def _open_regular_no_follow(path: Path) -> tuple[int, os.stat_result]:
    """Open ``path`` without following/blocking, then bind validation to its fd."""
    flags = os.O_RDONLY | _O_NOFOLLOW | _O_CLOEXEC | _O_NONBLOCK
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise OSError(errno.ELOOP, "refusing a symbolic-link plaintext source", str(path)) from exc
        raise
    try:
        opened_stat = os.fstat(fd)
        if not stat.S_ISREG(opened_stat.st_mode):
            raise OSError(
                errno.EINVAL,
                "plaintext source must be a regular file (not FIFO, device, socket, or directory)",
                str(path),
            )
        return fd, opened_stat
    except BaseException:
        os.close(fd)
        raise


def read_regular_plaintext(path: Path, *, make_private: bool = False) -> bytes:
    """Read one regular plaintext inode without symlink following or FIFO waits."""
    fd, opened_stat = _open_regular_no_follow(path)
    try:
        if make_private and stat.S_IMODE(opened_stat.st_mode) != _PRIVATE_MODE:
            os.fchmod(fd, _PRIVATE_MODE)
            _storage._fsync_durable(fd)
        chunks: list[bytes] = []
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                return b"".join(chunks)
            chunks.append(chunk)
    finally:
        os.close(fd)


def read_captured_plaintext(candidate: Path) -> bytes:
    """Read a private capture, rejecting replacement with any unsafe object."""
    fd, opened_stat = _open_regular_no_follow(candidate)
    try:
        mode = stat.S_IMODE(opened_stat.st_mode)
        if mode != _PRIVATE_MODE:
            raise OSError(
                errno.EPERM,
                f"captured plaintext must be mode 0o{_PRIVATE_MODE:o}, got 0o{mode:o}",
                str(candidate),
            )
        chunks: list[bytes] = []
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                return b"".join(chunks)
            chunks.append(chunk)
    finally:
        os.close(fd)


def _validate_source_type(path: Path) -> bool:
    """Return false when absent; reject an observed non-regular source."""
    try:
        source_stat = path.lstat()
    except FileNotFoundError:
        return False
    if not stat.S_ISREG(source_stat.st_mode):
        raise OSError(errno.EINVAL, "plaintext reseal source must be a regular file", str(path))
    return True


def _move_to_private_candidate(path: Path) -> Path | None:
    """Rename the current live object over a fresh same-directory placeholder."""
    fd, candidate_name = tempfile.mkstemp(
        prefix=f".{path.name}.mordred-reseal-",
        dir=path.parent,
    )
    os.close(fd)
    candidate = Path(candidate_name)
    try:
        os.replace(path, candidate)
    except FileNotFoundError:
        discard_capture(candidate)
        return None
    except BaseException:
        discard_capture(candidate)
        raise
    return candidate


def _secure_captured_candidate(candidate: Path) -> None:
    """Validate, privatize, and durably flush the captured inode."""
    # The pre-rename lstat above is only an early diagnostic. Validate again
    # *after* rename through O_NOFOLLOW|O_NONBLOCK + fstat: the source may have
    # been swapped for a symlink/FIFO in the mkstemp→replace window. fchmod on
    # that bound descriptor can never follow a raced symlink.
    fd, opened_stat = _open_regular_no_follow(candidate)
    try:
        if stat.S_IMODE(opened_stat.st_mode) != _PRIVATE_MODE:
            os.fchmod(fd, _PRIVATE_MODE)
        _storage._fsync_durable(fd)
    finally:
        os.close(fd)


def capture_plaintext(path: Path) -> Path | None:
    """Atomically move a regular ``path`` to a private same-directory name.

    Once the rename commits, a concurrent writer may create a new live
    ``path`` and resealing code can safely leave it alone. ``None`` means the
    source disappeared before capture. The private placeholder is mode 0600
    and cleaned on every pre-capture failure.
    """
    if not _validate_source_type(path):
        return None
    candidate = _move_to_private_candidate(path)
    if candidate is None:
        return None
    try:
        _secure_captured_candidate(candidate)
        # The rename removed the live name and published the private name.
        # Flush the 0600 inode first, then commit the directory transition
        # before any caller may rely on the candidate as the sole recoverable
        # plaintext after a power loss.
        _sync_directory(path.parent)
    except BaseException as exc:
        try:
            if not restore_capture_no_replace(candidate, path):
                exc.add_note(f"a newer plaintext exists at {path}; the captured copy remains at {candidate}")
        except BaseException as restore_exc:
            exc.add_note(f"the captured plaintext could not be restored and may remain at {candidate}: {restore_exc!r}")
        raise
    return candidate


def restore_capture_no_replace(candidate: Path, live_path: Path) -> bool:
    """Restore ``candidate`` only if no newer ``live_path`` exists.

    Uses a same-filesystem hard link as an atomic no-replace publication. On
    success the private name is removed and ``True`` is returned. If a
    concurrent writer already created the live path, returns ``False`` and
    leaves the captured file at ``candidate`` for explicit reconciliation.
    """
    # Validate and tighten the exact inode immediately before publication.
    # The safety here comes from ``_open_regular_no_follow`` (candidate proven a
    # regular file) plus the post-link inode comparison below — NOT from
    # ``follow_symlinks``, whose flag governs the link *source*, not the new
    # directory entry. It stays False so a raced symlink is never dereferenced
    # into the live pathname; the identity check is what catches the race.
    fd, candidate_stat = _open_regular_no_follow(candidate)
    try:
        if stat.S_IMODE(candidate_stat.st_mode) != _PRIVATE_MODE:
            os.fchmod(fd, _PRIVATE_MODE)
            candidate_stat = os.fstat(fd)
            _storage._fsync_durable(fd)
        try:
            os.link(candidate, live_path, follow_symlinks=False)
        except FileExistsError:
            return False
    finally:
        os.close(fd)

    published_stat = live_path.lstat()
    if not stat.S_ISREG(published_stat.st_mode) or (published_stat.st_dev, published_stat.st_ino) != (
        candidate_stat.st_dev,
        candidate_stat.st_ino,
    ):
        raise OSError(
            errno.EIO,
            "restored plaintext is not the validated captured inode",
            str(live_path),
        )

    # The candidate was the only rename-durable name. Make the new live hard
    # link durable before removing that recovery copy; otherwise a power loss
    # could roll back the link while retaining the later unlink and lose the
    # plaintext entirely.
    _sync_directory(live_path.parent)
    candidate.unlink()
    _sync_directory(live_path.parent)
    return True


def discard_capture(candidate: Path) -> None:
    """Remove a private capture and durably commit that directory deletion."""
    try:
        candidate.unlink()
    except FileNotFoundError:
        return
    _sync_directory(candidate.parent)


def publish_plaintext_no_replace(path: Path, data: bytes) -> bool:
    """Atomically publish complete private plaintext without replacing ``path``.

    The bytes and 0600 mode are flushed under a private same-directory name,
    then a hard link publishes the complete inode with no-replace semantics.
    ``False`` means another writer already owns the live pathname; its object is
    left untouched for the caller to validate and reconcile. Directory syncs
    order publication before staging-name removal, matching
    :func:`restore_capture_no_replace`.
    """
    fd, staging_name = tempfile.mkstemp(
        prefix=f".{path.name}.mordred-materialize-",
        dir=path.parent,
    )
    staging = Path(staging_name)
    try:
        try:
            os.fchmod(fd, _PRIVATE_MODE)
            view = memoryview(data)
            offset = 0
            while offset < len(view):
                written = os.write(fd, view[offset:])
                if written <= 0:
                    raise OSError("os.write returned 0 bytes while materializing plaintext")
                offset += written
            _storage._fsync_durable(fd)
        finally:
            os.close(fd)
    except BaseException as exc:
        try:
            discard_capture(staging)
        except BaseException as cleanup_exc:
            exc.add_note(f"private staging cleanup failed: {cleanup_exc!r}")
        raise

    try:
        os.link(staging, path, follow_symlinks=False)
    except FileExistsError:
        discard_capture(staging)
        return False
    except BaseException as exc:
        try:
            discard_capture(staging)
        except BaseException as cleanup_exc:
            exc.add_note(f"private staging cleanup failed: {cleanup_exc!r}")
        raise

    # Do not remove the only pre-publication recovery name until the live link
    # is durable. A failure here intentionally leaves both names visible.
    _sync_directory(path.parent)
    discard_capture(staging)
    return True
