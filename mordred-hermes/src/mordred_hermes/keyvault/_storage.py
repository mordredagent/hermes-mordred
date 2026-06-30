"""mordred_hermes.keyvault._storage — file-safety helpers.

Phase 4 PR4 step-B (2026-05-15). Private to the keyvault module; api.py
and the encrypt/decrypt/generate/backup layers consume these helpers.
Frozen contract: SPEC.md §"PR4 API contract / File-safety semantics".

Codex pre-implementation review HIGH #4 demanded:

- ``os.open(O_NOFOLLOW)`` — no symlink-follow on any keyvault path.
- File mode ``0o600`` and directory mode ``0o700`` enforced via
  ``fstat`` after open (mismatch → :exc:`KeyvaultPermissionError`).
- Atomic writes: ``<file>.tmp + fsync(tmp_fd) + os.replace + fsync(parent_fd)``.
- Exclusive ``fcntl.flock`` on ``<root>/.lock`` for write transactions.
- ``meta.json`` corruption raises :exc:`KeyvaultCorruptError` whose
  ``str()`` does NOT include the corrupted file contents (audit safety
  — a partially-overwritten file could contain secret-shaped bytes).
"""

from __future__ import annotations

import contextlib
import errno
import fcntl
import json
import os
import secrets
import stat
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from .._home import hermes_home as _hermes_home

_META_VERSION = 1
_FILE_MODE = 0o600
_DIR_MODE = 0o700


class KeyvaultPermissionError(OSError):
    """Filesystem permissions disagree with the keyvault security posture.

    Raised when a keyvault directory is not mode ``0o700``, a keyvault
    file is not mode ``0o600``, or a path is a symlink (``O_NOFOLLOW``
    refusal). Subclass of :class:`OSError` so callers using
    ``except OSError`` for filesystem error handling catch it naturally.
    """


class KeyvaultCorruptError(ValueError):
    """A keyvault state file failed to parse.

    Subclass of :class:`ValueError` (mirrors
    :class:`mordred_hermes.keyvault.digest.VerificationDigestMismatch`).
    The ``str()`` representation does NOT include corrupted file
    contents — a partially-overwritten file could contain secret-shaped
    bytes that must not leak into exception traces or log scrapers.
    """


def resolve_keyvault_dir(home: Path | None = None) -> Path:
    """Return the keyvault root directory.

    ``home=None`` uses :func:`mordred_hermes._home.hermes_home`. The
    function does NOT create any directories; call :func:`ensure_layout`
    for that.
    """
    base = home if home is not None else _hermes_home()
    return base / "mordred" / "keyvault"


def _check_dir_mode(path: Path) -> None:
    """Validate that ``path`` is a real directory with mode ``0o700``.

    Uses ``lstat`` (not ``stat``) so a symlinked directory is refused
    even when the target has correct mode (codex pre-merge P2-2:
    symlinked keyvault directories would otherwise pass the mode check
    and redirect writes outside the keyvault tree).

    Accepted TOCTOU caveat (in-tree code-reviewer LOW-1, 2026-05-15): the
    lstat result is not atomically tied to the subsequent open / mkdir
    that callers perform after the check. A same-host, same-UID attacker
    who can race the gap between ``_check_dir_mode`` and ``atomic_write``
    could in principle swap the directory for a symlink. Closing that
    window cleanly would require ``O_DIRECTORY | O_NOFOLLOW`` open +
    ``fdopen``-backed reads on every helper, which is not portable
    across Python versions on macOS. The SPEC threat model excludes
    same-UID attackers (mode ``0o700`` already gates non-owner access),
    so the project accepts this gap.
    """
    st = path.lstat()
    if stat.S_ISLNK(st.st_mode):
        raise KeyvaultPermissionError(errno.ELOOP, "refusing to follow symbolic link to keyvault directory", str(path))
    if not stat.S_ISDIR(st.st_mode):
        raise KeyvaultPermissionError(errno.ENOTDIR, "keyvault path exists but is not a directory", str(path))
    actual = stat.S_IMODE(st.st_mode)
    if actual != _DIR_MODE:
        raise KeyvaultPermissionError(
            errno.EPERM,
            f"keyvault directory must be mode 0o{_DIR_MODE:o}, got 0o{actual:o}",
            str(path),
        )


def _check_file_mode(path: Path) -> None:
    """Validate that ``path`` is a real file with mode ``0o600``.

    Uses ``lstat`` so a symlinked file is refused regardless of the
    target's mode (file-safety contract — codex pre-merge P2-2).
    Rejects non-regular files (FIFO / device / directory) via
    ``stat.S_ISREG`` — a 0o600 FIFO would otherwise pass the mode bit
    check and cause ``safe_read`` / ``keyvault_lock`` to block or
    operate on the wrong kind of inode (codex second-pass P2-C,
    2026-05-15).
    """
    st = path.lstat()
    if stat.S_ISLNK(st.st_mode):
        raise KeyvaultPermissionError(errno.ELOOP, "refusing to follow symbolic link to keyvault file", str(path))
    if not stat.S_ISREG(st.st_mode):
        raise KeyvaultPermissionError(
            errno.EINVAL,
            "keyvault file must be a regular file (not FIFO, device, directory)",
            str(path),
        )
    actual = stat.S_IMODE(st.st_mode)
    if actual != _FILE_MODE:
        raise KeyvaultPermissionError(
            errno.EPERM,
            f"keyvault file must be mode 0o{_FILE_MODE:o}, got 0o{actual:o}",
            str(path),
        )


def ensure_layout(root: Path) -> None:
    """Idempotently create the keyvault directory tree.

    Layout (PATHS.md L255-262):

    - ``root/`` (mode ``0o700``)
    - ``root/.lock`` (mode ``0o600``, empty; fcntl.flock target)
    - ``root/meta.json`` (mode ``0o600``, ``{"version": 1, "keys": {}}`` initially)
    - ``root/digests/`` (mode ``0o700``)
    - ``root/ciphertexts/`` (mode ``0o700``)

    Idempotent: re-running on an existing layout validates the modes
    without clobbering content. Wrong mode on any existing path raises
    :exc:`KeyvaultPermissionError`.
    """
    if root.exists():
        if not root.is_dir():
            raise KeyvaultPermissionError(errno.ENOTDIR, "keyvault root exists but is not a directory", str(root))
        _check_dir_mode(root)
    else:
        root.mkdir(mode=_DIR_MODE, parents=True)
        os.chmod(root, _DIR_MODE)

    for sub in ("digests", "ciphertexts"):
        d = root / sub
        if d.exists():
            _check_dir_mode(d)
        else:
            d.mkdir(mode=_DIR_MODE)
            os.chmod(d, _DIR_MODE)

    lock = root / ".lock"
    if not lock.exists():
        try:
            fd = os.open(
                lock,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                _FILE_MODE,
            )
            os.close(fd)
        except FileExistsError:
            # Lost the creation race to a concurrent ensure_layout — the
            # winner's lock file serves both processes; _check_file_mode
            # below validates it exactly as if we had created it.
            pass
    _check_file_mode(lock)

    meta = root / "meta.json"
    if not meta.exists():
        _write_meta_atomic(meta, {"version": _META_VERSION, "keys": {}})
    _check_file_mode(meta)


def atomic_write(path: Path, data: bytes) -> None:
    """Atomic write of ``data`` to ``path`` at mode ``0o600``.

    Sequence: open ``<path>.<rand>.tmp`` with ``O_EXCL | O_NOFOLLOW`` →
    ``os.write`` → ``os.fsync(tmp_fd)`` → ``os.replace(tmp, final)`` →
    ``os.fsync(parent_dir_fd)``. Cleans up the tmp file on any failure
    so the directory does not accumulate orphaned ``*.tmp`` files.

    Refuses to follow symlinks at the final path (existing symlink →
    :exc:`KeyvaultPermissionError`). If ``path`` already exists as a
    regular file, its current mode must be ``0o600`` or
    :exc:`KeyvaultPermissionError` is raised before any tmp file is
    created.
    """
    if path.is_symlink():
        raise KeyvaultPermissionError(errno.ELOOP, "refusing to write through a symbolic link", str(path))
    if path.exists():
        _check_file_mode(path)

    tmp_path = path.with_name(f"{path.name}.{secrets.token_hex(8)}.tmp")

    fd = os.open(
        tmp_path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
        _FILE_MODE,
    )
    try:
        try:
            # ``os.write`` is not guaranteed to flush the entire buffer
            # in a single call; loop until every byte is written so a
            # short write does not commit a truncated file via the
            # subsequent ``os.replace`` (codex pre-merge P2-3).
            view = memoryview(data)
            offset = 0
            while offset < len(view):
                written = os.write(fd, view[offset:])
                if written <= 0:
                    raise OSError("os.write returned 0 bytes — disk full or fd closed")
                offset += written
            os.fsync(fd)
        finally:
            os.close(fd)
    except BaseException:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(tmp_path)
        raise

    try:
        os.replace(tmp_path, path)
    except BaseException:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(tmp_path)
        raise

    parent_fd = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(parent_fd)
    finally:
        os.close(parent_fd)


def safe_read(path: Path) -> bytes:
    """Read ``path`` with ``O_NOFOLLOW`` + mode ``0o600`` enforcement.

    Raises:

    - :exc:`KeyvaultPermissionError` if ``path`` is a symlink, a
      non-regular file (FIFO / device / directory), or its mode is not
      ``0o600``.
    - :exc:`FileNotFoundError` if ``path`` does not exist (the standard
      :class:`OSError` subclass — callers handle it the same way they
      would for any missing file).
    """
    # Pre-check via lstat so we never call ``os.open`` on a FIFO (which
    # would block until a writer connects) or a symlink (which would
    # surface as ELOOP but only after the syscall — cheaper to refuse
    # here). The O_NOFOLLOW open below still defends against a
    # symlink-swap race after this check (codex second-pass P2-C).
    st = path.lstat()
    if stat.S_ISLNK(st.st_mode):
        raise KeyvaultPermissionError(errno.ELOOP, "refusing to follow symbolic link", str(path))
    if not stat.S_ISREG(st.st_mode):
        raise KeyvaultPermissionError(
            errno.EINVAL,
            "keyvault file must be a regular file (not FIFO, device, directory)",
            str(path),
        )

    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise KeyvaultPermissionError(errno.ELOOP, "refusing to follow symbolic link", str(path)) from exc
        raise

    try:
        st = os.fstat(fd)
        # Re-check S_ISREG and mode under the open fd to close the TOCTOU
        # window between lstat above and this open (codex second-pass P2-C).
        if not stat.S_ISREG(st.st_mode):
            raise KeyvaultPermissionError(
                errno.EINVAL,
                "keyvault file must be a regular file (not FIFO, device, directory)",
                str(path),
            )
        mode = stat.S_IMODE(st.st_mode)
        if mode != _FILE_MODE:
            raise KeyvaultPermissionError(
                errno.EPERM,
                f"keyvault file must be mode 0o{_FILE_MODE:o}, got 0o{mode:o}",
                str(path),
            )
        chunks: list[bytes] = []
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        os.close(fd)


@contextlib.contextmanager
def keyvault_lock(root: Path) -> Iterator[None]:
    """Acquire an exclusive ``fcntl.flock`` on ``<root>/.lock``.

    Holds the lock for the duration of the context. The lock file must
    already exist (call :func:`ensure_layout` first). On macOS and Linux
    the flock serializes contention across both threads and processes
    even though each opens its own file descriptor — POSIX-ish advisory
    lock semantics.

    The lock file is held to the same posture as every other keyvault
    file: it must be a regular file at mode ``0o600`` (verified via
    ``fstat`` on the open fd, mirroring :func:`safe_read`), or
    :exc:`KeyvaultPermissionError` is raised before any flock attempt.
    """
    lock_path = root / ".lock"
    fd = os.open(lock_path, os.O_RDWR | os.O_NOFOLLOW)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise KeyvaultPermissionError(
                errno.EINVAL,
                "keyvault lock must be a regular file (not FIFO, device, directory)",
                str(lock_path),
            )
        mode = stat.S_IMODE(st.st_mode)
        if mode != _FILE_MODE:
            raise KeyvaultPermissionError(
                errno.EPERM,
                f"keyvault lock file must be mode 0o{_FILE_MODE:o}, got 0o{mode:o}",
                str(lock_path),
            )
        fcntl.flock(fd, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)


def _write_meta_atomic(path: Path, meta: dict[str, Any]) -> None:
    """Internal: serialize ``meta`` as canonical JSON and atomic-write to ``path``."""
    data = json.dumps(meta, sort_keys=True, separators=(",", ":")).encode("utf-8")
    atomic_write(path, data)


def load_meta(root: Path) -> dict[str, Any]:
    """Read ``root/meta.json`` and validate the schema.

    Returns ``{"version": 1, "keys": {}}`` when the file does not exist
    (allows :func:`ensure_layout` callers to recover after a manual
    ``meta.json`` deletion). Raises :exc:`KeyvaultCorruptError` on:

    - JSON parse failure.
    - Root is not a JSON object.
    - Missing ``"version"`` field.
    - ``"version"`` is not ``1``.

    The exception's ``str()`` never includes the corrupted file contents
    (audit safety per SPEC.md §"File-safety semantics").
    """
    meta_path = root / "meta.json"
    if not meta_path.exists():
        return {"version": _META_VERSION, "keys": {}}
    raw = safe_read(meta_path)
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        # `from None` suppresses __cause__ + __context__ so the original
        # JSONDecodeError (which echoes the offending document slice in
        # its repr) does not leak through the cause chain.
        raise KeyvaultCorruptError("meta.json is not valid JSON") from None
    if not isinstance(parsed, dict):
        raise KeyvaultCorruptError("meta.json root must be a JSON object")
    if "version" not in parsed:
        raise KeyvaultCorruptError("meta.json is missing the required 'version' field")
    if parsed["version"] != _META_VERSION:
        raise KeyvaultCorruptError(f"meta.json version must be {_META_VERSION}; got an unsupported version")
    # codex pre-merge P2-4: the downstream read-modify-write code assumes
    # ``parsed["keys"]`` is a dict. An absent / non-object keys field
    # would surface as KeyError / TypeError far from the parse site;
    # reject here so the caller sees a clean KeyvaultCorruptError.
    if "keys" not in parsed:
        raise KeyvaultCorruptError("meta.json is missing the required 'keys' field")
    if not isinstance(parsed["keys"], dict):
        raise KeyvaultCorruptError("meta.json 'keys' field must be a JSON object")
    return parsed


def save_meta(root: Path, meta: dict[str, Any]) -> None:
    """Atomically write ``meta`` to ``root/meta.json``.

    Caller is expected to hold :func:`keyvault_lock` around any
    read-modify-write transaction. ``save_meta`` itself does not take
    the lock so callers can compose multi-step transactions (e.g.
    update meta.json + write digest commit in one critical section).
    """
    _write_meta_atomic(root / "meta.json", meta)
