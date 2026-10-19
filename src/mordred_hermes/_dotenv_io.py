"""Shared dotenv read/modify/write transaction for every Mordred consumer."""

from __future__ import annotations

import errno
import threading
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import NoReturn

from ._config_io import DOTENV_LIMIT, CanonicalPaths, canonical_session
from ._config_text_io import _atomic_write_text, _bounded_utf8, _ensure_real_directory, _read_regular_text, _windows
from ._file_lock import private_flock

_ENV_THREAD_LOCK = threading.RLock()


def _reject_unopenable_dotenv_lock(lock_path: Path, exc: OSError) -> NoReturn:
    """Wrap an ``os.open`` failure on the dotenv lock as a tagged ``EPERM``."""
    raise OSError(errno.EPERM, "dotenv lock is unsafe or unavailable", str(lock_path)) from exc


def _reject_unsafe_dotenv_lock(lock_path: Path) -> NoReturn:
    """Fail closed when ``.env.lock`` is not a private regular file."""
    raise OSError(errno.EPERM, "dotenv lock must be a mode-0600 regular file", str(lock_path))


@contextmanager
def _dotenv_lock(path: Path) -> Iterator[None]:
    """Stable sibling lock shared by every Mordred ``.env`` RMW writer.

    The descriptor lifecycle is :func:`mordred_hermes._file_lock.private_flock`;
    the in-process ``RLock``, the parent-directory check, and both raises stay
    here so the tagged ``EPERM`` :exc:`OSError`\\ s (and the ``from exc``
    chaining on the open failure) are unchanged.
    """
    with _ENV_THREAD_LOCK:
        _ensure_real_directory(path.parent)
        with private_flock(
            path.with_name(path.name + ".lock"),
            on_unsafe=_reject_unsafe_dotenv_lock,
            on_open_error=_reject_unopenable_dotenv_lock,
        ):
            yield


def update_dotenv_file(path: Path, transform: Callable[[str], str]) -> None:
    """Atomically transform a regular dotenv file under the shared RMW lock."""
    if _windows():
        if path.name != ".env":
            raise ValueError("canonical dotenv filename must be .env")
        with canonical_session(CanonicalPaths(path.parent), scope="home", create=True) as session:
            source = session.read_home(".env", max_bytes=DOTENV_LIMIT)
            updated = transform(source.data.decode("utf-8") if source is not None else "")
            session.write_home(".env", _bounded_utf8(updated, DOTENV_LIMIT))
        return
    with _dotenv_lock(path):
        existing = _read_regular_text(path)
        updated = transform(existing if existing is not None else "")
        _atomic_write_text(path, updated, mode=0o600)
