"""Opt-in private filesystem primitives; existing component I/O is unchanged."""

from __future__ import annotations

import os
from contextlib import AbstractContextManager
from pathlib import Path

from ._types import FileIdentity, PrivateDirectory, PrivateFSError, PrivateTransaction

__all__ = ["FileIdentity", "PrivateDirectory", "PrivateFSError", "PrivateTransaction", "open_private_directory"]
_platform = os.name


def open_private_directory(path: str | Path, *, create: bool = False) -> AbstractContextManager[PrivateDirectory]:
    if _platform == "posix":
        from ._posix import open_private_directory as posix_opener

        return posix_opener(path, create=create)
    elif _platform == "nt":
        from ._windows_io import open_private_directory as windows_opener

        return windows_opener(path, create=create)
    else:
        raise PrivateFSError("unsupported", "open_directory")
