"""Windows backend boundary; refused until native implementation passes acceptance."""

from contextlib import AbstractContextManager
from pathlib import Path

from ._types import PrivateDirectory, PrivateFSError


def open_private_directory(path: str | Path, *, create: bool = False) -> AbstractContextManager[PrivateDirectory]:
    raise PrivateFSError("unsupported", "windows_backend_pending")
