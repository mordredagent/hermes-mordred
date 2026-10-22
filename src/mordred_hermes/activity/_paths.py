"""Where the activity store lives: ``<profile-home>/plugin-data/mordred/mordred.db``.

Hermes 0.19.0 has no ``plugin_data_dir`` helper and the newer one reads the
process-global home, which queued work must not do. Every function here takes
the owning ``home`` explicitly; nothing in this package reads ``HERMES_HOME``.
"""

from __future__ import annotations

import contextlib
import os
import stat
from pathlib import Path
from typing import Final

PLUGIN_DATA_SUBPATH: Final = ("plugin-data", "mordred")
STORE_NAME: Final = "mordred.db"


def activity_dir(home: Path) -> Path:
    """``<home>/plugin-data/mordred``, created ``0700``; a symlink or non-directory is refused."""
    directory = home.joinpath(*PLUGIN_DATA_SUBPATH)
    try:
        metadata = directory.lstat()
    except FileNotFoundError:
        directory.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        with contextlib.suppress(FileExistsError):
            directory.mkdir(mode=0o700)
        metadata = directory.lstat()
    # A planted symlink would move the encrypted store (and its sidecars) to a
    # location this profile does not own.
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise OSError("activity data directory must be a real directory")
    if stat.S_IMODE(metadata.st_mode) != 0o700:
        os.chmod(directory, 0o700)  # lstat above: not a symlink
    return directory


def store_path(home: Path) -> Path:
    return activity_dir(home) / STORE_NAME
