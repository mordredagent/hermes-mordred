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
    """Create private physical directories using pinned parent handles, never chmod a path."""
    directory = home.joinpath(*PLUGIN_DATA_SUBPATH)
    from ..imports._protected_destination import checked_store_destination

    checked_store_destination(directory / STORE_NAME, home=home)
    if os.name == "nt":
        from .._private_fs import open_private_directory

        # Windows admission/creation owns the real directory handles and ACLs.
        with (
            open_private_directory(home / PLUGIN_DATA_SUBPATH[0], create=True),
            open_private_directory(directory, create=True),
        ):
            pass
        return directory
    with contextlib.ExitStack() as stack:
        parent = os.open(home, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        stack.callback(os.close, parent)
        for component in PLUGIN_DATA_SUBPATH:
            with contextlib.suppress(FileExistsError):
                os.mkdir(component, mode=0o700, dir_fd=parent)
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
            stack.callback(os.close, child)
            info = os.fstat(child)
            if info.st_uid != os.getuid() or info.st_mode & 0o022:
                raise OSError("activity data directory is not private")
            if component == PLUGIN_DATA_SUBPATH[-1] and stat.S_IMODE(info.st_mode) != 0o700:
                os.fchmod(child, 0o700)
            parent = child
    return directory


def store_path(home: Path) -> Path:
    return activity_dir(home) / STORE_NAME
