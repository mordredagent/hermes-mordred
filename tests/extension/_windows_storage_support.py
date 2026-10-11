"""Enable checked Windows extension storage on any host (tests and their children).

On Windows the real backend runs unchanged. On POSIX the stricter
descriptor-relative ``_private_fs`` backend stands beneath the same calls; the
only substitution is the Windows-only optional opener, replaced by a host
equivalent that reports absence solely for a missing final directory below an
existing parent (an absent intermediate still fails in the real opener).
"""

from __future__ import annotations

import contextlib
import os
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from mordred_hermes._private_fs import PrivateDirectory, open_private_directory

REPO_ROOT = Path(__file__).resolve().parents[2]


@contextlib.contextmanager
def host_optional_private_directory(path: str | Path) -> Iterator[PrivateDirectory | None]:
    raw = os.fspath(path)
    if not os.path.lexists(raw) and os.path.isdir(os.path.dirname(raw)):
        yield None
        return
    with open_private_directory(raw) as directory:
        yield directory


def enable_checked_storage(monkeypatch: Any = None) -> None:
    """Force the Windows storage branch; ``monkeypatch=None`` patches a child process."""
    from mordred_hermes.extension import _windows_storage

    replacements: dict[str, Any] = {"WINDOWS_STORAGE": True}
    if os.name != "nt":
        replacements["open_optional_private_directory"] = host_optional_private_directory
    for name, value in replacements.items():
        if monkeypatch is None:
            setattr(_windows_storage, name, value)
        else:
            monkeypatch.setattr(_windows_storage, name, value, raising=False)
