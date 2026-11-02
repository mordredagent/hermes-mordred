"""Erase only the regular file identities displayed in the confirmed plan."""

from __future__ import annotations

import stat
from pathlib import Path
from typing import TYPE_CHECKING

from .._database_contracts import DatabaseRefused
from ..dbcrypt import root_home
from . import _uninstall_databases
from ._uninstall_database_archives import protected_archives

if TYPE_CHECKING:
    from .uninstall_cli import UninstallContext

Stamp = tuple[int, int, int, int, int, int]


def stamp(path: Path) -> Stamp:
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or path.resolve(strict=True) != path:
        raise DatabaseRefused(f"erase target is not a single checked regular file: {path}")
    return info.st_dev, info.st_ino, info.st_mode, info.st_size, info.st_mtime_ns, info.st_ctime_ns


def inventory(ctx: UninstallContext) -> dict[Path, Stamp]:
    from .memory_cli import _sealed_memory_files

    paths = _sealed_memory_files(ctx.home)
    if root_home(ctx.home) == ctx.home:
        if _uninstall_databases._live_needed(ctx.home):
            paths += _uninstall_databases.database_files(ctx.home)
        paths += protected_archives(ctx.home)
        paths += [p for p in _uninstall_databases.state_paths(ctx.home) if p.exists() or p.is_symlink()]
    return {path: stamp(path) for path in sorted(set(paths))}


def erase(ctx: UninstallContext, reviewed: dict[Path, Stamp]) -> None:
    if inventory(ctx) != reviewed:
        raise DatabaseRefused("erase targets changed since confirmation; nothing erased")
    states = set(_uninstall_databases.state_paths(ctx.home))
    # Keep intent until all reviewed payloads have been removed. New files are
    # never added to this list, even if an uncooperative writer creates one.
    for path in sorted(reviewed, key=lambda path: (path in states, str(path))):
        if stamp(path) != reviewed[path]:
            raise DatabaseRefused(f"erase target identity or revision changed: {path}")
        path.unlink()
        print(f"Erased reviewed file {path}.")
    if inventory(ctx):
        raise DatabaseRefused("new encrypted state appeared during erasure; keys and package retained")
