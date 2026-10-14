"""Checked Windows placement and removal of the Hermes Desktop page (C11).

On ``win32`` the page and its API shim live under the selected Hermes home
(the shared resolver, honoring ``HERMES_HOME``; there is no second Windows
root):

- ``<home>\\desktop-plugins\\mordred\\plugin.js``
- ``<home>\\plugins\\mordred\\dashboard\\{manifest.json,plugin_api.py}``

The Hermes-owned parents (``desktop-plugins``, ``plugins``) are admitted
through the C1b trusted-parent capability and created only when missing.
Mordred's own folders are C1 checked private directories, created one level at
a time; every file is published with ``create_bytes`` (new) or
``replace_bytes`` (changed) inside the folder's transaction and read back.
Unsafe existing state (an inherited or broadened DACL, a foreign owner, a hard
link, a junction) refuses with its classified reason: no ACL is repaired.

Removal deletes only the enumerated asset files, each by its checked identity,
and never a directory: the folders, their permanent ``.mordred-fs.lock`` and
unknown files stay and are reported, because Windows has no checked recursive
removal yet. Heavy imports stay function-local.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from contextlib import AbstractContextManager
from dataclasses import dataclass, field
from functools import partial
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .._private_fs import PrivateDirectory, PrivateFSError, PrivateTransaction

__all__ = ["ASSET_FILES", "Placement", "PlacementRefused", "Removal", "missing", "place", "remove", "targets"]

PAGE = ("desktop-plugins", "mordred")
PLUGIN = ("plugins", "mordred")
API = ("plugins", "mordred", "dashboard")
LEGACY = ("plugins", "mordred", "desktop")
SHARED_PARENTS: tuple[tuple[str, ...], ...] = (("desktop-plugins",), ("plugins",))
#: Package asset name -> (folder parts, file name).
ASSET_FILES: dict[str, tuple[tuple[str, ...], str]] = {
    "desktop/plugin.js": (PAGE, "plugin.js"),
    "dashboard/manifest.json": (API, "manifest.json"),
    "dashboard/plugin_api.py": (API, "plugin_api.py"),
}
_LEGACY_FILES = ("plugin.js",)
_ASSET_LIMIT = 1024 * 1024
_LIST_LIMIT = 4096
LOCK_NAME = ".mordred-fs.lock"


class PlacementRefused(OSError):
    """A classified refusal for one exact path; nothing was repaired."""

    def __init__(self, path: Path, reason: str, operation: str, commit_state: str) -> None:
        uncertain = "; the outcome of the last change is uncertain" if commit_state == "uncertain" else ""
        super().__init__(f'"{path}" refused ({reason}) during {operation}{uncertain}')
        self.path, self.reason, self.operation, self.commit_state = path, reason, operation, commit_state


@dataclass(frozen=True)
class Placement:
    written: tuple[Path, ...]
    unchanged: tuple[Path, ...]
    legacy_removed: tuple[Path, ...]
    legacy_refused: tuple[PlacementRefused, ...] = ()

    @property
    def changed(self) -> bool:
        return bool(self.written or self.legacy_removed)


@dataclass
class Removal:
    removed: list[Path] = field(default_factory=list)
    absent: list[Path] = field(default_factory=list)
    kept: list[Path] = field(default_factory=list)
    refused: list[PlacementRefused] = field(default_factory=list)


# -----------------------------------------------------------------------------
# Openers (seams: the optional and shared-parent openers are Windows-only)
# -----------------------------------------------------------------------------
def _private(path: Path, *, create: bool) -> AbstractContextManager[PrivateDirectory]:
    from .._private_fs import open_private_directory

    return open_private_directory(path, create=create)


def _optional_private(path: Path) -> AbstractContextManager[PrivateDirectory | None]:
    from .._private_fs import open_optional_private_directory

    return open_optional_private_directory(path)


def _admit_shared(path: Path) -> None:
    """A Hermes-owned folder: the trusted-parent capability, created only when missing, never repaired."""
    from .._private_fs import open_confidential_directory

    with open_confidential_directory(path, create=True):
        pass


def _refused(path: Path, exc: PrivateFSError) -> PlacementRefused:
    return PlacementRefused(path, exc.reason, exc.operation, exc.commit_state)


def _missing(exc: PrivateFSError) -> bool:
    return exc.reason == "missing" and exc.commit_state == "not_committed"


def _absent_folder(exc: PrivateFSError) -> bool:
    """A definite missing ancestor (for example ``plugins``): nothing was ever placed there.

    Used only by removal and status, which decide nothing destructive from it.
    """
    return _missing(exc) and exc.operation in ("directory", "open")


# -----------------------------------------------------------------------------
# Placement
# -----------------------------------------------------------------------------
def targets(home: Path) -> dict[str, Path]:
    """Package asset name -> the exact destination file."""
    return {rel: home.joinpath(*parts, name) for rel, (parts, name) in ASSET_FILES.items()}


def _folders() -> dict[tuple[str, ...], tuple[str, ...]]:
    """Asset folders and the file names each holds, in a fixed order."""
    folders: dict[tuple[str, ...], list[str]] = {}
    for parts, name in ASSET_FILES.values():
        folders.setdefault(parts, []).append(name)
    return {parts: tuple(names) for parts, names in folders.items()}


def _read_optional(tx: PrivateTransaction, name: str) -> bytes | None:
    from .._private_fs import PrivateFSError

    try:
        return tx.read_bytes(name, max_bytes=_ASSET_LIMIT)
    except PrivateFSError as exc:
        if _missing(exc):
            return None
        raise


def _publish(directory: Path, files: Mapping[str, bytes], written: list[Path], unchanged: list[Path]) -> None:
    from .._private_fs import PrivateFSError

    with _private(directory, create=True) as checked, checked.transaction() as tx:
        for name, data in files.items():
            current = _read_optional(tx, name)
            if current == data:
                unchanged.append(directory / name)
                continue
            if current is None:
                tx.create_bytes(name, data)
            else:
                tx.replace_bytes(name, data)
            if tx.read_bytes(name, max_bytes=_ASSET_LIMIT) != data:
                raise PrivateFSError("io", "verify", commit_state="uncertain")
            written.append(directory / name)


def _step(path: Path, action: Callable[[], None]) -> None:
    from .._private_fs import PrivateFSError

    try:
        action()
    except PrivateFSError as exc:
        raise _refused(path, exc) from exc


def place(home: Path, assets: Mapping[str, bytes]) -> Placement:
    """Publish changed assets; refuse unsafe state with the exact path. Never repairs or follows links."""
    for shared_parts in SHARED_PARENTS:
        shared = home.joinpath(*shared_parts)
        _step(shared, partial(_admit_shared, shared))
    plugin = home.joinpath(*PLUGIN)

    def admit_plugin() -> None:
        with _private(plugin, create=True):
            pass

    _step(plugin, admit_plugin)
    written: list[Path] = []
    unchanged: list[Path] = []
    for parts in _folders():
        directory = home.joinpath(*parts)
        files = {name: assets[rel] for rel, (where, name) in ASSET_FILES.items() if where == parts}
        _step(directory, partial(_publish, directory, files, written, unchanged))
    # Earlier builds put the page under plugins/mordred/desktop/; drop only its known file.
    legacy = _remove_files(home.joinpath(*LEGACY), _LEGACY_FILES, Removal())
    return Placement(tuple(written), tuple(unchanged), tuple(legacy.removed), tuple(legacy.refused))


# -----------------------------------------------------------------------------
# Removal and status
# -----------------------------------------------------------------------------
def _remove_files(directory: Path, names: tuple[str, ...], result: Removal) -> Removal:
    from .._private_fs import PrivateFSError

    try:
        with _optional_private(directory) as checked:
            if checked is None:
                result.absent.extend(directory / name for name in names)
                return result
            with checked.transaction() as tx:
                for name in names:
                    try:
                        metadata = tx.stat(name)
                    except PrivateFSError as exc:
                        if not _missing(exc):
                            raise
                        result.absent.append(directory / name)
                        continue
                    tx.delete_file(name, expected_identity=metadata.identity)
                    result.removed.append(directory / name)
                leftovers = sorted(name for name in tx.list_names(max_entries=_LIST_LIMIT) if name not in names)
    except PrivateFSError as exc:
        if _absent_folder(exc):
            result.absent.extend(directory / name for name in names)
        else:
            result.refused.append(_refused(directory, exc))
        return result
    result.kept.append(directory)
    result.kept.extend(directory / name for name in leftovers)
    return result


def remove(home: Path) -> Removal:
    """Delete only the enumerated asset files (and the legacy page file); directories always stay."""
    from .._private_fs import PrivateFSError

    result = Removal()
    for parts, names in _folders().items():
        _remove_files(home.joinpath(*parts), names, result)
    legacy = _remove_files(home.joinpath(*LEGACY), _LEGACY_FILES, Removal())
    result.removed.extend(legacy.removed)
    result.kept.extend(legacy.kept)
    result.refused.extend(legacy.refused)
    plugin = home.joinpath(*PLUGIN)
    try:
        with _optional_private(plugin) as checked:
            if checked is not None:
                result.kept.append(plugin)
    except PrivateFSError as exc:
        if not _absent_folder(exc):
            result.refused.append(_refused(plugin, exc))
    return result


def missing(home: Path) -> tuple[list[Path], list[PlacementRefused]]:
    """Asset files that are absent, plus folders that could not be checked; reads only."""
    from .._private_fs import PrivateFSError

    absent: list[Path] = []
    refused: list[PlacementRefused] = []
    for parts, names in _folders().items():
        directory = home.joinpath(*parts)
        try:
            with _optional_private(directory) as checked:
                for name in names:
                    if checked is None:
                        absent.append(directory / name)
                        continue
                    try:
                        checked.stat(name)
                    except PrivateFSError as exc:
                        if not _missing(exc):
                            raise
                        absent.append(directory / name)
        except PrivateFSError as exc:
            if _absent_folder(exc):
                absent.extend(directory / name for name in names)
            else:
                refused.append(_refused(directory, exc))
    return absent, refused
