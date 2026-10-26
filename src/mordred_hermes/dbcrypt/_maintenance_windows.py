"""Prepared Windows maintenance route; production remains qualification gated.

Only internal EX-owned SQL can replace the default native authorizer. Its one
ATTACH destination is a checked, reserved staging inode under the registered
root. Runtime authorizers, extension loading policy, and native C are unchanged.
"""

from __future__ import annotations

import contextlib
from collections.abc import Iterator
from pathlib import Path
from typing import Any
from urllib.parse import quote

from .._database_contracts import DatabaseRefused
from .._database_lifecycle import ExclusiveLease, current_thread_exclusive_leases
from .._private_fs import open_private_directory


def require_qualified() -> None:
    from ._windows_vfs import NATIVE_QUALIFIED

    if not NATIVE_QUALIFIED:
        raise DatabaseRefused("Windows database maintenance awaits native qualification")


def exclusive_root(path: Path, requested: Path | None = None) -> tuple[Path, ExclusiveLease]:
    candidates = (requested,) if requested is not None else tuple(path.parents)
    for lease in current_thread_exclusive_leases():
        for root in candidates:
            try:
                ExclusiveLease.assert_held(lease, root)
            except (DatabaseRefused, OSError):
                continue
            return root, lease
    raise DatabaseRefused("Windows offline SQL requires a preceding exclusive root lease")


def authorizer(target: Path | None, alias: str | None) -> Any:
    import sqlcipher3.dbapi2 as sc

    def authorize(action: int, first: Any, second: Any, database: Any, trigger: Any) -> int:
        if action == sc.SQLITE_ATTACH:
            return int(sc.SQLITE_OK) if target is not None and first == str(target) else int(sc.SQLITE_DENY)
        if action == sc.SQLITE_DETACH:
            return int(sc.SQLITE_OK) if alias is not None and first == alias else int(sc.SQLITE_DENY)
        if action == sc.SQLITE_FUNCTION and str(second).casefold() == "load_extension":
            return int(sc.SQLITE_DENY)
        if action == sc.SQLITE_PRAGMA and second is not None:
            name, value = str(first).casefold(), str(second).casefold()
            if (
                name in {"temp_store_directory", "data_store_directory"}
                or (name == "temp_store" and value not in {"memory", "2"})
                or (name == "mmap_size" and value != "0")
            ):
                return int(sc.SQLITE_DENY)
        return int(sc.SQLITE_OK)

    return authorize


@contextlib.contextmanager
def connection(
    path: Path,
    *,
    readonly: bool = False,
    target: Path | None = None,
    alias: str | None = None,
    root: Path | None = None,
) -> Iterator[Any]:
    require_qualified()
    root, lease = exclusive_root(path, root)
    import sqlcipher3.dbapi2 as sc

    from ._windows_vfs import classify_windows_database, register_checked_vfs

    registered_root = root if path.is_relative_to(root) else path.parent
    checked = classify_windows_database(str(path), uri=False, root=registered_root)
    if checked != path:
        raise DatabaseRefused("offline Windows path is not canonical")
    if target is not None:
        if alias not in {"enc", "plain"} or not target.is_relative_to(registered_root):
            raise DatabaseRefused("Windows export staging is outside its checked root")
        classify_windows_database(str(target), uri=False, root=registered_root)
        with open_private_directory(target.parent) as directory:
            identity = directory.stat(target.name).identity
    else:
        identity = None
    registration = register_checked_vfs(sc, root=registered_root)
    raw = None
    try:
        mode = "ro" if readonly else "rw"
        uri = f"file:{quote(path.as_posix(), safe='/:')}?mode={mode}&vfs=mordred_checked_v1"
        from ._connection import _MaintenanceConnection

        raw = _MaintenanceConnection(sc.connect(uri, uri=True, timeout=0, cached_statements=0))
        raw._install_export_policy(target, alias)
        lease.assert_held(root)
        yield raw
        lease.assert_held(root)
        if target is not None:
            with open_private_directory(target.parent) as directory:
                if directory.stat(target.name).identity != identity:
                    raise DatabaseRefused("Windows export staging identity changed")
    finally:
        if raw is not None:
            raw.close()
        registration.close()


def holders(paths: list[Path]) -> list[int] | None:
    """A checked share-zero handle proves quiescence; uncertainty refuses."""
    require_qualified()
    try:
        for path in paths:
            with open_private_directory(path.parent) as directory, directory.transaction() as tx:
                tx.flush_file(path.name, expected_identity=tx.stat(path.name).identity)
    except OSError:
        return None
    return []
