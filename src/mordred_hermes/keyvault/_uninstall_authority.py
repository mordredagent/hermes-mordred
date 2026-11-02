"""SQL-free, ephemeral uninstall authority. Never ambient mutation permission."""

from __future__ import annotations

import hashlib
import stat
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from .._database_contracts import DatabaseRefused, Dependency, NativeSnapshot
from .._database_inventory import scan_dependencies
from .._database_lifecycle import ExclusiveLease

Purpose = Literal["restore", "delete"]


class UninstallAuthorization:
    """Opaque identity; constructing/copying attributes cannot grant authority."""

    __slots__ = ()

    def __new__(cls) -> UninstallAuthorization:
        raise DatabaseRefused("uninstall authority is issued only after database verification")


@dataclass(frozen=True)
class _Record:
    root: Path
    lease: ExclusiveLease
    purpose: Purpose
    snapshot: NativeSnapshot | None
    inventory: tuple[tuple[object, ...], ...]
    windows_source: tuple[tuple[str, bytes], ...] = ()


_ACTIVE: dict[UninstallAuthorization, _Record] = {}


def fingerprint(root: Path) -> tuple[tuple[object, ...], ...]:
    inventory = scan_dependencies(root)
    if not inventory.complete:
        raise DatabaseRefused("database dependency inventory is incomplete")
    result = []
    for entry in inventory.entries:
        info = entry.path.lstat()
        if entry.path != entry.path.resolve(strict=True):
            raise DatabaseRefused("database dependency path changed")
        # Include every ancestor's physical identity, without directory mtimes:
        # unrelated config cleanup must not invalidate a checked DB inventory.
        parents = tuple((p, p.stat().st_dev, p.stat().st_ino) for p in entry.path.parents)
        result.append((entry, info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns, parents))
    return tuple(result) + profile_fingerprint(root)


@contextmanager
def _issue(
    root: Path,
    lease: ExclusiveLease,
    purpose: Purpose,
    snapshot: NativeSnapshot | None,
    expected: tuple[tuple[object, ...], ...],
) -> Iterator[UninstallAuthorization]:
    ExclusiveLease.assert_held(lease, root)
    if fingerprint(root) != expected:
        raise DatabaseRefused("database dependencies changed before permit issuance")
    permit = object.__new__(UninstallAuthorization)
    _ACTIVE[permit] = _Record(root, lease, purpose, snapshot, expected, _windows_source(root, snapshot))
    try:
        yield permit
    finally:
        _ACTIVE.pop(permit, None)


def check_authorization(permit: UninstallAuthorization, *, root: Path, lease: ExclusiveLease, purpose: Purpose) -> None:
    record = _ACTIVE.get(permit) if type(permit) is UninstallAuthorization else None
    if record is None or record.root != root or record.lease is not lease:
        raise DatabaseRefused("uninstall authority is absent, expired or belongs to another operation")
    ExclusiveLease.assert_held(lease, root)
    if purpose == "delete" and record.purpose != "delete":
        raise DatabaseRefused("restore authority cannot authorize key/helper deletion")
    if record.snapshot is not None and record.snapshot.provider == "cng":
        if _windows_source(root, record.snapshot) != record.windows_source:
            raise DatabaseRefused("uninstall native source generation changed")
    elif record.snapshot is not None:
        # Public metadata only: no SQL and no native-key authentication.
        from ._database_authority import observe_database_source

        if observe_database_source(root=root) != record.snapshot:
            raise DatabaseRefused("uninstall native source generation changed")
    if fingerprint(root) != record.inventory:
        raise DatabaseRefused("database dependencies changed after uninstall verification")
    ExclusiveLease.assert_held(lease, root)


def _windows_source(root: Path, snapshot: NativeSnapshot | None) -> tuple[tuple[str, bytes], ...]:
    if snapshot is None or snapshot.provider != "cng":
        return ()
    from .._private_fs import open_private_directory

    with open_private_directory(root / "mordred") as directory:
        return tuple(
            (name, hashlib.sha256(directory.read_bytes(name, max_bytes=8 * 1024 * 1024)).digest())
            for name in ("windows-custody.json", "memory-key.wrapped")
        )


def profile_fingerprint(root: Path) -> tuple[tuple[object, ...], ...]:
    """Bind direct profile membership/physical identity, even with no DB files."""
    directory = root / "profiles"
    try:
        info = directory.lstat()
    except FileNotFoundError:
        return ((Dependency(directory, "unknown", None), "absent"),)
    if not stat.S_ISDIR(info.st_mode) or directory.resolve() != directory:
        raise DatabaseRefused("profile directory is not a physical directory")
    result: list[tuple[object, ...]] = [
        (Dependency(directory, "unknown", None), "profiles", info.st_dev, info.st_ino, info.st_mode)
    ]
    for path in sorted(directory.iterdir()):
        info = path.lstat()
        result.append((Dependency(path, "unknown", None), "profile", info.st_dev, info.st_ino, info.st_mode))
    return tuple(result)
