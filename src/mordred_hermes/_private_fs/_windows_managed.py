"""Read-only managed installation image admission, with pinned NTFS ancestry.

This is narrower than public build input admission and grants no filesystem or
process authority. Metadata cannot prove who owns a process or whether its
native image embeds an interpreter. No descriptors, locks or bytes are written.
"""

from __future__ import annotations

import contextlib
import os
from dataclasses import dataclass
from pathlib import Path

from ._types import FileMetadata, PrivateFSError
from ._windows_api import Metadata, OwnedHandle, get_api
from ._windows_paths import split_path
from ._windows_security import Descriptor, check_managed_image


@dataclass(frozen=True)
class _Observation:
    handle: OwnedHandle
    path: str
    metadata: Metadata
    descriptor: Descriptor
    file: FileMetadata | None


def _observe(
    handle: OwnedHandle, path: str, volume: int, user: bytes, service: bytes, *, directory: bool
) -> _Observation:
    api = handle.api
    info = api.metadata(handle)
    if (
        info.directory != directory
        or info.reparse
        or info.identity.volume != volume
        or info.links < 1
        or not 0 <= info.size <= (1 << 63) - 1
    ):
        raise PrivateFSError("unsafe", "managed_image_metadata")
    descriptor = api.descriptor(handle)
    check_managed_image(descriptor, user, service, directory=directory)
    if api.final_path(handle).casefold() != path.casefold():
        raise PrivateFSError("unsafe", "managed_image_path")
    file = None
    if not directory:
        mtime = api.mtime_ns(handle)
        # BasicInfo exposes a signed FILETIME. Reject impossible timestamps,
        # while allowing pre-Unix-epoch files and 100ns native resolution.
        if not 0 <= mtime + 11644473600000000000 <= ((1 << 63) - 1) * 100 or mtime % 100:
            raise PrivateFSError("unsafe", "managed_image_mtime")
        file = FileMetadata(info.identity, info.size, mtime)
    return _Observation(handle, path, info, descriptor, file)


def _recheck(original: _Observation, handle: OwnedHandle, user: bytes, service: bytes) -> None:
    fresh = _observe(
        handle, original.path, original.metadata.identity.volume, user, service, directory=original.metadata.directory
    )
    if fresh.metadata != original.metadata or fresh.descriptor != original.descriptor or fresh.file != original.file:
        raise PrivateFSError("unsafe", "managed_image_changed")


def inspect_managed_installation_image(path: str | Path) -> FileMetadata:
    raw = os.fspath(path)
    if len(raw) > 32767:
        raise PrivateFSError("unsafe", "managed_image_bound")
    try:
        length = len(raw.encode("utf-16-le")) // 2
    except UnicodeError as exc:
        raise PrivateFSError("unsafe", "managed_image_path") from exc
    if length > 32767 or raw.replace("/", "\\").count("\\") > 256:
        raise PrivateFSError("unsafe", "managed_image_bound")
    drive, parts = split_path(path)
    api = get_api()
    user, service = api.user_sid(), api.managed_service_sid()
    api.validate_drive(drive)
    with contextlib.ExitStack() as stack:
        root = stack.enter_context(api.open(drive, access=0x20080, share=1))
        api.validate_volume(root)
        root_path = api.final_path(root)
        closing = root_path.find("}")
        if not root_path.startswith("\\\\?\\Volume{") or closing < 0 or root_path[closing + 1 :] != "\\":
            raise PrivateFSError("unsupported", "managed_image_root")
        volume = api.metadata(root).identity.volume
        observations = [_observe(root, root_path, volume, user, service, directory=True)]
        for index, part in enumerate(parts):
            directory = index < len(parts) - 1
            bound = observations[-1].path.rstrip("\\") + "\\" + part
            handle = stack.enter_context(api.open(bound, access=0x20080 if directory else 0x20081, share=1))
            observations.append(_observe(handle, bound, volume, user, service, directory=directory))
        for original in observations:
            _recheck(original, original.handle, user, service)
        # Reopen the drive as well as each GUID-bound name: a concurrent DOS
        # mapping change must not return an observation of the old namespace.
        api.validate_drive(drive)
        for index, original in enumerate(observations):
            with api.open(
                drive if index == 0 else original.path,
                access=0x20080 if original.metadata.directory else 0x20081,
                share=1,
            ) as named:
                _recheck(original, named, user, service)
        for original in observations:
            _recheck(original, original.handle, user, service)
        if api.user_sid() != user:
            raise PrivateFSError("unsafe", "managed_image_principal")
        result = observations[-1].file
        assert result is not None
    # All named and pinned handles must close successfully before metadata exits.
    return result
