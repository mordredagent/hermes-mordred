"""Portable Win32 boundary double; real checked path and ACL policy stay active."""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Any, cast

from mordred_hermes._private_fs._types import FileIdentity, PrivateFSError
from mordred_hermes._private_fs._windows_api import Metadata, NativeAPI, OwnedHandle, native_error
from mordred_hermes._private_fs._windows_security import ADMINISTRATORS, SYSTEM, Ace, Descriptor

USER = bytes.fromhex("010100000000000515000000")
HOME = "C:\\Users\\Example\\.hermes"
VOLUME = "\\\\?\\Volume{test}"


@dataclass
class Node:
    path: str
    metadata: Metadata
    descriptor: Descriptor


class WindowsAPI:
    """Model only native handles; this does not qualify Windows lease support."""

    def __init__(self) -> None:
        self.sid = USER
        self.nodes: dict[str, Node] = {}
        self.handles: dict[int, Node] = {}
        self.handle_requests: dict[int, tuple[int, int]] = {}
        self.opens: list[tuple[str, int, int, bool]] = []
        self.flushes: list[str] = []
        self.flush_errors: list[int | None] = []
        self.locks: dict[int, bool] = {}
        self.lock_flags: list[int] = []
        self.unlocks: list[int] = []
        self.lock_errors: list[int] = []
        self.on_lock: Any = None
        self.unlock_error: int | None = None
        self._next_handle = 100
        self._last_error = 0
        for path in ("C:\\", "C:\\Users", "C:\\Users\\Example", HOME):
            self.add(path, directory=True, private=False)

    def _path(self, path: str) -> str:
        path = path.replace("/", "\\").rstrip("\\")
        if path.casefold().startswith(VOLUME.casefold()):
            path = "C:" + path[len(VOLUME) :]
        return path.casefold()

    def add(self, path: str, *, directory: bool, private: bool = True) -> Node:
        node = Node(
            path,
            Metadata(FileIdentity(7, len(self.nodes).to_bytes(16, "little")), directory, False, 1, 0),
            Descriptor(
                USER, private, [Ace(0, 0 if private else 0x13, 0x1F01FF, sid) for sid in (USER, SYSTEM, ADMINISTRATORS)]
            ),
        )
        self.nodes[self._path(path)] = node
        return node

    def node(self, path: str) -> Node:
        return self.nodes[self._path(path)]

    def change_identity(self, path: str) -> None:
        node = self.node(path)
        node.metadata = replace(node.metadata, identity=FileIdentity(7, b"changed-identity"))

    def open(self, path: str, *, access: int = 0x120089, share: int = 3, create: bool = False) -> OwnedHandle:
        self.opens.append((path, access, share, create))
        key = self._path(path)
        if create:
            if key in self.nodes:
                raise PrivateFSError("exists", "create", native_code=80)
            self.add(path, directory=False)
        if key not in self.nodes:
            raise PrivateFSError("missing", "open", native_code=2)
        value = self._next_handle
        self._next_handle += 1
        self.handles[value] = self.nodes[key]
        self.handle_requests[value] = (access, share)
        return OwnedHandle(cast(NativeAPI, self), value)

    def mkdir(self, path: str) -> None:
        if self._path(path) in self.nodes:
            raise PrivateFSError("exists", "mkdir", native_code=183)
        self.add(path, directory=True)

    def metadata(self, handle: OwnedHandle) -> Metadata:
        assert handle.value is not None
        return self.handles[handle.value].metadata

    def descriptor(self, handle: OwnedHandle) -> Descriptor:
        assert handle.value is not None
        return self.handles[handle.value].descriptor

    def final_path(self, handle: OwnedHandle) -> str:
        assert handle.value is not None
        path = self.handles[handle.value].path.replace("/", "\\")
        if path.casefold().startswith(VOLUME.casefold()):
            return path
        return VOLUME + path[2:]

    def user_sid(self) -> bytes:
        return self.sid

    def validate_drive(self, drive: str) -> None:
        if drive != "C:\\":
            raise PrivateFSError("unsupported", "drive")

    def validate_volume(self, handle: OwnedHandle) -> None:
        assert self.metadata(handle).identity.volume == 7

    def flush(self, handle: OwnedHandle) -> None:
        assert handle.value is not None
        node = self.handles[handle.value]
        assert node.metadata.directory
        assert self.handle_requests[handle.value] == (0xC0000000, 3)
        self.flushes.append(node.path)
        error = self.flush_errors.pop(0) if self.flush_errors else None
        if error is not None:
            raise native_error(error, "flush")

    def Lock(self, value: int, flags: int, reserved: int, low: int, high: int, overlap: Any) -> bool:
        assert reserved == high == 0 and low == 1
        assert overlap._obj.offset == overlap._obj.offset_high == 0
        self.lock_flags.append(flags)
        if self.on_lock is not None:
            self.on_lock()
        if self.lock_errors:
            self._last_error = self.lock_errors.pop(0)
            return False
        shared = flags == 1
        if self.locks and (not shared or not all(self.locks.values())):
            self._last_error = 33
            return False
        self.locks[value] = shared
        return True

    def checked(self, result: Any, operation: str) -> None:
        if not result:
            raise native_error(self._last_error, operation)

    def unlock(self, handle: OwnedHandle) -> None:
        assert handle.value is not None
        self.unlocks.append(handle.value)
        if self.unlock_error is not None:
            raise native_error(self.unlock_error, "unlock")
        del self.locks[handle.value]

    def CloseHandle(self, value: int) -> bool:
        del self.handles[value]
        del self.handle_requests[value]
        self.locks.pop(value, None)
        return True
