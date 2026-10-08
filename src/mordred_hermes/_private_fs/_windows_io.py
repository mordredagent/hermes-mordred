"""Private Windows reads and staged publication with an explicit commit point."""

from __future__ import annotations

import contextlib
import secrets
import threading
from collections.abc import Iterator
from pathlib import Path

from ._types import PrivateDirectory, PrivateFSError, PrivateTransaction
from ._windows_api import OwnedHandle
from ._windows_lock import exclusive_lock
from ._windows_paths import CheckedDirectory, checked_directory, windows_leaf
from ._windows_security import validate_private


@contextlib.contextmanager
def open_private_directory(path: str | Path, *, create: bool = False) -> Iterator[PrivateDirectory]:
    with checked_directory(path, create=create) as checked:
        directory = _Directory(checked)
        try:
            yield directory
        finally:
            directory.active = False


class _Directory:
    def __init__(self, checked: CheckedDirectory) -> None:
        self.checked = checked
        self.active = True

    def check(self) -> None:
        if not self.active:
            raise RuntimeError("private directory is closed")
        validate_private(self.checked.handle, directory=True)
        if self.checked.handle.api.metadata(self.checked.handle).identity != self.checked.identity:
            raise PrivateFSError("unsafe", "directory_identity")

    def path(self, name: str) -> str:
        windows_leaf(name)
        return self.checked.path + "\\" + name

    @contextlib.contextmanager
    def opened(self, name: str) -> Iterator[OwnedHandle]:
        self.check()
        api = self.checked.handle.api
        with api.open(self.path(name), access=0x120089, share=7) as handle:
            validate_private(handle, directory=False)
            yield handle

    def read_bytes(self, name: str, *, max_bytes: int) -> bytes:
        self.check()
        if max_bytes <= 0:
            raise ValueError("max_bytes must be positive")
        with self.opened(name) as handle:
            chunks: list[bytes] = []
            size = 0
            while size <= max_bytes:
                data = handle.api.read(handle, min(65536, max_bytes + 1 - size))
                if not data:
                    return b"".join(chunks)
                size += len(data)
                chunks.append(data)
        raise PrivateFSError("unsafe", "read_limit")

    @contextlib.contextmanager
    def transaction(self, *, blocking: bool = True) -> Iterator[PrivateTransaction]:
        self.check()
        with exclusive_lock(self.checked, blocking=blocking):
            transaction = _Transaction(self)
            try:
                yield transaction
            finally:
                transaction.active = False


class _Transaction:
    def __init__(self, directory: _Directory) -> None:
        self.directory = directory
        self.active = True
        self.thread = threading.get_ident()

    def check(self) -> None:
        self.directory.check()
        if not self.active or self.thread != threading.get_ident():
            raise RuntimeError("private transaction is closed or belongs to another thread")

    def read_bytes(self, name: str, *, max_bytes: int) -> bytes:
        self.check()
        return self.directory.read_bytes(name, max_bytes=max_bytes)

    def create_bytes(self, name: str, data: bytes) -> None:
        self.write(name, data, replace=False)

    def replace_bytes(self, name: str, data: bytes) -> None:
        self.write(name, data, replace=True)

    def write(self, name: str, data: bytes, *, replace: bool) -> None:
        self.check()
        destination = self.directory.path(name)
        api = self.directory.checked.handle.api
        if replace:
            with self.directory.opened(name):
                pass
        temporary = self.directory.checked.path + "\\.mordred-fs-tmp-" + secrets.token_hex(16)
        safe_to_discard = True
        try:
            with api.open(temporary, access=0xC0030000, share=0, create=True) as staging:
                try:
                    validate_private(staging, directory=False)
                    identity = api.metadata(staging).identity
                    _write_staging(staging, data)
                    self.directory.check()
                    if replace:
                        with self.directory.opened(name):
                            pass
                    safe_to_discard = False
                    try:
                        publish(staging, self.directory.checked, name, replace=replace)
                    except PrivateFSError as exc:
                        safe_to_discard = exc.commit_state == "not_committed"
                        raise
                    validate_private(staging, directory=False)
                    if (
                        api.metadata(staging).identity != identity
                        or api.final_path(staging).casefold() != destination.casefold()
                    ):
                        raise PrivateFSError("unsafe", "published_identity", commit_state="uncertain")
                    api.flush(staging)
                finally:
                    if safe_to_discard:
                        with contextlib.suppress(OSError):
                            api.discard(staging)
        except PrivateFSError as exc:
            if not safe_to_discard and exc.commit_state != "uncertain":
                raise PrivateFSError(
                    exc.reason, exc.operation, native_code=exc.native_code, commit_state="uncertain"
                ) from exc
            raise


def publish(staging: OwnedHandle, directory: CheckedDirectory, name: str, *, replace: bool) -> None:
    """Classify a rename failure before allowing any staging cleanup or retry."""
    windows_leaf(name)
    source = staging.api.final_path(staging)
    destination = directory.path + "\\" + name
    try:
        staging.api.rename(staging, destination, replace=replace)
    except PrivateFSError as exc:
        try:
            unchanged = staging.api.final_path(staging).casefold() == source.casefold()
        except OSError as query_error:
            raise PrivateFSError(
                exc.reason, "rename", native_code=exc.native_code, commit_state="uncertain"
            ) from query_error
        if not unchanged:
            raise PrivateFSError(exc.reason, "rename", native_code=exc.native_code, commit_state="uncertain") from exc
        raise


def _write_staging(staging: OwnedHandle, data: bytes) -> None:
    offset = 0
    while offset < len(data):
        count = staging.api.write(staging, data[offset : offset + 65536])
        if count <= 0:
            raise PrivateFSError("io", "zero_write")
        offset += count
    staging.api.flush(staging)
