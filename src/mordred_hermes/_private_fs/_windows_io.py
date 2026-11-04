"""Private Windows reads and staged publication with an explicit commit point."""

from __future__ import annotations

import contextlib
import os
import secrets
import sys
import threading
from collections.abc import Iterator
from pathlib import Path

from ._types import (
    ConfidentialDirectory,
    FileIdentity,
    FileMetadata,
    PrivateDirectory,
    PrivateFSError,
    PrivateTransaction,
    cleanup_failure,
    reserved,
    validate_limit,
)
from ._windows_api import NativeAPI, OwnedHandle
from ._windows_lock import exclusive_lock
from ._windows_paths import CheckedDirectory, checked_directory, checked_directory_optional, windows_leaf
from ._windows_security import validate_confidential_file, validate_private


@contextlib.contextmanager
def open_private_directory(path: str | Path, *, create: bool = False) -> Iterator[PrivateDirectory]:
    directory: _Directory | None = None
    try:
        with checked_directory(path, create=create) as checked:
            directory = _Directory(checked)
            try:
                yield directory
            finally:
                directory.active = False
    except PrivateFSError as exc:
        if directory is not None and directory.published:
            exc.commit_state = "uncertain"
        raise


@contextlib.contextmanager
def open_confidential_directory(path: str | Path, *, create: bool = False) -> Iterator[ConfidentialDirectory]:
    with _open_directory(path, create=create, confidential=True) as directory:
        assert directory is not None
        yield directory


@contextlib.contextmanager
def open_optional_confidential_directory(path: str | Path) -> Iterator[ConfidentialDirectory | None]:
    with _open_directory(path, confidential=True, optional=True) as directory:
        yield directory


@contextlib.contextmanager
def open_optional_private_directory(path: str | Path) -> Iterator[PrivateDirectory | None]:
    with _open_directory(path, optional=True) as directory:
        yield directory


@contextlib.contextmanager
def _open_directory(
    path: str | Path,
    *,
    create: bool = False,
    confidential: bool = False,
    optional: bool = False,
) -> Iterator[_Directory | None]:
    directory: _Directory | None = None
    try:
        with checked_directory_optional(path, create=create, confidential=confidential, optional=optional) as checked:
            if checked is None:
                yield None
            else:
                directory = _Directory(checked)
                try:
                    yield directory
                finally:
                    directory.active = False
    except PrivateFSError as exc:
        if directory is not None and directory.published:
            exc.commit_state = "uncertain"
        raise


class _Directory:
    def __init__(self, checked: CheckedDirectory) -> None:
        self.checked = checked
        self.active = True
        self.published = False
        self.pid = os.getpid()
        self.thread = threading.get_ident()
        self._custody_read: _CustodyReadScope | None = None

    def check(self) -> None:
        if not self.active or self.pid != os.getpid() or self.thread != threading.get_ident():
            raise RuntimeError("private directory is closed")
        if self._custody_read is None:
            self.checked.check()
        else:
            self._custody_read.check_lifetime()

    def directory_identity(self) -> FileIdentity:
        self.check()
        return self.checked.identity

    def validate_file(self, handle: OwnedHandle) -> None:
        if self.checked.confidential:
            validate_confidential_file(handle)
        else:
            validate_private(handle, directory=False)

    def file_identity(self, handle: OwnedHandle, expected: FileIdentity | None) -> FileIdentity:
        self.validate_file(handle)
        identity = handle.api.metadata(handle).identity
        if expected is not None and identity != expected:
            raise PrivateFSError("unsafe", "identity")
        return identity

    def verify_read(self, handle: OwnedHandle, name: str, identity: FileIdentity) -> None:
        if not self.checked.confidential:
            return
        self.check()
        self.file_identity(handle, identity)
        path = self.path(name)
        if handle.api.final_path(handle).casefold() != path.casefold():
            raise PrivateFSError("unsafe", "file_path")
        with handle.api.open(path, share=7) as named:
            self.file_identity(named, identity)
        self.check()

    def path(self, name: str) -> str:
        windows_leaf(name)
        return self.checked.path + "\\" + name

    @contextlib.contextmanager
    def opened(self, name: str, *, access: int = 0x120089, share: int = 7) -> Iterator[OwnedHandle]:
        path = self.path(name)
        self.check()
        api = self.checked.handle.api
        with api.open(path, access=access, share=share) as handle:
            self.validate_file(handle)
            if api.final_path(handle).casefold() != path.casefold():
                raise PrivateFSError("unsafe", "file_path")
            yield handle

    def stat(self, name: str) -> FileMetadata:
        self.path(name)
        self.check()
        with self.opened(name) as handle:
            metadata = handle.api.metadata(handle)
            result = FileMetadata(metadata.identity, metadata.size, handle.api.mtime_ns(handle))
            self.verify_read(handle, name, metadata.identity)
            return result

    def read_prefix(self, name: str, *, max_bytes: int) -> bytes:
        self.path(name)
        validate_limit(max_bytes)
        self.check()
        with self.opened(name) as handle:
            remaining = max_bytes
            chunks: list[bytes] = []
            while remaining:
                data = handle.api.read(handle, min(65536, remaining))
                if not data:
                    break
                chunks.append(data)
                remaining -= len(data)
            return b"".join(chunks)

    def list_names(self, *, max_entries: int) -> tuple[str, ...]:
        validate_limit(max_entries)
        self.check()
        names: list[str] = []
        for examined, name in enumerate(self.checked.handle.api.names(self.checked.handle), 1):
            if examined > max_entries + 1:
                raise PrivateFSError("unsafe", "list_limit")
            if reserved(name):
                continue
            windows_leaf(name)
            if len(names) == max_entries:
                raise PrivateFSError("unsafe", "list_limit")
            names.append(name)
        self.check()
        return tuple(sorted(names))

    def read_bytes(self, name: str, *, max_bytes: int) -> bytes:
        windows_leaf(name)
        validate_limit(max_bytes)
        self.check()
        if max_bytes <= 0:
            raise ValueError("max_bytes must be positive")
        with self.opened(name) as handle:
            identity = handle.api.metadata(handle).identity
            chunks: list[bytes] = []
            size = 0
            while size <= max_bytes:
                data = handle.api.read(handle, min(65536, max_bytes + 1 - size))
                if not data:
                    self.verify_read(handle, name, identity)
                    return b"".join(chunks)
                size += len(data)
                chunks.append(data)
        raise PrivateFSError("unsafe", "read_limit")

    @contextlib.contextmanager
    def transaction(self, *, blocking: bool = True) -> Iterator[PrivateTransaction]:
        self.check()
        transaction = _Transaction(self)
        try:
            with exclusive_lock(self.checked, blocking=blocking):
                try:
                    yield transaction
                finally:
                    transaction.active = False
        except PrivateFSError as exc:
            if transaction.published:
                exc.commit_state = "uncertain"
            raise


class _Transaction:
    def __init__(self, directory: _Directory) -> None:
        self.directory = directory
        self.active = True
        self.thread = threading.get_ident()
        self.published = False

    def check(self) -> None:
        if not self.active or self.thread != threading.get_ident():
            raise RuntimeError("private transaction is closed or belongs to another thread")
        self.directory.check()

    def _check_write(self) -> None:
        self.check()
        if self.directory._custody_read is not None:
            raise RuntimeError("mutation inside custody read")

    def assert_private_admission(self) -> None:
        """Validate lifetime/security and require exact-private admission."""
        self.check()
        if self.directory.checked.confidential:
            raise PrivateFSError("unsafe", "private_admission")

    def directory_identity(self) -> FileIdentity:
        self.check()
        return self.directory.directory_identity()

    def read_bytes(self, name: str, *, max_bytes: int) -> bytes:
        windows_leaf(name)
        validate_limit(max_bytes)
        self.check()
        return self.directory.read_bytes(name, max_bytes=max_bytes)

    def stat(self, name: str) -> FileMetadata:
        windows_leaf(name)
        self.check()
        return self.directory.stat(name)

    def read_prefix(self, name: str, *, max_bytes: int) -> bytes:
        windows_leaf(name)
        validate_limit(max_bytes)
        self.check()
        return self.directory.read_prefix(name, max_bytes=max_bytes)

    def list_names(self, *, max_entries: int) -> tuple[str, ...]:
        validate_limit(max_entries)
        self.check()
        return self.directory.list_names(max_entries=max_entries)

    def _mark_mutated(self) -> None:
        self.published = self.directory.published = True

    def flush_directory(self) -> None:
        self._check_write()
        self.directory.checked.flush()

    def flush_file(self, name: str, *, expected_identity: FileIdentity | None = None) -> None:
        """Flush a checked owned file; share-zero also refuses active holders."""
        self._check_write()
        with self.directory.opened(name, access=0x40120089, share=0) as handle:
            identity = _check_identity(handle, expected_identity)
            handle.api.flush(handle)
            _check_identity(handle, identity)
        if self.directory.stat(name).identity != identity:
            raise PrivateFSError("unsafe", "flush_identity")

    def delete_file(self, name: str, *, expected_identity: FileIdentity | None = None) -> None:
        self.directory.path(name)
        self._check_write()
        attempted = False
        try:
            with self.directory.opened(name, access=0x40130089, share=0) as handle:
                self.directory.file_identity(handle, expected_identity)
                self.flush_directory()  # Admit writable parent before disposition.
                attempted = True
                handle.api.discard(handle)
            self._absent(name)
            self.flush_directory()  # Disposition takes effect on CLOSE, not before.
        except PrivateFSError as exc:
            if attempted:
                exc.commit_state = "uncertain"
            raise
        finally:
            if attempted:
                self._mark_mutated()

    def _absent(self, name: str) -> None:
        self.directory.check()
        api = self.directory.checked.handle.api
        try:
            handle = api.open(self.directory.path(name), share=0)
        except PrivateFSError as exc:
            if exc.reason == "missing":
                return
            raise
        with handle:
            raise PrivateFSError("unsafe", "expected_absent")

    def rename_file(self, name: str, destination: str, *, expected_identity: FileIdentity | None = None) -> None:
        source_path = self.directory.path(name)
        destination_path = self.directory.path(destination)
        self._check_write()
        changed = False
        try:
            with self.directory.opened(name, access=0x40130089, share=0) as handle:
                identity = _check_identity(handle, expected_identity)
                self.flush_directory()  # Admit writable parent before rename.
                changed = True
                try:
                    handle.api.rename(handle, destination_path, replace=False)
                except PrivateFSError as exc:
                    try:
                        _check_identity(handle, identity)
                        unchanged = handle.api.final_path(handle).casefold() == source_path.casefold()
                    except OSError:
                        unchanged = False
                    if unchanged:
                        changed = False
                    else:
                        exc.commit_state = "uncertain"
                    raise
                handle.api.flush(handle)
                _check_identity(handle, identity)
                if handle.api.final_path(handle).casefold() != destination_path.casefold():
                    raise PrivateFSError("unsafe", "renamed_identity")
            self._absent(name)
            if self.directory.stat(destination).identity != identity:
                raise PrivateFSError("unsafe", "renamed_identity")
            self.flush_directory()
        except PrivateFSError as exc:
            if changed:
                exc.commit_state = "uncertain"
            raise
        finally:
            if changed:
                self._mark_mutated()

    def append_bytes(self, name: str, data: bytes) -> None:
        path = self.directory.path(name)
        self._check_write()
        changed = False
        try:
            with self.directory.opened(name, access=0xC0020000, share=0) as handle:
                api = handle.api
                identity = _check_identity(handle, None)
                self.flush_directory()  # Admit writable parent before changing bytes.
                length = api.metadata(handle).size
                api.seek(handle, length)
                changed = True
                try:
                    _write_staging(handle, data)
                    _check_identity(handle, identity)
                except PrivateFSError as exc:
                    try:
                        _check_identity(handle, identity)
                        if api.final_path(handle).casefold() != path.casefold():
                            raise PrivateFSError("unsafe", "append_identity")
                        api.truncate(handle, length)
                        api.flush(handle)
                        changed = False
                    except OSError as rollback:
                        exc.add_note(f"append rollback failed: {type(rollback).__name__}")
                    raise
        except PrivateFSError as exc:
            if changed:
                exc.commit_state = "uncertain"
            raise
        finally:
            if changed:
                self._mark_mutated()

    def create_bytes(self, name: str, data: bytes) -> None:
        self.write(name, data, replace=False)

    def replace_bytes(self, name: str, data: bytes) -> None:
        self.write(name, data, replace=True)

    def write(self, name: str, data: bytes, *, replace: bool) -> None:
        self._check_write()
        destination = self.directory.path(name)
        api = self.directory.checked.handle.api
        if replace:
            with self.directory.opened(name):
                pass
        self.flush_directory()  # Admit writable parent before staging creation.
        temporary = self.directory.checked.path + "\\.mordred-fs-tmp-" + secrets.token_hex(16)
        safe_to_discard = True
        cleanup_attempted = False
        try:
            with _created_staging(api, temporary) as staging:
                try:
                    validate_private(staging, directory=False)
                    identity = api.metadata(staging).identity
                    _write_staging(staging, data)
                    safe_to_discard = False
                    self.flush_directory()  # Persist the new staging name before publication.
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
                    api.flush(staging)
                    validate_private(staging, directory=False)
                    if (
                        api.metadata(staging).identity != identity
                        or api.final_path(staging).casefold() != destination.casefold()
                    ):
                        raise PrivateFSError("unsafe", "published_identity", commit_state="uncertain")
                    self.directory.check()
                finally:
                    if not safe_to_discard:
                        self.published = True
                        self.directory.published = True
                    if safe_to_discard:
                        cleanup_attempted = True
                        _discard_staging(staging, sys.exception())
            self.flush_directory()
        except PrivateFSError as exc:
            if cleanup_attempted:
                self._flush_cleanup(exc)
            if not safe_to_discard and exc.commit_state != "uncertain":
                exc.commit_state = "uncertain"
            raise

    def _flush_cleanup(self, error: PrivateFSError) -> None:
        try:
            self.flush_directory()
        except OSError as cleanup:
            cleanup_failure(error, cleanup, committed=True)


class _CustodyReadScope:
    """Coalesce only the canonical loan's held home/policy traversals.

    The coordinator owns these directory/transaction lifetimes across the
    entire read. This is not a path or HANDLE cache: every skipped traversal
    checks the exact enrolled objects and each pinned handle's open lifetime.
    Leaf and coordinator checks still run, with fresh directory validation
    before entry and on every exit (including exceptional/missing reads).
    """

    def __init__(self, home: _Transaction, policy: _Transaction) -> None:
        self.transactions = (home, policy)
        self.directories = (home.directory, policy.directory)
        self.checked = tuple(directory.checked for directory in self.directories)
        self.handles = tuple(
            (handle, handle.api, handle.value, handle._lifetime)
            for checked in self.checked
            for handle in (checked.handle, *(handle for handle, _ in checked.ancestors))
        )
        self.pid, self.thread = os.getpid(), threading.get_ident()

    def check_lifetime(self) -> None:
        if self.pid != os.getpid() or self.thread != threading.get_ident():
            raise RuntimeError("custody read belongs to another process or thread")
        for transaction, directory, checked in zip(self.transactions, self.directories, self.checked, strict=True):
            if (
                not transaction.active
                or transaction.thread != self.thread
                or transaction.directory is not directory
                or not directory.active
                or directory.pid != self.pid
                or directory.thread != self.thread
                or directory.checked is not checked
            ):
                raise RuntimeError("custody read directory or transaction lifetime changed")
        for handle, api, value, lifetime in self.handles:
            if value is None or handle.api is not api or handle.value != value or handle._lifetime is not lifetime:
                raise RuntimeError("custody read pinned handle lifetime changed")

    def __enter__(self) -> None:
        if any(directory._custody_read is not None for directory in self.directories):
            raise RuntimeError("nested custody read")
        self.check_lifetime()
        for directory in self.directories:
            directory.check()
        for directory in self.directories:
            directory._custody_read = self

    def __exit__(self, kind: object, original: BaseException | None, traceback: object) -> None:
        # Never let nesting or a failed body erase the outer scope's checks.
        failure: BaseException | None = None
        try:
            self.check_lifetime()
        except BaseException as exc:
            failure = exc
        finally:
            for directory in self.directories:
                directory._custody_read = None
        for directory in self.directories:
            try:
                directory.check()
            except BaseException as exc:
                if failure is None:
                    failure = exc
        try:
            self.check_lifetime()
        except BaseException as exc:
            if failure is None:
                failure = exc
        if failure is not None:
            raise failure from original


def _discard_staging(staging: OwnedHandle, original: BaseException | None) -> None:
    try:
        staging.api.discard(staging)
    except OSError as cleanup:
        cleanup_failure(original, cleanup, committed=True)


@contextlib.contextmanager
def _created_staging(api: NativeAPI, temporary: str) -> Iterator[OwnedHandle]:
    staging = api.open(temporary, access=0xC0030000, share=0, create=True)
    try:
        yield staging
    except BaseException as original:
        try:
            staging.close()
        except OSError as cleanup:
            cleanup_failure(original, cleanup, committed=True)
        raise
    else:
        try:
            staging.close()
        except PrivateFSError as exc:
            exc.commit_state = "uncertain"
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


def _check_identity(handle: OwnedHandle, expected: FileIdentity | None) -> FileIdentity:
    validate_private(handle, directory=False)
    identity = handle.api.metadata(handle).identity
    if expected is not None and identity != expected:
        raise PrivateFSError("unsafe", "identity")
    return identity
