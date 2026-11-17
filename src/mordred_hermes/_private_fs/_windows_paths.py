"""Checked local NTFS paths, with all ancestor handles pinned until exit."""

from __future__ import annotations

import contextlib
import os
import re
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

from ._types import FileIdentity, PrivateFSError, cleanup_failure, validate_leaf
from ._windows_api import OwnedHandle, get_api
from ._windows_security import validate_ancestor, validate_private


def windows_leaf(name: str) -> None:
    validate_leaf(name.casefold())
    base = name.split(".")[0].upper()
    if (
        name.endswith((" ", "."))
        or any(ord(char) < 32 or char in '<>"|?*' for char in name)
        or base in {"CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"}
        or re.fullmatch(r"(COM|LPT)[1-9¹²³]", base)
    ):
        raise PrivateFSError("unsafe", "windows_leaf")


def split_path(path: str | Path) -> tuple[str, list[str]]:
    raw = os.fspath(path).replace("/", "\\")
    if raw.startswith("\\\\"):
        raise PrivateFSError("unsupported", "namespace")
    if not re.match(r"^[a-zA-Z]:\\", raw):
        raise PrivateFSError("unsafe", "absolute_path")
    drive = raw[:3]
    parts = raw[3:].split("\\")
    if not parts or any(not part for part in parts):
        raise PrivateFSError("unsafe", "directory_path")
    for part in parts:
        windows_leaf(part)
    return drive, parts


@dataclass(frozen=True)
class CheckedDirectory:
    handle: OwnedHandle
    identity: FileIdentity
    path: str
    confidential: bool = False
    ancestors: tuple[tuple[OwnedHandle, FileIdentity], ...] = ()

    def check(self) -> None:
        for handle, identity in self.ancestors:
            validate_ancestor(handle, creating_child=False)
            if handle.api.metadata(handle).identity != identity:
                raise PrivateFSError("unsafe", "ancestor_identity")
        if self.confidential:
            validate_ancestor(self.handle, creating_child=True)
        else:
            validate_private(self.handle, directory=True)
        if self.handle.api.metadata(self.handle).identity != self.identity:
            raise PrivateFSError("unsafe", "directory_identity")
        if self.ancestors and self.handle.api.final_path(self.handle).casefold() != self.path.casefold():
            raise PrivateFSError("unsafe", "directory_path")

    def flush(self) -> None:
        """Full NTFS namespace barrier with the original read pins retained.

        The local directory-flush/MS-FSA mapping is an approved engineering
        inference under honored storage flushes, not a volume privilege fallback.
        """
        self.check()
        api = self.handle.api
        with api.open(self.path, access=0xC0000000, share=3) as writable:
            admitted = CheckedDirectory(
                writable,
                self.identity,
                self.path,
                self.confidential,
                (*self.ancestors, (self.handle, self.identity)),
            )
            admitted.check()
            api.validate_volume(writable)
            api.flush(writable)
            admitted.check()
            api.validate_volume(writable)
            self.check()
        self.check()


@contextlib.contextmanager
def checked_directory(path: str | Path, *, create: bool = False) -> Iterator[CheckedDirectory]:
    with checked_directory_optional(path, create=create) as checked:
        assert checked is not None
        yield checked


@contextlib.contextmanager
def checked_directory_optional(
    path: str | Path,
    *,
    create: bool = False,
    confidential: bool = False,
    optional: bool = False,
) -> Iterator[CheckedDirectory | None]:
    drive, parts = split_path(path)
    api = get_api()
    api.validate_drive(drive)
    bootstrapped = False
    try:
        with contextlib.ExitStack() as stack:
            parent = stack.enter_context(api.open(drive))
            api.validate_volume(parent)
            volume = api.metadata(parent).identity.volume
            ancestors: list[tuple[OwnedHandle, FileIdentity]] = []
            for index, part in enumerate(parts):
                validate_ancestor(parent, creating_child=False)
                ancestors.append((parent, api.metadata(parent).identity))
                destination = api.final_path(parent).rstrip("\\") + "\\" + part
                admitted_parent = CheckedDirectory(
                    parent,
                    api.metadata(parent).identity,
                    api.final_path(parent),
                    confidential=True,
                    ancestors=tuple(ancestors[:-1]),
                )
                last = index == len(parts) - 1
                child, created = _open_child(
                    destination, admitted_parent, create=create and last, optional=optional and last
                )
                if child is None:
                    for ancestor, identity in ancestors:
                        validate_ancestor(ancestor, creating_child=ancestor is parent)
                        if api.metadata(ancestor).identity != identity:
                            raise PrivateFSError("unsafe", "ancestor_identity")
                    # No missing exception crosses either the yield or cleanup.
                    yield None
                    return
                parent = stack.enter_context(child)
                if created:
                    bootstrapped = True
                    validate_private(parent, directory=True)
                metadata = api.metadata(parent)
                if metadata.reparse or not metadata.directory or metadata.identity.volume != volume:
                    raise PrivateFSError("unsafe", "ancestor_identity")
            checked = CheckedDirectory(
                parent, api.metadata(parent).identity, api.final_path(parent), confidential, tuple(ancestors)
            )
            checked.check()
            yield checked

    except PrivateFSError as exc:
        if bootstrapped:
            exc.commit_state = "uncertain"
        raise


def _open_child(
    destination: str, parent: CheckedDirectory, *, create: bool, optional: bool
) -> tuple[OwnedHandle | None, bool]:
    try:
        return parent.handle.api.open(destination), False
    except PrivateFSError as exc:
        if (
            exc.reason != "missing"
            or exc.operation != "open"
            or exc.commit_state != "not_committed"
            or not (optional or create)
        ):
            raise
        parent.check()
        return _create_directory(destination, parent) if create else (None, False)


def _create_directory(destination: str, parent: CheckedDirectory) -> tuple[OwnedHandle, bool]:
    api = parent.handle.api
    parent.flush()  # Prove writable parent admission before creating anything.
    created = False
    child: OwnedHandle | None = None
    try:
        try:
            api.mkdir(destination)
            created = True
        except PrivateFSError as exc:
            if exc.reason != "exists" or exc.commit_state != "not_committed":
                raise
        child = api.open(destination)
        if (
            api.metadata(child).identity.volume != parent.identity.volume
            or api.final_path(child).casefold() != destination.casefold()
        ):
            raise PrivateFSError("unsafe", "created_directory_identity")
        admitted = CheckedDirectory(
            child,
            api.metadata(child).identity,
            api.final_path(child),
            ancestors=(*parent.ancestors, (parent.handle, parent.identity)),
        )
        admitted.check()
        admitted.flush()
        parent.flush()
        return child, created
    except BaseException as exc:
        if created and isinstance(exc, PrivateFSError):
            exc.commit_state = "uncertain"
        if child is not None:
            try:
                child.close()
            except OSError as cleanup:
                cleanup_failure(exc, cleanup, committed=created)
        raise
