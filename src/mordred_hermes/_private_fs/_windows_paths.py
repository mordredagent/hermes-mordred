"""Checked local NTFS paths, with all ancestor handles pinned until exit."""

from __future__ import annotations

import contextlib
import os
import re
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

from ._types import FileIdentity, PrivateFSError, validate_leaf
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


@dataclass
class CheckedDirectory:
    handle: OwnedHandle
    identity: FileIdentity
    path: str


@contextlib.contextmanager
def checked_directory(path: str | Path, *, create: bool = False) -> Iterator[CheckedDirectory]:
    drive, parts = split_path(path)
    api = get_api()
    api.validate_drive(drive)
    with contextlib.ExitStack() as stack:
        parent = stack.enter_context(api.open(drive))
        api.validate_volume(parent)
        volume = api.metadata(parent).identity.volume
        for index, part in enumerate(parts):
            validate_ancestor(parent, creating_child=False)
            destination = api.final_path(parent).rstrip("\\") + "\\" + part
            try:
                child = api.open(destination)
            except PrivateFSError as exc:
                if exc.reason != "missing" or not create or index != len(parts) - 1:
                    raise
                validate_ancestor(parent, creating_child=True)
                try:
                    api.mkdir(destination)
                except PrivateFSError as creation:
                    if creation.reason != "exists":
                        raise
                child = api.open(destination)
            parent = stack.enter_context(child)
            metadata = api.metadata(parent)
            if metadata.reparse or not metadata.directory or metadata.identity.volume != volume:
                raise PrivateFSError("unsafe", "ancestor_identity")
        validate_private(parent, directory=True)
        yield CheckedDirectory(parent, api.metadata(parent).identity, api.final_path(parent))
