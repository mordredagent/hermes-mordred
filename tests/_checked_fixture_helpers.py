"""Checked test fixture creation and separate privacy assertions.

Creation is deliberately create-only. Unsafe existing parents are never repaired.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from mordred_hermes._private_fs import open_private_directory


def seed_private_directory(path: Path) -> None:
    missing = []
    parent = path
    while not parent.exists():
        missing.append(parent)
        parent = parent.parent
    for directory in reversed(missing):
        with open_private_directory(directory, create=True):
            pass
    with open_private_directory(path):
        pass


def seed_private_file(path: Path, data: bytes) -> None:
    seed_private_directory(path.parent)
    with open_private_directory(path.parent) as directory, directory.transaction() as tx:
        tx.create_bytes(path.name, data)


def seed_private_text(path: Path, text: str, *, encoding: str = "utf-8") -> None:
    seed_private_file(path, text.encode(encoding))


def assert_private(path: Path, *, directory: bool = False) -> None:
    if os.name == "nt":
        from mordred_hermes._private_fs._windows_api import get_api
        from mordred_hermes._private_fs._windows_security import validate_private

        with get_api().open(str(path)) as handle:
            validate_private(handle, directory=directory)
    else:
        info = path.lstat()
        assert (stat.S_ISDIR if directory else stat.S_ISREG)(info.st_mode)
        assert stat.S_IMODE(info.st_mode) == (0o700 if directory else 0o600)


def assert_confidential_file(path: Path) -> None:
    if os.name == "nt":
        from mordred_hermes._private_fs._windows_api import get_api
        from mordred_hermes._private_fs._windows_security import validate_confidential_file

        with get_api().open(str(path)) as handle:
            validate_confidential_file(handle)
    else:
        assert_private(path)


@pytest.fixture
def tmp_path(tmp_path: Path) -> Path:
    # Pytest's inherited Windows temp DACL is not an exact-private profile.
    if os.name == "nt":
        private = tmp_path / "checked-profile"
        seed_private_directory(private)
        return private
    return tmp_path


@pytest.fixture
def file_symlink(tmp_path: Path) -> None:
    """Probe only the file-link operation; do not hide unrelated I/O failures."""
    target = tmp_path / "symlink-probe-target"
    link = tmp_path / "symlink-probe-link"
    target.write_bytes(b"probe")
    try:
        try:
            link.symlink_to(target)
        except OSError as exc:
            if os.name == "nt" and getattr(exc, "winerror", None) == 1314:
                pytest.skip("file_symlink unavailable: owned probe returned ERROR_PRIVILEGE_NOT_HELD (1314)")
            raise
        assert link.is_symlink() and link.resolve() == target
    finally:
        link.unlink(missing_ok=True)
        target.unlink()
