"""Declared platform boundaries for portability tests; never production fallbacks."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest


def require_legacy_file_vault() -> None:
    if os.name == "nt":
        pytest.skip("legacy_file_vault: product excludes POSIX file-vault custody on Windows")


@pytest.fixture
def legacy_file_vault() -> None:
    require_legacy_file_vault()


@pytest.fixture
def legacy_secret_store() -> None:
    require_legacy_secret_store()


def require_legacy_secret_store() -> None:
    if os.name == "nt":
        pytest.skip("legacy_secret_store: product excludes POSIX secret-store lifecycle on Windows")


@pytest.fixture
def posix_modes() -> None:
    if os.name == "nt":
        pytest.skip("posix_mode_bits: exact mode-0600/0700 descriptor semantics required")


def _directory_redirect(link: Path, target: Path) -> None:
    """Owned junction on Windows, symlink on POSIX; retain raw-target evidence."""
    assert not link.exists()
    if os.name == "nt":
        result = subprocess.run(
            ["cmd", "/c", "mklink", "/J", str(link), str(target)], capture_output=True, text=True, check=False
        )
        assert result.returncode == 0, result.stdout + result.stderr
        raw = os.readlink(link)
        assert Path(raw.removeprefix("\\\\?\\")).absolute() == target.absolute()
    else:
        link.symlink_to(target, target_is_directory=True)
        assert Path(os.readlink(link)) == target
    if link != target:
        assert link.resolve() == target.resolve()


@pytest.fixture
def directory_redirect():
    links = []

    def create(link, target):
        _directory_redirect(link, target)
        links.append(link)

    yield create
    for link in reversed(links):
        if os.name == "nt":
            os.rmdir(link)  # remove only the junction, never its target tree
        else:
            link.unlink()


def require_posix_tee() -> None:
    if os.name == "nt":
        pytest.skip("legacy_posix_tee: TeeSecretStore explicitly excludes the native Windows storage backend")


def require_legacy_sealed_install() -> None:
    if os.name == "nt":
        pytest.skip(
            "legacy_sealed_install: composed file-vault/config/env/memory custody and Unix launcher installation"
        )


def require_legacy_encrypted_database_custody() -> None:
    if os.name == "nt":
        pytest.skip("legacy_encrypted_database_custody: SQLCipher conversion using the legacy file-vault key")


@pytest.fixture
def rename_open_inode() -> None:
    if os.name == "nt":
        pytest.skip("rename_open_inode: POSIX replacement of a pathname whose old inode remains open")


@pytest.fixture
def posix_audit_migration() -> None:
    if os.name == "nt":
        pytest.skip(
            "posix_audit_migration: legacy audit.log migration requires POSIX audit locks; "
            "Windows source admission excludes this artifact"
        )


@pytest.fixture
def posix_tree_migration() -> None:
    if os.name == "nt":
        pytest.skip(
            "posix_tree_migration: sensitive-tree copy requires dir_fd/O_NOFOLLOW/mode repair; "
            "Windows source admission excludes these trees"
        )
