"""Actual NTFS inherited ACL admission without modifying the shared parent."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

from mordred_hermes._private_fs import (
    PrivateFSError,
    open_confidential_directory,
    open_optional_confidential_directory,
    open_private_directory,
)

pytestmark = pytest.mark.skipif(os.name != "nt", reason="actual Win32 filesystem")


def powershell(path: Path, script: str) -> str:
    result = subprocess.run(
        ["powershell.exe", "-NoProfile", "-Command", "$ErrorActionPreference='Stop'; " + script],
        env={k: v for k, v in os.environ.items() if k.casefold() != "psmodulepath"}
        | {"MORDRED_ACL_FIXTURE": str(path)},
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


@pytest.fixture
def shared_home(tmp_path):
    root = tmp_path / "共有 home"
    root.mkdir()
    # Profile-style inheritable owner/SYSTEM/Admin grants, plus read-only access
    # to the directory itself. The sensitive child has only safe inherited ACEs.
    powershell(
        root,
        """
    $u=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value;
    $a=Get-Acl -LiteralPath $env:MORDRED_ACL_FIXTURE;
    $a.SetSecurityDescriptorSddlForm("O:${u}D:P(A;OICI;FA;;;${u})(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;;FR;;;WD)");
    Set-Acl -LiteralPath $env:MORDRED_ACL_FIXTURE -AclObject $a
    """,
    )
    (root / "config.yaml").write_bytes(b"old")
    return root


def descriptor(path):
    return powershell(path, "(Get-Acl -LiteralPath $env:MORDRED_ACL_FIXTURE).Sddl")


def test_native_inherited_safe_update_keeps_shared_parent(shared_home):
    root = shared_home
    parent_before = descriptor(root)
    file_before = descriptor(root / "config.yaml")
    assert "ID;" in file_before
    with open_confidential_directory(root) as directory:
        identity = directory.directory_identity()
        assert directory.read_bytes("config.yaml", max_bytes=3) == b"old"
        assert descriptor(root / "config.yaml") == file_before
        with directory.transaction() as tx:
            tx.replace_bytes("config.yaml", b"new")
            tx.create_bytes("backup.yaml", b"old")
            assert tx.read_bytes("config.yaml", max_bytes=3) == b"new"
        assert directory.directory_identity() == identity
    assert descriptor(root) == parent_before
    from mordred_hermes._private_fs._windows_api import get_api
    from mordred_hermes._private_fs._windows_security import validate_private

    for name in ("config.yaml", "backup.yaml", ".mordred-fs.lock"):
        with get_api().open(str(root / name)) as handle:
            validate_private(handle, directory=False)
    with pytest.raises(PrivateFSError), open_private_directory(root):
        pass


@pytest.mark.parametrize("acl", ["restricted", "deny_allow", "broad"])
def test_native_explicit_file_dacl_cases(shared_home, acl):
    path = shared_home / "config.yaml"
    suffix = {"restricted": "(A;;FR;;;SY)", "deny_allow": "(D;;FR;;;WD)(A;;FR;;;WD)", "broad": "(A;;FR;;;WD)"}[acl]
    powershell(
        path,
        """
    $u=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value;
    $a=Get-Acl -LiteralPath $env:MORDRED_ACL_FIXTURE;
    """
        + '$a.SetSecurityDescriptorSddlForm("O:${u}D:P(A;;FA;;;${u})'
        + suffix
        + '");'
        + """
    Set-Acl -LiteralPath $env:MORDRED_ACL_FIXTURE -AclObject $a
    """,
    )
    before = descriptor(path)
    with open_confidential_directory(shared_home) as directory:
        if acl == "restricted":
            assert directory.read_bytes("config.yaml", max_bytes=3) == b"old"
        else:
            with pytest.raises(PrivateFSError):
                directory.read_bytes("config.yaml", max_bytes=3)
    assert descriptor(path) == before


@pytest.mark.parametrize("kind", ["hardlink", "junction"])
def test_native_confidential_refuses_links(shared_home, tmp_path, kind):
    if kind == "hardlink":
        os.link(shared_home / "config.yaml", shared_home / "alias")
        with open_confidential_directory(shared_home) as directory, pytest.raises(PrivateFSError):
            directory.read_bytes("config.yaml", max_bytes=3)
    else:
        junction = tmp_path / "junction"
        subprocess.run(
            ["cmd.exe", "/c", "mklink", "/J", str(junction), str(shared_home)], check=True, capture_output=True
        )
        with pytest.raises(PrivateFSError), open_optional_confidential_directory(junction):
            pass


def test_native_optional_absence_and_missing_intermediate(shared_home):
    with open_optional_confidential_directory(shared_home / "absent") as directory:
        assert directory is None
    assert not (shared_home / "absent").exists()
    with pytest.raises(PrivateFSError), open_optional_confidential_directory(shared_home / "absent" / "nested"):
        pass


@pytest.mark.integration
@pytest.mark.skipif(os.environ.get("MORDRED_WINDOWS_FS_LIVE") != "1", reason="explicit ordinary-user acceptance")
def test_ordinary_user_inherited_roundtrip(shared_home):
    import ctypes

    assert not ctypes.windll.shell32.IsUserAnAdmin(), "Elevated run is not ordinary-user acceptance"
    test_native_inherited_safe_update_keeps_shared_parent(shared_home)
