"""Actual protected OS images and explicitly new administrator-owned fixtures.

Ordinary-token acceptance can use a controller-created fixture root containing
safe/image.exe, safe/alias.exe, writable-file/image.exe, writable-parent/image.exe,
delete-child/image.exe and current-owned/image.exe. These tests never modify that
supplied root. Elevated CI creates and removes only its own nonce-named fixture.
"""

from __future__ import annotations

import ctypes
import hashlib
import os
import shutil
import subprocess
import sys
import uuid
from pathlib import Path

import pytest

from mordred_hermes._private_fs import PrivateFSError, inspect_managed_installation_image
from mordred_hermes._private_fs._windows_api import get_api
from mordred_hermes._private_fs._windows_security import ADMINISTRATORS, check_managed_image

pytestmark = pytest.mark.skipif(os.name != "nt", reason="actual Win32 filesystem")


def system_directory():
    function = ctypes.WinDLL("kernel32", use_last_error=True).GetSystemDirectoryW
    function.argtypes = [ctypes.c_wchar_p, ctypes.c_uint32]
    function.restype = ctypes.c_uint32
    buffer = ctypes.create_unicode_buffer(32768)
    count = function(buffer, len(buffer))
    assert 0 < count < len(buffer)
    return Path(buffer.value)


def acl(path):
    with get_api().open(str(path), access=0x20080, share=7) as handle:
        return get_api().descriptor(handle)


def icacls(*arguments):
    subprocess.run(["icacls.exe", *map(str, arguments)], check=True, capture_output=True)


def set_managed(path):
    # Only new test-owned fixtures. Grant before removing inherited rules.
    icacls(path, "/grant:r", "*S-1-5-32-544:(F)", "*S-1-5-18:(F)", "*S-1-1-0:(RX)")
    icacls(path, "/inheritance:r")
    icacls(path, "/setowner", "*S-1-5-32-544")


@pytest.fixture
def managed_root():
    selected = os.environ.get("MORDRED_MANAGED_IMAGE_TEST_ROOT")
    if selected:
        # Input location alone is never trusted: production admission checks it.
        yield Path(selected)
        return
    shell = ctypes.WinDLL("shell32", use_last_error=True).IsUserAnAdmin
    shell.argtypes, shell.restype = [], ctypes.c_int
    if not shell():
        pytest.skip("new admin-owned fixture requires elevated setup or controller-supplied root")
    root = system_directory().anchor
    directory = Path(root) / ("mordred-managed-test-" + uuid.uuid4().hex)
    directory.mkdir()
    try:
        variants = ["safe", "writable-file", "writable-parent", "delete-child", "current-owned"]
        for name in variants:
            parent = directory / name
            parent.mkdir()
            image = parent / "image.exe"
            shutil.copyfile(sys.executable, image)
            set_managed(image)
            set_managed(parent)
        os.link(directory / "safe" / "image.exe", directory / "safe" / "alias.exe")
        subprocess.run(
            ["cmd.exe", "/d", "/c", "mklink", "/J", str(directory / "junction"), str(directory / "safe")],
            check=True,
            capture_output=True,
        )
        icacls(directory / "writable-file" / "image.exe", "/grant", "*S-1-1-0:(W)")
        icacls(directory / "writable-parent", "/grant", "*S-1-1-0:(W)")
        icacls(directory / "delete-child", "/grant", "*S-1-1-0:(DC)")
        user = get_api().sid_text(get_api().user_sid())
        icacls(directory / "current-owned" / "image.exe", "/setowner", "*" + user)
        set_managed(directory)
        yield directory
    finally:
        shutil.rmtree(directory)  # Exactly the nonce-named fixture created here.


def test_native_protected_windows_binary_metadata_and_descriptor_unchanged():
    image = system_directory() / "svchost.exe"
    before = acl(image)
    info = inspect_managed_installation_image(image)
    stat = image.stat()
    assert info.size == stat.st_size > 0
    assert info.mtime_ns == stat.st_mtime_ns
    assert acl(image) == before


def test_native_current_user_owned_readonly_image_is_refused_without_changes(tmp_path):
    image = tmp_path / "svchost.exe"
    shutil.copyfile(sys.executable, image)
    api = get_api()
    # Elevated Windows may default newly created owners to BA; explicitly make
    # the new test file current-SID-owned so this tests the claimed premise.
    icacls(image, "/setowner", "*" + api.sid_text(api.user_sid()))
    image.chmod(0o444)
    before, content = acl(image), image.read_bytes()
    assert before.owner == api.user_sid()
    try:
        with pytest.raises(PrivateFSError):
            check_managed_image(before, api.user_sid(), api.managed_service_sid(), role="image")
        with pytest.raises(PrivateFSError):
            inspect_managed_installation_image(image)
        assert acl(image) == before
        assert image.read_bytes() == content
    finally:
        image.chmod(0o666)


def test_native_admin_owned_public_hardlinks_admit_without_acl_or_bytes_changes(managed_root):
    image, alias = managed_root / "safe" / "image.exe", managed_root / "safe" / "alias.exe"
    assert acl(image).owner == ADMINISTRATORS
    before = acl(image)
    digest = hashlib.sha256(image.read_bytes()).digest()
    info = inspect_managed_installation_image(image)
    assert inspect_managed_installation_image(alias) == info
    assert image.stat().st_nlink >= 2
    assert acl(image) == before
    assert hashlib.sha256(image.read_bytes()).digest() == digest


@pytest.mark.parametrize("variant", ["writable-file", "writable-parent", "delete-child", "current-owned"])
def test_native_admin_fixture_unsafe_selected_file_or_namespace_refuses(managed_root, variant):
    image = managed_root / variant / "image.exe"
    before = (acl(image), acl(image.parent))
    content = image.read_bytes()
    with pytest.raises(PrivateFSError) as err:
        inspect_managed_installation_image(image)
    assert err.value.reason == "unsafe"
    assert (acl(image), acl(image.parent)) == before
    assert image.read_bytes() == content


def test_native_held_mutation_handle_blocks_admission(managed_root):
    api = get_api()
    image = managed_root / "safe" / "image.exe"
    try:
        writer = api.open(str(image), access=0x40000000, share=3)
    except PrivateFSError as exc:
        if exc.reason == "access_denied":
            pytest.skip("ordinary reader cannot open an administrative mutation handle")
        raise
    with writer, pytest.raises(PrivateFSError) as err:
        inspect_managed_installation_image(image)
    assert err.value.reason == "busy"


def test_native_junction_in_user_namespace_refuses(tmp_path):
    junction = tmp_path / "system-alias"
    subprocess.run(
        ["cmd.exe", "/d", "/c", "mklink", "/J", str(junction), str(system_directory())], check=True, capture_output=True
    )
    try:
        with pytest.raises(PrivateFSError):
            inspect_managed_installation_image(junction / "svchost.exe")
    finally:
        junction.rmdir()  # Only this test's junction, never the OS destination.


def test_native_managed_junction_refuses(managed_root):
    with pytest.raises(PrivateFSError) as err:
        inspect_managed_installation_image(managed_root / "junction" / "image.exe")
    assert err.value.operation == "managed_image_metadata"


def test_native_file_security_change_during_observation_refuses(managed_root, monkeypatch):
    if os.environ.get("MORDRED_MANAGED_IMAGE_TEST_ROOT"):
        pytest.skip("supplied ordinary fixture remains read-only")
    api = get_api()
    image = managed_root / "safe" / "image.exe"
    original = api.mtime_ns
    changed = False

    def change_acl(handle):
        nonlocal changed
        result = original(handle)
        if not changed:
            changed = True
            icacls(image, "/grant", "*S-1-1-0:(W)")
        return result

    monkeypatch.setattr(api, "mtime_ns", change_acl)
    with pytest.raises(PrivateFSError) as err:
        inspect_managed_installation_image(image)
    assert changed
    assert err.value.operation == "managed_image_acl"
