"""Actual protected OS images and explicitly new administrator-owned fixtures.

Ordinary-token acceptance can use a controller-created fixture root containing
safe/image.exe, safe/alias.exe, writable-file/image.exe, writable-parent/image.exe,
delete-child/image.exe, current-owned/image.exe, relaxed/parent/image.exe (the
ProgramData-shaped Users ACE on the upper ancestor ``relaxed``) and
relaxed-parent/parent/image.exe (the same ACE on the immediate parent). The
admission tests never modify that supplied root. The ``probe`` tests attempt
ordinary-token mutation of ``relaxed`` (hardlink, mount-point tag and
directory-bit reparse tags); a successful hardlink also raises the link count
of ``safe/image.exe``. They record each outcome as a ``managed-image-probe``
line and remove any tag they managed to set; an ordinary token may be unable
to remove a hardlink it created, so the elevated controller removes the whole
nonce root afterwards. Elevated CI creates and removes only its own nonce root.
"""

from __future__ import annotations

import ctypes
import hashlib
import json
import os
import shutil
import struct
import subprocess
import sys
import uuid
from pathlib import Path

import pytest

from mordred_hermes._private_fs import PrivateFSError, inspect_managed_installation_image
from mordred_hermes._private_fs._windows_api import get_api
from mordred_hermes._private_fs._windows_security import ADMINISTRATORS, check_managed_image

pytestmark = pytest.mark.skipif(os.name != "nt", reason="actual Win32 filesystem")

USERS = bytes((1, 2)) + (5).to_bytes(6, "big") + (32).to_bytes(4, "little") + (545).to_bytes(4, "little")
# BUILTIN\Users container-inherit ADD_FILE, ADD_SUBDIRECTORY, WRITE_EA and
# WRITE_ATTRIBUTES: the Windows default ProgramData grant (mask 0x116).
PROGRAMDATA_GRANT = "*S-1-5-32-545:(CI)(WD,AD,WEA,WA)"
FSCTL_SET_REPARSE_POINT = 0x000900A4
FSCTL_DELETE_REPARSE_POINT = 0x000900AC
IO_REPARSE_TAG_MOUNT_POINT = 0xA0000003
# Microsoft tags with the directory bit (0x10000000), which NTFS exempts from
# the non-empty-directory restriction: cloud files and Windows Container
# Isolation.
DIRECTORY_BIT_TAGS = {"cloud": 0x9000001A, "wci-1": 0x90001018}
VARIANTS = ["safe", "writable-file", "writable-parent", "delete-child", "current-owned"]


def system_directory():
    function = ctypes.WinDLL("kernel32", use_last_error=True).GetSystemDirectoryW
    function.argtypes = [ctypes.c_wchar_p, ctypes.c_uint32]
    function.restype = ctypes.c_uint32
    buffer = ctypes.create_unicode_buffer(32768)
    count = function(buffer, len(buffer))
    assert 0 < count < len(buffer)
    return Path(buffer.value)


def is_admin():
    function = ctypes.WinDLL("shell32", use_last_error=True).IsUserAnAdmin
    function.argtypes, function.restype = [], ctypes.c_int
    return bool(function())


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


def has_programdata_grant(path):
    return any(
        ace.kind == 0 and ace.flags & 0x02 and not ace.flags & 0x08 and ace.mask & 0x116 == 0x116 and ace.sid == USERS
        for ace in acl(path).aces or []
    )


def create_hard_link(link, target):
    function = ctypes.WinDLL("kernel32", use_last_error=True).CreateHardLinkW
    function.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_void_p]
    function.restype = ctypes.c_int32
    return 0 if function(str(link), str(target), None) else ctypes.get_last_error()


def fsctl(path, code, payload):
    """Return (Win32 error or 0, failing stage); never raises for OS refusals."""
    try:
        # FILE_WRITE_DATA | FILE_WRITE_ATTRIBUTES: either suffices for reparse
        # data on a directory (MS-FSA); the relaxed Users ACE grants both.
        handle = get_api().open(str(path), access=0x102, share=7)
    except PrivateFSError as exc:
        return exc.native_code or -1, "open"
    with handle:
        function = ctypes.WinDLL("kernel32", use_last_error=True).DeviceIoControl
        function.argtypes = [
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.c_char_p,
            ctypes.c_uint32,
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.POINTER(ctypes.c_uint32),
            ctypes.c_void_p,
        ]
        function.restype = ctypes.c_int32
        returned = ctypes.c_uint32()
        okay = function(handle.value, code, payload, len(payload), None, 0, ctypes.byref(returned), None)
        return (0 if okay else ctypes.get_last_error()), "fsctl"


def mount_point(target):
    substitute = ("\\??\\" + str(target)).encode("utf-16-le")
    printed = str(target).encode("utf-16-le")
    names = substitute + b"\0\0" + printed + b"\0\0"
    data = struct.pack("<HHHH", 0, len(substitute), len(substitute) + 2, len(printed)) + names
    return struct.pack("<IHH", IO_REPARSE_TAG_MOUNT_POINT, len(data), 0) + data


def opaque_tag(tag):
    data = bytes(8)
    return struct.pack("<IHH", tag, len(data), 0) + data


def remove_tag(path, tag):
    return fsctl(path, FSCTL_DELETE_REPARSE_POINT, struct.pack("<IHH", tag, 0, 0))[0]


def record(record_property, capsys, probe, **values):
    line = json.dumps({"probe": probe, "elevated": is_admin(), **values}, sort_keys=True)
    record_property("managed_image_probe", line)
    with capsys.disabled():
        print("managed-image-probe " + line, flush=True)


@pytest.fixture
def managed_root():
    selected = os.environ.get("MORDRED_MANAGED_IMAGE_TEST_ROOT")
    if selected:
        # Input location alone is never trusted: production admission checks it.
        yield Path(selected)
        return
    if not is_admin():
        pytest.skip("new admin-owned fixture requires elevated setup or controller-supplied root")
    root = system_directory().anchor
    directory = Path(root) / ("mordred-managed-test-" + uuid.uuid4().hex)
    directory.mkdir()
    try:
        for name in VARIANTS:
            parent = directory / name
            parent.mkdir()
            image = parent / "image.exe"
            shutil.copyfile(sys.executable, image)
            set_managed(image)
            set_managed(parent)
        for name in ["relaxed", "relaxed-parent"]:
            parent = directory / name / "parent"
            parent.mkdir(parents=True)
            image = parent / "image.exe"
            shutil.copyfile(sys.executable, image)
            set_managed(image)
            set_managed(parent)
            set_managed(parent.parent)
        os.link(directory / "safe" / "image.exe", directory / "safe" / "alias.exe")
        icacls(directory / "writable-file" / "image.exe", "/grant", "*S-1-1-0:(W)")
        icacls(directory / "writable-parent", "/grant", "*S-1-1-0:(W)")
        icacls(directory / "delete-child", "/grant", "*S-1-1-0:(DC)")
        # Children are protected, so these container-inherit grants stay on
        # the named directory only.
        icacls(directory / "relaxed", "/grant", PROGRAMDATA_GRANT)
        icacls(directory / "relaxed-parent" / "parent", "/grant", PROGRAMDATA_GRANT)
        user = get_api().sid_text(get_api().user_sid())
        icacls(directory / "current-owned" / "image.exe", "/setowner", "*" + user)
        set_managed(directory)
        # Only after the root is protected: a junction created earlier keeps no
        # inherited ACE once the root's inheritance is removed, and an empty
        # DACL refuses even the elevated open (and teardown delete) before the
        # reparse point itself is classified. Created now, it gets the
        # creator's default DACL (Administrators/SYSTEM) and stays openable.
        subprocess.run(
            ["cmd.exe", "/d", "/c", "mklink", "/J", str(directory / "junction"), str(directory / "safe")],
            check=True,
            capture_output=True,
        )
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


def test_native_real_defender_platform_image_is_admitted_with_descriptors_unchanged():
    # Read-only: never modifies ProgramData; skipped where Defender is absent.
    platform = Path(system_directory().anchor) / "ProgramData" / "Microsoft" / "Windows Defender" / "Platform"
    images = sorted(platform.glob("*/MsMpEng.exe")) if platform.is_dir() else []
    if not images:
        pytest.skip("no Windows Defender platform image on this host")
    for image in images[:8]:
        chain = [image, *image.parents]
        before = [acl(path) for path in chain]
        info = inspect_managed_installation_image(image)
        assert info.size == image.stat().st_size > 0
        assert [acl(path) for path in chain] == before


def test_native_current_user_owned_readonly_image_is_refused_without_changes(tmp_path):
    image = tmp_path / "svchost.exe"
    shutil.copyfile(sys.executable, image)
    api = get_api()
    user = "*" + api.sid_text(api.user_sid())
    # A pytest base temp created with mode 0o700 by Python >= 3.13 grants the
    # ordinary user access only through an inheritable OWNER RIGHTS ACE, which
    # the owner change below leaves inherit-only. Grant the owner explicitly so
    # the premise (a current-user-owned, writable-by-owner image) holds there.
    icacls(image, "/grant", user + ":(F)")
    # Elevated Windows may default newly created owners to BA; explicitly make
    # the new test file current-SID-owned so this tests the claimed premise.
    icacls(image, "/setowner", user)
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


def test_native_programdata_shaped_upper_ancestor_is_admitted_without_changes(managed_root):
    relaxed = managed_root / "relaxed"
    image = relaxed / "parent" / "image.exe"
    assert has_programdata_grant(relaxed)
    assert not has_programdata_grant(image.parent)
    chain = [image, image.parent, relaxed]
    before = [acl(path) for path in chain]
    digest = hashlib.sha256(image.read_bytes()).digest()
    info = inspect_managed_installation_image(image)
    assert info.size == image.stat().st_size > 0
    assert [acl(path) for path in chain] == before
    assert hashlib.sha256(image.read_bytes()).digest() == digest


@pytest.mark.parametrize(
    "variant",
    [
        "writable-file/image.exe",
        # Everyone W (0x120116) on the immediate parent must keep refusing.
        "writable-parent/image.exe",
        "delete-child/image.exe",
        "current-owned/image.exe",
        # The ProgramData-shaped ACE refuses on the immediate parent.
        "relaxed-parent/parent/image.exe",
    ],
)
def test_native_admin_fixture_unsafe_selected_file_or_namespace_refuses(managed_root, variant):
    image = managed_root / variant
    if variant.startswith("relaxed-parent"):
        assert has_programdata_grant(image.parent)
    before = (acl(image), acl(image.parent))
    content = image.read_bytes()
    with pytest.raises(PrivateFSError) as err:
        inspect_managed_installation_image(image)
    assert (err.value.reason, err.value.operation) == ("unsafe", "managed_image_acl")
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


def test_native_user_namespace_alias_refuses_on_mutable_ancestry(tmp_path):
    # The current user's own profile/temp directories refuse first, before the
    # junction is reached; test_native_managed_junction_refuses covers the
    # junction itself inside an otherwise admitted namespace.
    junction = tmp_path / "system-alias"
    subprocess.run(
        ["cmd.exe", "/d", "/c", "mklink", "/J", str(junction), str(system_directory())], check=True, capture_output=True
    )
    try:
        with pytest.raises(PrivateFSError) as err:
            inspect_managed_installation_image(junction / "svchost.exe")
        assert (err.value.reason, err.value.operation) == ("unsafe", "managed_image_acl")
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


def test_native_probe_hardlink_into_relaxed_directory(managed_root, record_property, capsys):
    target = managed_root / "safe" / "image.exe"
    link = managed_root / "relaxed" / ("probe-link-" + uuid.uuid4().hex + ".exe")
    code = create_hard_link(link, target)
    values: dict[str, object] = {"create_hard_link": code}
    try:
        if code == 0:
            # The link's immediate parent is relaxed, whose ProgramData-shaped
            # Users ACE the image_parent role refuses.
            with pytest.raises(PrivateFSError) as err:
                inspect_managed_installation_image(link)
            values["link_refusal"] = [err.value.reason, err.value.operation]
            assert (err.value.reason, err.value.operation) == ("unsafe", "managed_image_acl")
    finally:
        if code == 0:
            try:
                link.unlink()
                values["link_removed"] = True
            except OSError as exc:
                # An ordinary token may lack DELETE; the controller removes
                # the whole nonce root after validation.
                values["link_removed"] = False
                values["link_remove_error"] = getattr(exc, "winerror", None)
        record(record_property, capsys, "create_hard_link", **values)


def test_native_probe_mount_point_tag_on_nonempty_relaxed_directory_fails(managed_root, record_property, capsys):
    relaxed = managed_root / "relaxed"
    assert any(relaxed.iterdir())
    code, stage = fsctl(relaxed, FSCTL_SET_REPARSE_POINT, mount_point(managed_root / "safe"))
    values: dict[str, object] = {"code": code, "stage": stage}
    try:
        if stage != "fsctl":
            pytest.fail(
                f"mount-point probe did not run: opening relaxed for reparse data failed with {code}; "
                "the fixture must grant BUILTIN\\Users write-data/write-attributes on relaxed"
            )
        # The probe must reach FSCTL_SET_REPARSE_POINT and fail there with
        # ERROR_DIR_NOT_EMPTY (145); ERROR_ACCESS_DENIED (5) at that stage is
        # accepted and recorded. Success would invalidate the R-C5c-1 premise.
        assert code in (145, 5)
    finally:
        if code == 0:
            values["removed"] = remove_tag(relaxed, IO_REPARSE_TAG_MOUNT_POINT)
        record(record_property, capsys, "mount_point_tag", **values)


@pytest.mark.parametrize("name", sorted(DIRECTORY_BIT_TAGS))
def test_native_probe_directory_bit_tag_on_relaxed_directory(managed_root, record_property, capsys, name):
    tag = DIRECTORY_BIT_TAGS[name]
    relaxed = managed_root / "relaxed"
    image = relaxed / "parent" / "image.exe"
    code, stage = fsctl(relaxed, FSCTL_SET_REPARSE_POINT, opaque_tag(tag))
    values: dict[str, object] = {"tag": hex(tag), "code": code, "stage": stage}
    try:
        if code == 0:
            # Whether the tag can be set is OS/filter behaviour we only record;
            # while it is present the inspection must refuse on the reparse
            # attribute of relaxed. The outcome is recorded either way.
            try:
                inspect_managed_installation_image(image)
                values["refusal"] = None
            except PrivateFSError as exc:
                values["refusal"] = [exc.reason, exc.operation]
    finally:
        if code == 0:
            values["removed"] = remove_tag(relaxed, tag)
        record(record_property, capsys, "directory_bit_tag", **values)
    if code == 0:
        assert values["removed"] == 0, "probe tag must be removed before the fixture root is reused"
        assert values["refusal"] == ["unsafe", "managed_image_metadata"]
        assert inspect_managed_installation_image(image).size > 0
