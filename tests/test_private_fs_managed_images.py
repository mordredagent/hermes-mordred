"""Managed image policy and read-only Win32 boundary faults on every host."""

from __future__ import annotations

from dataclasses import replace

import pytest

import mordred_hermes._private_fs as fs
from mordred_hermes._private_fs import FileIdentity, FileMetadata, PrivateFSError
from mordred_hermes._private_fs import _windows_security as s
from mordred_hermes._private_fs._windows_api import Metadata, OwnedHandle


def policy(descriptor, *, directory=False, user=b"user"):
    checker = getattr(s, "check_managed_image", None)
    assert callable(checker), "managed installation policy is missing"
    checker(descriptor, user, s.TRUSTED_INSTALLER, directory=directory)


def inspect(path):
    inspector = getattr(fs, "inspect_managed_installation_image", None)
    assert callable(inspector), "managed installation inspection is missing"
    return inspector(path)


@pytest.mark.parametrize("owner", [s.SYSTEM, s.ADMINISTRATORS, s.TRUSTED_INSTALLER])
def test_managed_owner_with_inherited_public_read_is_admitted(owner):
    policy(s.Descriptor(owner, False, [s.Ace(0, 0x10, 0x1200A9, b"everyone")]))


@pytest.mark.parametrize("owner", [b"user", b"other"])
def test_readonly_user_or_untrusted_owner_can_rewrite_dacl_and_is_refused(owner):
    with pytest.raises(PrivateFSError) as err:
        policy(s.Descriptor(owner, True, [s.Ace(0, 0, 0x120089, b"everyone")]))
    assert err.value.reason == "unsafe"


@pytest.mark.parametrize("sid", [b"user", b"other", b"everyone"])
@pytest.mark.parametrize("mask", [2, 4, 0x10, 0x40, 0x100, 0x10000, 0x40000, 0x80000, 0x40000000, 0x10000000])
def test_managed_file_current_or_untrusted_mutation_refuses(sid, mask):
    with pytest.raises(PrivateFSError):
        policy(s.Descriptor(s.SYSTEM, False, [s.Ace(0, 0x10, mask, sid)]))


@pytest.mark.parametrize("mask", [2, 0x10, 0x40, 0x100, 0x10000, 0x40000, 0x80000])
def test_ancestor_mutation_including_delete_child_refuses(mask):
    with pytest.raises(PrivateFSError):
        policy(s.Descriptor(s.SYSTEM, False, [s.Ace(0, 0, mask, b"user")]), directory=True)


def test_ancestor_sibling_directory_creation_does_not_admit_file_append():
    descriptor = s.Descriptor(s.ADMINISTRATORS, False, [s.Ace(0, 0, 4, b"users")])
    policy(descriptor, directory=True)
    with pytest.raises(PrivateFSError):
        policy(descriptor)


@pytest.mark.parametrize("sid", [s.SYSTEM, s.ADMINISTRATORS, s.TRUSTED_INSTALLER, s.OWNER_RIGHTS])
def test_administrative_writers_are_distinct_from_current_user(sid):
    descriptor = s.Descriptor(s.SYSTEM, False, [s.Ace(0, 3, s.FULL_CONTROL, sid)])
    policy(descriptor)
    with pytest.raises(PrivateFSError):
        policy(descriptor, user=s.SYSTEM)


@pytest.mark.parametrize(
    "aces", [None, [s.Ace(2, 0, 1, b"user")], [s.Ace(0, 0x20, 1, b"user")], [s.Ace(0, 0, 0x200, s.SYSTEM)]]
)
def test_unknown_descriptor_or_rights_refuse(aces):
    with pytest.raises(PrivateFSError):
        policy(s.Descriptor(s.SYSTEM, False, aces))


def test_deny_does_not_excuse_untrusted_allow_and_inherit_only_is_not_effective():
    policy(s.Descriptor(s.SYSTEM, False, [s.Ace(0, 0x0B, s.FULL_CONTROL, b"creator")]))
    with pytest.raises(PrivateFSError):
        policy(s.Descriptor(s.SYSTEM, False, [s.Ace(1, 0, 2, b"user"), s.Ace(0, 0, 2, b"user")]))


class API:
    """External native boundary only; real policy/owned-handle/path logic runs."""

    def __init__(self):
        self.objects = {}
        self.names = {}
        self.closed = []
        self.fail = None
        self.mutation = None
        self.observations = {}
        self.opens = []
        self.next = 1
        root = "\\\\?\\Volume{test}\\"
        for i, path in enumerate(
            [root, root + "Windows", root + "Windows\\System32", root + "Windows\\System32\\image.exe"]
        ):
            self.objects[path] = (
                Metadata(FileIdentity(9, bytes([i]) * 16), i < 3, False, 3 if i == 3 else 1, 500 if i == 3 else 0),
                s.Descriptor(s.SYSTEM, False, [s.Ace(0, 0x10, 0x1200A9, b"everyone")]),
            )
        self.root = root
        self.image = root + "Windows\\System32\\image.exe"

    def user_sid(self):
        return b"user"

    def managed_service_sid(self):
        if self.fail == "service_sid":
            raise PrivateFSError("access_denied", "service_sid")
        return s.TRUSTED_INSTALLER

    def validate_drive(self, drive):
        assert drive == "C:\\"
        if self.fail == "drive":
            raise PrivateFSError("unsupported", "drive_mapping")

    def validate_volume(self, handle):
        if self.fail == "volume":
            raise PrivateFSError("unsupported", "filesystem")

    def open(self, path, *, access=0x120089, share=3, create=False):
        assert not create
        # Pinning must deny preexisting data-write/delete access; directories
        # need only descriptor/attributes, not directory enumeration rights.
        assert share == 1
        assert access == (0x20081 if path.endswith("image.exe") else 0x20080)
        path = self.root if path == "C:\\" else path
        self.opens.append(path)
        if self.fail == "open" or (self.fail == "writer" and path == self.image):
            raise PrivateFSError("busy", "open", native_code=32)
        if path not in self.objects:
            raise PrivateFSError("missing", "open")
        value = self.next
        self.next += 1
        self.names[value] = path
        return OwnedHandle(self, value)

    def CloseHandle(self, value):
        self.closed.append(value)
        return self.fail != "close"

    def checked(self, okay, operation):
        if not okay:
            raise PrivateFSError("io", operation, native_code=6)

    def final_path(self, handle):
        path = self.names[handle.value]
        if self.fail == "final_path":
            raise PrivateFSError("access_denied", "final_path")
        if self.mutation == "path" and path == self.image:
            return path + "changed"
        return path

    def metadata(self, handle):
        path = self.names[handle.value]
        self.observations[path] = self.observations.get(path, 0) + 1
        if self.fail == "metadata":
            raise PrivateFSError("io", "file_identity")
        info = self.objects[path][0]
        if self.mutation == "identity" and path == self.image and self.observations[path] > 1:
            return replace(info, identity=FileIdentity(9, b"changed" * 2 + b"!!"))
        return info

    def descriptor(self, handle):
        path = self.names[handle.value]
        if self.fail == "descriptor":
            raise PrivateFSError("access_denied", "security_info")
        desc = self.objects[path][1]
        if self.mutation == "acl" and path == self.image and self.observations[path] > 1:
            return replace(desc, aces=[*desc.aces, s.Ace(0, 0, 2, b"user")])
        return desc

    def mtime_ns(self, handle):
        if self.fail == "mtime":
            raise PrivateFSError("io", "file_basic")
        return 12345678900


@pytest.fixture
def native(monkeypatch):
    from mordred_hermes._private_fs import _windows_api, _windows_managed

    api = API()
    monkeypatch.setattr(_windows_api, "get_api", lambda: api)
    monkeypatch.setattr(_windows_managed, "get_api", lambda: api)
    monkeypatch.setattr(fs, "_platform", "nt")
    return api


def test_inspection_returns_hardlinked_metadata_only_after_every_handle_closes(native):
    assert inspect("C:\\Windows\\System32\\image.exe") == FileMetadata(FileIdentity(9, b"\x03" * 16), 500, 12345678900)
    assert set(native.closed) == set(native.names)
    assert len(native.closed) == len(native.names)
    assert len(native.opens) >= 8  # Fresh named path observations, including root.


@pytest.mark.parametrize(
    "failure",
    ["open", "writer", "metadata", "descriptor", "final_path", "mtime", "volume", "drive", "service_sid", "close"],
)
def test_failed_native_query_or_cleanup_never_returns_metadata(native, failure):
    native.fail = failure
    with pytest.raises(PrivateFSError):
        inspect("C:\\Windows\\System32\\image.exe")
    assert set(native.closed) == set(native.names)


@pytest.mark.parametrize("mutation", ["path", "identity", "acl"])
def test_changed_identity_path_or_security_refuses(native, mutation):
    native.mutation = mutation
    with pytest.raises(PrivateFSError) as err:
        inspect("C:\\Windows\\System32\\image.exe")
    assert err.value.reason == "unsafe"
    assert set(native.closed) == set(native.names)


@pytest.mark.parametrize(
    "node,change",
    [
        (node, change)
        for node in ["root", "parent", "image"]
        for change in ["reparse", "owner", "write", "volume", "type"]
        if (node, change) != ("root", "volume")
    ],
)
def test_every_selected_namespace_object_is_checked(native, node, change):
    path = {"root": native.root, "parent": native.root + "Windows", "image": native.image}[node]
    info, desc = native.objects[path]
    if change == "reparse":
        info = replace(info, reparse=True)
    elif change == "owner":
        desc = replace(desc, owner=b"user")
    elif change == "write":
        desc = replace(desc, aces=[*desc.aces, s.Ace(0, 0, 0x40 if node != "image" else 2, b"user")])
    elif change == "volume":
        info = replace(info, identity=FileIdentity(8, info.identity.file_id))
    else:
        info = replace(info, directory=not info.directory)
    native.objects[path] = (info, desc)
    with pytest.raises(PrivateFSError):
        inspect("C:\\Windows\\System32\\image.exe")


@pytest.mark.parametrize(
    "path",
    [
        "relative.exe",
        "C:relative.exe",
        "\\\\server\\share\\image.exe",
        "C:\\Windows\\..\\image.exe",
        "C:\\image.exe:stream",
        "C:\\" + ("x\\" * 257) + "image.exe",
        pytest.param("C:\\" + "x" * 32768 + ".exe", id="long-path"),
    ],
)
def test_unsupported_or_unbounded_paths_refuse_before_native_use(monkeypatch, path):
    monkeypatch.setattr(fs, "_platform", "nt")
    with pytest.raises(PrivateFSError):
        inspect(path)


def test_nonwindows_platform_refuses(monkeypatch):
    monkeypatch.setattr(fs, "_platform", "posix")
    with pytest.raises(PrivateFSError) as err:
        inspect("C:\\Windows\\image.exe")
    assert err.value.reason == "unsupported"


@pytest.mark.parametrize("failure", ["size", "lookup", "sid", "domain", "kind", "growth"])
def test_service_sid_resolution_refuses_unvalidated_or_unbounded_result(failure):
    import ctypes as c

    from mordred_hermes._private_fs._windows_api import DWORD, NativeAPI

    api = NativeAPI.__new__(NativeAPI)
    resolver = getattr(api, "managed_service_sid", None)
    assert callable(resolver), "native service SID validation is missing"
    calls = []

    def lookup(system, name, sid, sid_size, domain, domain_size, kind):
        assert system is None and name == "NT SERVICE\\TrustedInstaller"
        calls.append(sid is not None)
        c.cast(sid_size, c.POINTER(DWORD))[0] = 1000 if failure == "size" else len(s.TRUSTED_INSTALLER)
        c.cast(domain_size, c.POINTER(DWORD))[0] = 11
        c.cast(kind, c.POINTER(DWORD))[0] = 1 if failure == "kind" else 5
        if sid is None:
            return False
        if failure == "lookup":
            return False
        raw = s.TRUSTED_INSTALLER if failure != "sid" else s.TRUSTED_INSTALLER[:-1] + b"\x00"
        c.memmove(sid, raw, len(raw))
        domain.value = "NT SERVICE" if failure != "domain" else "OTHER"
        if failure == "growth":
            c.cast(sid_size, c.POINTER(DWORD))[0] = 1000
        return True

    api.LookupAccountName = lookup
    api.last_error = lambda: 122
    api.ValidSid = lambda p: True
    api.SidLength = lambda p: len(s.TRUSTED_INSTALLER)
    with pytest.raises(PrivateFSError):
        resolver()
    assert len(calls) <= 2


def test_service_sid_success_requires_exact_native_bytes_and_two_bounded_calls():
    import ctypes as c

    from mordred_hermes._private_fs._windows_api import DWORD, NativeAPI

    api = NativeAPI.__new__(NativeAPI)
    calls = []

    def lookup(system, name, sid, sid_size, domain, domain_size, kind):
        calls.append(sid is not None)
        c.cast(sid_size, c.POINTER(DWORD))[0] = 32
        c.cast(domain_size, c.POINTER(DWORD))[0] = 11 if sid is None else 10
        c.cast(kind, c.POINTER(DWORD))[0] = 5
        if sid is None:
            return False
        c.memmove(sid, bytes.fromhex("010600000000000550000000b589fb381984c2cb5c6c236d5700776ec0026487"), 32)
        domain.value = "NT SERVICE"
        return True

    api.LookupAccountName = lookup
    api.last_error = lambda: 122
    api.ValidSid = lambda p: True
    api.SidLength = lambda p: 32
    assert api.managed_service_sid() == bytes.fromhex(
        "010600000000000550000000b589fb381984c2cb5c6c236d5700776ec0026487"
    )
    assert calls == [False, True]


@pytest.mark.parametrize("body_error", [False, True])
def test_security_descriptor_free_failure_prevents_metadata_or_preserves_body(body_error):
    import ctypes as c

    from mordred_hermes._private_fs._windows_api import PTR, NativeAPI

    api = NativeAPI.__new__(NativeAPI)

    def info(handle, object_type, requested, owner, group, dacl, sacl, sd):
        c.cast(owner, c.POINTER(PTR))[0] = 123
        c.cast(sd, c.POINTER(PTR))[0] = 456
        return 0

    api.SecurityInfo = info
    api._sid_bytes = lambda ptr: s.SYSTEM
    api.SDControl = lambda *args: not body_error
    api.LocalFree = lambda ptr: 456
    api.last_error = lambda: 6
    handle = OwnedHandle(api, 123)
    with pytest.raises(PrivateFSError) as err:
        api.descriptor(handle)
    assert err.value.operation == ("descriptor_control" if body_error else "free_descriptor")
    if body_error:
        assert any("cleanup failed" in note for note in err.value.__notes__)


@pytest.mark.parametrize("body_error", [False, True])
def test_sid_string_free_failure_is_checked_or_preserves_body(monkeypatch, body_error):
    import ctypes as c

    from mordred_hermes._private_fs._windows_api import PTR, NativeAPI

    api = NativeAPI.__new__(NativeAPI)
    text = c.create_unicode_buffer("S-1-5-18")

    def convert(sid, output):
        c.cast(output, c.POINTER(PTR))[0] = c.addressof(text)
        return True

    def unreadable(pointer):
        raise ValueError("body")

    api.SidString = convert
    api.LocalFree = lambda ptr: 456
    api.last_error = lambda: 6
    if body_error:
        monkeypatch.setattr(c, "wstring_at", unreadable)
        with pytest.raises(ValueError, match="body") as body:
            api.sid_text(s.SYSTEM)
        assert any("cleanup failed" in note for note in body.value.__notes__)
        return
    with pytest.raises(PrivateFSError) as err:
        api.sid_text(s.SYSTEM)
    assert (err.value.operation, err.value.native_code) == ("free_sid_string", 6)


def test_successful_sid_string_free_returns_text():
    import ctypes as c

    from mordred_hermes._private_fs._windows_api import PTR, NativeAPI

    api = NativeAPI.__new__(NativeAPI)
    text = c.create_unicode_buffer("S-1-5-18")
    freed = []

    def convert(sid, output):
        c.cast(output, c.POINTER(PTR))[0] = c.addressof(text)
        return True

    api.SidString = convert
    api.LocalFree = lambda ptr: freed.append(ptr.value) or None
    assert api.sid_text(s.SYSTEM) == "S-1-5-18"
    assert freed == [c.addressof(text)]


@pytest.mark.parametrize("path", ["\\\\?\\Volume{broken", "\\\\?\\Volume{"])
def test_malformed_native_volume_guid_path_is_classified(path):
    from mordred_hermes._private_fs._windows_api import NativeAPI

    api = NativeAPI.__new__(NativeAPI)

    def volume_info(handle, name, size, serial, length, flags, filesystem, filesystem_size):
        filesystem.value = "NTFS"
        return True

    api.VolumeInfo = volume_info
    api.final_path = lambda handle: path
    api.DriveType = lambda root: 3
    with pytest.raises(PrivateFSError) as err:
        api.validate_volume(OwnedHandle(api, 123))
    assert (err.value.reason, err.value.operation) == ("unsupported", "volume_path")


@pytest.mark.parametrize("root_path", ["\\\\?\\Volume{broken", "\\\\?\\Volume{test}\\nested\\", "C:\\"])
def test_malformed_native_root_is_classified_and_closed(native, monkeypatch, root_path):
    original = native.final_path
    monkeypatch.setattr(
        native, "final_path", lambda h: root_path if native.names[h.value] == native.root else original(h)
    )
    with pytest.raises(PrivateFSError) as err:
        inspect("C:\\Windows\\System32\\image.exe")
    assert err.value.reason == "unsupported"
    assert set(native.closed) == set(native.names)


@pytest.mark.parametrize("size,links", [(-1, 1), (1 << 63, 1), (10, 0)])
def test_invalid_file_metadata_is_classified(native, size, links):
    info, desc = native.objects[native.image]
    native.objects[native.image] = (replace(info, size=size, links=links), desc)
    with pytest.raises(PrivateFSError) as err:
        inspect("C:\\Windows\\System32\\image.exe")
    assert err.value.reason == "unsafe"


@pytest.mark.parametrize("mtime", [-11644473600000000100, 1 << 72, 123])
def test_invalid_native_timestamp_is_classified(native, monkeypatch, mtime):
    monkeypatch.setattr(native, "mtime_ns", lambda handle: mtime)
    with pytest.raises(PrivateFSError) as err:
        inspect("C:\\Windows\\System32\\image.exe")
    assert err.value.reason == "unsafe"


def test_changed_effective_user_at_return_refuses(native, monkeypatch):
    users = iter([b"user", b"different"])
    monkeypatch.setattr(native, "user_sid", lambda: next(users))
    with pytest.raises(PrivateFSError) as err:
        inspect("C:\\Windows\\System32\\image.exe")
    assert err.value.operation == "managed_image_principal"


def test_fresh_named_identity_must_match_pinned_source(native, monkeypatch):
    metadata = native.metadata

    def changed(handle):
        info = metadata(handle)
        if native.names[handle.value] == native.image and handle.value > 4:
            return replace(info, identity=FileIdentity(9, b"replacement!!!!!"))
        return info

    monkeypatch.setattr(native, "metadata", changed)
    with pytest.raises(PrivateFSError) as err:
        inspect("C:\\Windows\\System32\\image.exe")
    assert err.value.operation == "managed_image_changed"


def test_handle_close_errors_do_not_mask_security_refusal(native):
    info, desc = native.objects[native.image]
    native.objects[native.image] = (info, replace(desc, owner=b"user"))
    native.fail = "close"
    with pytest.raises(PrivateFSError) as err:
        inspect("C:\\Windows\\System32\\image.exe")
    assert err.value.operation == "managed_image_acl"
    assert err.value.commit_state == "not_committed"
    assert any("cleanup failed" in note for note in err.value.__notes__)
    assert set(native.closed) == set(native.names)
