"""Managed image policy and read-only Win32 boundary faults on every host."""

from __future__ import annotations

from dataclasses import replace

import pytest

import mordred_hermes._private_fs as fs
from mordred_hermes._private_fs import FileIdentity, FileMetadata, PrivateFSError
from mordred_hermes._private_fs import _windows_security as s
from mordred_hermes._private_fs._windows_api import Metadata, OwnedHandle

ROLES = ["image", "image_parent", "upper_ancestor"]
STRICT_ROLES = ["image", "image_parent"]
USERS = b"users"
# The Windows default ProgramData shape: BUILTIN\Users container-inherit
# ADD_FILE, ADD_SUBDIRECTORY, WRITE_EA and WRITE_ATTRIBUTES (0x116).
PROGRAMDATA_ACE = s.Ace(0, 0x02, 0x116, USERS)
PROGRAMDATA = s.Descriptor(
    s.SYSTEM,
    False,
    [
        s.Ace(0, 0x03, s.FULL_CONTROL, s.SYSTEM),
        s.Ace(0, 0x03, s.FULL_CONTROL, s.ADMINISTRATORS),
        s.Ace(0, 0x0B, 0x10000000, b"creator-owner"),
        s.Ace(0, 0x03, 0x1200A9, USERS),
        PROGRAMDATA_ACE,
    ],
)
# The default system volume root: Users may create subdirectories there.
DEFAULT_ROOT = s.Descriptor(
    s.TRUSTED_INSTALLER,
    False,
    [
        s.Ace(0, 0, 0x1000A1, b"app-capability"),
        s.Ace(0, 0x03, s.FULL_CONTROL, s.SYSTEM),
        s.Ace(0, 0x03, s.FULL_CONTROL, s.ADMINISTRATORS),
        s.Ace(0, 0x03, 0x1200A9, USERS),
        s.Ace(0, 0x02, 0x4, USERS),
        s.Ace(0, 0x0A, 0x2, USERS),
        s.Ace(0, 0x0B, 0x10000000, b"creator-owner"),
    ],
)
IMAGE = "C:\\Windows\\System32\\image.exe"
ROOT_IMAGE = "C:\\image.exe"


def policy(descriptor, *, role="image", user=b"user"):
    s.check_managed_image(descriptor, user, s.TRUSTED_INSTALLER, role=role)


def refused(descriptor, *, role="image", user=b"user"):
    with pytest.raises(PrivateFSError) as err:
        policy(descriptor, role=role, user=user)
    assert (err.value.reason, err.value.operation) == ("unsafe", "managed_image_acl")


def inspect(path):
    inspector = getattr(fs, "inspect_managed_installation_image", None)
    assert callable(inspector), "managed installation inspection is missing"
    return inspector(path)


@pytest.mark.parametrize("role", ROLES)
@pytest.mark.parametrize("owner", [s.SYSTEM, s.ADMINISTRATORS, s.TRUSTED_INSTALLER])
def test_managed_owner_with_inherited_public_read_is_admitted(owner, role):
    policy(s.Descriptor(owner, False, [s.Ace(0, 0x10, 0x1200A9, b"everyone")]), role=role)


@pytest.mark.parametrize("role", ROLES)
@pytest.mark.parametrize("owner", [b"user", b"other"])
def test_readonly_user_or_untrusted_owner_can_rewrite_dacl_and_is_refused(owner, role):
    refused(s.Descriptor(owner, True, [s.Ace(0, 0, 0x120089, b"everyone")]), role=role)


@pytest.mark.parametrize("sid", [b"user", b"other", b"everyone"])
@pytest.mark.parametrize("mask", [2, 4, 0x10, 0x40, 0x100, 0x10000, 0x40000, 0x80000, 0x40000000, 0x10000000])
def test_managed_file_current_or_untrusted_mutation_refuses(sid, mask):
    refused(s.Descriptor(s.SYSTEM, False, [s.Ace(0, 0x10, mask, sid)]), role="image")


@pytest.mark.parametrize("sid", [b"user", b"other", USERS])
@pytest.mark.parametrize("mask", [2, 4, 0x10, 0x40, 0x100, 0x116, 0x10000, 0x40000, 0x80000, 0x40000000, 0x10000000])
def test_image_parent_refuses_entry_creation_and_every_mutation(sid, mask):
    # ADD_SUBDIRECTORY (0x4) is refused too: a planted <image>.local folder or
    # DLL in the application directory would run inside the admitted image.
    refused(s.Descriptor(s.SYSTEM, False, [s.Ace(0, 0, mask, sid)]), role="image_parent")


@pytest.mark.parametrize("flags", [0, 0x02, 0x03])
@pytest.mark.parametrize("sid", [b"user", b"other", USERS])
@pytest.mark.parametrize("mask", [2, 4, 0x10, 0x100, 0x116, 0x40000000, 0x1201BF])
def test_upper_ancestor_admits_entry_creation_ea_and_attribute_grants(sid, mask, flags):
    policy(s.Descriptor(s.SYSTEM, False, [s.Ace(0, flags, mask, sid)]), role="upper_ancestor")


@pytest.mark.parametrize("sid", [b"user", b"other", USERS])
@pytest.mark.parametrize(
    "mask", [0x40, 0x10000, 0x40000, 0x80000, 0x10000000, s.FULL_CONTROL, 0x116 | 0x40, 0x40000000 | 0x10000]
)
def test_upper_ancestor_refuses_delete_child_delete_dac_owner_and_full_grants(sid, mask):
    refused(s.Descriptor(s.SYSTEM, False, [s.Ace(0, 0x02, mask, sid)]), role="upper_ancestor")


def test_programdata_descriptor_is_admitted_only_as_an_upper_ancestor():
    policy(PROGRAMDATA, role="upper_ancestor")
    for role in STRICT_ROLES:
        refused(PROGRAMDATA, role=role)


def test_sibling_directory_creation_is_admitted_only_above_the_parent():
    descriptor = s.Descriptor(s.ADMINISTRATORS, False, [s.Ace(0, 0, 4, USERS)])
    policy(descriptor, role="upper_ancestor")
    for role in STRICT_ROLES:
        refused(descriptor, role=role)


@pytest.mark.parametrize("role", ROLES)
@pytest.mark.parametrize("sid", [s.SYSTEM, s.ADMINISTRATORS, s.TRUSTED_INSTALLER, s.OWNER_RIGHTS])
def test_administrative_writers_are_distinct_from_current_user(sid, role):
    descriptor = s.Descriptor(s.SYSTEM, False, [s.Ace(0, 3, s.FULL_CONTROL, sid)])
    policy(descriptor, role=role)
    refused(descriptor, role=role, user=s.SYSTEM)


@pytest.mark.parametrize("role", ROLES)
@pytest.mark.parametrize(
    "aces",
    [
        None,
        [s.Ace(2, 0, 1, b"user")],
        [s.Ace(0, 0x20, 1, b"user")],
        [s.Ace(0, 0, 0x200, s.SYSTEM)],
        [s.Ace(0, 0, 0x01000000, USERS)],
    ],
)
def test_unknown_descriptor_or_rights_refuse(aces, role):
    refused(s.Descriptor(s.SYSTEM, False, aces), role=role)


@pytest.mark.parametrize("role", ["ancestor", "directory", "", None, True])
def test_unknown_role_refuses(role):
    with pytest.raises(PrivateFSError) as err:
        policy(s.Descriptor(s.SYSTEM, False, [s.Ace(0, 0x10, 0x1200A9, b"everyone")]), role=role)
    assert (err.value.reason, err.value.operation) == ("unsafe", "managed_image_role")


@pytest.mark.parametrize("role", ROLES)
def test_deny_does_not_excuse_untrusted_allow_and_inherit_only_is_not_effective(role):
    policy(s.Descriptor(s.SYSTEM, False, [s.Ace(0, 0x0B, s.FULL_CONTROL, b"creator")]), role=role)
    refused(s.Descriptor(s.SYSTEM, False, [s.Ace(1, 0, 0x40, b"user"), s.Ace(0, 0, 0x40, b"user")]), role=role)


def test_unvalidated_service_sid_refuses_every_role():
    descriptor = s.Descriptor(s.SYSTEM, False, [s.Ace(0, 0x10, 0x1200A9, b"everyone")])
    for role in ROLES:
        with pytest.raises(PrivateFSError) as err:
            s.check_managed_image(descriptor, b"user", b"service", role=role)
        assert err.value.operation == "managed_service_sid"


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
        # A later open of an already opened name is a fresh named reopen; the
        # first open of each name is the pinned handle.
        self.opened = set()
        self.reopened = set()
        self.handle_metadata = {}
        self.handle_descriptors = {}
        # path -> predicate(named, count) selecting observations that see a
        # reparse attribute or a replacement descriptor.
        self.reparse_when = {}
        self.descriptor_when = {}
        root = "\\\\?\\Volume{test}\\"
        for i, path in enumerate(
            [
                root,
                root + "Windows",
                root + "Windows\\System32",
                root + "Windows\\System32\\image.exe",
                root + "image.exe",
            ]
        ):
            image = path.endswith("image.exe")
            self.objects[path] = (
                Metadata(FileIdentity(9, bytes([i]) * 16), not image, False, 3 if image else 1, 500 if image else 0),
                s.Descriptor(s.SYSTEM, False, [s.Ace(0, 0x10, 0x1200A9, b"everyone")]),
            )
        self.root = root
        self.upper = root + "Windows"
        self.parent = root + "Windows\\System32"
        self.image = root + "Windows\\System32\\image.exe"
        self.root_image = root + "image.exe"

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
        # Share-read only. The image handle holds FILE_READ_DATA, so it refuses
        # preexisting writers/deleters and blocks new ones while pinned.
        # Directory handles hold only READ_CONTROL and FILE_READ_ATTRIBUTES;
        # NT share checking ignores them, so they do NOT block a later rename
        # or delete. Directory safety comes from the role-based DACL policy
        # plus final-path and identity rechecks, never from pinning alone.
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
        if path in self.opened:
            self.reopened.add(value)
        self.opened.add(path)
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

    def _count(self, counts, handle):
        counts[handle.value] = counts.get(handle.value, 0) + 1
        return handle.value in self.reopened, counts[handle.value]

    def metadata(self, handle):
        path = self.names[handle.value]
        self.observations[path] = self.observations.get(path, 0) + 1
        named, count = self._count(self.handle_metadata, handle)
        if self.fail == "metadata":
            raise PrivateFSError("io", "file_identity")
        info = self.objects[path][0]
        if self.mutation == "identity" and path == self.image and self.observations[path] > 1:
            return replace(info, identity=FileIdentity(9, b"changed" * 2 + b"!!"))
        if path in self.reparse_when and self.reparse_when[path](named, count):
            return replace(info, reparse=True)
        return info

    def descriptor(self, handle):
        path = self.names[handle.value]
        named, count = self._count(self.handle_descriptors, handle)
        if self.fail == "descriptor":
            raise PrivateFSError("access_denied", "security_info")
        desc = self.objects[path][1]
        if self.mutation == "acl" and path == self.image and self.observations[path] > 1:
            return replace(desc, aces=[*desc.aces, s.Ace(0, 0, 2, b"user")])
        if path in self.descriptor_when and self.descriptor_when[path][0](named, count):
            return self.descriptor_when[path][1]
        return desc

    def mtime_ns(self, handle):
        if self.fail == "mtime":
            raise PrivateFSError("io", "file_basic")
        return 12345678900


# Observation phases of a non-root object, counted per handle: the pinned
# handle is observed at the walk, at the first pinned recheck and at the final
# pinned recheck; the fresh named reopen is observed once in between.
PHASES = {
    "walk": lambda named, count: True,
    "pinned_recheck": lambda named, count: not named and count == 2,
    "named_reopen": lambda named, count: named,
    "final_recheck": lambda named, count: not named and count == 3,
}


@pytest.fixture
def native(monkeypatch):
    from mordred_hermes._private_fs import _windows_api, _windows_managed

    api = API()
    monkeypatch.setattr(_windows_api, "get_api", lambda: api)
    monkeypatch.setattr(_windows_managed, "get_api", lambda: api)
    monkeypatch.setattr(fs, "_platform", "nt")
    return api


def set_descriptor(native, path, descriptor):
    info, _ = native.objects[path]
    native.objects[path] = (info, descriptor)


def refuses(native, path, operation, reason="unsafe"):
    with pytest.raises(PrivateFSError) as err:
        inspect(path)
    assert (err.value.reason, err.value.operation) == (reason, operation)
    assert set(native.closed) == set(native.names)
    assert len(native.closed) == len(native.names)


def test_inspection_returns_hardlinked_metadata_only_after_every_handle_closes(native):
    assert inspect(IMAGE) == FileMetadata(FileIdentity(9, b"\x03" * 16), 500, 12345678900)
    assert set(native.closed) == set(native.names)
    assert len(native.closed) == len(native.names)
    assert len(native.opens) >= 8  # Fresh named path observations, including root.


@pytest.mark.parametrize(
    "failure,reason,operation",
    [
        ("open", "busy", "open"),
        ("writer", "busy", "open"),
        ("metadata", "io", "file_identity"),
        ("descriptor", "access_denied", "security_info"),
        ("final_path", "access_denied", "final_path"),
        ("mtime", "io", "file_basic"),
        ("volume", "unsupported", "filesystem"),
        ("drive", "unsupported", "drive_mapping"),
        ("service_sid", "access_denied", "service_sid"),
        ("close", "io", "close"),
    ],
)
def test_failed_native_query_or_cleanup_never_returns_metadata(native, failure, reason, operation):
    native.fail = failure
    refuses(native, IMAGE, operation, reason)


@pytest.mark.parametrize("mutation", ["path", "identity", "acl"])
def test_changed_identity_path_or_security_refuses(native, mutation):
    native.mutation = mutation
    with pytest.raises(PrivateFSError) as err:
        inspect(IMAGE)
    assert err.value.reason == "unsafe"
    assert set(native.closed) == set(native.names)


# root and upper (Windows) are upper ancestors, parent is the immediate parent
# (System32). Each "write" uses a right refused for that role, and the parent
# uses ADD_SUBDIRECTORY, which only the immediate parent newly refuses.
WRITES = {"root": 0x40, "upper": 0x80000, "parent": 0x4, "image": 2}
EXPECTED = {
    "reparse": "managed_image_metadata",
    "owner": "managed_image_acl",
    "write": "managed_image_acl",
    "volume": "managed_image_metadata",
    "type": "managed_image_metadata",
}


@pytest.mark.parametrize(
    "node,change",
    [
        (node, change)
        for node in ["root", "upper", "parent", "image"]
        for change in ["reparse", "owner", "write", "volume", "type"]
        if (node, change) != ("root", "volume")
    ],
)
def test_every_selected_namespace_object_is_checked(native, node, change):
    path = {"root": native.root, "upper": native.upper, "parent": native.parent, "image": native.image}[node]
    info, desc = native.objects[path]
    if change == "reparse":
        info = replace(info, reparse=True)
    elif change == "owner":
        desc = replace(desc, owner=b"user")
    elif change == "write":
        desc = replace(desc, aces=[*desc.aces, s.Ace(0, 0, WRITES[node], b"user")])
    elif change == "volume":
        info = replace(info, identity=FileIdentity(8, info.identity.file_id))
    else:
        info = replace(info, directory=not info.directory)
    native.objects[path] = (info, desc)
    refuses(native, IMAGE, EXPECTED[change])


@pytest.mark.parametrize("node", ["root", "upper"])
@pytest.mark.parametrize("ace", [PROGRAMDATA_ACE, s.Ace(0, 0x02, 0x40000000, USERS), s.Ace(0, 0, 0x4, USERS)])
def test_programdata_shape_on_an_upper_ancestor_is_admitted(native, node, ace):
    path = {"root": native.root, "upper": native.upper}[node]
    set_descriptor(native, path, replace(PROGRAMDATA, aces=[*PROGRAMDATA.aces, ace]))
    assert inspect(IMAGE) == FileMetadata(FileIdentity(9, b"\x03" * 16), 500, 12345678900)
    assert set(native.closed) == set(native.names)


def test_default_volume_root_is_admitted_as_an_upper_ancestor(native):
    set_descriptor(native, native.root, DEFAULT_ROOT)
    set_descriptor(native, native.upper, PROGRAMDATA)
    assert inspect(IMAGE).identity == FileIdentity(9, b"\x03" * 16)


@pytest.mark.parametrize("ace", [PROGRAMDATA_ACE, s.Ace(0, 0x02, 0x40000000, USERS)])
@pytest.mark.parametrize("node", ["parent", "image", "root_parent"])
def test_programdata_shape_on_parent_image_or_root_parent_refuses(native, node, ace):
    path, image = {
        "parent": (native.parent, IMAGE),
        "image": (native.image, IMAGE),
        "root_parent": (native.root, ROOT_IMAGE),
    }[node]
    _, desc = native.objects[path]
    set_descriptor(native, path, replace(desc, aces=[*desc.aces, ace]))
    refuses(native, image, "managed_image_acl")


def test_default_volume_root_refuses_when_it_is_the_immediate_parent(native):
    set_descriptor(native, native.root, DEFAULT_ROOT)
    refuses(native, ROOT_IMAGE, "managed_image_acl")


def test_image_directly_under_a_safe_root_is_admitted(native):
    assert inspect(ROOT_IMAGE) == FileMetadata(FileIdentity(9, b"\x04" * 16), 500, 12345678900)


@pytest.mark.parametrize("node", ["root", "upper"])
@pytest.mark.parametrize("mask", [0x10000000, 0x10000, 0x40, 0x40000, 0x80000])
def test_upper_ancestor_delete_child_delete_dac_owner_or_all_grants_refuse(native, node, mask):
    path = {"root": native.root, "upper": native.upper}[node]
    set_descriptor(native, path, replace(PROGRAMDATA, aces=[*PROGRAMDATA.aces, s.Ace(0, 0x02, mask, USERS)]))
    refuses(native, IMAGE, "managed_image_acl")


@pytest.mark.parametrize("node", ["root", "upper"])
@pytest.mark.parametrize("owner", [b"user", b"other"])
def test_current_or_untrusted_owner_of_an_upper_ancestor_refuses(native, node, owner):
    path = {"root": native.root, "upper": native.upper}[node]
    set_descriptor(native, path, replace(PROGRAMDATA, owner=owner))
    refuses(native, IMAGE, "managed_image_acl")


@pytest.mark.parametrize("phase", list(PHASES))
@pytest.mark.parametrize("node", ["upper", "parent", "image"])
def test_reparse_appearing_at_any_observation_refuses(native, node, phase):
    path = {"upper": native.upper, "parent": native.parent, "image": native.image}[node]
    set_descriptor(native, native.upper, PROGRAMDATA)
    native.reparse_when[path] = PHASES[phase]
    # The direct reparse check, not only the later metadata comparison, refuses.
    refuses(native, IMAGE, "managed_image_metadata")


def test_reparse_on_the_root_refuses(native):
    native.reparse_when[native.root] = PHASES["walk"]
    refuses(native, IMAGE, "managed_image_metadata")


@pytest.mark.parametrize("phase", ["pinned_recheck", "named_reopen", "final_recheck"])
def test_parent_role_is_preserved_through_rechecks_and_named_reopens(native, phase):
    # Only a later observation of System32 sees the ProgramData ACE. Rechecked
    # with its stored image_parent role, the policy refuses (managed_image_acl);
    # an upper_ancestor recheck would admit it and only the descriptor
    # comparison would notice (managed_image_changed).
    _, desc = native.objects[native.parent]
    native.descriptor_when[native.parent] = (PHASES[phase], replace(desc, aces=[*desc.aces, PROGRAMDATA_ACE]))
    refuses(native, IMAGE, "managed_image_acl")


@pytest.mark.parametrize(
    "path,roles",
    [
        (IMAGE, ["upper_ancestor", "upper_ancestor", "image_parent", "image"]),
        (ROOT_IMAGE, ["image_parent", "image"]),
    ],
)
def test_every_observation_reuses_the_stored_role(native, monkeypatch, path, roles):
    from mordred_hermes._private_fs import _windows_managed

    seen = []
    checker = _windows_managed.check_managed_image

    def recording(descriptor, user, service, *, role):
        seen.append(role)
        checker(descriptor, user, service, role=role)

    monkeypatch.setattr(_windows_managed, "check_managed_image", recording)
    inspect(path)
    # Walk, first pinned recheck, named reopens, final pinned recheck.
    assert seen == roles * 4


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
        inspect(IMAGE)
    assert err.value.reason == "unsupported"
    assert set(native.closed) == set(native.names)


@pytest.mark.parametrize("size,links", [(-1, 1), (1 << 63, 1), (10, 0)])
def test_invalid_file_metadata_is_classified(native, size, links):
    info, desc = native.objects[native.image]
    native.objects[native.image] = (replace(info, size=size, links=links), desc)
    with pytest.raises(PrivateFSError) as err:
        inspect(IMAGE)
    assert err.value.reason == "unsafe"


@pytest.mark.parametrize("mtime", [-11644473600000000100, 1 << 72, 123])
def test_invalid_native_timestamp_is_classified(native, monkeypatch, mtime):
    monkeypatch.setattr(native, "mtime_ns", lambda handle: mtime)
    with pytest.raises(PrivateFSError) as err:
        inspect(IMAGE)
    assert err.value.reason == "unsafe"


def test_changed_effective_user_at_return_refuses(native, monkeypatch):
    users = iter([b"user", b"different"])
    monkeypatch.setattr(native, "user_sid", lambda: next(users))
    with pytest.raises(PrivateFSError) as err:
        inspect(IMAGE)
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
        inspect(IMAGE)
    assert err.value.operation == "managed_image_changed"


def test_handle_close_errors_do_not_mask_security_refusal(native):
    info, desc = native.objects[native.image]
    native.objects[native.image] = (info, replace(desc, owner=b"user"))
    native.fail = "close"
    with pytest.raises(PrivateFSError) as err:
        inspect(IMAGE)
    assert err.value.operation == "managed_image_acl"
    assert err.value.commit_state == "not_committed"
    assert any("cleanup failed" in note for note in err.value.__notes__)
    assert set(native.closed) == set(native.names)
