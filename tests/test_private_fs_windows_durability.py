"""NTFS namespace ordering with real admission/policy and a faultable API seam."""

from __future__ import annotations

import contextlib

import pytest

from mordred_hermes import _private_fs as fs
from mordred_hermes._private_fs import _windows_paths as paths
from mordred_hermes._private_fs._windows_api import NativeAPI
from tests.test_private_fs_confidential import PRIVATE, Native, Node


class DurableNative(Native):
    def __init__(self):
        super().__init__()
        self.nodes["C:\\home"].descriptor = PRIVATE
        self.events = []
        self.pending = {}
        self.fail = lambda event: False
        self.mutated = False

    def event(self, kind, path):
        item = (kind, path)
        self.events.append(item)
        if self.fail(item):
            raise fs.PrivateFSError("io", "injected_" + kind)

    def open(self, path, *, access=0x120089, share=3, create=False):
        handle = super().open(path, access=access, share=share, create=create)
        if self.nodes[path].directory and access & 0x40000000:
            assert share == 3
            assert any(
                value != handle.value and pinned_path == path for value, (pinned_path, _) in self.handles.items()
            )
            self.event("writable_directory", path)
        if create:
            self.event("create", path)
        return handle

    def flush(self, handle):
        path, node = self.handles[handle.value]
        self.event("directory_flush" if node.directory else "file_flush", path)

    def mkdir(self, path):
        super().mkdir(path)
        self.mutated = True
        self.event("mkdir", path)

    def rename(self, handle, destination, *, replace):
        super().rename(handle, destination, replace=replace)
        self.mutated = True
        self.event("rename", destination)

    def discard(self, handle):
        path, _ = self.handles[handle.value]
        self.pending[handle.value] = path
        self.event("disposition", path)

    def CloseHandle(self, value):
        path, _ = self.handles[value]
        if value in self.pending:
            del self.nodes[self.pending.pop(value)]
            self.mutated = True
        result = super().CloseHandle(value)
        self.event("close", path)
        return result


@pytest.fixture
def native(monkeypatch):
    api = DurableNative()
    monkeypatch.setattr(paths, "get_api", lambda: api)
    monkeypatch.setattr(fs, "_platform", "nt")
    return api


@pytest.mark.parametrize("access,create", [(0xC0030000, True), (0x40130089, False), (0xC0000000, False)])
def test_mutating_native_handles_use_write_through(access, create):
    api = object.__new__(NativeAPI)
    calls = []
    api.CreateFile = lambda *args: calls.append(args) or 123
    api.last_error = lambda: 0
    api.attributes = lambda: contextlib.nullcontext(None)
    api.open("checked", access=access, create=create)
    assert calls[0][5] == 0x82200000


def test_passive_reads_do_not_upgrade_directory_or_flush(native):
    with fs.open_private_directory("C:\\home") as directory:
        directory.list_names(max_entries=20)
    assert not any(kind in {"writable_directory", "directory_flush", "file_flush"} for kind, _ in native.events)


@pytest.mark.parametrize("operation", ["create", "rename", "delete"])
def test_namespace_transition_finishes_with_parent_flush_after_file_close(native, operation):
    native.nodes["C:\\home\\source"] = Node(False, PRIVATE, b"original")
    with fs.open_private_directory("C:\\home") as directory, directory.transaction() as tx:
        if operation == "create":
            tx.create_bytes("target", b"data")
            name = "target"
        elif operation == "rename":
            tx.rename_file("source", "target")
            name = "target"
        else:
            tx.delete_file("source")
            name = "source"
        final_close = max(i for i, item in enumerate(native.events) if item == ("close", "C:\\home\\" + name))
        assert any(item == ("directory_flush", "C:\\home") for item in native.events[final_close + 1 :])
    assert ("C:\\home\\target" in native.nodes) == (operation != "delete")


@pytest.mark.parametrize("operation", ["create", "rename", "delete"])
def test_parent_barrier_failure_is_uncertain_and_retains_other_state(native, operation):
    native.nodes["C:\\home\\source"] = Node(False, PRIVATE, b"original")
    native.nodes["C:\\home\\pending"] = Node(False, PRIVATE, b"key dependency")
    with fs.open_private_directory("C:\\home") as directory, directory.transaction() as tx:
        native.fail = lambda event: native.mutated and event == ("directory_flush", "C:\\home")
        with pytest.raises(fs.PrivateFSError) as error:
            if operation == "create":
                tx.create_bytes("target", b"data")
            elif operation == "rename":
                tx.rename_file("source", "target")
            else:
                tx.delete_file("source")
        assert error.value.commit_state == "uncertain"
        assert native.nodes["C:\\home\\pending"].data == b"key dependency"
        assert ("C:\\home\\target" in native.nodes) == (operation != "delete")


def test_bootstrap_flushes_child_then_parent_link_before_yield(native):
    child = "C:\\home\\new"
    with fs.open_private_directory(child, create=True):
        created = native.events.index(("mkdir", child))
        child_flush = native.events.index(("directory_flush", child), created)
        parent_flush = native.events.index(("directory_flush", "C:\\home"), child_flush)
        assert created < child_flush < parent_flush
    assert native.nodes[child].descriptor == PRIVATE


@pytest.mark.parametrize("point", ["before_create", "child_flush", "parent_flush", "child_close"])
def test_bootstrap_barrier_failures_preserve_created_child_and_refuse_dependents(native, point):
    child = "C:\\home\\new"

    def fail(event):
        if point == "before_create":
            return event == ("directory_flush", "C:\\home")
        if point == "child_flush":
            return event == ("directory_flush", child)
        if point == "parent_flush":
            return native.mutated and event == ("directory_flush", "C:\\home")
        return event == ("close", child)

    native.fail = fail
    with pytest.raises(fs.PrivateFSError) as error, fs.open_private_directory(child, create=True):
        pytest.fail("dependent work admitted after a failed bootstrap barrier")
    assert error.value.commit_state == ("not_committed" if point == "before_create" else "uncertain")
    assert (child in native.nodes) == (point != "before_create")
    assert not any(name.endswith("journal") for name in native.nodes)


@pytest.mark.parametrize("damage", ["replacement", "security", "volume", "after_flush"])
def test_directory_flush_rechecks_actual_identity_policy_and_volume(native, monkeypatch, damage):
    with fs.open_private_directory("C:\\home") as directory:
        checked = directory.checked
        original = checked.handle.value
        if damage == "replacement":
            native.nodes["C:\\home"] = Node(True, PRIVATE)
        elif damage == "security":
            native.nodes["C:\\home"].reparse = True
        elif damage == "volume":
            monkeypatch.setattr(
                native,
                "validate_volume",
                lambda handle: (_ for _ in ()).throw(fs.PrivateFSError("unsupported", "volume")),
            )
        else:
            flush = native.flush

            def changed(handle):
                flush(handle)
                native.nodes["C:\\home"].reparse = True

            monkeypatch.setattr(native, "flush", changed)
        with pytest.raises(fs.PrivateFSError):
            checked.flush()
        assert original in native.handles  # The original pin is never closed/replaced.
        if damage != "after_flush":
            assert not any(kind == "directory_flush" for kind, _ in native.events)


def test_staging_write_and_close_failure_is_uncertain(native, monkeypatch):
    with fs.open_private_directory("C:\\home") as directory, directory.transaction() as tx:
        monkeypatch.setattr(native, "write", lambda *args: (_ for _ in ()).throw(fs.PrivateFSError("io", "write")))
        native.fail = lambda event: event[0] == "close" and ".mordred-fs-tmp-" in event[1]
        with pytest.raises(fs.PrivateFSError) as error:
            tx.create_bytes("target", b"new")
        assert error.value.operation == "write"
        assert error.value.commit_state == "uncertain"
        assert not any(event == ("rename", "C:\\home\\target") for event in native.events)


def test_bootstrap_accepts_trusted_system_owned_parent_without_relaxing_new_child(native):
    from mordred_hermes._private_fs import _windows_security as security

    native.nodes["C:\\home"].descriptor = security.Descriptor(
        security.SYSTEM,
        True,
        [security.Ace(0, 3, 0x1F01FF, sid) for sid in (security.SYSTEM, security.ADMINISTRATORS, b"user")]
        + [security.Ace(0, 0, 0x100020, b"capability-traverse")],
    )
    with fs.open_private_directory("C:\\home\\new", create=True) as directory:
        directory.directory_identity()
    assert native.nodes["C:\\home\\new"].descriptor == PRIVATE


def test_staging_namespace_barrier_failure_preserves_unpublished_bytes(native):
    with fs.open_private_directory("C:\\home") as directory, directory.transaction() as tx:
        native.fail = lambda event: event == ("directory_flush", "C:\\home")
        with pytest.raises(fs.PrivateFSError) as error:
            tx.create_bytes("target", b"unpublished data")
        assert error.value.commit_state == "uncertain"
        assert "C:\\home\\target" not in native.nodes
        assert [node.data for name, node in native.nodes.items() if ".mordred-fs-tmp-" in name] == [b"unpublished data"]


def test_delete_close_failure_never_claims_parent_barrier(native):
    native.nodes["C:\\home\\source"] = Node(False, PRIVATE, b"original")
    with fs.open_private_directory("C:\\home") as directory, directory.transaction() as tx:
        native.events.clear()
        native.fail = lambda event: event == ("close", "C:\\home\\source")
        with pytest.raises(fs.PrivateFSError) as error:
            tx.delete_file("source")
        assert error.value.commit_state == "uncertain"
        assert not any(kind == "directory_flush" for kind, _ in native.events)


def test_failed_staging_cleanup_is_uncertain_and_preserves_original_error(native, monkeypatch):
    with fs.open_private_directory("C:\\home") as directory, directory.transaction() as tx:
        original = fs.PrivateFSError("io", "write")
        monkeypatch.setattr(native, "write", lambda *args: (_ for _ in ()).throw(original))
        monkeypatch.setattr(
            native, "discard", lambda *args: (_ for _ in ()).throw(fs.PrivateFSError("io", "disposition"))
        )
        with pytest.raises(fs.PrivateFSError) as error:
            tx.create_bytes("target", b"new")
        assert error.value is original
        assert error.value.commit_state == "uncertain"
        assert any(".mordred-fs-tmp-" in name for name in native.nodes)
