"""One real custody read keeps leaf checks and fresh held-directory boundaries."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
from dataclasses import replace
from pathlib import Path

import pytest

from mordred_hermes import _config_io as cio
from mordred_hermes._private_fs import FileIdentity, PrivateFSError
from mordred_hermes._private_fs import _windows_io as win
from mordred_hermes._private_fs._windows_api import Metadata, OwnedHandle
from mordred_hermes._private_fs._windows_paths import CheckedDirectory
from mordred_hermes._private_fs._windows_security import ADMINISTRATORS, SYSTEM, Ace, Descriptor
from mordred_hermes.keyvault._windows_custody import _read


class ReadAPI:
    """Native boundary only; coordinator, directory and transaction code are real."""

    def __init__(self):
        self.paths = {1: "C:\\", 2: "C:\\home", 3: "C:\\home\\mordred"}
        self.nodes = {
            path: Metadata(FileIdentity(1, bytes([value])), True, False, 1, 0) for value, path in self.paths.items()
        }
        self.source = "C:\\home\\mordred\\source"
        self.nodes[self.source] = Metadata(FileIdentity(1, b"source"), False, False, 1, 3)
        self.data = {self.source: b"old"}
        self.offsets = {}
        self.next_handle = 10
        self.bad_acl = set()
        self.redirect = {}
        self.on_read = lambda: None
        self.on_open = lambda path: None
        self.opens = []
        self.leaf_validations = 0

    def open(self, path, *, access=0x120089, share=7):
        assert access == 0x120089 and share == 7
        self.on_open(path)
        self.opens.append(path)
        if path not in self.nodes:
            raise PrivateFSError("missing", "open")
        self.next_handle += 1
        self.paths[self.next_handle] = path
        self.offsets[self.next_handle] = 0
        return OwnedHandle(self, self.next_handle)

    def metadata(self, handle):
        return self.nodes[self.paths[handle.value]]

    def descriptor(self, handle):
        path = self.paths[handle.value]
        if not self.nodes[path].directory:
            self.leaf_validations += 1
        if path in self.bad_acl:
            return Descriptor(b"stranger", True, [])
        return Descriptor(b"user", True, [Ace(0, 0, 0x1F01FF, sid) for sid in (b"user", SYSTEM, ADMINISTRATORS)])

    def user_sid(self):
        return b"user"

    def final_path(self, handle):
        path = self.paths[handle.value]
        return self.redirect.get(path, path)

    def mtime_ns(self, handle):
        return 1

    def read(self, handle, count):
        path = self.paths[handle.value]
        offset = self.offsets[handle.value]
        result = self.data[path][offset : offset + count]
        self.offsets[handle.value] += len(result)
        if path == self.source and result:
            self.on_read()
        return result

    def CloseHandle(self, value):
        self.paths.pop(value)
        return True

    def checked(self, result, operation):
        assert result


@pytest.fixture
def custody_read(monkeypatch):
    api = ReadAPI()
    root, home_handle, policy_handle = (OwnedHandle(api, value) for value in (1, 2, 3))
    root_pin = (root, api.metadata(root).identity)
    home_pin = (home_handle, api.metadata(home_handle).identity)
    home = win._Directory(CheckedDirectory(home_handle, home_pin[1], api.paths[2], True, (root_pin,)))
    policy = win._Directory(
        CheckedDirectory(policy_handle, api.metadata(policy_handle).identity, api.paths[3], False, (root_pin, home_pin))
    )
    state = cio._State(cio.CanonicalPaths(Path("/synthetic")), ExitStack())
    state.home, state.policy = home, policy
    state.home_identity, state.policy_identity = home.checked.identity, policy.checked.identity
    state.home_tx, state.policy_tx = win._Transaction(home), win._Transaction(policy)
    state.policy_opened = True
    session = cio.CanonicalSession(state)
    loan = cio._MordredTransaction(session, state.policy_tx)
    traversals = []
    original = CheckedDirectory.check

    def checked(directory):
        traversals.append(directory)
        original(directory)

    monkeypatch.setattr(CheckedDirectory, "check", checked)
    return api, home, policy, state, loan, traversals


def test_logical_read_coalesces_only_live_directory_traversals(custody_read):
    api, home, policy, _, loan, traversals = custody_read
    assert _read(loan, "source") == b"old"
    assert traversals == [home.checked, policy.checked, home.checked, policy.checked]
    assert api.opens.count(api.source) == 2  # Existing stat then read, each opening the leaf.
    assert api.leaf_validations == 2
    assert api.opens.count("C:\\home\\mordred\\.policy-write.pending") >= 4
    traversals.clear()
    assert _read(loan, "source") == b"old"
    assert traversals == [home.checked, policy.checked, home.checked, policy.checked]


@pytest.mark.parametrize("path", ["C:\\", "C:\\home", "C:\\home\\mordred"])
@pytest.mark.parametrize("damage", ["acl", "identity", "reparse"])
@pytest.mark.parametrize("phase", ["entry", "exit"])
def test_directory_validation_prevents_bytes_escape(custody_read, path, damage, phase):
    api, _, _, _, loan, _ = custody_read

    def mutate():
        if damage == "acl":
            api.bad_acl.add(path)
        elif damage == "identity":
            api.nodes[path] = replace(api.nodes[path], identity=FileIdentity(1, b"replacement"))
        elif damage == "reparse":
            api.nodes[path] = replace(api.nodes[path], reparse=True)

    if phase == "entry":
        mutate()
    else:
        api.on_read = mutate
    with pytest.raises(PrivateFSError):
        _read(loan, "source")
    if phase == "entry":
        assert api.source not in api.opens


@pytest.mark.parametrize("path", ["C:\\home", "C:\\home\\mordred"])
def test_final_path_validation_prevents_bytes_escape(custody_read, path):
    api, _, _, _, loan, _ = custody_read
    api.on_read = lambda: api.redirect.update({path: path + "-renamed"})
    with pytest.raises(PrivateFSError) as caught:
        _read(loan, "source")
    assert caught.value.operation == "directory_path"


@pytest.mark.parametrize("damage", ["acl", "reparse", "missing", "replacement"])
def test_leaf_changes_remain_checked_on_stat_to_read_race(custody_read, damage):
    api, _, _, _, loan, _ = custody_read
    opens = 0

    def mutate(path):
        nonlocal opens
        if path != api.source:
            return
        opens += 1
        if opens == 2:
            if damage == "acl":
                api.bad_acl.add(path)
            elif damage == "reparse":
                api.nodes[path] = replace(api.nodes[path], reparse=True)
            elif damage == "missing":
                del api.nodes[path]
            else:
                # Existing stat/read behavior admits a safely reopened new leaf.
                api.nodes[path] = replace(api.nodes[path], identity=FileIdentity(1, b"replacement"))
                api.data[path] = b"new"

    api.on_open = mutate
    if damage == "replacement":
        assert _read(loan, "source") == b"new"
    else:
        with pytest.raises(PrivateFSError):
            _read(loan, "source")


def test_missing_stat_still_gets_final_validation(custody_read):
    api, home, policy, _, loan, traversals = custody_read
    assert _read(loan, "absent") is None
    assert traversals == [home.checked, policy.checked, home.checked, policy.checked]
    assert api.source not in api.opens


@pytest.mark.parametrize(
    "damage", ["directory", "transaction", "loan", "session", "state", "handle", "reuse", "checked", "ancestor"]
)
def test_scope_rejects_expired_or_replaced_objects(custody_read, damage):
    api, home, _, state, loan, _ = custody_read

    def mutate():
        if damage == "directory":
            home.active = False
        elif damage == "transaction":
            state.home_tx.active = False
        elif damage == "loan":
            loan._live = False
        elif damage == "session":
            loan._session._live = False
        elif damage == "state":
            state.live = False
        elif damage in ("handle", "reuse", "ancestor"):
            handle = home.checked.ancestors[0][0] if damage == "ancestor" else home.checked.handle
            value, path = handle.value, api.paths[handle.value]
            handle.close()
            if damage == "reuse":
                handle.value = value
                api.paths[value] = path
        else:
            home.checked = replace(home.checked, handle=OwnedHandle(api, 2))

    api.on_read = mutate
    with pytest.raises(RuntimeError):
        _read(loan, "source")


@pytest.mark.parametrize("boundary", ["thread", "process"])
def test_scope_rejects_foreign_execution(custody_read, monkeypatch, boundary):
    api, _, _, _, loan, _ = custody_read

    def mutate():
        if boundary == "thread":
            with ThreadPoolExecutor(1) as executor, pytest.raises(RuntimeError):
                executor.submit(loan.stat, "source").result()
        else:
            monkeypatch.setattr(cio.os, "getpid", lambda: -1)

    api.on_read = mutate
    if boundary == "thread":
        assert _read(loan, "source") == b"old"
    else:
        with pytest.raises(RuntimeError):
            _read(loan, "source")


def test_nested_read_refuses_without_erasing_outer_exit(custody_read):
    api, home, policy, _, loan, traversals = custody_read

    def nested():
        with pytest.raises(RuntimeError, match="nested"):
            _read(loan, "source")
        api.bad_acl.add(policy.checked.path)

    api.on_read = nested
    with pytest.raises(PrivateFSError):
        _read(loan, "source")
    assert traversals[-2:] == [home.checked, policy.checked]


def test_read_and_exit_errors_retain_body_cause(custody_read):
    api, _, policy, _, loan, _ = custody_read
    original = PrivateFSError("io", "read_failure")

    def fail():
        api.bad_acl.add(policy.checked.path)
        raise original

    api.on_read = fail
    with pytest.raises(PrivateFSError) as caught:
        _read(loan, "source")
    assert caught.value.operation == "private_acl"
    assert caught.value.__cause__ is original


def test_pending_marker_appearing_during_read_refuses(custody_read):
    api, _, _, _, loan, _ = custody_read

    def pending():
        path = "C:\\home\\mordred\\.policy-write.pending"
        api.nodes[path] = Metadata(FileIdentity(1, b"pending"), False, False, 1, 7)
        api.data[path] = b"pending"

    api.on_read = pending
    with pytest.raises(cio.PolicyPendingError):
        _read(loan, "source")


def test_foreign_directory_with_same_checked_object_is_not_enrolled(custody_read):
    api, _, policy, _, loan, traversals = custody_read
    foreign = win._Directory(policy.checked)

    def check_foreign():
        foreign.check()
        foreign.check()

    api.on_read = check_foreign
    assert _read(loan, "source") == b"old"
    assert sum(checked is policy.checked for checked in traversals) == 4


@pytest.mark.parametrize("damage", ["home", "policy", "home_tx", "policy_tx", "foreign_loan"])
def test_scope_refuses_noncanonical_directory_or_transaction(custody_read, damage):
    api, home, policy, state, loan, _ = custody_read
    if damage == "home":
        state.home = win._Directory(home.checked)
    elif damage == "policy":
        state.policy = win._Directory(policy.checked)
    elif damage == "home_tx":
        state.home_tx = win._Transaction(policy)
    elif damage == "policy_tx":
        state.policy_tx = win._Transaction(policy)
    else:
        loan._transaction = win._Transaction(policy)
    with pytest.raises(RuntimeError, match="canonical held directories"):
        _read(loan, "source")
    assert api.source not in api.opens


@pytest.mark.parametrize(
    "operation", ["flush_directory", "flush_file", "delete", "rename", "append", "create", "replace"]
)
def test_mutation_is_refused_inside_read(custody_read, operation):
    api, _, _, state, loan, _ = custody_read

    def mutate():
        with pytest.raises(RuntimeError, match="mutation inside custody read"):
            tx = state.policy_tx
            if operation == "flush_directory":
                tx.flush_directory()
            elif operation == "flush_file":
                tx.flush_file("source")
            elif operation == "delete":
                tx.delete_file("source")
            elif operation == "rename":
                tx.rename_file("source", "target")
            elif operation == "append":
                tx.append_bytes("source", b"bad")
            elif operation == "create":
                tx.create_bytes("target", b"bad")
            else:
                tx.replace_bytes("source", b"bad")

    api.on_read = mutate
    assert _read(loan, "source") == b"old"
    assert api.data[api.source] == b"old"


def test_next_read_checks_new_directory_damage(custody_read):
    api, _, policy, _, loan, _ = custody_read
    assert _read(loan, "source") == b"old"
    api.bad_acl.add(policy.checked.path)
    with pytest.raises(PrivateFSError):
        _read(loan, "source")


def test_missing_leaf_cannot_hide_final_directory_failure(custody_read):
    api, _, policy, _, loan, _ = custody_read

    def damage(path):
        if path.endswith("\\absent"):
            api.bad_acl.add(policy.checked.path)

    api.on_open = damage
    with pytest.raises(PrivateFSError) as caught:
        _read(loan, "absent")
    assert caught.value.operation == "private_acl"


def test_confidential_leaf_named_reopen_checks_remain_inside_scope(custody_read):
    # A confidential checked directory's extra held/named file identity checks
    # must not be bypassed by its enrolled directory traversal scope.
    api, home, policy, state, _, _ = custody_read
    confidential = win._Directory(replace(policy.checked, confidential=True))
    tx = win._Transaction(confidential)
    with win._CustodyReadScope(state.home_tx, tx):
        assert confidential.read_bytes("source", max_bytes=3) == b"old"
    assert api.opens.count(api.source) == 2
    assert api.leaf_validations == 3
    assert home._custody_read is None and confidential._custody_read is None
