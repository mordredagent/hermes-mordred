"""Portable lease policy tests; native Windows rename qualification is deferred."""

from __future__ import annotations

import importlib
import importlib.util
from dataclasses import replace
from pathlib import Path

import pytest

from mordred_hermes._database_contracts import DatabaseBusy, DatabaseRefused, RootIdentity
from mordred_hermes._private_fs import _windows_api
from mordred_hermes._private_fs._types import FileIdentity
from mordred_hermes._private_fs._windows_security import SYSTEM, Ace
from tests._dbcrypt_native_support import HOME, USER, WindowsAPI

LOCK = HOME + "\\mordred\\db-encryption.lock"


@pytest.fixture
def api(monkeypatch: pytest.MonkeyPatch) -> WindowsAPI:
    fake = WindowsAPI()
    monkeypatch.setattr(_windows_api, "_api", fake)
    return fake


def adapter():
    name = "mordred_hermes._database_locking_windows"
    assert importlib.util.find_spec(name) is not None, "checked Windows lease adapter is missing"
    return importlib.import_module(name)


def test_open_pins_root_without_acquiring_lock_or_reading_database(api: WindowsAPI) -> None:
    lock = adapter().open_lock(Path(HOME))
    assert lock.identity == RootIdentity("win32", 7, "03000000000000000000000000000000", USER.hex())
    assert api.lock_flags == []
    assert api.handles
    assert all(share == 3 for _, _, share, _ in api.opens)
    assert any(path.endswith("db-encryption.lock") and create for path, _, _, create in api.opens)
    assert not any(path.endswith(".db") for path, _, _, _ in api.opens)
    assert [api._path(path) for path in api.flushes] == [
        HOME.casefold(),
        (HOME + "\\mordred").casefold(),
        HOME.casefold(),
    ]
    lock.close()
    lock.close()
    assert api.handles == {}
    assert api.unlocks == []


@pytest.mark.parametrize("failed_barrier", [0, 1, 2], ids=["parent-before", "created-child", "parent-after"])
def test_directory_flush_failure_refuses_before_lock_creation_and_closes_handles(
    api: WindowsAPI, failed_barrier: int
) -> None:
    api.flush_errors = [None] * failed_barrier + [1117]
    with pytest.raises(DatabaseRefused):
        adapter().open_lock(Path(HOME))
    assert len(api.flushes) == failed_barrier + 1
    assert api.handles == {}
    assert api.handle_requests == {}
    assert api.lock_flags == []
    assert api._path(LOCK) not in api.nodes
    # The first durability refusal prevents creation; later failures retain the
    # newly created directory without proceeding to a lock or repairing it.
    assert (api._path(HOME + "\\mordred") in api.nodes) is (failed_barrier > 0)


@pytest.mark.parametrize(("shared", "flags"), [(True, 1), (False, 3)])
def test_acquire_uses_nonblocking_shared_or_exclusive_byte_lock(api: WindowsAPI, shared: bool, flags: int) -> None:
    lock = adapter().open_lock(Path(HOME))
    lock.acquire(shared=shared, timeout=0)
    assert api.lock_flags == [flags]
    lock.check()
    lock.close()
    lock.close()
    assert api.handles == {}
    assert len(api.unlocks) == 1


def test_shared_holders_coexist_and_exclusive_timeout_releases_only_own_handles(api: WindowsAPI) -> None:
    first = adapter().open_lock(Path(HOME))
    first.acquire(shared=True, timeout=0)
    second = adapter().open_lock(Path(HOME))
    second.acquire(shared=True, timeout=0)
    original_handles = set(api.handles)
    exclusive = adapter().open_lock(Path(HOME))
    with pytest.raises(DatabaseBusy):
        exclusive.acquire(shared=False, timeout=0)
    assert set(api.handles) == original_handles
    assert len(api.locks) == 2
    assert api.unlocks == []
    first.close()
    second.check()
    second.close()
    assert api.handles == {}


@pytest.mark.parametrize(
    "change",
    [
        "root_identity",
        "root_owner",
        "ancestor_identity",
        "sid",
        "lock_identity",
        "lock_owner",
        "lock_hardlink",
        "lock_reparse",
        "lock_acl",
        "directory_identity",
    ],
)
def test_changed_native_authority_refuses_check(api: WindowsAPI, change: str) -> None:
    lock = adapter().open_lock(Path(HOME))
    lock.acquire(shared=True, timeout=0)
    target = api.node(LOCK)
    if change == "root_identity":
        api.change_identity(HOME)
    elif change == "root_owner":
        root = api.node(HOME)
        root.descriptor = replace(root.descriptor, owner=b"foreign")
    elif change == "ancestor_identity":
        api.change_identity("C:\\Users")
    elif change == "sid":
        api.sid = b"foreign"
    elif change == "lock_identity":
        api.nodes[api._path(LOCK)] = replace(
            target, metadata=replace(target.metadata, identity=FileIdentity(7, b"replacement"))
        )
    elif change == "lock_owner":
        target.descriptor = replace(target.descriptor, owner=b"foreign")
    elif change == "lock_hardlink":
        target.metadata = replace(target.metadata, links=2)
    elif change == "lock_reparse":
        target.metadata = replace(target.metadata, reparse=True)
    elif change == "lock_acl":
        assert target.descriptor.aces is not None
        target.descriptor.aces.append(Ace(0, 0, 1, b"foreign"))
    else:
        api.change_identity(HOME + "\\mordred")
    with pytest.raises(DatabaseRefused):
        lock.check()
    lock.close()
    assert api.handles == {}


@pytest.mark.parametrize("change", ["owner", "hardlink", "directory", "reparse", "acl"])
def test_existing_unsafe_lock_never_acquires_and_closes_every_handle(api: WindowsAPI, change: str) -> None:
    api.add(HOME + "\\mordred", directory=True)
    target = api.add(LOCK, directory=False)
    if change == "owner":
        target.descriptor = replace(target.descriptor, owner=b"foreign")
    elif change == "acl":
        target.descriptor = replace(target.descriptor, protected=False)
    else:
        target.metadata = replace(
            target.metadata, **{change if change != "hardlink" else "links": 2 if change == "hardlink" else True}
        )
    with pytest.raises(DatabaseRefused):
        adapter().open_lock(Path(HOME))
    assert api.handles == {}
    assert api.lock_flags == []


def test_foreign_root_owner_refuses_before_creating_lock(api: WindowsAPI) -> None:
    root = api.node(HOME)
    root.descriptor = replace(root.descriptor, owner=b"foreign")
    with pytest.raises(DatabaseRefused):
        adapter().open_lock(Path(HOME))
    assert api.handles == {}
    assert not any(create for _, _, _, create in api.opens)


@pytest.mark.parametrize("owner", [USER, SYSTEM])
def test_identify_root_is_metadata_only_and_requires_effective_owner(api: WindowsAPI, owner: bytes) -> None:
    root = api.node(HOME)
    root.descriptor = replace(root.descriptor, owner=owner)
    if owner == USER:
        assert adapter().identify_root(Path(HOME)) == RootIdentity(
            "win32", 7, "03000000000000000000000000000000", USER.hex()
        )
    else:
        with pytest.raises(DatabaseRefused):
            adapter().identify_root(Path(HOME))
    assert api.handles == {}
    assert not any(create for _, _, _, create in api.opens)
    assert not any("mordred" in path for path, _, _, _ in api.opens)


def test_unprotected_lock_directory_is_not_repaired(api: WindowsAPI) -> None:
    directory = api.add(HOME + "\\mordred", directory=True, private=False)
    with pytest.raises(DatabaseRefused):
        adapter().open_lock(Path(HOME))
    assert directory.descriptor.protected is False
    assert api.handles == {}
    assert not any(create for _, _, _, create in api.opens)


@pytest.mark.parametrize("timeout", [-1, float("inf"), float("nan")])
def test_invalid_timeout_cannot_leave_open_resources(api: WindowsAPI, timeout: float) -> None:
    lock = adapter().open_lock(Path(HOME))
    with pytest.raises(DatabaseRefused):
        lock.acquire(shared=True, timeout=timeout)
    assert api.handles == {}
    assert api.lock_flags == []


def test_lock_conflict_retries_until_deadline_then_cleans_up(api: WindowsAPI, monkeypatch: pytest.MonkeyPatch) -> None:
    module = adapter()
    now = [0.0]
    monkeypatch.setattr(module.time, "monotonic", lambda: now[0])
    monkeypatch.setattr(module.time, "sleep", lambda seconds: now.__setitem__(0, now[0] + seconds))
    lock = module.open_lock(Path(HOME))
    api.lock_errors = [33] * 10
    with pytest.raises(DatabaseBusy):
        lock.acquire(shared=False, timeout=0.11)
    assert 0.11 <= now[0] <= 0.16
    assert 2 <= len(api.lock_flags) <= 4
    assert api.handles == {}
    assert api.unlocks == []


def test_unknown_lock_error_is_not_retried(api: WindowsAPI) -> None:
    lock = adapter().open_lock(Path(HOME))
    api.lock_errors = [1117, 33]
    with pytest.raises(DatabaseRefused) as error:
        lock.acquire(shared=True, timeout=120)
    assert not isinstance(error.value, DatabaseBusy)
    assert api.lock_flags == [1]
    assert api.handles == {}


def test_success_after_transient_conflict_revalidates_identity(
    api: WindowsAPI, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = adapter()
    monkeypatch.setattr(module.time, "sleep", lambda seconds: None)
    lock = module.open_lock(Path(HOME))
    api.lock_errors = [33]
    lock.acquire(shared=True, timeout=1)
    assert api.lock_flags == [1, 1]
    lock.close()
    assert api.handles == {}


def test_authority_change_during_acquire_unlocks_and_closes(api: WindowsAPI) -> None:
    lock = adapter().open_lock(Path(HOME))
    api.on_lock = lambda: api.change_identity(HOME)
    with pytest.raises(DatabaseRefused):
        lock.acquire(shared=True, timeout=0)
    assert len(api.unlocks) == 1
    assert api.handles == {}


def test_reacquire_never_upgrades_or_downgrades_owned_lock(api: WindowsAPI) -> None:
    lock = adapter().open_lock(Path(HOME))
    lock.acquire(shared=True, timeout=0)
    with pytest.raises(DatabaseRefused):
        lock.acquire(shared=False, timeout=0)
    assert api.lock_flags == [1]
    lock.check()
    lock.close()


def test_closed_lease_cannot_check_or_acquire(api: WindowsAPI) -> None:
    lock = adapter().open_lock(Path(HOME))
    lock.close()
    with pytest.raises(DatabaseRefused):
        lock.check()
    with pytest.raises(DatabaseRefused):
        lock.acquire(shared=True, timeout=0)
    assert api.lock_flags == []


def test_unlock_failure_still_closes_every_handle_once(api: WindowsAPI) -> None:
    lock = adapter().open_lock(Path(HOME))
    lock.acquire(shared=True, timeout=0)
    api.unlock_error = 1117
    with pytest.raises(DatabaseRefused):
        lock.close()
    lock.close()
    assert len(api.unlocks) == 1
    assert api.handles == {}
