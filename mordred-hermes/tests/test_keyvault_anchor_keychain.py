"""Tests for the production macOS Keychain ``AnchorStore`` (design note §8.1).

The device-bound freshness anchor (``anchor.py``) needs a store an offline
attacker can read but not write. On macOS that is a Keychain generic-password
item (``AfterFirstUnlock`` + ``ThisDeviceOnly``).

Mirroring ``_seckey_backend.py``, the production store is two layers:

1. ``_KeychainOps`` — the narrowest pyobjc-touching surface (add / get /
   update / delete a generic-password). No ``Security.framework`` object
   crosses the boundary; each method returns plain ``bytes``/``None`` or raises
   ``_OpsError`` carrying the ``OSStatus``.
2. ``KeychainAnchorStore`` — implements ``anchor.AnchorStore`` (read / write /
   delete by label), orchestrating add-or-update and translating ``_OpsError``.

Cross-platform tests inject a software ``_FakeOps`` (in-memory), so the store's
flow + status translation run on any platform; the real Keychain binding is
exercised only by the ``MORDRED_KEYVAULT_LIVE``-gated test.
"""

from __future__ import annotations

import os

import pytest

from mordred_hermes.keyvault import anchor
from mordred_hermes.keyvault._anchor_keychain import (
    KeychainAnchorError,
    KeychainAnchorStore,
    _OpsError,
    errSecDuplicateItem,
    errSecItemNotFound,
)

_OTHER_STATUS = -25291  # errSecNotAvailable — an "unexpected" status for tests.


class _FakeOps:
    """In-memory software stand-in for ``_KeychainOps``.

    Keyed by ``(service, account)``. The ``*_error`` hooks let a test force a
    specific ``_OpsError`` from any operation to exercise translation.
    """

    def __init__(self) -> None:
        self._items: dict[tuple[str, str], bytes] = {}
        self.add_error: _OpsError | None = None
        self.get_error: _OpsError | None = None
        self.update_error: _OpsError | None = None
        self.delete_error: _OpsError | None = None
        self.calls: list[tuple[str, str]] = []

    def add(self, service: str, account: str, value: bytes) -> None:
        self.calls.append(("add", account))
        if self.add_error is not None:
            raise self.add_error
        if (service, account) in self._items:
            raise _OpsError(errSecDuplicateItem)
        self._items[(service, account)] = value

    def get(self, service: str, account: str) -> bytes | None:
        self.calls.append(("get", account))
        if self.get_error is not None:
            raise self.get_error
        return self._items.get((service, account))

    def update(self, service: str, account: str, value: bytes) -> None:
        self.calls.append(("update", account))
        if self.update_error is not None:
            raise self.update_error
        if (service, account) not in self._items:
            raise _OpsError(errSecItemNotFound)
        self._items[(service, account)] = value

    def delete(self, service: str, account: str) -> None:
        self.calls.append(("delete", account))
        if self.delete_error is not None:
            raise self.delete_error
        self._items.pop((service, account), None)


@pytest.fixture
def ops() -> _FakeOps:
    return _FakeOps()


@pytest.fixture
def store(ops: _FakeOps) -> KeychainAnchorStore:
    return KeychainAnchorStore(service="mordred-hermes.test.anchor", ops=ops)


def test_module_imports_on_any_platform() -> None:
    # Importing must not touch Security.framework (lazy in the production ops).
    from mordred_hermes.keyvault import _anchor_keychain

    assert hasattr(_anchor_keychain, "KeychainAnchorStore")


def test_store_satisfies_anchor_store_protocol(store: KeychainAnchorStore) -> None:
    assert isinstance(store, anchor.AnchorStore)


def test_read_absent_returns_none(store: KeychainAnchorStore) -> None:
    assert store.read("mordred.vault.absent") is None


def test_write_then_read_round_trips(store: KeychainAnchorStore) -> None:
    store.write("mordred.vault.x", b"anchor-bytes")
    assert store.read("mordred.vault.x") == b"anchor-bytes"


def test_write_overwrites_existing_via_update(store: KeychainAnchorStore, ops: _FakeOps) -> None:
    store.write("mordred.vault.x", b"first")
    store.write("mordred.vault.x", b"second")  # add -> errSecDuplicateItem -> update
    assert store.read("mordred.vault.x") == b"second"
    assert ("update", "mordred.vault.x") in ops.calls


def test_delete_present_then_absent_is_idempotent(store: KeychainAnchorStore) -> None:
    store.write("mordred.vault.x", b"v")
    store.delete("mordred.vault.x")
    assert store.read("mordred.vault.x") is None
    store.delete("mordred.vault.x")  # already gone — must not raise


def test_read_unexpected_status_raises_fail_closed(store: KeychainAnchorStore, ops: _FakeOps) -> None:
    ops.get_error = _OpsError(_OTHER_STATUS)
    with pytest.raises(KeychainAnchorError) as exc:
        store.read("mordred.vault.x")
    assert exc.value.status == _OTHER_STATUS
    assert isinstance(exc.value.__cause__, _OpsError)


def test_write_unexpected_status_raises_fail_closed(store: KeychainAnchorStore, ops: _FakeOps) -> None:
    ops.add_error = _OpsError(_OTHER_STATUS)
    with pytest.raises(KeychainAnchorError) as exc:
        store.write("mordred.vault.x", b"v")
    assert exc.value.status == _OTHER_STATUS


def test_update_failure_during_overwrite_raises(store: KeychainAnchorStore, ops: _FakeOps) -> None:
    store.write("mordred.vault.x", b"first")
    ops.update_error = _OpsError(_OTHER_STATUS)
    with pytest.raises(KeychainAnchorError) as exc:
        store.write("mordred.vault.x", b"second")
    assert exc.value.status == _OTHER_STATUS


def test_composes_with_vault_anchor_helpers(store: KeychainAnchorStore) -> None:
    """The production store drops into anchor.py's write/read/verify logic."""
    label = "mordred.vault.compose"
    wmk = b"\xab" * 48
    anchor.write_anchor(store, label, wmk=wmk, generation=3)

    pinned = anchor.read_anchor(store, label)
    assert pinned.wmk_sha256 == anchor.wmk_fingerprint(wmk)
    assert pinned.generation == 3

    anchor.verify_anchor(store, label, wmk=wmk, generation=3)  # matches -> no raise
    with pytest.raises(anchor.AnchorMismatch):
        anchor.verify_anchor(store, label, wmk=wmk, generation=4)


@pytest.mark.skipif(
    not os.environ.get("MORDRED_KEYVAULT_LIVE"),
    reason="live Keychain test — set MORDRED_KEYVAULT_LIVE=1 on macOS to run",
)
def test_live_keychain_round_trip() -> None:
    """Real generic-password round-trip through the pyobjc ops (macOS only)."""
    live = KeychainAnchorStore(service="mordred-hermes.test.LIVE")
    label = "mordred.vault.live.DELETE_ME"
    try:
        live.delete(label)  # clean any leftover
        assert live.read(label) is None
        live.write(label, b"live-anchor")
        assert live.read(label) == b"live-anchor"
        live.write(label, b"live-anchor-2")  # exercise the update path
        assert live.read(label) == b"live-anchor-2"
    finally:
        live.delete(label)
        assert live.read(label) is None
