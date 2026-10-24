"""Opt-in creation receipts for the shared software keyvault test double.

This adapter never issues production native authority or patches native deletion.
Concrete native backends and unrelated protocol implementations always use the
original production functions, even inside an opted-in legacy test module.
"""

from __future__ import annotations

import os
import threading
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any

import pytest
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from mordred_hermes._database_contracts import DatabaseRefused
from mordred_hermes.keyvault import wrap
from tests._keyvault_fakes import FakeBackend

RegisterFakeBackend = Callable[[type[object], Callable[[Any], FakeBackend]], None]


@dataclass
class _FakeCreateRecord:
    backend: wrap.NativeBackend
    resolve_store: Callable[[Any], FakeBackend]
    key_store: FakeBackend
    selector: str
    store: object
    public_key: bytes
    origin: tuple[int, int]
    active: bool = True
    consumed: bool = False


def install_fake_creation_receipts(monkeypatch: pytest.MonkeyPatch) -> RegisterFakeBackend:
    """Adapt shared fakes and explicitly registered exact wrapper types."""
    original_create = wrap.create_wrapping_key_scope
    original_commit = wrap.commit_created_key
    original_rollback = wrap.rollback_created_key
    records: dict[_FakeCreateReceipt, _FakeCreateRecord] = {}
    registered: dict[type[object], Callable[[Any], FakeBackend]] = {}

    def register_backend(backend_type: type[object], resolve_store: Callable[[Any], FakeBackend]) -> None:
        # Exact, explicit registration supports the legacy ambient-store wrapper;
        # no attributes or protocol conformance opt an unrelated backend in.
        registered[backend_type] = resolve_store

    def shared_store(backend: FakeBackend) -> FakeBackend:
        return backend

    def checked_store(record: _FakeCreateRecord) -> FakeBackend:
        selected = record.resolve_store(record.backend)
        if selected is not record.key_store or selected._keys is not record.store:
            raise DatabaseRefused("test native key store changed")
        return selected

    def checked(receipt: _FakeCreateReceipt) -> _FakeCreateRecord:
        record = records.get(receipt)
        if (
            record is None
            or not record.active
            or record.consumed
            or record.origin != (os.getpid(), threading.get_ident())
        ):
            raise DatabaseRefused("test creation receipt is expired or consumed")
        return record

    class _FakeCreateReceipt:
        __slots__ = ()

        @property
        def public_key(self) -> bytes:
            return checked(self).public_key

    @contextmanager
    def create(
        key_id: str,
        *,
        backend: wrap.NativeBackend,
        unattended: bool | None = None,
        native_key_id: str | None = None,
    ) -> Iterator[object]:
        # Native backends must always take the production path, even if a
        # caller accidentally registers a resolver for their concrete type.
        from mordred_hermes.keyvault._seckey_backend import _SecKeyBackend

        resolve_store = shared_store if isinstance(backend, FakeBackend) else registered.get(type(backend))
        if isinstance(backend, _SecKeyBackend) or resolve_store is None:
            with original_create(
                key_id, backend=backend, unattended=unattended, native_key_id=native_key_id
            ) as receipt:
                yield receipt
            return
        selector = key_id if native_key_id is None else native_key_id
        key_store = resolve_store(backend)
        if not isinstance(key_store, FakeBackend):
            raise DatabaseRefused("test creation adapter requires the shared software key store")
        store = key_store._keys
        public_key = backend.generate_enclave_key(selector, unattended=unattended)
        wrap._decode_sec1_uncompressed_p256(public_key)
        if resolve_store(backend) is not key_store or key_store._keys is not store:
            raise DatabaseRefused("test native key store changed during create")
        # No receipt exists when generation publishes a key and then raises.
        fake_receipt = _FakeCreateReceipt()
        record = _FakeCreateRecord(
            backend, resolve_store, key_store, selector, store, public_key, (os.getpid(), threading.get_ident())
        )
        records[fake_receipt] = record
        try:
            yield fake_receipt
        finally:
            record.active = False

    def commit(receipt: object) -> None:
        if type(receipt) is not _FakeCreateReceipt:
            original_commit(receipt)
            return
        checked(receipt).consumed = True

    def rollback(receipt: object) -> None:
        if type(receipt) is not _FakeCreateReceipt:
            original_rollback(receipt)
            return
        record = checked(receipt)
        record.consumed = True
        key_store = checked_store(record)
        # Production receipts compare the native ops' stored key rather than
        # invoking the high-level public lookup. Mirror that distinction so
        # tests can still observe a blocked encrypt's absence of get_pub calls.
        stored_key = key_store._keys.get(record.selector)
        if (
            stored_key is None
            or stored_key.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint) != record.public_key
        ):
            raise DatabaseRefused("test native public key changed")
        # Dynamic dispatch retains subclass delete failures and call recording.
        key_store.delete_enclave_key(record.selector)

    monkeypatch.setattr(wrap, "create_wrapping_key_scope", create)
    monkeypatch.setattr(wrap, "commit_created_key", commit)
    monkeypatch.setattr(wrap, "rollback_created_key", rollback)
    return register_backend
