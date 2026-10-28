"""Explicit test-only native-ops adapters; custody remains genuine and checked."""

from __future__ import annotations

from collections.abc import Callable, Iterator
from contextlib import contextmanager
from typing import Any

import pytest

from mordred_hermes._database_contracts import DatabaseRefused
from mordred_hermes.keyvault import _storage, wrap
from mordred_hermes.keyvault._seckey_backend import _SecKeyBackend
from mordred_hermes.keyvault._seckey_errors import _OpsError, errSecItemNotFound
from tests._keyvault_fakes import FakeBackend

RegisterFakeBackend = Callable[[type[object], Callable[[Any], FakeBackend]], None]


def install_fake_creation_receipts(monkeypatch: pytest.MonkeyPatch) -> RegisterFakeBackend:
    """Only explicitly opted-in software doubles gain a real native-ops adapter.

    Production functions, actual OS custody and pending validation stay intact.
    Concrete native backends never enter this adapter.
    """
    original_create = wrap.create_wrapping_key_scope
    original_custody = _storage.keyvault_custody
    registered = {}
    adapters = {}

    def register_backend(backend_type, resolve_store):
        registered[backend_type] = resolve_store

    def adapter(backend):
        if type(backend) is _SecKeyBackend:
            return backend
        resolver = (lambda value: value) if isinstance(backend, FakeBackend) else registered.get(type(backend))
        if resolver is None:
            return backend
        if backend in adapters:
            return adapters[backend]
        selected = resolver(backend)
        store = selected._keys
        selectors = {}

        def checked():
            if resolver(backend) is not selected or selected._keys is not store:
                raise DatabaseRefused("test native store changed")
            return selected

        class Ops:
            def create_keypair(self, tag, label, *, unattended=False):
                checked()
                return backend.generate_enclave_key(selectors[tag], unattended=unattended)

            def copy_public_key(self, tag):
                try:
                    # Use the stored public key to retain original fake call-count semantics.
                    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

                    return (
                        checked()
                        ._keys[selectors[tag]]
                        .public_key()
                        .public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
                    )
                except KeyError:
                    raise _OpsError(errSecItemNotFound) from None

            def key_exchange(self, tag, peer_pub):
                checked()
                return backend.enclave_ecdh(selectors[tag], peer_pub)

            def delete_key(self, tag):
                from mordred_hermes.keyvault._native_deletion import _assert_native_tag_delete

                _assert_native_tag_delete(ops=self, tag=tag)
                checked().delete_enclave_key(selectors[tag])

        proxy = _SecKeyBackend(ops=Ops(), sw_ops=None, legacy_ops=None)
        proxy._test_selectors = selectors
        adapters[backend] = proxy
        return proxy

    @contextmanager
    def custody(root, *, backend, reset=False) -> Iterator[_storage.KeyvaultCustody]:
        with original_custody(root, backend=adapter(backend), reset=reset) as handle:
            yield handle

    @contextmanager
    def create(key_id, *, backend, custody, unattended=None, native_key_id=None):
        from mordred_hermes.keyvault._seckey_errors import _application_tag

        proxy = adapter(backend)
        if proxy is not backend:
            selector = key_id if native_key_id is None else native_key_id
            proxy._test_selectors[_application_tag(selector)] = selector
        with original_create(
            key_id, backend=proxy, custody=custody, unattended=unattended, native_key_id=native_key_id
        ) as receipt:
            yield receipt

    monkeypatch.setattr(_storage, "keyvault_custody", custody)
    monkeypatch.setattr(wrap, "create_wrapping_key_scope", create)
    return register_backend
