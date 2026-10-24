"""Portable Task 9 fixtures: fake custody, real authority and SQLCipher; no native acceptance."""

from __future__ import annotations

import pytest

from mordred_hermes import dbcrypt
from mordred_hermes.dbcrypt import _capability, _shim
from mordred_hermes.dbcrypt._key import KeyProvider
from tests.test_dbcrypt_authority import native_root as native_root


@pytest.fixture
def protected_runtime(native_root, monkeypatch):
    root, backend, _, _ = native_root
    # The host's closed activation policy remains intact in production. This
    # explicit portable seam qualifies the adapter with fake custody only.
    monkeypatch.setattr(
        _capability,
        "database_status",
        lambda home: _capability.DatabaseStatus(
            True, 0, "unknown", False, "native database authority has not been authenticated"
        ),
    )
    monkeypatch.setattr(_shim, "is_installed", lambda: True)
    provider = KeyProvider(home=root)
    monkeypatch.setattr(dbcrypt, "_PROVIDER", provider)
    try:
        yield root, provider, backend
    finally:
        provider.close()
