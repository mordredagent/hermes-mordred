"""Checked Windows credential presence survives unusable non-secret metadata."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from mordred_hermes._private_fs import open_private_directory
from mordred_hermes.extension.telegram import _windows_archive as checked
from mordred_hermes.extension.telegram import tee
from mordred_hermes.extension.telegram.windows_secrets import WindowsCustodySecretStore
from mordred_hermes.keyvault import wrap
from mordred_hermes.wizard import _windows_telegram
from tests.extension._windows_storage_support import host_optional_private_directory

DEFAULT_FLAGS = {"version": 1, "logged_in": False, "llm_backend": None, "llm_model": None}
# Status treats the sealed payload as opaque; it must never try to open it.
SEALED = b"MTC1-synthetic-sealed-credential-payload"
NON_OBJECT_META = [b"[]", b"null", b'"metadata"', b"42", b"1.5", b"true"]


@pytest.fixture
def windows_store(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> WindowsCustodySecretStore:
    if os.name != "nt":
        monkeypatch.setattr(checked, "open_optional_private_directory", host_optional_private_directory)
    home = tmp_path / "home"
    with open_private_directory(home, create=True), open_private_directory(home / "mordred", create=True):
        pass
    vault = WindowsCustodySecretStore(home)
    with checked.transaction(vault.root, create=True):
        pass

    def forbidden(*args, **kwargs):
        raise AssertionError("credential observation must not enter custody or unseal")

    monkeypatch.setattr(vault, "_custody", forbidden)
    monkeypatch.setattr(vault, "_unseal", forbidden)
    monkeypatch.setattr(wrap, "unwrap_dek", forbidden)
    return vault


@pytest.mark.parametrize("metadata", [*NON_OBJECT_META, b"{invalid", None])
def test_unusable_metadata_keeps_checked_credentials_and_fresh_conservative_flags(windows_store, metadata):
    vault = windows_store
    with checked.transaction(vault.root) as tx:
        assert tx is not None
        tx.create_bytes(tee._SEALED_NAME, SEALED)
        if metadata is not None:
            tx.create_bytes(tee._META_NAME, metadata)

    flags = vault.flags()
    assert flags == DEFAULT_FLAGS
    assert flags is not tee._DEFAULT_FLAGS
    flags["logged_in"] = True
    flags["extra"] = "caller mutation"
    again = vault.flags()
    assert again == DEFAULT_FLAGS
    assert again is not flags and again is not tee._DEFAULT_FLAGS
    assert tee._DEFAULT_FLAGS == DEFAULT_FLAGS
    with checked.transaction(vault.root) as tx:
        assert tx is not None
        assert checked.read_optional(tx, tee._SEALED_NAME, 65536) == SEALED
        assert checked.read_optional(tx, tee._META_NAME, 16384) == metadata


@pytest.mark.parametrize("metadata", [*NON_OBJECT_META, b'{"logged_in":true}'])
def test_metadata_without_checked_sealed_credentials_is_absent(windows_store, metadata):
    vault = windows_store
    with checked.transaction(vault.root) as tx:
        assert tx is not None
        tx.create_bytes(tee._META_NAME, metadata)
    assert vault.flags() is None


@pytest.mark.parametrize("metadata", NON_OBJECT_META)
def test_c6_observe_reports_retained_credentials_with_non_object_metadata(windows_store, monkeypatch, metadata):
    vault = windows_store
    with checked.transaction(vault.root) as tx:
        assert tx is not None
        tx.create_bytes(tee._SEALED_NAME, SEALED)
        tx.create_bytes(tee._META_NAME, metadata)
    # The unrelated custody inventory is unreadable; credential and archive
    # observation still use the real checked store and directory transactions.
    monkeypatch.setattr(_windows_telegram, "telegram_role", lambda home=None: None)

    state = _windows_telegram.observe(vault, vault.root, vault.root.parent.parent)

    assert state.credentials is True
    assert state.directory is True
    assert state.archive is False
    assert state.generations is None
    assert state.empty is False
