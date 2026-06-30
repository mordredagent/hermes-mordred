"""Unit tests for the backend-free keyvault-initialized probe (TODO §4.1).

Exercises the real ``keyvault_initialized`` against an on-disk keyvault
layout under ``tmp_path`` — no Secure-Enclave backend involved. The
install_wrapper tests inject a fake probe; these cover the probe itself.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from mordred_hermes.keyvault import _storage
from mordred_hermes.privacy_check._keyvault_probe import (
    KeyvaultProbeError,
    keyvault_initialized,
)


def test_missing_layout_is_not_initialized(tmp_path: Path) -> None:
    """A home with no keyvault layout at all -> not initialized (no raise)."""
    assert keyvault_initialized(home=tmp_path) is False


def test_empty_keyvault_is_not_initialized(tmp_path: Path) -> None:
    """ensure_layout writes meta.json with an empty keys map -> not initialized."""
    _storage.ensure_layout(_storage.resolve_keyvault_dir(tmp_path))
    assert keyvault_initialized(home=tmp_path) is False


def test_populated_keyvault_is_initialized(tmp_path: Path) -> None:
    """A keyvault with at least one key row -> initialized."""
    root = _storage.resolve_keyvault_dir(tmp_path)
    _storage.ensure_layout(root)
    meta = _storage.load_meta(root)
    meta["keys"]["deadbeef"] = {"key_id": "k", "created_at": "2026-05-16T00:00:00.000Z"}
    _storage.save_meta(root, meta)
    assert keyvault_initialized(home=tmp_path) is True


def test_corrupt_meta_raises_keyvault_probe_error(tmp_path: Path) -> None:
    """A structurally corrupt meta.json surfaces as KeyvaultProbeError, not a
    raw keyvault-internal exception — so install-time callers can catch it
    without importing keyvault plugin internals."""
    root = _storage.resolve_keyvault_dir(tmp_path)
    _storage.ensure_layout(root)
    meta_path = root / "meta.json"
    meta_path.write_text("{not valid json", encoding="utf-8")
    meta_path.chmod(0o600)
    with pytest.raises(KeyvaultProbeError):
        keyvault_initialized(home=tmp_path)
