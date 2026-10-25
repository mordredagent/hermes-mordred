"""Shared activity authority: passive observation and real guarded SQLCipher access."""

from __future__ import annotations

import sqlite3
from types import SimpleNamespace

import pytest

from mordred_hermes import dbcrypt
from mordred_hermes.activity import _gate
from mordred_hermes.activity._gate import ActivityRefused, check_protection, open_store
from mordred_hermes.dbcrypt import _capability, _shim
from mordred_hermes.dbcrypt._key import KeyProvider
from tests._activity_protection import native_root as native_root
from tests._activity_protection import protected_runtime as protected_runtime


def test_passive_gate_does_not_acquire_key_sql_or_create_state(native_root, monkeypatch):
    root = native_root[0]
    provider = KeyProvider(home=root)
    monkeypatch.setattr(dbcrypt, "_PROVIDER", provider)
    monkeypatch.setattr(_capability, "sys", SimpleNamespace(platform="darwin"))
    monkeypatch.setattr(_shim, "is_installed", lambda: True)

    def forbidden(*args, **kwargs):
        raise AssertionError("passive observation authenticated or opened SQL")

    monkeypatch.setattr(KeyProvider, "__call__", forbidden)
    monkeypatch.setattr(sqlite3, "connect", forbidden)
    before = tuple(root.rglob("*"))
    assert check_protection(root) is None
    assert provider.current_authority is None
    assert tuple(root.rglob("*")) == before


def test_missing_authority_no_store_created(protected_runtime, monkeypatch):
    root, _, _ = protected_runtime
    monkeypatch.setattr(dbcrypt, "_PROVIDER", None)
    monkeypatch.setenv("HERMES_MEMORY_KEY", "hex:" + "11" * 32)
    with pytest.raises(ActivityRefused) as caught:
        open_store(root)
    assert caught.value.code == "no_key"
    assert not (root / "plugin-data").exists()


def test_environment_provider_is_not_runtime_authority(protected_runtime, monkeypatch):
    root, _, _ = protected_runtime
    monkeypatch.setattr(dbcrypt, "_PROVIDER", KeyProvider(environ={"HERMES_MEMORY_KEY": "hex:" + "11" * 32}))
    with pytest.raises(ActivityRefused) as caught:
        open_store(root)
    assert caught.value.code == "no_key"
    assert not (root / "plugin-data").exists()


def test_activity_uses_existing_runtime_one_unwrap(protected_runtime):
    root, provider, backend = protected_runtime
    authority = provider.authority
    calls = list(backend.calls)
    store = open_store(root)
    assert store.meta().profile_home == str(root)
    assert store.status().counts["activity_events"] == 0
    assert provider.current_authority is authority
    assert backend.calls == calls
    with store.connection() as conn:
        assert conn.execute("PRAGMA temp_store").fetchone() == (2,)
        assert conn.execute("PRAGMA journal_mode").fetchone() == ("delete",)


def test_terminal_authority_never_reacquires_or_creates(protected_runtime):
    root, provider, backend = protected_runtime
    provider.authority.close()
    calls = list(backend.calls)
    with pytest.raises(ActivityRefused):
        open_store(root)
    assert backend.calls == calls
    assert not (root / "plugin-data").exists()


@pytest.mark.parametrize("name", ["db-encryption.journal.json", "db-encryption.pending", "db-decryption.pending"])
def test_pending_state_refuses_without_creating_store(protected_runtime, name):
    root, _, _ = protected_runtime
    (root / "mordred" / name).write_text("{}")
    with pytest.raises(ActivityRefused) as caught:
        open_store(root)
    assert caught.value.code == "conversion_pending"
    assert not (root / "plugin-data").exists()


def test_activity_profile_uses_root_authority(protected_runtime):
    root, provider, _ = protected_runtime
    authority = provider.authority
    child = root / "profiles/work"
    store = open_store(child)
    assert store.meta().profile_home == str(child)
    assert provider.current_authority is authority


def test_foreign_home_refuses_before_directory_creation(protected_runtime, tmp_path):
    _, provider, _ = protected_runtime
    assert provider.authority.root == tmp_path
    foreign = tmp_path / "foreign"
    foreign.mkdir(mode=0o700)
    with pytest.raises(ActivityRefused):
        open_store(foreign)
    assert not (foreign / "plugin-data").exists()


def test_guarded_store_refuses_plaintext_without_raw_probe(protected_runtime, monkeypatch):
    root, _, _ = protected_runtime
    path = root / "plugin-data/mordred/mordred.db"
    path.parent.mkdir(mode=0o700, parents=True)
    with sqlite3.connect(path) as conn:
        conn.execute("CREATE TABLE planted(x)")
    from mordred_hermes.dbcrypt import _monitor

    def forbidden(*args, **kwargs):
        raise AssertionError("activity must not open a second raw DB handle")

    monkeypatch.setattr(_monitor, "is_plaintext", forbidden)
    with pytest.raises(ActivityRefused):
        open_store(root)


def test_unqualified_platform_is_closed(native_root, monkeypatch):
    root, backend, _, _ = native_root
    before = {path: path.read_bytes() for path in root.rglob("*") if path.is_file()}
    calls = list(backend.calls)
    monkeypatch.setattr(_capability, "sys", SimpleNamespace(platform="unknown"))

    def forbidden(*args, **kwargs):
        pytest.fail("unsupported platform authenticated or opened SQL")

    monkeypatch.setattr(KeyProvider, "__call__", forbidden)
    monkeypatch.setattr(sqlite3, "connect", forbidden)
    assert check_protection(root).code == "unsupported_platform"
    with pytest.raises(ActivityRefused) as caught:
        open_store(root)
    assert caught.value.code == "unsupported_platform"
    assert backend.calls == calls
    assert {path: path.read_bytes() for path in root.rglob("*") if path.is_file()} == before
    assert not (root / "plugin-data").exists()


def test_unkeyed_connection_cannot_claim_protection(tmp_path):
    conn = sqlite3.connect(":memory:")
    try:
        assert _gate.verify_keyed_connection(conn, tmp_path / "x.db").code == "unkeyed_connection"
    finally:
        conn.close()


def test_planted_activity_parent_refuses_before_any_directory_write(protected_runtime):
    root, _, _ = protected_runtime
    elsewhere = root / "elsewhere"
    elsewhere.mkdir(mode=0o700)
    (root / "plugin-data").symlink_to(elsewhere, target_is_directory=True)
    with pytest.raises(ActivityRefused):
        open_store(root)
    assert list(elsewhere.iterdir()) == []


def test_live_protected_restore_does_not_upgrade_or_touch_files(protected_runtime, monkeypatch):
    root, _, _ = protected_runtime
    store = open_store(root)

    def forbidden(*args, **kwargs):
        raise AssertionError("live restore must refuse before raw file access")

    monkeypatch.setattr("os.open", forbidden)
    with pytest.raises(ActivityRefused):
        store.restore(root / "snapshot.db")
    assert not (root / "snapshot.db").exists()


def test_authority_revoked_before_directory_creation_is_content_free_refusal(protected_runtime, monkeypatch):
    root, _, _ = protected_runtime
    real_authority = _gate.runtime_authority

    def revoked(home):
        authority = real_authority(home)
        authority.close()
        return authority

    monkeypatch.setattr(_gate, "runtime_authority", revoked)
    with pytest.raises(ActivityRefused):
        open_store(root)
    assert not (root / "plugin-data").exists()
