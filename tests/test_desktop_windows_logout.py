"""Desktop logout against real checked Windows custody and archive APIs; no network.

The C6/C10b fixture injects only native/platform boundaries. Telegram clients
are synthetic; filesystem, snapshot reuse, deletion and state checks are real.
"""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import pytest

pytest.importorskip("fastapi")

from mordred_hermes._private_fs import PrivateFSError, open_private_directory
from mordred_hermes.desktop import api
from mordred_hermes.extension.telegram import _windows_archive, secrets, store
from mordred_hermes.extension.telegram.windows_secrets import WindowsCustodySecretStore
from mordred_hermes.wizard.uninstall_cli import PURGE_PHRASE
from tests.test_desktop_windows_api import _Client, client, desktop_windows, post
from tests.test_desktop_windows_api import windows_api as windows_api
from tests.test_windows_telegram_archive import held_in_thread
from tests.test_windows_telegram_custody import custody_fixture as custody_fixture
from tests.test_windows_telegram_custody import ops, sealed_path, windows_store
from tests.test_windows_telegram_custody import telegram_fs as telegram_fs
from tests.test_wizard_windows_telegram import role, seed, tree
from tests.test_wizard_windows_telegram import wt as wt


class RevokeClient(_Client):
    """Observe actual local state at the external client boundary."""

    def __init__(self, env, *, fail=False):
        super().__init__()
        self.env = env
        self.fail = fail
        self.credentials_at_connect = []

    async def connect(self):
        self.credentials_at_connect.append(sealed_path(self.env.home).exists())
        if self.fail:
            raise OSError("synthetic network outage")


@pytest.fixture
def logout(wt, windows_api, monkeypatch):
    seed(wt)
    vault = windows_store(wt.home, wt.backend, audit=[])
    tg = RevokeClient(wt)
    monkeypatch.setattr(api, "_store", lambda: vault)
    monkeypatch.setattr(api, "_home", lambda: wt.home)
    monkeypatch.setattr(desktop_windows(), "_client_factory", lambda: lambda *a, **k: tg)
    wt.store, wt.client, wt.http = vault, tg, client()
    return wt


def forget(env):
    return post(env.http, "/telegram/logout", {"forget": True, "confirm": PURGE_PHRASE})


def assert_safe_result(result):
    text = json.dumps(result)
    for secret in ("WINDOWS-SESSION", "1BVtsOK8Bu-TELETHON-SESSION-SECRET", "VENICE-API-KEY-SECRET", "ab" * 16):
        assert secret not in text


@pytest.mark.parametrize("logged_in", [False, True])
def test_real_store_logout_reuses_full_snapshot_once_and_keeps_archive_and_roles(logout, logged_in):
    if not logged_in:
        logout.store.update(lambda old: secrets.with_session(old, None))
    credentials = logout.store.load()
    before = tree(logout)
    leases = {name: role(logout, name) for name in ("memory", "audit", "telegram")}
    unwraps = ops(logout.backend, "ecdh")

    result = post(logout.http, "/telegram/logout", {})

    assert result == {"ok": True, "forgot": False, "revoked": True if logged_in else None}
    assert ops(logout.backend, "ecdh") == unwraps + 1, "the unchanged snapshot avoids a second unwrap"
    assert logout.store.flags()["logged_in"] is False
    after = tree(logout)
    changed = {Path(name).as_posix() for name in before if before[name] != after.get(name)}
    expected_changed = {"telegram/credentials.sealed"}
    if logged_in:
        expected_changed.add("telegram/credentials.meta.json")
    assert changed == expected_changed
    assert {name: role(logout, name) for name in leases} == leases
    value = logout.store.load()
    assert value == replace(credentials, session=None), "API, archive and LLM credentials are retained"
    assert logout.client.logged_out is logged_in and logout.client.disconnected is logged_in
    assert_safe_result(result)


@pytest.mark.parametrize("code", ["secrets_corrupt", "telegram_not_enrolled"])
def test_unreadable_forget_preserves_data_and_points_to_existing_cli_recovery(logout, monkeypatch, code):
    before = tree(logout)

    def unreadable():
        raise secrets.TelegramSecretsError(code)

    monkeypatch.setattr(logout.store, "load_snapshot", unreadable)
    result = forget(logout)
    assert result["ok"] is False and result["error"] == code
    assert "hermes-mordred telegram logout --forget" in result["remedy"]
    assert tree(logout) == before and logout.client.credentials_at_connect == []


def test_forget_busy_refusal_keeps_credentials_archive_and_remote_session(logout):
    before = tree(logout)
    with held_in_thread(logout.root):
        result = forget(logout)
    assert result["ok"] is False and result["error"] == "sync_in_progress"
    assert result["revoked"] is None
    assert logout.client.credentials_at_connect == []
    assert tree(logout) == before
    assert "Nothing was deleted." in result["outcome"]
    assert "Still present:" in result["outcome"]
    assert_safe_result(result)


def test_non_object_metadata_cannot_make_busy_forget_revoke_retained_credentials(logout):
    with open_private_directory(logout.root) as directory, directory.transaction() as tx:
        tx.replace_bytes("credentials.meta.json", b"[]")
    before = tree(logout)
    with held_in_thread(logout.root):
        result = forget(logout)
    assert result["ok"] is False and result["error"] == "sync_in_progress"
    assert result["revoked"] is None and logout.client.credentials_at_connect == []
    assert tree(logout) == before
    assert "credentials.sealed" not in "\n".join(result["outcome"]).partition("Still present:")[0]


def test_unreadable_absence_corroboration_is_unknown_and_never_revokes(logout, monkeypatch):
    real_present = _windows_archive.present
    real_wipe = store.wipe_archive
    wiped = False

    def present(tx, name):
        if wiped and name == "credentials.sealed":
            raise PrivateFSError("io", "telegram_credential_presence")
        return real_present(tx, name)

    def wipe(*args, **kwargs):
        nonlocal wiped
        real_wipe(*args, **kwargs)
        wiped = True

    # flags deliberately says absent, while the authoritative checked presence
    # read fails. Both the observer and corroboration must refuse remote revoke.
    monkeypatch.setattr(logout.store, "flags", lambda: None)
    monkeypatch.setattr(_windows_archive, "present", present)
    monkeypatch.setattr(store, "wipe_archive", wipe)
    result = forget(logout)
    assert result["ok"] is True and result["revoked"] is None
    assert result["manual_revoke"] is True and "Devices" in result["remedy"]
    assert logout.client.credentials_at_connect == []
    assert "could not be re-checked" in "\n".join(result["outcome"])


def test_forget_custody_preflight_refusal_keeps_local_and_remote_state(logout):
    with open_private_directory(logout.home / "mordred") as directory, directory.transaction() as tx:
        tx.create_bytes("windows-memory.pending.json", b"{}")
    before = tree(logout)
    result = forget(logout)
    assert result["ok"] is False and result["error"] == "custody_broken"
    assert result["revoked"] is None and logout.client.credentials_at_connect == []
    assert tree(logout) == before and ops(logout.backend, "delete") == 0
    assert "Nothing was deleted." in result["outcome"]


def test_successful_forget_wipes_before_remote_revoke_and_keeps_other_roles(logout):
    leases = {name: role(logout, name) for name in ("memory", "audit")}
    result = forget(logout)
    assert result["ok"] is True and result["forgot"] is True and result["revoked"] is True
    assert logout.client.credentials_at_connect == [False]
    assert logout.store.flags() is None and not (logout.root / "index.enc").exists()
    assert role(logout, "telegram").current is None
    assert {name: role(logout, name) for name in leases} == leases
    assert_safe_result(result)


def test_partial_forget_revokes_after_credentials_are_confirmed_gone(logout, monkeypatch):
    real_delete = logout.backend.delete_enclave_key

    def lost(key_id):
        real_delete(key_id)
        raise RuntimeError("native deletion result lost")

    monkeypatch.setattr(logout.backend, "delete_enclave_key", lost)
    result = forget(logout)
    assert result["ok"] is False and result["error"] == "custody_uncertain"
    assert result["revoked"] is True
    assert logout.client.credentials_at_connect == [False]
    assert logout.store.flags() is None
    assert (logout.home / "mordred" / "windows-telegram.pending.json").exists()
    outcome = "\n".join(result["outcome"])
    assert "Deleted:" in outcome and "credentials.sealed" in outcome and "deletion journal is kept" in outcome
    assert_safe_result(result)


@pytest.mark.parametrize("wipe_fails", [False, True])
def test_unknown_post_wipe_credentials_never_revoke_and_show_manual_remedy(logout, monkeypatch, wipe_fails):
    real_flags = WindowsCustodySecretStore.flags
    real_wipe = store.wipe_archive

    def flags(self):
        if not sealed_path(logout.home).exists():
            raise secrets.TelegramSecretsError("store_busy")
        return real_flags(self)

    def wipe(*args, **kwargs):
        real_wipe(*args, **kwargs)
        if wipe_fails:
            raise store.StoreError("store_write_uncertain")

    monkeypatch.setattr(WindowsCustodySecretStore, "flags", flags)
    monkeypatch.setattr(store, "wipe_archive", wipe)
    result = forget(logout)
    assert result["ok"] is not wipe_fails
    if wipe_fails:
        assert result["error"] == "store_write_uncertain"
    assert result["revoked"] is None
    assert result["manual_revoke"] is True and "Settings" in result["remedy"] and "Devices" in result["remedy"]
    assert logout.client.credentials_at_connect == []
    assert "could not be re-checked" in "\n".join(result["outcome"])
    assert_safe_result(result)


@pytest.mark.parametrize("partial", [False, True])
def test_failed_remote_revoke_preserves_local_outcome_and_manual_remedy(logout, monkeypatch, partial):
    logout.client.fail = True
    if partial:
        real_delete = logout.backend.delete_enclave_key

        def lost(key_id):
            real_delete(key_id)
            raise RuntimeError("native deletion result lost")

        monkeypatch.setattr(logout.backend, "delete_enclave_key", lost)
    result = forget(logout)
    assert result["ok"] is not partial
    if partial:
        assert result["error"] == "custody_uncertain"
    assert result["revoked"] is False and result["manual_revoke"] is True
    assert "Settings" in result["remedy"] and "Devices" in result["remedy"]
    assert logout.client.credentials_at_connect == [False]
    assert logout.store.flags() is None
    assert "credentials.sealed" in "\n".join(result["outcome"])
    assert_safe_result(result)


def test_loaded_credentials_are_authority_when_pre_wipe_flags_fails(logout, monkeypatch):
    real = WindowsCustodySecretStore.flags
    calls = 0

    def flaky(self):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise secrets.TelegramSecretsError("store_busy")
        return real(self)

    monkeypatch.setattr(WindowsCustodySecretStore, "flags", flaky)
    result = forget(logout)
    assert result["ok"] is True and result["revoked"] is True
    assert logout.client.credentials_at_connect == [False]
    assert "credentials.sealed" in "\n".join(result["outcome"])
    assert_safe_result(result)
