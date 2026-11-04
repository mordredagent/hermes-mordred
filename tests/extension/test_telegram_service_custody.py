"""Revoked-session sync cleanup authenticates outside archive exclusion."""

from __future__ import annotations

import asyncio
from dataclasses import replace

import pytest


@pytest.mark.parametrize("changed_source", [False, True])
def test_revoked_sync_releases_archive_before_fresh_native_authentication(tmp_path, monkeypatch, changed_source):
    # Isolate the home before application imports and replace the audit hook
    # before driving the real service. No ambient audit or native helper runs.
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    from mordred_hermes.extension.telegram import service, store
    from tests.test_posix_telegram_custody import native_store, value

    audit = []
    monkeypatch.setattr(service, "_audit", lambda *args, **fields: audit.append((args, fields)))
    vault, native = native_store(tmp_path)
    vault.ensure_key()
    vault.store(value())
    root = vault.sealed_path.parent
    archive = store.ArchiveStore(value().store_key, root)
    archive.save_index(store.ArchiveIndex(dialogs={1: store.DialogInfo(1, "user", "synthetic")}))
    acquired_at_unwrap = []
    disconnected = []

    def attended_unwrap():
        try:
            with store._posix_archive_lock(root):
                acquired_at_unwrap.append(True)
        except store.StoreError as exc:
            assert exc.code == "sync_in_progress"
            acquired_at_unwrap.append(False)

    native.on_unwrap = attended_unwrap

    class RevokedClient:
        async def connect(self):
            return None

        async def is_user_authorized(self):
            if changed_source:
                # A public-key-only publisher runs while sync owns the archive
                # lock. Cleanup must authenticate this current source afresh.
                vault.store(replace(value(), venice_model="published-during-sync"))
            return False

        async def disconnect(self):
            disconnected.append(True)

    svc = service.TelegramService(
        secret_store=vault,
        archive_root=root,
        client_factory=lambda *_args, **_kwargs: RevokedClient(),
        installed=lambda: True,
        memory_guard=lambda: None,
        home=tmp_path,
    )

    async def sync():
        await svc.start_sync()
        await svc.wait_for_sync()
        return await svc.status()

    status = asyncio.run(sync())
    assert acquired_at_unwrap == [True, True]  # sync login read, then revoked-session update
    assert native.ecdh_calls == 2
    assert disconnected == [True]
    assert status["last_error"] == "telegram_session_revoked" and status["logged_in"] is False
    assert status["syncing"] is False and status["progress"]["finished_at"] > 0
    assert (("telegram.session", "revoked"), {}) in audit
    with store._posix_archive_lock(root):
        pass
    native.on_unwrap = None
    kept = vault.load()
    assert kept.session is None and kept.api_id == value().api_id and kept.store_key == value().store_key
    assert kept.venice_model == ("published-during-sync" if changed_source else None)
    assert "delete" not in native.calls
