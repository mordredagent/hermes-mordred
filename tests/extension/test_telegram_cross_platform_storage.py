"""Portable Telegram consumers; explicit SQLite seam is not native acceptance."""

from __future__ import annotations

import os
import sqlite3
from dataclasses import replace
from pathlib import Path

import pytest

from mordred_hermes.extension.telegram import history, migrate, secrets, store
from mordred_hermes.imports import store as import_store_module
from mordred_hermes.imports.store import TELEGRAM_RETIRED_ACCOUNT, ImportRefused, ImportStore
from tests._activity_protection import native_root as native_root
from tests._activity_protection import protected_runtime as protected_runtime
from tests.imports._factories import authored, mail_conv, mail_uid, message, part, tg_conv

from .test_telegram_tee import _tee_store


@pytest.mark.parametrize("platform", ["linux", "win32"])
def test_fresh_admitted_sync_uses_shared_store(tmp_path: Path, monkeypatch, platform: str) -> None:
    """A successful shared opener must select canonical history on each admitted platform."""
    monkeypatch.setattr(history, "_platform", lambda: platform)
    imports = ImportStore(tmp_path / "portable-test.db", sqlite3.connect)
    imports.initialize(tmp_path)
    archive = store.ArchiveStore(b"a" * 32, tmp_path / "archive")
    index = archive.load_index()
    selected = history.select_sink(archive, index, home=tmp_path, opener=lambda home: imports)
    assert isinstance(selected, history.ImportSink)
    assert selected.store is imports
    assert archive.load_index().retired_to == "mordred.db"


@pytest.fixture
def protected_archive(request, monkeypatch):
    if os.name == "nt":
        pytest.skip("POSIX fake native-root fixture; Windows shared storage awaits its native acceptance gate")
    home, provider, backend = request.getfixturevalue("protected_runtime")
    held, native = _tee_store(home)
    held.ensure_key()
    held.store(secrets.TelegramSecrets(api_id=1, api_hash="ab" * 16, store_key=b"a" * 32))
    monkeypatch.setattr(migrate, "_migration_secrets", lambda requested_home: held, raising=False)
    archive = store.ArchiveStore(b"a" * 32, home / "mordred" / "telegram")
    archive.append_messages(
        11,
        [
            store.StoredMessage(1, 1790000000, "田中", "明日の会議"),
            store.StoredMessage(2, 1790000060, "鈴木", "会議は午後"),
        ],
    )
    archive.save_index(
        store.ArchiveIndex(
            account_id=7, dialogs={11: store.DialogInfo(11, "user", "会議", message_count=2, last_message_id=2)}
        )
    )
    return home, provider, backend, held, native, archive


def test_telegram_import_search_forget_restart(protected_archive, monkeypatch, request):
    from mordred_hermes.extension.telegram.search import SearchRequest, search_history

    home, provider, _backend, held, _native, archive = protected_archive
    generation_before = provider.authority.snapshot.generation
    credentials_before = held.sealed_path.read_bytes()
    requested_message_count = 2
    assert migrate.migrate_telegram_store(archive._root, home=home) == requested_message_count
    # A new provider/Authority after the original lifetime closes must reopen
    # the same SQLCipher database under the unchanged root generation.
    from mordred_hermes import dbcrypt
    from mordred_hermes.dbcrypt._key import KeyProvider

    provider.close()
    provider = KeyProvider(home=home)
    request.addfinalizer(provider.close)
    monkeypatch.setattr(dbcrypt, "_PROVIDER", provider)
    repeated_import_count = migrate.migrate_telegram_store(archive._root / "index.enc", home=home)
    assert repeated_import_count == 0
    restarted = import_store_module.open_import_store(home)
    assert len(search_history(restarted, SearchRequest(query="会議")).items) == 2
    # Another Telegram account and a different source are outside the retirement binding.
    foreign = replace(tg_conv(), source_account="99")
    run = restarted.run_begin("telegram")
    restarted.write_thread(run, [authored(1, text="別のアカウント")], conversation=foreign)
    restarted.run_commit(run, {})
    mail = mail_conv()
    run = restarted.run_begin("mail")
    uid = mail_uid("synthetic@example.test")
    restarted.write_thread(
        run, [message(uid, (part(uid, text="mail stays"),), conv_uid=mail.conv_uid)], conversation=mail
    )
    restarted.run_commit(run, {})
    assert store.forget_telegram_storage(home=home, remove_records=False) == 0
    forgotten_count = store.forget_telegram_storage(home=home, remove_records=True)
    assert forgotten_count == requested_message_count
    restarted = import_store_module.open_import_store(home)
    assert search_history(restarted, SearchRequest(query="会議")).items == ()
    assert len(search_history(restarted, SearchRequest(query="アカウント")).items) == 1
    assert len(search_history(restarted, SearchRequest(query="mail stays")).items) == 1
    assert restarted.get_meta(TELEGRAM_RETIRED_ACCOUNT) is None
    assert held.sealed_path.read_bytes() == credentials_before
    assert held.load() is not None
    database_generation_after = provider.authority.snapshot.generation
    assert database_generation_after == generation_before


def test_migration_wrong_key_preserves_source(protected_archive):
    home, _provider, _backend, held, _native, archive = protected_archive
    held.update(lambda value: replace(value, store_key=b"b" * 32))
    source_before = {
        path.relative_to(archive._root): path.read_bytes() for path in archive._root.rglob("*") if path.is_file()
    }
    with pytest.raises(store.StoreError, match="store_undecryptable"):
        migrate.migrate_telegram_store(archive._root, home=home)
    source_after = {
        path.relative_to(archive._root): path.read_bytes() for path in archive._root.rglob("*") if path.is_file()
    }
    assert source_after == source_before
    assert not (home / "plugin-data").exists()


@pytest.mark.parametrize("marker", [None, "invalid", "8"])
def test_forget_refuses_unbound_history(tmp_path: Path, monkeypatch, marker):
    imports = ImportStore(tmp_path / "portable-test.db", sqlite3.connect)
    imports.initialize(tmp_path)
    conv = replace(tg_conv(), source_account="7")
    run = imports.run_begin("telegram")
    imports.write_thread(run, [authored(1)], conversation=conv)
    imports.run_commit(run, {})
    if marker is not None:
        imports.set_meta(TELEGRAM_RETIRED_ACCOUNT, marker)
    monkeypatch.setattr(import_store_module, "open_import_store", lambda home: imports)
    with pytest.raises(ImportRefused):
        store.forget_telegram_storage(home=tmp_path, remove_records=True)
    assert imports.contains(["tg:-100123:1"]) == {"tg:-100123:1"}


def test_forget_without_record_request_has_no_io(tmp_path: Path, monkeypatch):
    def forbidden(home):
        raise AssertionError("unexpected storage access")

    monkeypatch.setattr(import_store_module, "open_import_store", forbidden)
    assert store.forget_telegram_storage(home=tmp_path / "absent", remove_records=False) == 0
    assert not (tmp_path / "absent").exists()


@pytest.mark.parametrize("damage", ["hardlink", "dialogs_symlink"])
def test_migration_refuses_aliased_source_before_destination(protected_archive, damage):
    home, _provider, _backend, _held, _native, archive = protected_archive
    if damage == "hardlink":
        os.link(archive._root / "index.enc", home / "foreign.enc")
    else:
        (archive._root / "dialogs").rename(home / "foreign-dialogs")
        (archive._root / "dialogs").symlink_to(home / "foreign-dialogs", target_is_directory=True)
    before = (archive._root / "index.enc").read_bytes()
    with pytest.raises(store.StoreError, match="store_path_unsafe"):
        migrate.migrate_telegram_store(archive._root, home=home)
    assert (archive._root / "index.enc").read_bytes() == before
    assert not (home / "plugin-data").exists()


@pytest.mark.skipif(os.name == "nt", reason="POSIX checked-reader boundary; Windows has its own containing module")
def test_archive_read_refuses_source_swap(tmp_path: Path, monkeypatch):
    from mordred_hermes._private_fs import _posix

    archive = store.ArchiveStore(b"a" * 32, tmp_path)
    archive.save_index(store.ArchiveIndex(account_id=7))
    original = _posix._Directory.read_bytes

    def swapped(directory, name, *, max_bytes):
        data = original(directory, name, max_bytes=max_bytes)
        (tmp_path / "index.enc").rename(tmp_path / "retained.enc")
        archive.save_index(store.ArchiveIndex(account_id=8))
        return data

    monkeypatch.setattr(_posix._Directory, "read_bytes", swapped)
    with pytest.raises(store.StoreError, match="store_path_unsafe"):
        archive.load_index()


@pytest.mark.parametrize("code", ["no_key", "conversion_pending", "unprotected_process", "store_unavailable"])
def test_fresh_managed_store_refusal_cannot_fall_back(tmp_path: Path, code):
    archive = store.ArchiveStore(b"a" * 32, tmp_path / "archive")

    def refused(home):
        raise ImportRefused(code)

    with pytest.raises(store.StoreError, match="import_store_unavailable"):
        history.select_sink(archive, store.ArchiveIndex(), home=tmp_path, opener=refused)
    assert not archive._root.exists()


@pytest.mark.parametrize("operation", ["dialogs", "sync", "search"])
def test_foreground_acquires_root_before_telegram_unseal(protected_archive, monkeypatch, operation):
    import asyncio

    from mordred_hermes.extension.telegram import service
    from mordred_hermes.extension.telegram.search import SearchRequest, search_service

    from .test_telegram_history import _fake_client

    home, provider, _backend, held, native, archive = protected_archive
    held.update(lambda value: replace(value, session="synthetic-session"))
    monkeypatch.setattr(service, "_audit", lambda *args, **kwargs: None)
    authenticated_under_root = []

    actual_ecdh = native.enclave_ecdh

    def unwrap(key_id, peer_pub):
        authenticated_under_root.append(provider.current_authority is not None)
        return actual_ecdh(key_id, peer_pub)

    monkeypatch.setattr(native, "enclave_ecdh", unwrap)

    def guard():
        authenticated_under_root.append(provider.current_authority is not None)

    svc = service.TelegramService(
        secret_store=held,
        archive_root=archive._root,
        home=home,
        memory_guard=guard,
        client_factory=lambda *a, **k: _fake_client(),
        installed=lambda: True,
    )

    async def run():
        if operation == "dialogs":
            assert len(await svc.dialogs()) == 1
        elif operation == "sync":
            await svc.start_sync()
            await svc.wait_for_sync()
            assert svc._last_error is None
        else:
            assert len((await search_service(svc, SearchRequest(query="会議"))).items) == 2

    asyncio.run(run())
    assert authenticated_under_root == [True, True]


@pytest.mark.skipif(os.name == "nt", reason="POSIX checked-directory boundary")
def test_archive_read_refuses_parent_disappearance_after_admission(tmp_path: Path, monkeypatch):
    from mordred_hermes._private_fs import _posix

    root = tmp_path / "archive"
    archive = store.ArchiveStore(b"a" * 32, root)
    archive.save_index(store.ArchiveIndex(account_id=7))
    identity = root.stat().st_ino
    original = _posix._Directory.directory_identity
    moved = False

    def disappear(directory):
        nonlocal moved
        if not moved and os.fstat(directory.fd).st_ino == identity:
            moved = True
            root.rename(tmp_path / "retained-archive")
        return original(directory)

    monkeypatch.setattr(_posix._Directory, "directory_identity", disappear)
    with pytest.raises(store.StoreError, match="store_path_unsafe"):
        archive.load_index()
