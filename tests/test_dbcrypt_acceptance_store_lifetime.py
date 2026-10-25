"""Native collector writable-store calls use real per-operation connection owners.

Only tests supply an explicit SQLite opener and synthetic credentials/transport;
no production plaintext fallback or fake store.close method is introduced.
"""

from __future__ import annotations

import runpy
import sqlite3
from pathlib import Path
from types import SimpleNamespace

import pytest

from mordred_hermes.imports import store as stores
from mordred_hermes.imports.mail import imap_sync, secrets
from mordred_hermes.wizard import mail_cli
from tests._mail_sync_helpers import FakeSecrets, make_env
from tests.imports._factories import authored, tg_conv
from tests.imports.test_import_store import commit


@pytest.fixture
def collector_store(tmp_path, monkeypatch):
    helper = runpy.run_path(str(Path(__file__).with_name("_dbcrypt_acceptance_native.py")))
    home = tmp_path / "profiles/other"
    home.mkdir(parents=True, mode=0o700)
    (home / "mordred").mkdir(mode=0o700)
    connections = []

    def opener(path):
        connection = sqlite3.connect(path)
        connections.append(connection)
        return connection

    store = stores.ImportStore(home / "mordred.db", opener)
    store.initialize(home)
    monkeypatch.setattr(stores, "open_import_store", lambda _home: store)
    monkeypatch.setattr(mail_cli, "_audit", lambda _entry: None)
    credentials = secrets.MailCredentials(
        "owner@example.invalid",
        "synthetic-password",
        "imap.example.invalid",
        993,
        ("owner@example.invalid",),
        "native_sync",
        False,
        {"inbox": "INBOX"},
    )
    secret = FakeSecrets(credentials)
    monkeypatch.setattr(secrets, "MailSecretStore", lambda *_a, **_kw: secret)
    monkeypatch.setattr(imap_sync, "default_env", lambda actual_home: make_env(actual_home, store, None, secret))
    yield helper, home, store, secret, connections
    assert connections
    for connection in connections:
        with pytest.raises(sqlite3.ProgrammingError, match="closed"):
            connection.execute("SELECT 1")


def prepare_telegram(helper, home, store, monkeypatch):
    from mordred_hermes.extension.telegram.secrets import TelegramSecrets
    from mordred_hermes.extension.telegram.store import ArchiveIndex, ArchiveStore, DialogInfo, StoredMessage

    value = TelegramSecrets(api_id=7, api_hash="a" * 32, store_key=b"a" * 32, session="synthetic")
    archive = ArchiveStore(value.store_key, home / "mordred/telegram")
    archive.append_messages(11, [StoredMessage(id=1, date=1001, sender="Synthetic", text=helper["TEXT"], out=True)])
    archive.save_index(
        ArchiveIndex(
            account_label="Synthetic",
            account_id=7,
            dialogs={11: DialogInfo(11, "user", "Synthetic", last_message_id=1, message_count=1, last_date=1001)},
        )
    )
    commit(store, tg_conv(), [authored(1, text=helper["TEXT"])])
    secret = SimpleNamespace(value=value)
    secret.load = lambda **_kw: secret.value
    secret.load_snapshot = lambda: secret.value
    secret.forget_from_snapshot = lambda _snapshot: setattr(secret, "value", None)
    monkeypatch.setitem(helper["_telegram"].__globals__, "_telegram_store", lambda _home: secret)
    return secret


def seed_mail(store, helper):
    from mordred_hermes.imports.mail.source import MboxBytes

    data = (
        "From synthetic Thu Oct 1 12:00:00 2026\nFrom: owner@example.invalid\r\n"
        "To: other@example.invalid\r\nDate: Thu, 1 Oct 2026 12:00:00 +0000\r\n"
        "Message-ID: <native@example.invalid>\r\nSubject: 日本語\r\n"
        "Content-Type: text/plain; charset=utf-8\r\n\r\n" + helper["TEXT"]
    ).encode()
    for account in ("native-mbox", "native_sync"):
        request = mail_cli._Request((MboxBytes(data),), account, ("owner@example.invalid",), "Sent", False, True, 0)
        assert mail_cli._locked_import(store, request) == 0


def test_telegram_collector_returns_digest_with_real_writable_store(collector_store, monkeypatch):
    helper, home, store, _secret, _connections = collector_store
    prepare_telegram(helper, home, store, monkeypatch)
    assert len(helper["_telegram"](home, False)) == 64
    assert len(store.search("日本語", source="telegram")) == 1


@pytest.mark.parametrize("seed", [True, False])
def test_mail_collector_completes_import_and_read_with_real_writable_store(collector_store, seed):
    helper, home, store, _secret, _connections = collector_store
    if not seed:
        seed_mail(store, helper)
    assert len(helper["_mail"](home, seed)) == 64
    assert len(store.search("日本語", source="mail")) == 2


def test_telegram_underlying_store_failure_is_not_masked_by_fake_close(collector_store, monkeypatch):
    helper, home, store, _secret, _connections = collector_store
    prepare_telegram(helper, home, store, monkeypatch)

    def failed_query(*_args, **_kwargs):
        # Exercise the real connection context's exception cleanup.
        with store.connection() as connection:
            connection.execute("SELECT 1")
            raise ValueError("owned-query-failure")

    monkeypatch.setattr(store, "search", failed_query)
    with pytest.raises(ValueError, match="owned-query-failure"):
        helper["_telegram"](home, False)


def test_role_retirement_continues_after_real_writable_store_operations(collector_store, monkeypatch):
    from mordred_hermes.extension.telegram import store as archive
    from mordred_hermes.keyvault import _database_authority, _mail_custody

    helper, home, store, old_secret, _connections = collector_store
    prepare_telegram(helper, home, store, monkeypatch)
    seed_mail(store, helper)

    class NativeSecretBoundary:
        def __init__(self, *_args, **_kwargs):
            self.credentials = old_secret.creds

        def _platform(self):
            return "linux"

        def _native(self):
            return True

        def _profile_home(self):
            return home

        def load_snapshot(self):
            return self.credentials, None

        def forget_from_snapshot(self, _snapshot):
            self.credentials = None
            return True

        def residue(self):
            return self.credentials is not None

        def load(self):
            return self.credentials

    monkeypatch.setattr(secrets, "MailSecretStore", NativeSecretBoundary)
    monkeypatch.setattr(_mail_custody, "pending_mail_retirement", lambda _home: False)
    monkeypatch.setattr(_database_authority, "observe_database_source", lambda **_kw: "unchanged-root")
    retired = []
    monkeypatch.setattr(archive, "forget_telegram_storage", lambda **_kw: retired.append("telegram") or 1)
    monkeypatch.setattr(archive, "wipe_archive", lambda *_a, **_kw: None)
    monkeypatch.setitem(helper["_forget_roles"].__globals__, "_session", lambda *_a: True)
    helper["_forget_roles"](home.parents[1])
    assert retired == ["telegram"]
    assert len(store.search("日本語", source="mail")) == 1
    assert store.search("日本語", source="telegram")
