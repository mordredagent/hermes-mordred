"""Shared fakes for the IMAP sync tests: credentials, a plain-SQLite store and a fetch environment."""

from __future__ import annotations

import contextlib
import sqlite3
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

from mordred_hermes.imports.mail.imap import ImapSession, IoLimits
from mordred_hermes.imports.mail.imap_sync import FetchEnv, fetch_lock
from mordred_hermes.imports.mail.secrets import MailCredentials
from mordred_hermes.imports.store import ImportStore
from tests._fake_imap import FakeImapServer, FakeMailbox, FakeMessage, mail

ADDRESS = "owner@example.com"
PASSWORD = "app-password-1"
#: Strings of the fixtures that must never reach output, logs, audit entries or a tool result.
CANARIES = ("SUBJCANARY", "BODYCANARY", "taro@example.net", "owner@example.com", "Taro Tanaka", "imap.example.com")


def gmail_creds(account: str = "mail") -> MailCredentials:
    return MailCredentials(
        address=ADDRESS,
        app_password=PASSWORD,
        imap_host="imap.example.com",
        imap_port=993,
        own_addresses=(ADDRESS,),
        account=account,
        gmail=True,
        mailboxes={"all": "[Gmail]/All Mail"},
    )


def generic_creds(account: str = "mail", *, sent: bool = True) -> MailCredentials:
    boxes = {"inbox": "INBOX", "sent": "Sent Items"} if sent else {"inbox": "INBOX"}
    return MailCredentials(
        address=ADDRESS,
        app_password=PASSWORD,
        imap_host="imap.example.com",
        imap_port=993,
        own_addresses=(ADDRESS,),
        account=account,
        gmail=False,
        mailboxes=boxes,
    )


class FakeSecrets:
    """``MailSecretStore`` stand-in: flags without unsealing, ``load`` counts unseals."""

    def __init__(self, creds: MailCredentials | None) -> None:
        self.creds = creds
        self.loads = 0

    def flags(self) -> dict[str, Any] | None:
        if self.creds is None:
            return None
        return {"account": self.creds.account, "gmail": self.creds.gmail, "roles": list(self.creds.roles)}

    def load(self) -> MailCredentials | None:
        self.loads += 1
        return self.creds

    def residue(self) -> bool:
        return self.creds is not None


class Clock:
    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now


def make_store(tmp_path: Path, home: Path) -> ImportStore:
    store = ImportStore(tmp_path / "mordred.db", sqlite3.connect)
    store.initialize(home)
    return store


def make_env(
    home: Path,
    store: ImportStore | None,
    server: FakeImapServer,
    secrets: FakeSecrets,
    *,
    audits: list[Mapping[str, Any]] | None = None,
    clock: Callable[[], float] | None = None,
    platform: str = "darwin",
    memory_guard: Callable[[Path], None] | None = None,
    open_store: Callable[[Path], Any] | None = None,
    lock: Callable[[Path], contextlib.AbstractContextManager[None]] = fetch_lock,
    connect: Callable[[MailCredentials, IoLimits], ImapSession] | None = None,
) -> FetchEnv:
    sink: list[Mapping[str, Any]] = audits if audits is not None else []
    return FetchEnv(
        home=home,
        secret_store=secrets,
        connect=connect or (lambda _creds, limits: server.session(limits)),
        open_store=open_store or (lambda _home: store),
        memory_guard=memory_guard or (lambda _home: None),
        audit=sink.append,
        platform=lambda: platform,
        clock=clock or Clock(),
        lock=lock,
    )


def gmail_server(**kwargs: Any) -> FakeImapServer:
    """All Mail with a received message, the owner's Sent reply, a forged-header message and a draft."""
    forged = "X-Gmail-Labels: Sent\r\nX-GM-THRID: 999\r\n"  # typed by a stranger: must be ignored
    box = FakeMailbox(
        uidvalidity=7,
        attributes=("\\All",),
        messages={
            1: FakeMessage(mail(1), labels=("\\Inbox", "Work"), thread_id=1001),
            2: FakeMessage(
                mail(
                    2, sender=f"Owner <{ADDRESS}>", to="Taro Tanaka <taro@example.net>", references="msg1@example.net"
                ),
                labels=("\\Sent",),
                thread_id=1001,
            ),
            3: FakeMessage(mail(3, extra_headers=forged), labels=("\\Inbox",), thread_id=1003),
            4: FakeMessage(mail(4, sender=f"Owner <{ADDRESS}>"), labels=("\\Draft",), thread_id=1004),
        },
    )
    return FakeImapServer({"INBOX": FakeMailbox(5), "[Gmail]/All Mail": box}, gmail=True, **kwargs)


def generic_server(**kwargs: Any) -> FakeImapServer:
    inbox = FakeMailbox(uidvalidity=11, messages={1: FakeMessage(mail(1)), 2: FakeMessage(mail(2))})
    sent = FakeMailbox(
        uidvalidity=12,
        attributes=("\\Sent",),
        messages={1: FakeMessage(mail(10, sender=f"Owner <{ADDRESS}>", to="Taro Tanaka <taro@example.net>"))},
    )
    return FakeImapServer({"INBOX": inbox, "Sent Items": sent}, **kwargs)


def many(count: int, *, start: int = 1, size: int | None = None) -> dict[int, FakeMessage]:
    return {uid: FakeMessage(mail(uid), size=size) for uid in range(start, start + count)}


def rows(store: ImportStore, sql: str, *params: Any) -> list[tuple[Any, ...]]:
    with store.connection() as conn:
        return [tuple(row) for row in conn.execute(sql, params).fetchall()]


def committed_messages(store: ImportStore) -> dict[str, tuple[str, str, str]]:
    """source_uid → (owner_class, owner_evidence, provenance_quality) of committed mail messages."""
    found = rows(
        store,
        "SELECT m.source_uid, m.owner_class, m.owner_evidence, m.provenance_quality FROM import_messages m "
        "JOIN import_runs r ON r.run_id = m.run_id AND r.state = 'committed'",
    )
    return {uid: (owner, evidence, quality) for uid, owner, evidence, quality in found}
