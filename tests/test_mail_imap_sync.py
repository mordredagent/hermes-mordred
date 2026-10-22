"""IMAP sync end to end against the scripted fake server: classification, cursors, batches, budgets, gates."""

from __future__ import annotations

import datetime as dt
import json
import logging
import sqlite3
import sys
import threading
import time
import tracemalloc
from pathlib import Path
from typing import Any

import pytest

from mordred_hermes.imports.mail import imap_sync
from mordred_hermes.imports.mail.imap_sync import (
    RESULT_FIELDS,
    Cursor,
    FetchOptions,
    FetchResult,
    checked_result,
    cursor_key,
    mailbox_digest,
    run_fetch,
)
from mordred_hermes.imports.store import ImportRefused, ImportStore
from tests._fake_imap import FakeImapServer, FakeMailbox, FakeMessage, mail
from tests._mail_sync_helpers import (
    ADDRESS,
    CANARIES,
    Clock,
    FakeSecrets,
    committed_messages,
    generic_creds,
    generic_server,
    gmail_creds,
    gmail_server,
    make_env,
    make_store,
    many,
    rows,
)

MiB = 1024 * 1024


@pytest.fixture
def home(tmp_path: Path) -> Path:
    path = tmp_path / "home"
    path.mkdir()
    return path


@pytest.fixture
def store(tmp_path: Path, home: Path) -> ImportStore:
    return make_store(tmp_path, home)


def assert_read_only(server: FakeImapServer) -> None:
    assert server.violations == []
    assert set(server.verbs) <= {"CAPABILITY", "LOGIN", "LIST", "EXAMINE", "UID SEARCH", "UID FETCH", "LOGOUT"}
    assert "SELECT" not in server.verbs and "UID STORE" not in server.verbs
    for line in server.commands:
        if "BODY" in line.upper():
            assert "BODY.PEEK[]" in line.upper()


def assert_no_canaries(*texts: str) -> None:
    joined = "\n".join(texts)
    assert [canary for canary in CANARIES if canary in joined] == []


def forward_cursor(store: ImportStore, creds: Any, mailbox: str) -> Cursor | None:
    digest = mailbox_digest(creds, mailbox)
    return Cursor.parse(store.get_meta(cursor_key(creds.account, digest)), digest)


# --- Gmail path -----------------------------------------------------------------------------------


def test_gmail_labels_and_thread_ids_come_from_the_server_only(
    home: Path, store: ImportStore, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG)
    server, audits = gmail_server(), []
    result = run_fetch(FetchOptions(), make_env(home, store, server, FakeSecrets(gmail_creds()), audits=audits))
    assert result.error is None, result
    assert (result.fetched, result.skipped, result.inserted, result.batches, result.mailboxes) == (4, 1, 3, 1, 1)
    assert result.gmail is True and result.partial is False
    found = committed_messages(store)
    assert found["mail:mail:msg1@example.net"] == ("other", "from_address", "source_claimed")
    assert found["mail:mail:msg2@example.net"] == ("account_owner", "gmail_label_sent", "api_identity")
    # Forged X-Gmail-Labels: Sent / X-GM-THRID in the bytes are ignored: the server said Inbox, thread 1003.
    assert found["mail:mail:msg3@example.net"] == ("other", "from_address", "source_claimed")
    assert "mail:mail:msg4@example.net" not in found  # \Draft is skipped
    convs = dict(rows(store, "SELECT conv_uid, message_count FROM import_conversations"))
    assert convs == {"mail:mail:t:g.1001": 2, "mail:mail:t:g.1003": 1}
    assert_read_only(server)
    assert any(line.endswith('EXAMINE "[Gmail]/All Mail"') for line in server.commands)
    assert_no_canaries(json.dumps(result.as_dict()), caplog.text, json.dumps(audits))
    [entry] = audits
    assert entry["event"] == "mail.fetch" and entry["decision"] == "committed" and entry["inserted"] == 3


def test_raw_bytes_are_stored_unmodified(home: Path, store: ImportStore) -> None:
    server = gmail_server()
    run_fetch(FetchOptions(), make_env(home, store, server, FakeSecrets(gmail_creds())))
    import hashlib

    revision = rows(
        store, "SELECT source_revision FROM import_messages WHERE source_uid = ?", "mail:mail:msg2@example.net"
    )
    expected = hashlib.sha256(server.mailboxes["[Gmail]/All Mail"].messages[2].data).hexdigest()
    assert revision == [(expected,)]


# --- generic path ---------------------------------------------------------------------------------


def test_generic_server_reads_inbox_and_the_chosen_sent_folder(home: Path, store: ImportStore) -> None:
    server = generic_server()
    result = run_fetch(FetchOptions(), make_env(home, store, server, FakeSecrets(generic_creds())))
    assert result.error is None and result.gmail is False
    assert (result.mailboxes, result.inserted) == (2, 3)
    found = committed_messages(store)
    # The sent folder vouches for its purpose only: owner for display, source_claimed, never an anchor.
    assert found["mail:mail:msg10@example.net"] == ("account_owner", "imap_sent_folder", "source_claimed")
    assert found["mail:mail:msg1@example.net"] == ("other", "from_address", "source_claimed")
    examined = [line.split(" ", 2)[2] for line in server.commands if " EXAMINE " in line]
    assert examined == ['"INBOX"', '"Sent Items"']
    assert "X-GM-LABELS" not in " ".join(server.commands)
    assert_read_only(server)


def test_a_generic_inbox_ignores_forged_gmail_headers(home: Path, store: ImportStore) -> None:
    forged = "X-Gmail-Labels: Sent\r\nX-GM-THRID: 4242\r\n"
    inbox = FakeMailbox(uidvalidity=3, messages={1: FakeMessage(mail(1, extra_headers=forged))})
    server = FakeImapServer({"INBOX": inbox})
    run_fetch(FetchOptions(), make_env(home, store, server, FakeSecrets(generic_creds(sent=False))))
    assert committed_messages(store)["mail:mail:msg1@example.net"][1] == "from_address"
    [(conv,)] = rows(store, "SELECT conv_uid FROM import_conversations")
    assert "g.4242" not in conv


# --- cursors --------------------------------------------------------------------------------------


def test_cursor_persists_and_the_self_included_last_uid_is_filtered(home: Path, store: ImportStore) -> None:
    server = gmail_server()
    creds = gmail_creds()
    env = make_env(home, store, server, FakeSecrets(creds))
    assert run_fetch(FetchOptions(), env).inserted == 3
    cursor = forward_cursor(store, creds, "[Gmail]/All Mail")
    assert cursor is not None and (cursor.uid, cursor.base, cursor.uidvalidity, cursor.epoch) == (4, 1, 7, 0)
    server.commands.clear()
    box = server.mailboxes["[Gmail]/All Mail"]
    box.uidnext = 10  # newer messages were deleted: UIDNEXT is past the highest UID
    again = run_fetch(FetchOptions(), env)
    assert (again.fetched, again.inserted, again.batches, again.cursor_reset) == (0, 0, 0, False)
    # "UID 5:*" makes the server return UID 4 (the last one); it is filtered, nothing is fetched.
    assert any(line.endswith("UID SEARCH UID 5:*") for line in server.commands)
    assert not any("UID FETCH" in line for line in server.commands)
    box.uidnext = None
    box.messages[5] = FakeMessage(mail(5), labels=("\\Inbox",), thread_id=1001)
    third = run_fetch(FetchOptions(), env)
    assert (third.fetched, third.inserted) == (1, 1)
    assert server.body_fetch_sets()[-1] == "5"
    assert forward_cursor(store, creds, "[Gmail]/All Mail").uid == 5  # type: ignore[union-attr]


def test_a_changed_uidvalidity_starts_a_new_epoch(home: Path, store: ImportStore) -> None:
    server = gmail_server()
    creds = gmail_creds()
    env = make_env(home, store, server, FakeSecrets(creds))
    run_fetch(FetchOptions(), env)
    server.mailboxes["[Gmail]/All Mail"].uidvalidity = 8
    result = run_fetch(FetchOptions(), env)
    assert result.cursor_reset is True
    assert (result.fetched, result.inserted, result.duplicates) == (4, 0, 3)  # idempotent re-fetch
    cursor = forward_cursor(store, creds, "[Gmail]/All Mail")
    assert cursor is not None and (cursor.uidvalidity, cursor.epoch, cursor.uid) == (8, 1, 4)


def test_first_run_takes_the_newest_messages_and_counts_the_rest(home: Path, store: ImportStore) -> None:
    server = FakeImapServer({"INBOX": FakeMailbox(uidvalidity=2, messages=many(10))})
    creds = generic_creds(sent=False)
    result = run_fetch(FetchOptions(max_messages=4), make_env(home, store, server, FakeSecrets(creds)))
    assert (result.fetched, result.excluded_history, result.partial) == (4, 6, False)
    assert server.body_fetch_sets() == ["7:10"]
    cursor = forward_cursor(store, creds, "INBOX")
    assert cursor is not None and (cursor.uid, cursor.base) == (10, 7)


def test_since_backfills_older_mail_without_moving_the_forward_cursor(home: Path, store: ImportStore) -> None:
    messages = many(10)
    for uid, message in messages.items():
        message.date = dt.date(2026, 9, uid)
    server = FakeImapServer({"INBOX": FakeMailbox(uidvalidity=2, messages=messages)})
    creds = generic_creds(sent=False)
    env = make_env(home, store, server, FakeSecrets(creds))
    run_fetch(FetchOptions(max_messages=4), env)
    since = dt.date(2026, 9, 4)
    result = run_fetch(FetchOptions(max_messages=2, since=since), env)
    assert (result.fetched, result.partial, result.partial_reason) == (2, True, "max_messages")
    assert server.body_fetch_sets()[-1] == "5:6"
    assert any("SINCE 4-Sep-2026" in line for line in server.commands)
    forward = forward_cursor(store, creds, "INBOX")
    assert forward is not None and (forward.uid, forward.base) == (10, 7)
    digest = mailbox_digest(creds, "INBOX")
    back = Cursor.parse(store.get_meta(cursor_key("mail", digest) + ".back"), digest)
    assert back is not None and back.low == 5
    rest = run_fetch(FetchOptions(max_messages=10, since=since), env)
    assert (rest.fetched, rest.partial) == (1, False)  # UID 4 only: 1-3 are older than the --since day
    assert server.body_fetch_sets()[-1] == "4"


def test_max_messages_stops_with_partial_and_the_next_run_continues(home: Path, store: ImportStore) -> None:
    box = FakeMailbox(uidvalidity=2, messages=many(2))
    server = FakeImapServer({"INBOX": box})
    creds = generic_creds(sent=False)
    env = make_env(home, store, server, FakeSecrets(creds))
    run_fetch(FetchOptions(), env)
    box.messages.update(many(10, start=3))
    result = run_fetch(FetchOptions(max_messages=4), env)
    assert (result.fetched, result.partial, result.partial_reason) == (4, True, "max_messages")
    assert forward_cursor(store, creds, "INBOX").uid == 6  # type: ignore[union-attr]
    rest = run_fetch(FetchOptions(), env)
    assert (rest.fetched, rest.partial) == (6, False)


# --- batches and sizes ----------------------------------------------------------------------------


def test_groups_of_200_uids_become_one_committed_run_each(home: Path, store: ImportStore) -> None:
    server = FakeImapServer({"INBOX": FakeMailbox(uidvalidity=2, messages=many(450))})
    result = run_fetch(FetchOptions(), make_env(home, store, server, FakeSecrets(generic_creds(sent=False))))
    assert (result.fetched, result.inserted, result.batches) == (450, 450, 3)
    assert server.body_fetch_sets() == ["1:200", "201:400", "401:450"]
    size_fetches = [line for line in server.commands if "RFC822.SIZE" in line]
    assert len(size_fetches) == 3
    assert rows(store, "SELECT state, count(*) FROM import_runs GROUP BY state") == [("committed", 3)]


def test_batches_are_planned_at_48_mib_of_announced_sizes(home: Path, store: ImportStore) -> None:
    # 48 MiB of announced sizes per batch leaves room under the 64 MiB the session accepts per response.
    server = FakeImapServer({"INBOX": FakeMailbox(uidvalidity=2, messages=many(4, size=20 * MiB))})
    result = run_fetch(FetchOptions(), make_env(home, store, server, FakeSecrets(generic_creds(sent=False))))
    assert result.batches == 2
    assert server.body_fetch_sets() == ["1:2", "3:4"]


def test_oversize_messages_are_skipped_before_any_literal_is_downloaded(home: Path, store: ImportStore) -> None:
    messages = many(3)
    messages[2].size = 26 * MiB
    server = FakeImapServer({"INBOX": FakeMailbox(uidvalidity=2, messages=messages)})
    creds = generic_creds(sent=False)
    result = run_fetch(FetchOptions(), make_env(home, store, server, FakeSecrets(creds)))
    assert (result.skipped_oversize, result.fetched, result.inserted) == (1, 2, 2)
    assert server.body_fetch_sets() == ["1,3"]
    assert forward_cursor(store, creds, "INBOX").uid == 3  # type: ignore[union-attr]  # passed, never retried


def test_a_failed_batch_leaves_the_cursor_at_the_last_committed_batch(
    home: Path, store: ImportStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    server = FakeImapServer({"INBOX": FakeMailbox(uidvalidity=2, messages=many(450))})
    creds = generic_creds(sent=False)
    real = store.write_batch
    calls: list[int] = []

    def flaky(*args: Any, **kwargs: Any) -> Any:
        calls.append(1)
        if len(calls) == 2:
            raise ImportRefused("disk_full")
        return real(*args, **kwargs)

    monkeypatch.setattr(store, "write_batch", flaky)
    result = run_fetch(FetchOptions(), make_env(home, store, server, FakeSecrets(creds)))
    assert (result.error, result.partial, result.partial_reason, result.inserted) == ("run_failed", True, "error", 200)
    assert forward_cursor(store, creds, "INBOX").uid == 200  # type: ignore[union-attr]
    assert rows(store, "SELECT state, count(*) FROM import_runs GROUP BY state ORDER BY state") == [
        ("committed", 1),
        ("failed", 1),
    ]
    assert int(store.status()["sources"]["mail"]["messages"]) == 200
    again = run_fetch(FetchOptions(), make_env(home, store, server, FakeSecrets(creds)))
    assert (again.error, again.inserted) == (None, 250)  # the failed batch's rows are reclaimed


def test_a_server_hang_up_mid_fetch_keeps_committed_batches(home: Path, store: ImportStore) -> None:
    server = FakeImapServer({"INBOX": FakeMailbox(uidvalidity=2, messages=many(250))})
    server.fail_body_fetch_after = 1
    creds = generic_creds(sent=False)
    result = run_fetch(FetchOptions(), make_env(home, store, server, FakeSecrets(creds)))
    assert (result.error, result.partial_reason, result.inserted) == ("imap_unreachable", "error", 200)
    assert forward_cursor(store, creds, "INBOX").uid == 200  # type: ignore[union-attr]


def test_the_time_budget_returns_partial_at_a_batch_boundary(home: Path, store: ImportStore) -> None:
    server = FakeImapServer({"INBOX": FakeMailbox(uidvalidity=2, messages=many(450))})
    clock = Clock()

    def slow(_uids: list[int]) -> None:
        clock.now += 61.0

    server.on_body_fetch = slow
    creds = generic_creds(sent=False)
    env = make_env(home, store, server, FakeSecrets(creds), clock=clock)
    result = run_fetch(FetchOptions(budget_s=60.0, via="tool"), env)
    assert (result.partial, result.partial_reason, result.error, result.inserted) == (True, "time_budget", None, 200)
    assert forward_cursor(store, creds, "INBOX").uid == 200  # type: ignore[union-attr]
    assert server.verbs[-1] == "LOGOUT"


def test_crashed_open_runs_are_marked_failed_under_the_lock(home: Path, store: ImportStore) -> None:
    stale = store.run_begin("mail")
    run_fetch(FetchOptions(), make_env(home, store, gmail_server(), FakeSecrets(gmail_creds())))
    assert rows(store, "SELECT state FROM import_runs WHERE run_id = ?", stale) == [("failed",)]


def test_conversation_rows_merge_across_batches(home: Path, store: ImportStore) -> None:
    box = FakeMailbox(uidvalidity=2, messages={1: FakeMessage(mail(1), labels=("\\Inbox",), thread_id=77)})
    server = FakeImapServer({"[Gmail]/All Mail": box}, gmail=True)
    env = make_env(home, store, server, FakeSecrets(gmail_creds()))
    run_fetch(FetchOptions(), env)
    reply = mail(
        2, sender="Hanako <hanako@example.org>", references="msg1@example.net", date="Fri, 02 Oct 2026 10:00:00 +0900"
    )
    box.messages[2] = FakeMessage(reply, labels=("\\Inbox",), thread_id=77)
    run_fetch(FetchOptions(), env)
    [(count, last, participants)] = rows(
        store, "SELECT message_count, last_message_at, participants_json FROM import_conversations"
    )
    assert count == 2
    assert last == int(dt.datetime(2026, 10, 2, 1, 0, tzinfo=dt.UTC).timestamp())
    assert "taro@example.net" in participants and "hanako@example.org" in participants


# --- dry run, gates and refusals ------------------------------------------------------------------


def test_dry_run_writes_nothing_and_moves_no_cursor(home: Path, store: ImportStore) -> None:
    server = gmail_server()
    before = rows(store, "SELECT key, value FROM import_meta ORDER BY key")
    audits: list[Any] = []
    result = run_fetch(
        FetchOptions(dry_run=True), make_env(home, store, server, FakeSecrets(gmail_creds()), audits=audits)
    )
    assert (result.dry_run, result.fetched, result.batches, result.inserted) == (True, 4, 1, 0)
    assert rows(store, "SELECT count(*) FROM import_messages") == [(0,)]
    assert rows(store, "SELECT count(*) FROM import_runs") == [(0,)]
    assert rows(store, "SELECT key, value FROM import_meta ORDER BY key") == before
    assert audits == []
    assert_read_only(server)


@pytest.mark.parametrize(
    ("change", "code"),
    [
        ({"platform": "linux"}, "unsupported_platform"),
        ({"secrets": None}, "mail_not_configured"),
        ({"memory": True}, "memory_encryption_required"),
        ({"store_error": "not_armed"}, "not_armed"),
        ({"store_error": "busy"}, "import_store_unavailable"),
        ({"password": "wrong"}, "imap_auth_failed"),
    ],
)
def test_refusals_are_codes_and_write_nothing(
    change: dict[str, Any], code: str, home: Path, store: ImportStore
) -> None:
    from mordred_hermes.extension.telegram.memory_guard import MemoryEncryptionRequired

    server = gmail_server()
    if "password" in change:
        server.password = change["password"]
    secrets = FakeSecrets(None if "secrets" in change else gmail_creds())

    def guard(_home: Path) -> None:
        if change.get("memory"):
            raise MemoryEncryptionRequired()

    def opener(_home: Path) -> ImportStore:
        if "store_error" in change:
            raise ImportRefused(change["store_error"])
        return store

    audits: list[Any] = []
    env = make_env(
        home, store, server, secrets, audits=audits, platform=change.get("platform", "darwin"),
        memory_guard=guard, open_store=opener,
    )  # fmt: skip
    result = run_fetch(FetchOptions(), env)
    assert result.as_dict()["error"] == code
    assert (result.inserted, result.batches, result.partial) == (0, 0, False)
    assert rows(store, "SELECT count(*) FROM import_messages") == [(0,)]
    if code != "imap_auth_failed":
        assert secrets.loads == 0  # refused before any unseal (Touch ID)
    assert [entry["error"] for entry in audits] == [code]


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX flock")
def test_a_second_fetch_while_one_runs_is_sync_in_progress(home: Path, store: ImportStore) -> None:
    with imap_sync.fetch_lock(home):
        result = run_fetch(FetchOptions(), make_env(home, store, gmail_server(), FakeSecrets(gmail_creds())))
    assert result.error == "sync_in_progress"
    assert rows(store, "SELECT count(*) FROM import_runs") == [(0,)]


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX flock")
def test_an_abandoned_lease_releases_the_writer_lock_its_holder_still_keeps(home: Path) -> None:
    lease = imap_sync.FetchLease()
    inside, leave = threading.Event(), threading.Event()

    def holder() -> None:
        with imap_sync.fetch_lock(home, lease):
            inside.set()
            leave.wait(10)  # a worker blocked under the lock

    thread = threading.Thread(target=holder)
    thread.start()
    try:
        assert inside.wait(5)
        with pytest.raises(imap_sync.FetchStop) as busy, imap_sync.fetch_lock(home):
            pass
        assert busy.value.code == "sync_in_progress"
        lease.abandon()
        with imap_sync.fetch_lock(home):  # taken while the holder is still blocked
            pass
    finally:
        leave.set()
        thread.join(5)
    with pytest.raises(imap_sync._Abandoned), imap_sync.fetch_lock(home, lease):
        pytest.fail("nothing runs under an abandoned lease")
    with imap_sync.fetch_lock(home):  # ... and that refusal left no lock behind
        pass


def test_an_abandoned_lease_fails_its_open_run_and_refuses_later_writes(store: ImportStore) -> None:
    lease = imap_sync.FetchLease()
    run_id = store.run_begin("mail")
    assert lease.opened(store, run_id)
    lease.abandon()
    assert rows(store, "SELECT state, counts_json FROM import_runs") == [("failed", '{"abandoned":1}')]
    with pytest.raises(ImportRefused) as refused:
        store.write_batch(run_id, [], conversations=[], meta_updates={"mail_imap.mail.mabc": "1"})
    assert refused.value.code == "run_not_open" and store.get_meta("mail_imap.mail.mabc") is None
    assert not lease.opened(store, store.run_begin("mail"))
    with pytest.raises(imap_sync._Abandoned):
        lease.write(lambda: store.set_meta("mail_imap.mail.mabc", "1"))
    assert store.get_meta("mail_imap.mail.mabc") is None


def test_a_mailbox_restriction_outside_the_configured_roles_is_invalid(home: Path, store: ImportStore) -> None:
    result = run_fetch(FetchOptions(roles=("sent",)), make_env(home, store, gmail_server(), FakeSecrets(gmail_creds())))
    assert result.error == "invalid_request"


# --- the fixed serializer -------------------------------------------------------------------------


def test_the_result_serializer_is_a_closed_allowlist() -> None:
    data = FetchResult(inserted=2, error="imap_protocol", partial=True, partial_reason="error").as_dict()
    assert set(data) == RESULT_FIELDS
    with pytest.raises(ValueError):
        checked_result({**data, "subject": "SUBJCANARY"})
    with pytest.raises(ValueError):
        checked_result({**data, "error": "boom: taro@example.net"})
    with pytest.raises(ValueError):
        checked_result({**data, "partial_reason": "whatever"})
    with pytest.raises(ValueError):
        checked_result({**data, "inserted": True})
    with pytest.raises(ValueError):
        checked_result({key: value for key, value in data.items() if key != "gmail"})


def test_cursor_keys_fit_the_store_key_grammar(store: ImportStore) -> None:
    creds = gmail_creds("work_1")
    key = cursor_key(creds.account, mailbox_digest(creds, "[Gmail]/All Mail"))
    assert key.startswith("mail_imap.work_1.m") and len(key.split(".")) == 3
    store.set_meta(key, "{}")
    store.set_meta(key + ".back", "{}")
    assert set(store.meta_items("mail_imap.work_1.")) == {key, key + ".back"}


def test_a_failed_first_batch_is_an_error_without_partial_progress(
    home: Path, store: ImportStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    def broken(*_args: Any, **_kwargs: Any) -> None:
        raise ImportRefused("busy")

    monkeypatch.setattr(store, "write_batch", broken)
    creds = gmail_creds()
    result = run_fetch(FetchOptions(), make_env(home, store, gmail_server(), FakeSecrets(creds)))
    assert (result.error, result.partial, result.batches, result.inserted) == ("run_failed", False, 0, 0)
    assert forward_cursor(store, creds, "[Gmail]/All Mail") is None
    assert rows(store, "SELECT state FROM import_runs") == [("failed",)]


# --- review regressions: sizes, deadlines, cursors, threading, provenance, labels -------------------


def _watchdogs() -> list[str]:
    return [thread.name for thread in threading.enumerate() if thread.name == "mordred-imap-watchdog"]


def test_an_announced_size_lie_stops_the_run_without_reading_the_literal(home: Path, store: ImportStore) -> None:
    messages = many(3)
    messages[2] = FakeMessage(b"x", size=1, literal=256 * MiB)  # RFC822.SIZE 1, then a 256 MiB literal header
    server = FakeImapServer({"INBOX": FakeMailbox(uidvalidity=2, messages=messages)})
    creds = generic_creds(sent=False)
    tracemalloc.start()
    started = time.monotonic()
    try:
        result = run_fetch(FetchOptions(), make_env(home, store, server, FakeSecrets(creds)))
        _current, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert (result.error, result.inserted, result.batches) == ("imap_protocol", 0, 0)
    assert peak < 8 * MiB and time.monotonic() - started < 5.0
    assert forward_cursor(store, creds, "INBOX") is None  # nothing published, the cursor never moved
    assert "LOGOUT" not in server.verbs  # the stream was abandoned mid-literal: shut down, not logged out
    assert _watchdogs() == []


def test_an_under_reported_message_is_drained_and_counted(home: Path, store: ImportStore) -> None:
    messages = many(3)
    messages[2] = FakeMessage(b"y" * (30 * MiB), size=1)
    server = FakeImapServer({"INBOX": FakeMailbox(uidvalidity=2, messages=messages)})
    creds = generic_creds(sent=False)
    result = run_fetch(FetchOptions(), make_env(home, store, server, FakeSecrets(creds)))
    assert (result.error, result.skipped_oversize, result.inserted, result.fetched) == (None, 1, 2, 2)
    assert forward_cursor(store, creds, "INBOX").uid == 3  # type: ignore[union-attr]


def test_a_trickling_server_cannot_hold_the_fetch_past_its_deadline(home: Path, store: ImportStore) -> None:
    server = FakeImapServer({"INBOX": FakeMailbox(uidvalidity=2, messages=many(3))})
    server.trickle_s = 0.01
    creds = generic_creds(sent=False)
    env = make_env(home, store, server, FakeSecrets(creds), clock=time.monotonic)
    started = time.monotonic()
    result = run_fetch(FetchOptions(budget_s=0.5, via="tool"), env)
    assert (result.partial, result.partial_reason, result.error) == (True, "time_budget", None)
    assert time.monotonic() - started < 4.0 and server.trickled > 5
    assert forward_cursor(store, creds, "INBOX") is None
    assert server.closed.wait(5) and _watchdogs() == []


def test_an_exhausted_cap_never_moves_a_later_mailbox_cursor(home: Path, store: ImportStore) -> None:
    inbox = FakeMailbox(uidvalidity=11, messages=many(4))
    sent = FakeMailbox(uidvalidity=12, attributes=("\\Sent",), messages=many(3, start=20))
    server = FakeImapServer({"INBOX": inbox, "Sent Items": sent})
    creds = generic_creds()
    env = make_env(home, store, server, FakeSecrets(creds))
    result = run_fetch(FetchOptions(max_messages=4), env)
    assert (result.fetched, result.partial, result.partial_reason) == (4, True, "max_messages")
    assert forward_cursor(store, creds, "Sent Items") is None  # never set to its top without fetching
    rest = run_fetch(FetchOptions(), env)
    assert (rest.fetched, rest.partial) == (3, False)
    assert forward_cursor(store, creds, "Sent Items").uid == 22  # type: ignore[union-attr]


def test_backfill_walks_by_uid_and_a_wider_since_rescans_what_it_never_covered(home: Path, store: ImportStore) -> None:
    messages = many(10)
    for uid, message in messages.items():
        message.date = dt.date(2026, 9, uid)
    messages[6].date = dt.date(2026, 8, 20)  # appended later with an old date: dates are not monotonic in UIDs
    server = FakeImapServer({"INBOX": FakeMailbox(uidvalidity=2, messages=messages)})
    creds = generic_creds(sent=False)
    env = make_env(home, store, server, FakeSecrets(creds))
    run_fetch(FetchOptions(max_messages=3), env)  # forward: 8, 9, 10 (base 8)
    september = run_fetch(FetchOptions(max_messages=10, since=dt.date(2026, 9, 4)), env)
    assert (september.fetched, september.partial) == (3, False)  # 7, 5, 4 by date; 6 is from August
    assert server.body_fetch_sets()[-1] == "4:5,7"
    digest = mailbox_digest(creds, "INBOX")
    back = Cursor.parse(store.get_meta(cursor_key("mail", digest) + ".back"), digest)
    assert back is not None and (back.low, back.since) == (1, dt.date(2026, 9, 4).toordinal())
    wider = run_fetch(FetchOptions(max_messages=10, since=dt.date(2026, 8, 1)), env)
    assert (wider.fetched, wider.partial, wider.inserted) == (4, False, 4)  # 6 (re-scanned range) and 1-3
    assert any("SINCE 1-Aug-2026 BEFORE 4-Sep-2026" in line for line in server.commands)
    found = committed_messages(store)
    assert all(f"mail:mail:msg{uid}@example.net" in found for uid in range(1, 11))
    again = run_fetch(FetchOptions(max_messages=10, since=dt.date(2026, 8, 1)), env)
    assert again.fetched == 0  # everything since August is covered now


def test_a_widening_interrupted_by_the_cap_resumes_where_it_stopped(home: Path, store: ImportStore) -> None:
    messages = many(10)
    for uid, message in messages.items():
        message.date = dt.date(2026, 7, uid)  # every message older than the first --since
    server = FakeImapServer({"INBOX": FakeMailbox(uidvalidity=2, messages=messages)})
    creds = generic_creds(sent=False)
    env = make_env(home, store, server, FakeSecrets(creds))
    run_fetch(FetchOptions(max_messages=2), env)  # forward: 9, 10
    assert run_fetch(FetchOptions(max_messages=10, since=dt.date(2026, 9, 1)), env).fetched == 0
    first = run_fetch(FetchOptions(max_messages=3, since=dt.date(2026, 7, 1)), env)
    assert (first.fetched, first.partial, first.partial_reason) == (3, True, "max_messages")
    second = run_fetch(FetchOptions(max_messages=10, since=dt.date(2026, 7, 1)), env)
    assert (second.fetched, second.inserted, second.partial) == (5, 5, False)
    assert len(committed_messages(store)) == 10


def test_a_reply_chain_split_across_batches_stays_one_conversation(home: Path, store: ImportStore) -> None:
    box = FakeMailbox(uidvalidity=2, messages={1: FakeMessage(mail(1))})
    server = FakeImapServer({"INBOX": box})
    creds = generic_creds(sent=False)
    env = make_env(home, store, server, FakeSecrets(creds))
    run_fetch(FetchOptions(), env)
    in_reply_only = "In-Reply-To: <msg{}@example.net>\r\n"
    box.messages[2] = FakeMessage(mail(2, extra_headers=in_reply_only.format(1), sender="Hanako <hanako@example.org>"))
    run_fetch(FetchOptions(), env)
    box.messages[3] = FakeMessage(mail(3, extra_headers=in_reply_only.format(2)))  # C names only B
    run_fetch(FetchOptions(), env)
    convs = rows(store, "SELECT conv_uid, message_count FROM import_conversations")
    assert len(convs) == 1 and convs[0][1] == 3
    [(people,)] = rows(store, "SELECT participants_json FROM import_conversations")
    assert "hanako@example.org" in people and "taro@example.net" in people


def test_a_sent_copy_upgrades_the_inbox_copy_of_the_same_message(home: Path, store: ImportStore) -> None:
    own = mail(10, sender=f"Owner <{ADDRESS}>", to="Taro Tanaka <taro@example.net>")
    inbox = FakeMailbox(uidvalidity=11, messages={1: FakeMessage(own)})  # e.g. Bcc to self
    sent = FakeMailbox(uidvalidity=12, attributes=("\\Sent",), messages={1: FakeMessage(own)})
    server = FakeImapServer({"INBOX": inbox, "Sent Items": sent})
    result = run_fetch(FetchOptions(), make_env(home, store, server, FakeSecrets(generic_creds())))
    assert (result.inserted, result.revised) == (1, 1)
    assert committed_messages(store)["mail:mail:msg10@example.net"][1] == "imap_sent_folder"


def test_a_changed_received_copy_never_overwrites_a_gmail_sent_record(home: Path, store: ImportStore) -> None:
    sent = FakeMessage(mail(10, sender=f"Owner <{ADDRESS}>", body="AS SENT"), labels=("\\Sent",), thread_id=5)
    box = FakeMailbox(uidvalidity=2, messages={1: sent})
    server = FakeImapServer({"[Gmail]/All Mail": box}, gmail=True)
    env = make_env(home, store, server, FakeSecrets(gmail_creds()))
    run_fetch(FetchOptions(), env)
    relayed = mail(10, sender=f"Owner <{ADDRESS}>", body="AS RELAYED")  # same Message-ID, other bytes
    box.messages[2] = FakeMessage(relayed, labels=("\\Inbox",), thread_id=5)
    result = run_fetch(FetchOptions(), env)
    assert (result.revised, result.duplicates) == (0, 1)
    assert committed_messages(store)["mail:mail:msg10@example.net"][1:] == ("gmail_label_sent", "api_identity")


def test_custom_labels_named_like_system_labels_never_classify(home: Path, store: ImportStore) -> None:
    many_custom = b" ".join(b'"tag %d"' % n for n in range(100))
    box = FakeMailbox(
        uidvalidity=2,
        messages={
            1: FakeMessage(mail(1, sender=f"Owner <{ADDRESS}>"), raw_labels=b'" \\\\Sent " &AFw-Sent', thread_id=1),
            2: FakeMessage(mail(2), raw_labels=b"&AFw-Draft &AFw-Spam", thread_id=2),
            3: FakeMessage(mail(3, sender=f"Owner <{ADDRESS}>"), raw_labels=many_custom + b" \\Draft", thread_id=3),
        },
    )
    server = FakeImapServer({"[Gmail]/All Mail": box}, gmail=True)
    result = run_fetch(FetchOptions(), make_env(home, store, server, FakeSecrets(gmail_creds())))
    found = committed_messages(store)
    assert found["mail:mail:msg1@example.net"][1] == "own_address"  # not gmail_label_sent
    assert found["mail:mail:msg2@example.net"][1] == "from_address"  # not skipped as a draft or spam
    assert "mail:mail:msg3@example.net" not in found and result.skipped == 1  # a late \Draft is still seen


def test_a_failed_batch_keeps_the_published_revision(
    home: Path, store: ImportStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    box = FakeMailbox(uidvalidity=2, messages={1: FakeMessage(mail(1, body="FIRST-REVISION"))})
    server = FakeImapServer({"INBOX": box})
    creds = generic_creds(sent=False)
    env = make_env(home, store, server, FakeSecrets(creds))
    run_fetch(FetchOptions(), env)
    before = rows(store, "SELECT message_count, last_message_at, participants_json FROM import_conversations")
    box.messages[2] = FakeMessage(mail(1, body="SECOND-REVISION"))  # the same Message-ID, revised
    box.messages[3] = FakeMessage(mail(3, sender="Hanako <hanako@example.org>", references="msg1@example.net"))

    def broken(*_args: Any, **_kwargs: Any) -> None:
        raise sqlite3.OperationalError("disk I/O error")

    monkeypatch.setattr(ImportStore, "_recount", staticmethod(broken))  # fails inside the batch transaction
    result = run_fetch(FetchOptions(), env)
    assert (result.error, result.inserted, result.revised) == ("run_failed", 0, 0)
    texts = [item.part.text for item in store.find_messages("mail", "mail", message_ids=["msg1@example.net"])]
    assert any("FIRST-REVISION" in text for text in texts)  # the published revision is still readable
    assert rows(store, "SELECT message_count, last_message_at, participants_json FROM import_conversations") == before
    assert forward_cursor(store, creds, "INBOX").uid == 1  # type: ignore[union-attr]


# --- thread reconciliation when missing parents arrive later ------------------------------------------

_DATES = {
    1: "Thu, 01 Oct 2026 10:00:00 +0900",
    2: "Fri, 02 Oct 2026 10:00:00 +0900",
    3: "Sat, 03 Oct 2026 10:00:00 +0900",
}


_CHAIN_SENDERS = ("Taro Tanaka <taro@example.net>", "Hanako <hanako@example.org>", "Jiro <jiro@example.com>")


def _chain_message(n: int, parent: int | None, *, offset: int = 0) -> FakeMessage:
    """Message ``offset + n`` replying to ``offset + parent`` only (``In-Reply-To`` and ``References``).

    A reply is addressed to its parent's sender with the owner in copy, as a reply is.
    """
    references = None if parent is None else f"msg{offset + parent}@example.net"
    to = f"Owner <{ADDRESS}>" if parent is None else f"{_CHAIN_SENDERS[parent - 1]}, Owner <{ADDRESS}>"
    return FakeMessage(mail(offset + n, references=references, sender=_CHAIN_SENDERS[n - 1], to=to, date=_DATES[n]))


def _fetch_one_by_one(home: Path, store: ImportStore, order: list[tuple[int, FakeMessage]]) -> None:
    """Each message arrives in its own fetch (its own batch), in ``order``."""
    box = FakeMailbox(uidvalidity=2)
    env = make_env(home, store, FakeImapServer({"INBOX": box}), FakeSecrets(generic_creds(sent=False)))
    for uid, (_n, message) in enumerate(order, start=1):
        box.messages[uid] = message
        result = run_fetch(FetchOptions(), env)
        assert (result.error, result.inserted) == (None, 1)


def _threads_of(store: ImportStore) -> dict[str, list[str]]:
    """conv_uid → its committed message ids, and every conversation row's count matches."""
    found: dict[str, list[str]] = {}
    for conv, message_id in rows(store, "SELECT conv_uid, message_id FROM import_messages ORDER BY message_id"):
        found.setdefault(conv, []).append(message_id)
    counts = dict(rows(store, "SELECT conv_uid, message_count FROM import_conversations"))
    assert counts == {conv: len(ids) for conv, ids in found.items()}  # no empty or stale row is left
    return found


@pytest.mark.parametrize("arrival", [(3, 2, 1), (1, 3, 2), (2, 3, 1), (3, 1, 2)])
def test_a_chain_fetched_in_any_order_ends_as_one_conversation(
    home: Path, store: ImportStore, arrival: tuple[int, int, int]
) -> None:
    chain = {1: _chain_message(1, None), 2: _chain_message(2, 1), 3: _chain_message(3, 2)}  # C names only B
    _fetch_one_by_one(home, store, [(n, chain[n]) for n in arrival])
    [(conv, ids)] = _threads_of(store).items()
    assert ids == ["msg1@example.net", "msg2@example.net", "msg3@example.net"]
    [(people, last)] = rows(store, "SELECT participants_json, last_message_at FROM import_conversations")
    assert all(who in people for who in ("taro@example.net", "hanako@example.org", "jiro@example.com"))
    assert last == max(item.message.sent_at or 0 for item in store.find_messages("mail", "mail"))
    hits = {hit.conv_uid for hit in store.search("BODYCANARY")}
    assert hits == {conv}  # readers see one conversation


def test_two_independent_threads_stay_separate_whatever_the_order(home: Path, store: ImportStore) -> None:
    x = {n: _chain_message(n, None if n == 1 else n - 1) for n in (1, 2)}
    y = {n: _chain_message(n, None if n == 1 else n - 1, offset=10) for n in (1, 2)}
    _fetch_one_by_one(home, store, [(2, x[2]), (2, y[2]), (1, y[1]), (1, x[1])])
    threads = sorted(_threads_of(store).values())
    assert threads == [["msg11@example.net", "msg12@example.net"], ["msg1@example.net", "msg2@example.net"]]


def test_a_strangers_message_naming_a_late_parent_stays_apart_and_is_reported(home: Path, store: ImportStore) -> None:
    box = FakeMailbox(uidvalidity=2)
    env = make_env(home, store, FakeImapServer({"INBOX": box}), FakeSecrets(generic_creds(sent=False)))
    stray = mail(9, sender="Mallory <mallory@example.com>", references="msg2@example.net", date=_DATES[3])
    box.messages[1] = FakeMessage(stray)  # names B before B is stored, and shares no participant with it
    assert run_fetch(FetchOptions(), env).merge_skipped == 0
    box.messages[2] = _chain_message(2, 1)
    result = run_fetch(FetchOptions(), env)
    assert (result.inserted, result.merge_skipped, result.as_dict()["merge_skipped"]) == (1, 1, 1)
    box.messages[3] = _chain_message(3, 2)  # a real reply to B joins B's conversation
    assert run_fetch(FetchOptions(), env).merge_skipped == 0
    assert sorted(_threads_of(store).values()) == [["msg2@example.net", "msg3@example.net"], ["msg9@example.net"]]


def test_references_are_kept_per_message_and_deleted_with_the_rows(home: Path, store: ImportStore) -> None:
    _fetch_one_by_one(home, store, [(3, _chain_message(3, 2)), (1, _chain_message(1, None))])
    assert rows(store, "SELECT source_uid, ref_message_id FROM import_mail_refs") == [
        ("mail:mail:msg3@example.net", "msg2@example.net")
    ]
    assert len(_threads_of(store)) == 2  # B is still missing: nothing connects A and C yet
    store.delete_source("mail", "mail")
    assert rows(store, "SELECT count(*) FROM import_mail_refs") == [(0,)]


def test_a_failed_batch_rolls_its_merge_back(home: Path, store: ImportStore, monkeypatch: pytest.MonkeyPatch) -> None:
    box = FakeMailbox(uidvalidity=2)
    env = make_env(home, store, FakeImapServer({"INBOX": box}), FakeSecrets(generic_creds(sent=False)))
    for uid, n in enumerate((3, 1), start=1):
        box.messages[uid] = _chain_message(n, None if n == 1 else n - 1)
        run_fetch(FetchOptions(), env)
    before = _threads_of(store)
    box.messages[3] = _chain_message(2, 1)  # B joins A and C ...

    def broken(*_args: Any, **_kwargs: Any) -> None:
        raise sqlite3.OperationalError("disk I/O error")

    monkeypatch.setattr(ImportStore, "_recount", staticmethod(broken))  # ... but the batch fails
    assert run_fetch(FetchOptions(), env).error == "run_failed"
    assert _threads_of(store) == before and len(before) == 2
    assert rows(store, "SELECT count(*) FROM import_mail_refs WHERE source_uid = 'mail:mail:msg2@example.net'") == [
        (0,)
    ]


def test_gmail_thread_ids_stay_authoritative_across_batches(home: Path, store: ImportStore) -> None:
    box = FakeMailbox(uidvalidity=2, attributes=("\\All",))
    env = make_env(home, store, FakeImapServer({"[Gmail]/All Mail": box}, gmail=True), FakeSecrets(gmail_creds()))
    box.messages[1] = FakeMessage(mail(2, references="msg1@example.net", date=_DATES[2]), thread_id=200)
    run_fetch(FetchOptions(), env)
    box.messages[2] = FakeMessage(mail(1, date=_DATES[1]), thread_id=100)  # Gmail split the thread: 100 and 200
    run_fetch(FetchOptions(), env)
    assert sorted(_threads_of(store)) == ["mail:mail:t:g.100", "mail:mail:t:g.200"]
