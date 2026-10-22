"""``ImportStore`` support for batched collectors: atomic publication with a cursor, reclaim, merge."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from mordred_hermes.imports.mail import EmlBytes, plan_import
from mordred_hermes.imports.records import RecordError
from mordred_hermes.imports.store import ImportRefused, ImportStore
from tests._fake_imap import mail
from tests._mail_sync_helpers import rows


@pytest.fixture
def store(tmp_path: Path) -> ImportStore:
    db = ImportStore(tmp_path / "mordred.db", sqlite3.connect)
    db.initialize(tmp_path)
    return db


def _thread(store: ImportStore, *messages: bytes):  # type: ignore[no-untyped-def]
    plan = plan_import([EmlBytes(list(messages))], account="mail", own_addresses=["owner@example.com"])
    [thread] = plan.threads
    return thread


def test_commit_batch_publishes_the_run_and_the_cursor_together(store: ImportStore) -> None:
    thread = _thread(store, mail(1))
    run_id = store.run_begin("mail")
    store.write_thread(run_id, thread.messages, conversation=thread.conversation)
    assert store.contains(["mail:mail:msg1@example.net"]) == set()  # unpublished
    store.commit_batch(run_id, {"inserted": 1}, {"mail_imap.mail.mabc": '{"uid":1}', "mail_imap.mail.gone": None})
    assert store.contains(["mail:mail:msg1@example.net"]) == {"mail:mail:msg1@example.net"}
    assert store.get_meta("mail_imap.mail.mabc") == '{"uid":1}'
    assert rows(store, "SELECT state, counts_json FROM import_runs") == [("committed", '{"inserted":1}')]


@pytest.mark.parametrize(
    "updates",
    [{"Bad.Key": "1"}, {"schema_version": "2"}, {"mail_imap.mail.mabc": "x" * 257}, {"mail_imap.mail.mabc": "a\nb"}],
)
def test_a_bad_cursor_update_publishes_nothing(store: ImportStore, updates: dict[str, str]) -> None:
    thread = _thread(store, mail(1))
    run_id = store.run_begin("mail")
    store.write_thread(run_id, thread.messages, conversation=thread.conversation)
    with pytest.raises(RecordError):
        store.commit_batch(run_id, {"inserted": 1}, updates)
    assert store.contains(["mail:mail:msg1@example.net"]) == set()
    assert rows(store, "SELECT state FROM import_runs") == [("open",)]
    assert store.get_meta("mail_imap.mail.mabc") is None


def test_commit_batch_refuses_dry_runs_and_closed_runs(store: ImportStore) -> None:
    dry = store.run_begin("mail", dry_run=True)
    with pytest.raises(ImportRefused) as raised:
        store.commit_batch(dry, {}, {"mail_imap.mail.mabc": "1"})
    assert raised.value.code == "run_not_open"
    done = store.run_begin("mail")
    store.run_commit(done, {})
    with pytest.raises(ImportRefused):
        store.commit_batch(done, {}, {})
    assert store.get_meta("mail_imap.mail.mabc") is None


def test_fail_open_runs_marks_only_open_runs_of_the_source(store: ImportStore) -> None:
    stale = store.run_begin("mail")
    other = store.run_begin("telegram")
    done = store.run_begin("mail")
    store.run_commit(done, {})
    assert store.fail_open_runs("mail") == 1
    states = dict(rows(store, "SELECT run_id, state FROM import_runs"))
    assert (states[stale], states[other], states[done]) == ("failed", "open", "committed")


def test_meta_items_match_a_literal_prefix(store: ImportStore) -> None:
    store.set_meta("mail_imap.mail.ma", "1")
    store.set_meta("mail_imap.mail.ma.back", "2")
    store.set_meta("mailximap.mail.mb", "3")  # "_" is not a wildcard
    store.set_meta("mail_imap.other.mc", "4")
    assert store.meta_items("mail_imap.mail.") == {"mail_imap.mail.ma": "1", "mail_imap.mail.ma.back": "2"}
    with pytest.raises(RecordError):
        store.meta_items("mail_imap.mail")


def test_merge_keeps_participants_dates_and_recounts(store: ImportStore) -> None:
    first = _thread(store, mail(1, date="Thu, 01 Oct 2026 10:00:00 +0900"))
    run_id = store.run_begin("mail")
    store.write_thread(run_id, first.messages, conversation=first.conversation, merge_conversation=True)
    store.run_commit(run_id, {})
    later = mail(
        2,
        sender="Hanako <hanako@example.org>",
        references="msg1@example.net",
        date="Wed, 30 Sep 2026 10:00:00 +0900",
    )
    second = _thread(store, later)
    assert second.conversation.conv_uid == first.conversation.conv_uid
    run_id = store.run_begin("mail")
    store.write_thread(run_id, second.messages, conversation=second.conversation, merge_conversation=True)
    store.run_commit(run_id, {})
    [(count, last, people, title)] = rows(
        store, "SELECT message_count, last_message_at, participants_json, title FROM import_conversations"
    )
    assert count == 2
    assert last == first.conversation.last_message_at  # the maximum, not the later batch's older date
    assert "taro@example.net" in people and "hanako@example.org" in people
    assert title == first.conversation.title


def test_without_merge_the_row_is_replaced_as_before(store: ImportStore) -> None:
    first = _thread(store, mail(1))
    run_id = store.run_begin("mail")
    store.write_thread(run_id, first.messages, conversation=first.conversation)
    second = _thread(store, mail(2, sender="Hanako <hanako@example.org>", references="msg1@example.net"))
    store.write_thread(run_id, second.messages, conversation=second.conversation)
    [(people,)] = rows(store, "SELECT participants_json FROM import_conversations")
    assert "taro@example.net" not in people
