"""``ImportStore`` support for batched collectors: atomic batches with a cursor, reclaim, merge, Sent evidence."""

from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path
from typing import Any

import pytest

from mordred_hermes.imports.mail import EmlBytes, TrustedBytes, TrustedMeta, plan_import
from mordred_hermes.imports.mail._imap_codec import system_label
from mordred_hermes.imports.mail.owner import SENT_EVIDENCE
from mordred_hermes.imports.records import RecordError
from mordred_hermes.imports.store import SENT_EVIDENCE_RANK, BatchResult, ImportRefused, ImportStore
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


# --- write_batch: one transaction for rows, publication, cursor and conversation merge ------------


def _batch(store: ImportStore, thread, cursor: str = '{"uid":1}', **kwargs: Any) -> BatchResult:  # type: ignore[no-untyped-def]
    run_id = store.run_begin("mail")
    return store.write_batch(
        run_id,
        [thread.messages],
        conversations=[thread.conversation],
        meta_updates={"mail_imap.mail.mabc": cursor},
        **kwargs,
    )


def _authored(store: ImportStore, message_id: str) -> list[str]:
    found = store.find_messages("mail", "mail", message_ids=[message_id])
    return [item.part.text for item in found if str(item.part.part_kind) == "authored"]


def _conversation(store: ImportStore) -> tuple[Any, ...]:
    [row] = rows(store, "SELECT message_count, last_message_at, participants_json, title FROM import_conversations")
    return row


def test_write_batch_publishes_rows_merge_and_cursor_together(store: ImportStore) -> None:
    result = _batch(store, _thread(store, mail(1)), counts={"fetched": 1})
    assert result == BatchResult(1, 0, 0, 0)
    assert store.contains(["mail:mail:msg1@example.net"]) == {"mail:mail:msg1@example.net"}
    assert store.get_meta("mail_imap.mail.mabc") == '{"uid":1}'
    [(state, counts)] = rows(store, "SELECT state, counts_json FROM import_runs")
    assert state == "committed" and json.loads(counts) == {"fetched": 1, **result.counts()}
    assert _conversation(store)[0] == 1


def test_a_failed_batch_keeps_the_published_revision_and_the_conversation(
    store: ImportStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    _batch(store, _thread(store, mail(1, body="FIRST-REVISION")))
    before = _conversation(store)
    revised_and_new = _thread(
        store,
        mail(1, body="SECOND-REVISION"),  # same Message-ID, new bytes: a revision of the published record
        mail(
            2,
            sender="Hanako <hanako@example.org>",
            references="msg1@example.net",
            date="Sat, 03 Oct 2026 10:00:00 +0900",
        ),
    )

    def broken(*_args: Any, **_kwargs: Any) -> None:
        raise sqlite3.OperationalError("disk I/O error")  # the very last step of the transaction

    monkeypatch.setattr(ImportStore, "_apply_meta", staticmethod(broken))
    with pytest.raises(ImportRefused):
        _batch(store, revised_and_new, cursor='{"uid":2}')
    assert any("FIRST-REVISION" in text for text in _authored(store, "msg1@example.net"))  # still readable
    assert store.contains(["mail:mail:msg2@example.net"]) == set()
    assert _conversation(store) == before  # no participant, date or count of the failed batch
    assert "hanako@example.org" not in before[2]
    assert store.get_meta("mail_imap.mail.mabc") == '{"uid":1}'
    monkeypatch.undo()
    assert _batch(store, revised_and_new, cursor='{"uid":2}') == BatchResult(1, 0, 1, 0)
    assert any("SECOND-REVISION" in text for text in _authored(store, "msg1@example.net"))
    count, last, people, _title = _conversation(store)
    assert count == 2 and last > before[1] and "hanako@example.org" in people


def test_a_concurrent_reader_sees_the_old_or_the_new_state_never_between(
    store: ImportStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    _batch(store, _thread(store, mail(1, body="FIRST-REVISION")))
    before = _conversation(store)
    batch = _thread(
        store,
        mail(1, body="SECOND-REVISION"),
        mail(2, sender="Hanako <hanako@example.org>", references="msg1@example.net"),
    )
    inside, release = threading.Event(), threading.Event()
    real = ImportStore._store_message

    def paused(conn: sqlite3.Connection, run_id: str, msg: Any) -> None:
        real(conn, run_id, msg)
        inside.set()
        assert release.wait(10)

    monkeypatch.setattr(ImportStore, "_store_message", staticmethod(paused))
    errors: list[BaseException] = []

    def write() -> None:
        try:
            _batch(store, batch, cursor='{"uid":2}')
        except BaseException as exc:  # reported below
            errors.append(exc)

    writer = threading.Thread(target=write)
    writer.start()
    try:
        assert inside.wait(10)  # the writer holds its transaction with one row already replaced
        assert any("FIRST-REVISION" in text for text in _authored(store, "msg1@example.net"))
        assert store.contains(["mail:mail:msg2@example.net"]) == set()
        assert _conversation(store) == before
        assert store.get_meta("mail_imap.mail.mabc") == '{"uid":1}'
    finally:
        release.set()
        writer.join(10)
    assert errors == []
    assert any("SECOND-REVISION" in text for text in _authored(store, "msg1@example.net"))
    assert store.contains(["mail:mail:msg2@example.net"]) == {"mail:mail:msg2@example.net"}
    assert _conversation(store)[0] == 2 and store.get_meta("mail_imap.mail.mabc") == '{"uid":2}'


def test_write_batch_refuses_dry_and_closed_runs_and_bad_cursors(store: ImportStore) -> None:
    thread = _thread(store, mail(1))
    dry = store.run_begin("mail", dry_run=True)
    with pytest.raises(ImportRefused):
        store.write_batch(dry, [thread.messages], conversations=[thread.conversation], meta_updates={})
    run_id = store.run_begin("mail")
    with pytest.raises(RecordError):
        store.write_batch(run_id, [thread.messages], conversations=[thread.conversation], meta_updates={"Bad": "1"})
    assert store.contains(["mail:mail:msg1@example.net"]) == set()
    assert rows(store, "SELECT count(*) FROM import_conversations") == [(0,)]


# --- Sent evidence wins -----------------------------------------------------------------------------


def _fetched(data: bytes, *, role: str, sent_label: bool = False):  # type: ignore[no-untyped-def]
    labels = (system_label("\\Sent"),) if sent_label else ()
    trusted = TrustedMeta(labels=tuple(label for label in labels if label), folder_role=role)
    plan = plan_import([TrustedBytes([(data, trusted)])], account="mail", own_addresses=["owner@example.com"])
    [thread] = plan.threads
    return thread


def _evidence(store: ImportStore) -> str:
    [(evidence,)] = rows(store, "SELECT owner_evidence FROM import_messages")
    return str(evidence)


def test_sent_evidence_upgrades_an_identical_received_copy(store: ImportStore) -> None:
    own = mail(10, sender="Owner <owner@example.com>", to="Taro Tanaka <taro@example.net>")
    assert _batch(store, _fetched(own, role="inbox")) == BatchResult(1, 0, 0, 0)
    assert _evidence(store) == "own_address"
    assert _batch(store, _fetched(own, role="sent")) == BatchResult(0, 0, 1, 0)  # same bytes, stronger evidence
    assert _evidence(store) == "imap_sent_folder"
    assert _batch(store, _fetched(own, role="all", sent_label=True)) == BatchResult(0, 0, 1, 0)
    assert _evidence(store) == "gmail_label_sent"
    assert _batch(store, _fetched(own, role="sent")) == BatchResult(0, 1, 0, 0)  # never downgraded
    assert _evidence(store) == "gmail_label_sent"


def test_a_changed_received_copy_never_replaces_a_sent_record(store: ImportStore) -> None:
    sent = mail(10, sender="Owner <owner@example.com>", body="AS SENT")
    _batch(store, _fetched(sent, role="all", sent_label=True))
    received = mail(10, sender="Owner <owner@example.com>", body="AS RELAYED BY A LIST")  # new revision
    assert _batch(store, _fetched(received, role="inbox")) == BatchResult(0, 1, 0, 0)
    assert _evidence(store) == "gmail_label_sent"
    assert any("AS SENT" in text for text in _authored(store, "msg10@example.net"))


def test_the_store_rank_mirrors_the_mail_sent_evidence() -> None:
    assert set(SENT_EVIDENCE_RANK) == set(SENT_EVIDENCE)
    assert SENT_EVIDENCE_RANK["gmail_label_sent"] > SENT_EVIDENCE_RANK["imap_sent_folder"] > 0


# --- merge_conversations and import_mail_refs ------------------------------------------------------


def _committed(store: ImportStore, *messages: bytes, account: str = "mail"):  # type: ignore[no-untyped-def]
    plan = plan_import([EmlBytes(list(messages))], account=account, own_addresses=["owner@example.com"])
    [thread] = plan.threads
    run_id = store.run_begin("mail")
    store.write_batch(run_id, [thread.messages], conversations=[thread.conversation], meta_updates={}, refs=plan.refs)
    return thread


def test_merge_conversations_folds_rows_people_and_dates_into_the_survivor(store: ImportStore) -> None:
    first = _committed(store, mail(1, date="Thu, 01 Oct 2026 10:00:00 +0900"))
    second = _committed(store, mail(2, sender="Hanako <hanako@example.org>", date="Sat, 03 Oct 2026 10:00:00 +0900"))
    survivor, other = first.conversation.conv_uid, second.conversation.conv_uid
    assert survivor != other

    assert store.merge_conversations(survivor, [other, survivor]) == 1

    [(conv, count, last, people, title)] = rows(
        store, "SELECT conv_uid, message_count, last_message_at, participants_json, title FROM import_conversations"
    )
    assert (conv, count, last) == (survivor, 2, second.conversation.last_message_at)
    assert "taro@example.net" in people and "hanako@example.org" in people
    assert title == first.conversation.title
    assert rows(store, "SELECT DISTINCT conv_uid FROM import_messages") == [(survivor,)]
    assert store.merge_conversations(survivor, []) == 0


def test_merge_conversations_refuses_unknown_and_foreign_conversations(store: ImportStore) -> None:
    mine = _committed(store, mail(1)).conversation.conv_uid
    theirs = _committed(store, mail(2), account="work").conversation.conv_uid
    with pytest.raises(RecordError) as unknown:
        store.merge_conversations(mine, ["mail:mail:t:r.missing"])
    assert unknown.value.code == "unknown_conversation"
    with pytest.raises(ImportRefused) as foreign:
        store.merge_conversations(mine, [theirs])
    assert foreign.value.code == "conflict"
    assert len(rows(store, "SELECT conv_uid FROM import_conversations")) == 2  # nothing moved


@pytest.mark.parametrize(
    "refs",
    [
        {"mail:mail:msg9@example.net": ["msg1@example.net"]},  # not a message of the batch
        {"mail:mail:msg2@example.net": "msg1@example.net"},  # a string, not a list of ids
        {"mail:mail:msg2@example.net": ["bad\nid"]},
        {"mail:mail:msg2@example.net": [""]},
    ],
)
def test_bad_references_publish_nothing(store: ImportStore, refs: dict[str, Any]) -> None:
    thread = _thread(store, mail(2, references="msg1@example.net"))
    run_id = store.run_begin("mail")
    with pytest.raises(RecordError) as raised:
        store.write_batch(run_id, [thread.messages], conversations=[thread.conversation], meta_updates={}, refs=refs)
    assert raised.value.code == "bad_refs"
    assert rows(store, "SELECT count(*) FROM import_messages") == [(0,)]
    assert rows(store, "SELECT count(*) FROM import_mail_refs") == [(0,)]


def test_a_reply_stored_before_its_parent_is_merged_when_the_parent_arrives(store: ImportStore) -> None:
    late_reply = _committed(store, mail(3, sender="Jiro <jiro@example.com>", references="msg2@example.net"))
    root = _committed(store, mail(1, date="Wed, 30 Sep 2026 10:00:00 +0900"))
    assert rows(store, "SELECT ref_message_id FROM import_mail_refs") == [("msg2@example.net",)]
    assert len(rows(store, "SELECT conv_uid FROM import_conversations")) == 2
    middle = _committed(store, mail(2, sender="Hanako <hanako@example.org>", references="msg1@example.net"))
    assert len({late_reply.conversation.conv_uid, root.conversation.conv_uid, middle.conversation.conv_uid}) == 2
    [(conv, count)] = rows(store, "SELECT conv_uid, message_count FROM import_conversations")
    assert (conv, count) == (root.conversation.conv_uid, 3)  # the conversation of the earliest message survives
