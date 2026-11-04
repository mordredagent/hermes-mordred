"""The legacy ``.enc`` Telegram rows map onto canonical records without claiming more than they know."""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any, cast

import pytest

from mordred_hermes.extension.telegram.store import ArchiveIndex, DialogInfo, StoredMessage
from mordred_hermes.imports.legacy_enc import (
    EVIDENCE_NAMED_SENDER,
    EVIDENCE_NO_SENDER,
    EVIDENCE_OUT_FLAG,
    iter_legacy_archive,
    legacy_conversation,
    legacy_message,
)
from mordred_hermes.imports.records import (
    ConversationKind,
    OwnerClass,
    PartKind,
    ProvenanceQuality,
    SenderKind,
    Source,
    content_digest,
    validate_conversation,
    validate_message,
)
from mordred_hermes.imports.render import render_part
from mordred_hermes.imports.store import ImportStore, WriteResult

IMPORTED_AT = 1_790_000_000
DIALOG = -100123


def dialog(kind: str = "group", **overrides: Any) -> DialogInfo:
    fields: dict[str, Any] = {
        "dialog_id": DIALOG,
        "kind": kind,
        "title": "Team",
        "last_message_id": 12,
        "message_count": 3,
        "last_date": 1_789_000_000,
    }
    fields.update(overrides)
    return DialogInfo(**fields)


def index(*dialogs: DialogInfo) -> ArchiveIndex:
    return ArchiveIndex(account_label="Kazuko", account_id=99, dialogs={d.dialog_id: d for d in dialogs})


def stored(msg_id: int, sender: str = "Tanaka", text: str = "hello", **overrides: Any) -> StoredMessage:
    return StoredMessage(id=msg_id, date=1_789_000_000 + msg_id, sender=sender, text=text, **overrides)


def test_an_outgoing_row_is_the_account_owner() -> None:
    msg = legacy_message(dialog(), stored(5, "Kazuko", out=True), imported_at=IMPORTED_AT)

    validate_message(msg)
    assert (msg.source_uid, msg.conv_uid, msg.message_id) == (f"tg:{DIALOG}:5", f"tg:{DIALOG}", "5")
    assert (msg.owner_class, msg.owner_evidence, msg.sender_kind) == (
        OwnerClass.ACCOUNT_OWNER,
        EVIDENCE_OUT_FLAG,
        SenderKind.USER,
    )
    assert EVIDENCE_OUT_FLAG == "out_flag_legacy"
    assert msg.sender_id is None
    assert msg.provenance_quality is ProvenanceQuality.LEGACY
    assert msg.source_revision is None
    (only,) = msg.parts
    assert (only.part_uid, only.part_kind, only.ordinal) == (f"tg:{DIALOG}:5#a", PartKind.AUTHORED, 0)
    assert (only.author_owner_class, only.author_evidence, only.author_id) == (
        OwnerClass.ACCOUNT_OWNER,
        EVIDENCE_OUT_FLAG,
        None,
    )
    assert only.provenance_quality is ProvenanceQuality.LEGACY


@pytest.mark.parametrize(
    ("kind", "sender_kind"),
    [("group", SenderKind.USER), ("user", SenderKind.USER), ("channel", SenderKind.CHANNEL), ("bot", SenderKind.BOT)],
)
def test_a_named_sender_is_other(kind: str, sender_kind: SenderKind) -> None:
    msg = legacy_message(dialog(kind), stored(6, "Tanaka"), imported_at=IMPORTED_AT)

    validate_message(msg)
    assert (msg.owner_class, msg.owner_evidence, msg.sender_kind, msg.sender_name) == (
        OwnerClass.OTHER,
        EVIDENCE_NAMED_SENDER,
        sender_kind,
        "Tanaka",
    )
    assert (msg.parts[0].author_owner_class, msg.parts[0].author_name) == (OwnerClass.OTHER, "Tanaka")


def test_the_owners_display_name_without_the_out_flag_is_not_the_owner() -> None:
    msg = legacy_message(dialog(), stored(7, "Kazuko"), imported_at=IMPORTED_AT)
    assert msg.owner_class is OwnerClass.OTHER


def test_an_empty_sender_is_unknown() -> None:
    msg = legacy_message(dialog(), stored(8, ""), imported_at=IMPORTED_AT)

    validate_message(msg)
    assert (msg.owner_class, msg.owner_evidence, msg.sender_kind) == (
        OwnerClass.UNKNOWN,
        EVIDENCE_NO_SENDER,
        SenderKind.UNKNOWN,
    )
    assert msg.parts[0].author_kind is SenderKind.UNKNOWN


def test_dates_replies_media_and_digest() -> None:
    undated = legacy_message(dialog(), StoredMessage(id=9, date=0, sender="A", text="t"), imported_at=IMPORTED_AT)
    reply = legacy_message(dialog(), stored(10, reply_to=9, media="photo", text="look"), imported_at=IMPORTED_AT)
    no_reply = legacy_message(dialog(), stored(11, reply_to=0), imported_at=IMPORTED_AT)

    assert (undated.sent_at, undated.imported_at) == (None, IMPORTED_AT)
    assert reply.sent_at == 1_789_000_010
    assert (reply.reply_to_uid, reply.media) == (f"tg:{DIALOG}:9", "photo")
    assert reply.content_digest == content_digest("look")
    assert no_reply.reply_to_uid is None


def test_a_legacy_part_renders_with_the_legacy_qualifier() -> None:
    info = dialog()
    msg = legacy_message(info, stored(5, "Tanaka"), imported_at=IMPORTED_AT)

    head = render_part(legacy_conversation(info, index(info)), msg, msg.parts[0]).head

    assert head.startswith(f"[Telegram tg:{DIALOG}:5#a]")
    assert "legacy: forwards not distinguished" in head


@pytest.mark.parametrize(
    ("kind", "expected"),
    [
        ("user", ConversationKind.DIRECT),
        ("bot", ConversationKind.DIRECT),
        ("group", ConversationKind.GROUP),
        ("channel", ConversationKind.CHANNEL),
        ("something-new", ConversationKind.GROUP),
    ],
)
def test_conversation_kind_mapping(kind: str, expected: ConversationKind) -> None:
    info = dialog(kind)
    assert legacy_conversation(info, index(info)).kind is expected


def test_a_conversation_lists_senders_seen_in_the_archive() -> None:
    info = dialog(archived=True)
    messages = [stored(1, "Tanaka"), stored(2, "", text="?"), stored(3, "Kazuko", out=True), stored(4, "Tanaka")]
    messages.append(stored(5, "Suzuki"))

    conv = legacy_conversation(info, index(info), messages=messages)

    validate_conversation(conv)
    assert (conv.conv_uid, conv.source, conv.source_account, conv.conversation_id) == (
        f"tg:{DIALOG}",
        Source.TELEGRAM,
        "99",
        str(DIALOG),
    )
    assert (conv.title, conv.message_count, conv.archived) == ("Team", 3, True)
    assert (conv.last_message_at, conv.sync_cursor) == (1_789_000_000, "12")
    assert [(p.display_name, p.owner_class, p.stable_id) for p in conv.participants] == [
        ("Tanaka", OwnerClass.OTHER, None),
        ("Kazuko", OwnerClass.ACCOUNT_OWNER, None),
        ("Suzuki", OwnerClass.OTHER, None),
    ]


def test_an_empty_dialog_has_no_dates_or_cursor() -> None:
    info = dialog(last_message_id=0, last_date=0, message_count=0)
    conv = legacy_conversation(info, index(info))
    assert (conv.last_message_at, conv.sync_cursor, conv.participants) == (None, None, ())


class _FakeArchive:
    def __init__(self, archive: ArchiveIndex, messages: dict[int, list[StoredMessage]]) -> None:
        self._index = archive
        self._messages = messages

    def load_index(self) -> ArchiveIndex:
        return self._index

    def load_messages(self, dialog_id: int) -> list[StoredMessage]:
        return self._messages[dialog_id]


def test_iterating_an_archive_yields_every_dialog_in_id_order(tmp_path: Path) -> None:
    first, second = dialog("user", dialog_id=42, title="Tanaka"), dialog()
    archive = cast(Any, _FakeArchive(index(first, second), {42: [stored(1)], DIALOG: [stored(1), stored(2, out=True)]}))

    dialogs = list(iter_legacy_archive(archive, imported_at=IMPORTED_AT))

    assert [(conv.conv_uid, [m.source_uid for m in msgs]) for conv, msgs in dialogs] == [
        (f"tg:{DIALOG}", [f"tg:{DIALOG}:1", f"tg:{DIALOG}:2"]),
        ("tg:42", ["tg:42:1"]),
    ]
    assert {m.imported_at for _, msgs in dialogs for m in msgs} == {IMPORTED_AT}

    store = ImportStore(tmp_path / "mordred.db", sqlite3.connect)
    store.initialize(tmp_path)
    for attempt, expected in ((1, WriteResult(3, 0, 0, 0)), (2, WriteResult(0, 3, 0, 0))):
        run = store.run_begin("telegram")
        results = [store.write_thread(run, msgs, conversation=conv) for conv, msgs in dialogs]
        store.run_commit(run, {"attempt": attempt})
        assert (
            WriteResult(
                *(sum(getattr(r, f) for r in results) for f in ("inserted", "duplicates", "revised", "conflicts"))
            )
            == expected
        )


def test_iterating_without_a_timestamp_uses_the_current_time() -> None:
    archive = cast(Any, _FakeArchive(index(dialog()), {DIALOG: [stored(1)]}))
    ((_, (msg,)),) = list(iter_legacy_archive(archive))
    assert msg.imported_at > IMPORTED_AT
