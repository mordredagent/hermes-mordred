"""Map the legacy encrypted Telegram archive (``.enc``) onto canonical import records.

A legacy row knows only a display name, the ``out`` flag, the text and a
media placeholder, so the mapping claims no more than that (SPEC "Record
contract"):

- ``out=True`` is the account owner (evidence ``out_flag_legacy``); a named
  sender is ``other``; an empty sender is ``unknown``. The name never decides
  identity: a contact whose name equals the owner's stays ``other``.
- ``sender_id`` is ``None``: the archive never stored one.
- Exactly one authored part ``#a`` holds the whole text. Forwards and quotes
  were not separated, so every record is quality ``legacy`` and renders with
  "legacy: forwards not distinguished".
- ``date == 0`` (unknown) becomes ``sent_at=None``, never the import time.

Nothing here decrypts: :func:`iter_legacy_archive` reads through an already
unlocked :class:`~mordred_hermes.extension.telegram.store.ArchiveStore`.
"""

from __future__ import annotations

import time
from collections.abc import Iterator, Sequence
from typing import TYPE_CHECKING, Final

from .records import (
    ConversationKind,
    ImportConversation,
    ImportMessage,
    ImportPart,
    OwnerClass,
    Participant,
    PartKind,
    ProvenanceQuality,
    SenderKind,
    Source,
    content_digest,
    part_uid,
    telegram_conv_uid,
    telegram_source_uid,
)

if TYPE_CHECKING:
    from ..extension.telegram.store import ArchiveIndex, ArchiveStore, DialogInfo, StoredMessage

__all__ = [
    "EVIDENCE_NAMED_SENDER",
    "EVIDENCE_NO_SENDER",
    "EVIDENCE_OUT_FLAG",
    "iter_legacy_archive",
    "legacy_conversation",
    "legacy_message",
]

EVIDENCE_OUT_FLAG: Final = "out_flag_legacy"
EVIDENCE_NAMED_SENDER: Final = "named_sender_legacy"
EVIDENCE_NO_SENDER: Final = "no_sender_legacy"

#: Legacy ``DialogInfo.kind``; anything else is treated as a group (never claims a 1:1 chat).
_CONVERSATION_KINDS: Final = {
    "user": ConversationKind.DIRECT,
    "bot": ConversationKind.DIRECT,
    "group": ConversationKind.GROUP,
    "channel": ConversationKind.CHANNEL,
}
#: What a named, non-owner sender is, by the kind of dialog it was seen in.
_SENDER_KINDS: Final = {"bot": SenderKind.BOT, "channel": SenderKind.CHANNEL}


def _speaker(info: DialogInfo, m: StoredMessage) -> tuple[SenderKind, OwnerClass, str]:
    if m.out:
        return SenderKind.USER, OwnerClass.ACCOUNT_OWNER, EVIDENCE_OUT_FLAG
    if m.sender:
        return _SENDER_KINDS.get(info.kind, SenderKind.USER), OwnerClass.OTHER, EVIDENCE_NAMED_SENDER
    return SenderKind.UNKNOWN, OwnerClass.UNKNOWN, EVIDENCE_NO_SENDER


def _participants(info: DialogInfo, index: ArchiveIndex, messages: Sequence[StoredMessage]) -> tuple[Participant, ...]:
    """Senders seen in the archive, in first-seen order (names only; never a complete roster)."""
    seen: dict[tuple[OwnerClass, str], Participant] = {}
    for m in messages:
        kind, owner_class, _ = _speaker(info, m)
        if owner_class is OwnerClass.UNKNOWN:
            continue
        name = index.account_label if m.out else m.sender
        seen.setdefault(
            (owner_class, "" if m.out else name),
            Participant(kind=kind, stable_id=None, display_name=name, owner_class=owner_class),
        )
    return tuple(seen.values())


def legacy_conversation(
    info: DialogInfo, index: ArchiveIndex, *, messages: Sequence[StoredMessage] = ()
) -> ImportConversation:
    """One legacy dialog; ``messages`` (optional) supplies the senders seen in the archive."""
    return ImportConversation(
        conv_uid=telegram_conv_uid(info.dialog_id),
        source=Source.TELEGRAM,
        source_account=str(index.account_id),
        conversation_id=str(info.dialog_id),
        kind=_CONVERSATION_KINDS.get(info.kind, ConversationKind.GROUP),
        title=info.title,
        participants=_participants(info, index, messages),
        last_message_at=info.last_date if info.last_date > 0 else None,
        message_count=info.message_count,
        archived=info.archived,
        sync_cursor=str(info.last_message_id) if info.last_message_id > 0 else None,
    )


def legacy_message(info: DialogInfo, m: StoredMessage, *, imported_at: int) -> ImportMessage:
    """One legacy row as a message with a single authored ``#a`` part of quality ``legacy``."""
    source_uid = telegram_source_uid(info.dialog_id, m.id)
    sender_kind, owner_class, evidence = _speaker(info, m)
    reply_to = m.reply_to if m.reply_to is not None and m.reply_to > 0 else None
    authored = ImportPart(
        part_uid=part_uid(source_uid, PartKind.AUTHORED),
        source_uid=source_uid,
        ordinal=0,
        part_kind=PartKind.AUTHORED,
        author_kind=sender_kind,
        author_id=None,
        author_name=m.sender,
        author_owner_class=owner_class,
        author_evidence=evidence,
        original_sent_at=None,
        original_ref=None,
        text=m.text,
        provenance_quality=ProvenanceQuality.LEGACY,
    )
    return ImportMessage(
        source_uid=source_uid,
        conv_uid=telegram_conv_uid(info.dialog_id),
        message_id=str(m.id),
        sent_at=m.date if m.date > 0 else None,
        imported_at=imported_at,
        sender_kind=sender_kind,
        sender_id=None,
        sender_name=m.sender,
        owner_class=owner_class,
        owner_evidence=evidence,
        reply_to_uid=None if reply_to is None else telegram_source_uid(info.dialog_id, reply_to),
        media=m.media,
        provenance_quality=ProvenanceQuality.LEGACY,
        source_revision=None,
        content_digest=content_digest(m.text),
        parts=(authored,),
    )


def iter_legacy_archive(
    store: ArchiveStore, *, imported_at: int | None = None
) -> Iterator[tuple[ImportConversation, list[ImportMessage]]]:
    """Every dialog of an unlocked archive as ``(conversation, messages)``, in dialog-id order.

    A segment that cannot be decrypted raises the store's ``StoreError`` from
    the iteration; callers that count per-dialog failures iterate
    ``store.load_index().dialogs`` with :func:`legacy_conversation` /
    :func:`legacy_message` themselves.
    """
    stamp = int(time.time()) if imported_at is None else imported_at
    index = store.load_index()
    for dialog_id in sorted(index.dialogs):
        info = index.dialogs[dialog_id]
        stored = store.load_messages(dialog_id)
        conversation = legacy_conversation(info, index, messages=stored)
        yield conversation, [legacy_message(info, m, imported_at=stamp) for m in stored]
