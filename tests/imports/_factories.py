"""Builders for canonical import records used by ``tests/imports``.

All names, addresses and texts are synthetic (RFC 2606 domains only).
"""

from __future__ import annotations

import datetime as dt

from mordred_hermes.imports.records import (
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
    mail_conv_uid,
    mail_source_uid,
    part_uid,
    telegram_conv_uid,
    telegram_source_uid,
)

JST = 540
DIALOG = -100123
TG_CONV_UID = telegram_conv_uid(DIALOG)
MAIL_ACCOUNT = "work"
MAIL_CONV_UID = mail_conv_uid(MAIL_ACCOUNT, "thread-1")
OWNER_ID = "99"


def ts(year: int, month: int, day: int, hour: int = 0, minute: int = 0, *, offset_minutes: int = JST) -> int:
    zone = dt.timezone(dt.timedelta(minutes=offset_minutes))
    return int(dt.datetime(year, month, day, hour, minute, tzinfo=zone).timestamp())


SENT_AT = ts(2026, 10, 15, 14, 2)
ORIGINAL_AT = ts(2026, 10, 1, 9, 0)
IMPORTED_AT = ts(2026, 10, 20, 8, 0)


def participant(
    name: str,
    stable_id: str | None,
    owner_class: OwnerClass = OwnerClass.OTHER,
    kind: SenderKind = SenderKind.USER,
) -> Participant:
    return Participant(kind=kind, stable_id=stable_id, display_name=name, owner_class=owner_class)


OWNER = participant("Kazuko", OWNER_ID, OwnerClass.ACCOUNT_OWNER)
TANAKA = participant("田中 太郎", "11")
SUZUKI = participant("鈴木 花子", "12")


def tg_conv(
    *,
    kind: ConversationKind = ConversationKind.GROUP,
    title: str = "Team",
    participants: tuple[Participant, ...] = (TANAKA, SUZUKI, OWNER),
) -> ImportConversation:
    return ImportConversation(
        conv_uid=TG_CONV_UID,
        source=Source.TELEGRAM,
        source_account=OWNER_ID,
        conversation_id=str(DIALOG),
        kind=kind,
        title=title,
        participants=participants,
        last_message_at=SENT_AT,
        message_count=10,
        archived=False,
        sync_cursor=None,
    )


def mail_conv(
    *, title: str = "見積もりの件", participants: tuple[Participant, ...] = (TANAKA, OWNER)
) -> ImportConversation:
    return ImportConversation(
        conv_uid=MAIL_CONV_UID,
        source=Source.MAIL,
        source_account=MAIL_ACCOUNT,
        conversation_id="thread-1",
        kind=ConversationKind.THREAD,
        title=title,
        participants=participants,
        last_message_at=SENT_AT,
        message_count=2,
        archived=False,
        sync_cursor=None,
    )


def part(
    source_uid: str,
    kind: PartKind = PartKind.AUTHORED,
    n: int = 1,
    *,
    ordinal: int = 0,
    author: Participant | None = TANAKA,
    text: str = "hello",
    original_sent_at: int | None = None,
    quality: ProvenanceQuality = ProvenanceQuality.API_IDENTITY,
) -> ImportPart:
    if author is None:
        author = participant("", None, OwnerClass.UNKNOWN, SenderKind.UNKNOWN)
    return ImportPart(
        part_uid=part_uid(source_uid, kind, n),
        source_uid=source_uid,
        ordinal=ordinal,
        part_kind=kind,
        author_kind=author.kind,
        author_id=author.stable_id,
        author_name=author.display_name,
        author_owner_class=author.owner_class,
        author_evidence="test",
        original_sent_at=original_sent_at,
        original_ref=None,
        text=text,
        provenance_quality=quality,
    )


def message(
    source_uid: str,
    parts: tuple[ImportPart, ...],
    *,
    conv_uid: str = TG_CONV_UID,
    sender: Participant = OWNER,
    sent_at: int | None = SENT_AT,
    media: str | None = None,
    recipients: tuple[Participant, ...] = (),
    quality: ProvenanceQuality = ProvenanceQuality.API_IDENTITY,
) -> ImportMessage:
    return ImportMessage(
        source_uid=source_uid,
        conv_uid=conv_uid,
        message_id=source_uid.rsplit(":", 1)[-1],
        sent_at=sent_at,
        imported_at=IMPORTED_AT,
        sender_kind=sender.kind,
        sender_id=sender.stable_id,
        sender_name=sender.display_name,
        owner_class=sender.owner_class,
        owner_evidence="test",
        reply_to_uid=None,
        media=media,
        provenance_quality=quality,
        source_revision=None,
        content_digest=content_digest("".join(p.text for p in parts)),
        parts=parts,
        recipients=recipients,
    )


def tg_uid(msg_id: int) -> str:
    return telegram_source_uid(DIALOG, msg_id)


def mail_uid(message_id: str) -> str:
    return mail_source_uid(MAIL_ACCOUNT, message_id)


def authored(
    msg_id: int,
    author: Participant | None = TANAKA,
    text: str = "hello",
    *,
    quality: ProvenanceQuality = ProvenanceQuality.API_IDENTITY,
    media: str | None = None,
    sent_at: int | None = SENT_AT,
) -> ImportMessage:
    """A Telegram message whose only part is the sender's own text."""
    uid = tg_uid(msg_id)
    sender = author if author is not None else participant("", None, OwnerClass.UNKNOWN, SenderKind.UNKNOWN)
    only = part(uid, author=author, text=text, quality=quality)
    return message(uid, (only,), sender=sender, media=media, sent_at=sent_at, quality=quality)
