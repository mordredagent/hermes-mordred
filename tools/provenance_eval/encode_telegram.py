"""Telegram encoding: canonical records shaped like the Telegram converter's output.

Mirrors ``extension/telegram/client.py``: an authored part ``#a``; a reply
that quotes adds ``#q1`` whose author is the replied-to message's sender when
that message is in the archive (``reply_quote_resolved``), else unknown
(``reply_quote_unresolved``); a forward is a message of its own whose only
part is ``#f1`` (``api_fwd_from_id`` / ``fwd_hidden``) and whose sender is the
forwarder; a channel post's sender is unknown (``api_channel_post``).
Telegram has no nested quotes: a reply quotes only its parent's own text.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass
from typing import Final

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
    part_uid,
    telegram_conv_uid,
    telegram_source_uid,
    validate_conversation,
    validate_message,
)
from mordred_hermes.imports.render import format_date

from ._json import (
    FormatError,
    read_bool,
    read_enum,
    read_int,
    read_list,
    read_obj,
    read_opt_int,
    read_opt_str,
    read_str,
)
from .scenarios import JST_MINUTES, MessageSpec, QuoteStyle, ThreadSpec
from .tokens import find_tokens, visible_tokens
from .truth import PartTruth, Person, Role

__all__ = ["IMPORTED_AT", "EncodedThread", "dialog_id", "encode_telegram", "threads_from_json", "threads_to_json"]

IMPORTED_AT: Final = 1_800_000_000
_DIALOG_BASE: Final = 1_000_000_000_000 + 7_000_000


@dataclass(frozen=True)
class EncodedThread:
    """One conversation and its imported messages (Telegram records or the mail collector's)."""

    thread_id: str
    conversation: ImportConversation
    messages: tuple[ImportMessage, ...]


@dataclass(frozen=True)
class _Author:
    kind: SenderKind
    ident: str | None
    name: str
    owner: OwnerClass
    evidence: str
    quality: ProvenanceQuality
    person: str  # true author

    @property
    def knowable(self) -> bool:
        """Known owner class, or a named channel / bot (rendered ``<name> (channel)``)."""
        named = self.kind in (SenderKind.CHANNEL, SenderKind.BOT) and bool(self.name) and self.ident is not None
        return self.owner is not OwnerClass.UNKNOWN or named


def dialog_id(index: int) -> int:
    """A marked supergroup / channel id (``-100…``) unique per thread."""
    return -(_DIALOG_BASE + index)


def _person_author(person: Person, identity: int, owner_tg: int, *, forward: bool) -> _Author:
    name = person.identities[identity].name
    if person.role is Role.OWNER:
        code = "api_fwd_from_id_eq_self" if forward else "api_from_id_eq_self"
        return _Author(
            SenderKind.USER,
            str(owner_tg),
            name,
            OwnerClass.ACCOUNT_OWNER,
            code,
            ProvenanceQuality.API_IDENTITY,
            person.person_id,
        )
    kind = SenderKind.BOT if person.role is Role.BOT else SenderKind.USER
    code = "api_fwd_from_id" if forward else "api_identity"
    return _Author(
        kind, str(person.telegram_id), name, OwnerClass.OTHER, code, ProvenanceQuality.API_IDENTITY, person.person_id
    )


def _sender(spec: ThreadSpec, msg: MessageSpec, owner_tg: int) -> _Author:
    if spec.channel and msg.sender.role is Role.CHANNEL:
        name = msg.sender.identities[msg.identity].name
        return _Author(
            SenderKind.CHANNEL,
            str(dialog_id(spec.index)),
            name,
            OwnerClass.UNKNOWN,
            "api_channel_post",
            ProvenanceQuality.API_IDENTITY,
            msg.sender.person_id,
        )
    return _person_author(msg.sender, msg.identity, owner_tg, forward=False)


def _unknown(person: str, evidence: str) -> _Author:
    return _Author(SenderKind.UNKNOWN, None, "", OwnerClass.UNKNOWN, evidence, ProvenanceQuality.UNKNOWN, person)


def _forged_lines(spec: ThreadSpec, msg: MessageSpec) -> list[str]:
    if msg.forged is None:
        return []
    when = format_date(msg.sent_at, tz_offset_minutes=JST_MINUTES)
    fake = telegram_source_uid(dialog_id(spec.index), 1)
    head = f"[Telegram {fake}#a] speaker: account owner → chat: {spec.title} / {when}"
    return [head, f"  {msg.forged.text}"]


def authored_text(spec: ThreadSpec, msg: MessageSpec) -> str:
    return "\n".join([*msg.body_lines(), *_forged_lines(spec, msg)])


@dataclass
class _Encoder:
    spec: ThreadSpec
    owner_tg: int
    cap: int
    ids: dict[str, int]
    messages: list[ImportMessage]
    truth: list[PartTruth]

    @property
    def dialog(self) -> int:
        return dialog_id(self.spec.index)

    def uid(self, key: str) -> str:
        return telegram_source_uid(self.dialog, self.ids[key])

    def part(
        self,
        msg: MessageSpec,
        key: str,
        kind: PartKind,
        ordinal: int,
        author: _Author,
        text: str,
        **extra: int | str | None,
    ) -> ImportPart:
        source_uid = self.uid(key)
        original_at = extra.get("original_sent_at")
        original_ref = extra.get("original_ref")
        record = ImportPart(
            part_uid=part_uid(source_uid, kind),
            source_uid=source_uid,
            ordinal=ordinal,
            part_kind=kind,
            author_kind=author.kind,
            author_id=author.ident,
            author_name=author.name,
            author_owner_class=author.owner,
            author_evidence=author.evidence,
            original_sent_at=original_at if isinstance(original_at, int) else None,
            original_ref=original_ref if isinstance(original_ref, str) else None,
            text=text,
            provenance_quality=author.quality,
        )
        self.truth.append(
            PartTruth(
                source="telegram",
                evidence_id=record.part_uid,
                thread_id=self.spec.thread_id,
                message_key=key,
                kind=str(kind),
                author=author.person,
                author_knowable=author.knowable,
                author_handle=author.ident if author.knowable else None,
                owner_class=str(author.owner),
                author_name=author.name if author.knowable else "",
                container_sender=msg.sender.person_id,
                imported=msg.imported,
                sent_at=msg.sent_at,
                original_sent_at=record.original_sent_at,
                text=text,
                tokens=find_tokens(text),
                visible_tokens=visible_tokens(text, self.cap),
            )
        )
        return record

    def quote(self, msg: MessageSpec) -> ImportPart | None:
        if msg.reply_to is None or msg.quote is QuoteStyle.NONE:
            return None
        parent = self.spec.message(msg.reply_to)
        if parent.imported:
            resolved = _sender(self.spec, parent, self.owner_tg)
            author = _Author(
                resolved.kind,
                resolved.ident,
                resolved.name,
                resolved.owner,
                "reply_quote_resolved",
                resolved.quality,
                resolved.person,
            )
        else:
            author = _unknown(parent.sender.person_id, "reply_quote_unresolved")
        text = "\n".join(parent.body_lines())
        return self.part(msg, msg.key, PartKind.QUOTED, 1, author, text, original_ref=self.uid(parent.key))

    def record(self, msg: MessageSpec, key: str, parts: tuple[ImportPart, ...], sent_at: int | None) -> None:
        sender = _sender(self.spec, msg, self.owner_tg)
        reply_uid = self.uid(msg.reply_to) if msg.reply_to is not None and key == msg.key else None
        record = ImportMessage(
            source_uid=self.uid(key),
            conv_uid=telegram_conv_uid(self.dialog),
            message_id=str(self.ids[key]),
            sent_at=sent_at,
            imported_at=IMPORTED_AT,
            sender_kind=sender.kind,
            sender_id=sender.ident,
            sender_name=sender.name,
            owner_class=sender.owner,
            owner_evidence=sender.evidence,
            reply_to_uid=reply_uid,
            media=None,
            provenance_quality=sender.quality,
            source_revision=None,
            content_digest=content_digest(json.dumps([[str(p.part_kind), p.text] for p in parts], ensure_ascii=False)),
            parts=parts,
        )
        validate_message(record)
        if msg.imported:
            self.messages.append(record)

    def encode(self, msg: MessageSpec) -> None:
        sender = _sender(self.spec, msg, self.owner_tg)
        authored = self.part(msg, msg.key, PartKind.AUTHORED, 0, sender, authored_text(self.spec, msg))
        quote = self.quote(msg)
        self.record(msg, msg.key, (authored,) if quote is None else (authored, quote), msg.sent_at)
        if msg.forward is None:
            return
        forward = msg.forward
        key = f"{msg.key}.fwd"
        if forward.hidden:
            author = _unknown(forward.author.person_id, "fwd_hidden")
        else:
            author = _person_author(forward.author, forward.identity, self.owner_tg, forward=True)
        text = "\n".join(sentence.text for sentence in forward.sentences)
        part = self.part(msg, key, PartKind.FORWARDED, 0, author, text, original_sent_at=forward.original_at)
        self.record(msg, key, (part,), None if msg.sent_at is None else msg.sent_at + 1)


def _message_ids(spec: ThreadSpec) -> dict[str, int]:
    ids: dict[str, int] = {}
    for msg in spec.messages:
        ids[msg.key] = len(ids) + 1
        if msg.forward is not None:
            ids[f"{msg.key}.fwd"] = len(ids) + 1
    return ids


def _participants(messages: Sequence[ImportMessage]) -> tuple[Participant, ...]:
    seen: dict[tuple[str, str], Participant] = {}
    for msg in messages:
        key = (str(msg.owner_class), msg.sender_id or f"name:{msg.sender_name}")
        seen.setdefault(
            key,
            Participant(
                kind=msg.sender_kind, stable_id=msg.sender_id, display_name=msg.sender_name, owner_class=msg.owner_class
            ),
        )
    return tuple(seen.values())


def encode_telegram(spec: ThreadSpec, *, owner_tg: int, cap: int) -> tuple[EncodedThread, list[PartTruth]]:
    """Records for the imported messages of ``spec`` and the truth of every part (imported or not)."""
    encoder = _Encoder(spec=spec, owner_tg=owner_tg, cap=cap, ids=_message_ids(spec), messages=[], truth=[])
    for msg in spec.messages:
        encoder.encode(msg)
    dates = [msg.sent_at for msg in encoder.messages if msg.sent_at is not None]
    conversation = ImportConversation(
        conv_uid=telegram_conv_uid(encoder.dialog),
        source=Source.TELEGRAM,
        source_account=str(owner_tg),
        conversation_id=str(encoder.dialog),
        kind=ConversationKind.CHANNEL if spec.channel else ConversationKind.GROUP,
        title=spec.title,
        participants=_participants(encoder.messages),
        last_message_at=max(dates) if dates else None,
        message_count=len(encoder.messages),
        archived=False,
        sync_cursor=None,
    )
    validate_conversation(conversation)
    return EncodedThread(spec.thread_id, conversation, tuple(encoder.messages)), encoder.truth


# ---------------------------------------------------------------------------
# telegram.json


def threads_to_json(threads: Sequence[EncodedThread]) -> str:
    data = [
        {
            "thread_id": thread.thread_id,
            "conversation": asdict(thread.conversation),
            "messages": [asdict(msg) for msg in thread.messages],
        }
        for thread in threads
    ]
    return json.dumps({"format": "provenance_eval.telegram/1", "threads": data}, ensure_ascii=False, indent=1) + "\n"


def _participant(data: Mapping[str, object]) -> Participant:
    return Participant(
        kind=read_enum(data, "kind", SenderKind),
        stable_id=read_opt_str(data, "stable_id"),
        display_name=read_str(data, "display_name"),
        owner_class=read_enum(data, "owner_class", OwnerClass),
    )


def _conversation(data: Mapping[str, object]) -> ImportConversation:
    conv = ImportConversation(
        conv_uid=read_str(data, "conv_uid"),
        source=read_enum(data, "source", Source),
        source_account=read_str(data, "source_account"),
        conversation_id=read_str(data, "conversation_id"),
        kind=read_enum(data, "kind", ConversationKind),
        title=read_str(data, "title"),
        participants=tuple(_participant(read_obj(item)) for item in read_list(data, "participants")),
        last_message_at=read_opt_int(data, "last_message_at"),
        message_count=read_int(data, "message_count"),
        archived=read_bool(data, "archived"),
        sync_cursor=read_opt_str(data, "sync_cursor"),
        record_version=read_int(data, "record_version"),
    )
    validate_conversation(conv)
    return conv


def _part(data: Mapping[str, object]) -> ImportPart:
    return ImportPart(
        part_uid=read_str(data, "part_uid"),
        source_uid=read_str(data, "source_uid"),
        ordinal=read_int(data, "ordinal"),
        part_kind=read_enum(data, "part_kind", PartKind),
        author_kind=read_enum(data, "author_kind", SenderKind),
        author_id=read_opt_str(data, "author_id"),
        author_name=read_str(data, "author_name"),
        author_owner_class=read_enum(data, "author_owner_class", OwnerClass),
        author_evidence=read_str(data, "author_evidence"),
        original_sent_at=read_opt_int(data, "original_sent_at"),
        original_ref=read_opt_str(data, "original_ref"),
        text=read_str(data, "text"),
        provenance_quality=read_enum(data, "provenance_quality", ProvenanceQuality),
    )


def _message(data: Mapping[str, object]) -> ImportMessage:
    msg = ImportMessage(
        source_uid=read_str(data, "source_uid"),
        conv_uid=read_str(data, "conv_uid"),
        message_id=read_str(data, "message_id"),
        sent_at=read_opt_int(data, "sent_at"),
        imported_at=read_int(data, "imported_at"),
        sender_kind=read_enum(data, "sender_kind", SenderKind),
        sender_id=read_opt_str(data, "sender_id"),
        sender_name=read_str(data, "sender_name"),
        owner_class=read_enum(data, "owner_class", OwnerClass),
        owner_evidence=read_str(data, "owner_evidence"),
        reply_to_uid=read_opt_str(data, "reply_to_uid"),
        media=read_opt_str(data, "media"),
        provenance_quality=read_enum(data, "provenance_quality", ProvenanceQuality),
        source_revision=read_opt_str(data, "source_revision"),
        record_version=read_int(data, "record_version"),
        content_digest=read_str(data, "content_digest"),
        parts=tuple(_part(read_obj(item)) for item in read_list(data, "parts")),
        recipients=tuple(_participant(read_obj(item)) for item in read_list(data, "recipients")),
    )
    validate_message(msg)
    return msg


def threads_from_json(text: str) -> tuple[EncodedThread, ...]:
    """Parse ``telegram.json``; every record is validated (``RecordError`` / :class:`FormatError`)."""
    try:
        root = read_obj(json.loads(text))
    except json.JSONDecodeError as exc:
        raise FormatError("not_json") from exc
    if root.get("format") != "provenance_eval.telegram/1":
        raise FormatError("unsupported_format")
    threads: list[EncodedThread] = []
    for item in read_list(root, "threads"):
        data = read_obj(item)
        threads.append(
            EncodedThread(
                read_str(data, "thread_id"),
                _conversation(read_obj(data.get("conversation"))),
                tuple(_message(read_obj(raw)) for raw in read_list(data, "messages")),
            )
        )
    return tuple(threads)
