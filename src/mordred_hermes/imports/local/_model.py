"""The reader-neutral transcript shape and its mapping to canonical import records."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Final, Literal

from ..records import (
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
    local_conv_uid,
    local_source_uid,
    part_uid,
)

LOCAL_SOURCES: Final = (Source.CODEX, Source.CLAUDE_CODE, Source.GROK_BOT)

#: The agent's display name per source (the user is always ``you``).
AGENT_NAME: Final = {Source.CODEX: "codex", Source.CLAUDE_CODE: "claude", Source.GROK_BOT: "grok"}

_MAX_TITLE: Final = 80
_KEY_UNSAFE: Final = re.compile(r"[^A-Za-z0-9._-]+")
# ESC is refused by record validation; terminal transcripts carry ANSI colour codes.
_ESCAPES: Final = re.compile(r"\x1b(?:\[[0-?]*[ -/]*[@-~]|[@-Z\\-_])?")
_EVIDENCE: Final = "local_transcript_role"


@dataclass(frozen=True)
class Entry:
    """One turn: ``owner`` is the person using the app, ``agent`` the agent replying."""

    key: str
    role: Literal["owner", "agent"]
    sent_at: int | None
    text: str
    author: str = ""


@dataclass(frozen=True)
class Transcript:
    key: str
    title: str
    entries: tuple[Entry, ...]
    agent_name: str = ""


def safe_key(value: object, fallback: str) -> str:
    """A UID key from an id or file name: ``[A-Za-z0-9._-]``, starting alphanumeric, at most 128 characters."""
    cleaned = _KEY_UNSAFE.sub("-", str(value or "")).strip("-._")
    return (cleaned or fallback)[:128]


def clean_text(text: str) -> str:
    return _ESCAPES.sub("", text).replace("\x1b", "").strip()


def iso_seconds(value: object) -> int | None:
    """Unix seconds from an ISO-8601 timestamp (``Z`` accepted), else ``None``."""
    if not isinstance(value, str) or not value:
        return None
    try:
        moment = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=UTC)
    seconds = int(moment.timestamp())
    return seconds if seconds >= 0 else None


def ms_seconds(value: object) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int | float) or value < 0:
        return None
    return int(value // 1000)


def title_of(entries: tuple[Entry, ...]) -> str:
    first = next((entry.text for entry in entries if entry.role == "owner"), "")
    return first.splitlines()[0][:_MAX_TITLE] if first else ""


def to_records(
    source: Source, transcript: Transcript, *, imported_at: int
) -> tuple[ImportConversation, list[ImportMessage]]:
    """The conversation row and one single-part message per entry."""
    conv_uid = local_conv_uid(source, transcript.key)
    agent = transcript.agent_name or AGENT_NAME[source]
    owner = Participant(kind=SenderKind.USER, stable_id=None, display_name="you", owner_class=OwnerClass.ACCOUNT_OWNER)
    bot = Participant(kind=SenderKind.BOT, stable_id=None, display_name=agent, owner_class=OwnerClass.OTHER)
    messages: list[ImportMessage] = []
    for entry in transcript.entries:
        speaker = owner if entry.role == "owner" else bot
        name = entry.author or speaker.display_name
        source_uid = local_source_uid(source, transcript.key, entry.key)
        part = ImportPart(
            part_uid=part_uid(source_uid, PartKind.AUTHORED),
            source_uid=source_uid,
            ordinal=0,
            part_kind=PartKind.AUTHORED,
            author_kind=speaker.kind,
            author_id=None,
            author_name=name,
            author_owner_class=speaker.owner_class,
            author_evidence=_EVIDENCE,
            original_sent_at=None,
            original_ref=None,
            text=entry.text,
            provenance_quality=ProvenanceQuality.SOURCE_CLAIMED,
        )
        messages.append(
            ImportMessage(
                source_uid=source_uid,
                conv_uid=conv_uid,
                message_id=entry.key,
                sent_at=entry.sent_at,
                imported_at=imported_at,
                sender_kind=speaker.kind,
                sender_id=None,
                sender_name=name,
                owner_class=speaker.owner_class,
                owner_evidence=_EVIDENCE,
                reply_to_uid=None,
                media=None,
                provenance_quality=ProvenanceQuality.SOURCE_CLAIMED,
                source_revision=None,
                content_digest=content_digest(entry.text),
                parts=(part,),
            )
        )
    dates = [entry.sent_at for entry in transcript.entries if entry.sent_at is not None]
    conversation = ImportConversation(
        conv_uid=conv_uid,
        source=source,
        source_account="local",
        conversation_id=transcript.key,
        kind=ConversationKind.DIRECT,
        title=transcript.title or title_of(transcript.entries),
        participants=(owner, bot),
        last_message_at=max(dates) if dates else None,
        message_count=len(messages),
        archived=False,
        sync_cursor=None,
    )
    return conversation, messages
