"""Canonical records for imported messages (Telegram, mail).

Security contract:

- The speaker of every piece of imported text is decided at import time, from
  source identity, and stored per *part*: a message's own words (``#a``) and
  every quoted (``#q<n>``) or forwarded (``#f<n>``) span are separate parts
  with their own author. The transport sender never becomes the author of a
  quote or forward it carries.
- Owner classification is explicit (``account_owner`` / ``other`` /
  ``unknown``) and carries an evidence code. A display name never decides
  identity; unknown stays unknown.
- ``sent_at`` is the source's sent time or ``None``. Import time is recorded
  separately in ``imported_at`` and is never substituted for an unknown date.
- Source and part UIDs follow a fixed, namespaced grammar so an evidence id
  cited by a model can be matched exactly. Imported text cannot create a UID:
  UIDs come from the collector via the helpers below.
- :func:`validate_message` raises :class:`RecordError` whose ``code`` is a
  stable, content-free string. Error messages never contain imported text.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from enum import Enum, StrEnum
from typing import Final, TypeVar
from urllib.parse import quote


class RecordError(ValueError):
    """Invalid import record. ``code`` is stable and never contains content."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class Source(StrEnum):
    TELEGRAM = "telegram"
    MAIL = "mail"


class ConversationKind(StrEnum):
    DIRECT = "direct"
    GROUP = "group"
    CHANNEL = "channel"
    THREAD = "thread"  # a mail thread


class SenderKind(StrEnum):
    USER = "user"
    BOT = "bot"
    CHANNEL = "channel"
    UNKNOWN = "unknown"


class OwnerClass(StrEnum):
    ACCOUNT_OWNER = "account_owner"
    OTHER = "other"
    UNKNOWN = "unknown"


class PartKind(StrEnum):
    AUTHORED = "authored"
    QUOTED = "quoted"
    FORWARDED = "forwarded"


class ProvenanceQuality(StrEnum):
    API_IDENTITY = "api_identity"
    SOURCE_CLAIMED = "source_claimed"
    HEURISTIC = "heuristic"
    LEGACY = "legacy"
    UNKNOWN = "unknown"


RECORD_VERSION: Final = 1

# Largest unix timestamp datetime can represent (9999-12-31T23:59:59Z).
_MAX_TIMESTAMP: Final = 253_402_300_799
_MAX_INT_DIGITS: Final = 19
_MAX_MESSAGE_ID_CHARS: Final = 512

_ACCOUNT_PATTERN: Final = r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}"
_MESSAGE_ID_PATTERN: Final = r"(?:[A-Za-z0-9_.~@+=$!/-]|%[0-9A-F]{2})+"
_TG_DIALOG_PATTERN: Final = r"-?[1-9]\d{0,18}"
_TG_MESSAGE_PATTERN: Final = r"[1-9]\d{0,18}"

_ACCOUNT_RE: Final = re.compile(_ACCOUNT_PATTERN)
_THREAD_KEY_RE: Final = re.compile(r"[A-Za-z0-9._~@+=$!/-]{1,128}")
_HEX_RE: Final = re.compile(r"[0-9a-fA-F]{32,}")
_DIGEST_RE: Final = re.compile(r"[0-9a-f]{64}")

_TG_CONV_RE: Final = re.compile(rf"tg:(?P<dialog>{_TG_DIALOG_PATTERN})")
_TG_SOURCE_RE: Final = re.compile(rf"tg:(?P<dialog>{_TG_DIALOG_PATTERN}):{_TG_MESSAGE_PATTERN}")
_MAIL_CONV_RE: Final = re.compile(rf"mail:(?P<account>{_ACCOUNT_PATTERN}):t:[A-Za-z0-9._~@+=$!/-]{{1,128}}")
_MAIL_SOURCE_RE: Final = re.compile(rf"mail:(?P<account>{_ACCOUNT_PATTERN}):(?:h:[0-9a-f]{{32}}|{_MESSAGE_ID_PATTERN})")
_PART_SUFFIX_RE: Final = re.compile(r"#(?:a|q[1-9]\d{0,3}|f[1-9]\d{0,3})")

_PART_PREFIX: Final = {PartKind.AUTHORED: "a", PartKind.QUOTED: "q", PartKind.FORWARDED: "f"}

_E = TypeVar("_E", bound=Enum)


@dataclass(frozen=True, kw_only=True)
class Participant:
    """A participant observed in a conversation (never a complete roster)."""

    kind: SenderKind
    stable_id: str | None
    display_name: str
    owner_class: OwnerClass


@dataclass(frozen=True, kw_only=True)
class ImportConversation:
    conv_uid: str
    source: Source
    source_account: str
    conversation_id: str
    kind: ConversationKind
    title: str
    participants: tuple[Participant, ...]
    last_message_at: int | None
    message_count: int
    archived: bool
    sync_cursor: str | None
    record_version: int = RECORD_VERSION


@dataclass(frozen=True, kw_only=True)
class ImportPart:
    """One separately attributed span: the message's own words, a quote, or a forward."""

    part_uid: str
    source_uid: str
    ordinal: int
    part_kind: PartKind
    author_kind: SenderKind
    author_id: str | None
    author_name: str
    author_owner_class: OwnerClass
    author_evidence: str
    original_sent_at: int | None
    original_ref: str | None
    text: str
    provenance_quality: ProvenanceQuality


@dataclass(frozen=True, kw_only=True)
class ImportMessage:
    """One source message (the transport event) and its attributed parts."""

    source_uid: str
    conv_uid: str
    message_id: str
    sent_at: int | None  # unix seconds from the source; None = unknown, never import time
    imported_at: int
    sender_kind: SenderKind
    sender_id: str | None
    sender_name: str
    owner_class: OwnerClass
    owner_evidence: str
    reply_to_uid: str | None
    media: str | None
    provenance_quality: ProvenanceQuality
    source_revision: str | None
    record_version: int = RECORD_VERSION
    content_digest: str
    parts: tuple[ImportPart, ...]
    # Mail only: the message's own To/Cc recipients as observed in its headers.
    recipients: tuple[Participant, ...] = ()


# ---------------------------------------------------------------------------
# UID helpers


def _checked_int(value: object, code: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise RecordError(code)
    if len(str(abs(value))) > _MAX_INT_DIGITS:
        raise RecordError(code)
    return value


def _checked_account(account: object) -> str:
    if not isinstance(account, str) or not _ACCOUNT_RE.fullmatch(account):
        raise RecordError("bad_account")
    return account


def telegram_conv_uid(dialog_id: int) -> str:
    """``tg:<dialog_id>`` (dialog ids may be negative for groups/channels)."""
    dialog = _checked_int(dialog_id, "bad_conv_uid")
    if dialog == 0:
        raise RecordError("bad_conv_uid")
    return f"tg:{dialog}"


def telegram_source_uid(dialog_id: int, msg_id: int) -> str:
    """``tg:<dialog_id>:<msg_id>``."""
    dialog = _checked_int(dialog_id, "bad_source_uid")
    message = _checked_int(msg_id, "bad_source_uid")
    if dialog == 0 or message <= 0:
        raise RecordError("bad_source_uid")
    return f"tg:{dialog}:{message}"


def normalize_message_id(message_id: str) -> str:
    """Strip whitespace and one ``<...>`` pair, then percent-encode unsafe characters.

    ``#``, ``:``, ``%``, whitespace, brackets and non-ASCII are encoded, so a
    normalized id can never end a part suffix, forge the ``h:`` fallback form,
    or contain spaces that would split an evidence id.
    """
    if not isinstance(message_id, str):
        raise RecordError("bad_message_id")
    value = message_id.strip()
    if value.startswith("<") and value.endswith(">"):
        value = value[1:-1].strip()
    encoded = quote(value, safe="@+=$!/~")
    if not encoded or len(encoded) > _MAX_MESSAGE_ID_CHARS:
        raise RecordError("bad_message_id")
    return encoded


def mail_source_uid(account: str, message_id: str) -> str:
    """``mail:<account>:<Message-ID>``; ``account`` is an opaque label, not an address."""
    return f"mail:{_checked_account(account)}:{normalize_message_id(message_id)}"


def mail_fallback_uid(account: str, digest_hex: str) -> str:
    """``mail:<account>:h:<32 hex>`` for messages without a usable Message-ID."""
    if not isinstance(digest_hex, str) or not _HEX_RE.fullmatch(digest_hex):
        raise RecordError("bad_digest")
    return f"mail:{_checked_account(account)}:h:{digest_hex[:32].lower()}"


def mail_conv_uid(account: str, thread_key: str) -> str:
    """``mail:<account>:t:<thread key>`` (the collector chooses a bounded, safe key)."""
    if not isinstance(thread_key, str) or not _THREAD_KEY_RE.fullmatch(thread_key):
        raise RecordError("bad_conv_uid")
    return f"mail:{_checked_account(account)}:t:{thread_key}"


def part_uid(source_uid: str, kind: PartKind, n: int = 1) -> str:
    """``<source_uid>#a`` / ``#q<n>`` / ``#f<n>``; the authored part is always ``#a``."""
    if source_of(source_uid) is None:
        raise RecordError("bad_source_uid")
    number = _checked_int(n, "bad_part_uid")
    kind = _checked_enum(kind, PartKind)
    if kind is PartKind.AUTHORED:
        if number != 1:
            raise RecordError("bad_part_uid")
        return f"{source_uid}#a"
    if not 1 <= number <= 9999:
        raise RecordError("bad_part_uid")
    return f"{source_uid}#{_PART_PREFIX[kind]}{number}"


def content_digest(text: str) -> str:
    """SHA-256 hex of the UTF-8 text."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def source_of(source_uid: str) -> Source | None:
    """The source a well-formed source UID belongs to, else ``None``."""
    if not isinstance(source_uid, str):
        return None
    if _TG_SOURCE_RE.fullmatch(source_uid):
        return Source.TELEGRAM
    if _MAIL_SOURCE_RE.fullmatch(source_uid):
        return Source.MAIL
    return None


def is_part_uid(value: str) -> bool:
    """True when ``value`` is ``<well-formed source uid>#a|#q<n>|#f<n>``."""
    if not isinstance(value, str):
        return False
    base, sep, suffix = value.rpartition("#")
    return bool(sep) and source_of(base) is not None and bool(_PART_SUFFIX_RE.fullmatch(f"#{suffix}"))


# ---------------------------------------------------------------------------
# Validation


def _checked_enum(value: object, enum_cls: type[_E]) -> _E:
    try:
        return enum_cls(value)
    except ValueError:
        raise RecordError("unknown_enum") from None


def _check_timestamp(value: object, *, required: bool = False) -> None:
    if value is None and not required:
        return
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= _MAX_TIMESTAMP:
        raise RecordError("bad_timestamp")


def _check_no_escape(*values: str | None) -> None:
    for value in values:
        if value is not None and "\x1b" in value:
            raise RecordError("escape_character")


def _conv_matches(source_uid: str, conv_uid: str) -> bool:
    if (tg := _TG_SOURCE_RE.fullmatch(source_uid)) is not None:
        conv = _TG_CONV_RE.fullmatch(conv_uid)
        return conv is not None and conv.group("dialog") == tg.group("dialog")
    mail = _MAIL_SOURCE_RE.fullmatch(source_uid)
    conv = _MAIL_CONV_RE.fullmatch(conv_uid)
    return mail is not None and conv is not None and conv.group("account") == mail.group("account")


def _check_conv_uid(conv_uid: object) -> None:
    if not isinstance(conv_uid, str) or not (_TG_CONV_RE.fullmatch(conv_uid) or _MAIL_CONV_RE.fullmatch(conv_uid)):
        raise RecordError("bad_conv_uid")


def _check_participant(participant: Participant) -> None:
    _checked_enum(participant.kind, SenderKind)
    _checked_enum(participant.owner_class, OwnerClass)
    _check_no_escape(participant.display_name, participant.stable_id)


def validate_conversation(conv: ImportConversation) -> None:
    """Raise :class:`RecordError` unless ``conv`` is a well-formed v1 record."""
    if conv.record_version != RECORD_VERSION:
        raise RecordError("unsupported_record_version")
    source = _checked_enum(conv.source, Source)
    _checked_enum(conv.kind, ConversationKind)
    _check_conv_uid(conv.conv_uid)
    if not conv.conv_uid.startswith("tg:" if source is Source.TELEGRAM else "mail:"):
        raise RecordError("conv_mismatch")
    _check_timestamp(conv.last_message_at)
    _check_no_escape(conv.title, conv.source_account, conv.conversation_id)
    for participant in conv.participants:
        _check_participant(participant)


def _check_part(msg: ImportMessage, part: ImportPart) -> None:
    kind = _checked_enum(part.part_kind, PartKind)
    _checked_enum(part.author_kind, SenderKind)
    _checked_enum(part.author_owner_class, OwnerClass)
    _checked_enum(part.provenance_quality, ProvenanceQuality)
    if part.source_uid != msg.source_uid:
        raise RecordError("part_source_mismatch")
    prefix = f"{msg.source_uid}#"
    suffix = part.part_uid[len(prefix) :] if part.part_uid.startswith(prefix) else ""
    if not _PART_SUFFIX_RE.fullmatch(f"#{suffix}"):
        raise RecordError("bad_part_uid")
    if suffix[0] != _PART_PREFIX[kind]:
        raise RecordError("part_kind_mismatch")
    if isinstance(part.ordinal, bool) or not isinstance(part.ordinal, int) or part.ordinal < 0:
        raise RecordError("bad_ordinal")
    _check_timestamp(part.original_sent_at)
    _check_no_escape(part.text, part.author_name, part.author_id, part.author_evidence, part.original_ref)


def _check_parts(msg: ImportMessage) -> None:
    if not msg.parts:
        raise RecordError("no_parts")
    for part in msg.parts:
        _check_part(msg, part)
    if sum(1 for part in msg.parts if part.part_uid.endswith("#a")) > 1:
        raise RecordError("multiple_authored")
    if len({part.part_uid for part in msg.parts}) != len(msg.parts):
        raise RecordError("duplicate_part_uid")
    if len({part.ordinal for part in msg.parts}) != len(msg.parts):
        raise RecordError("duplicate_ordinal")


def validate_message(msg: ImportMessage) -> None:
    """Raise :class:`RecordError` unless ``msg`` and its parts are a well-formed v1 record."""
    if msg.record_version != RECORD_VERSION:
        raise RecordError("unsupported_record_version")
    _checked_enum(msg.sender_kind, SenderKind)
    _checked_enum(msg.owner_class, OwnerClass)
    _checked_enum(msg.provenance_quality, ProvenanceQuality)
    if source_of(msg.source_uid) is None:
        raise RecordError("bad_source_uid")
    _check_conv_uid(msg.conv_uid)
    if not _conv_matches(msg.source_uid, msg.conv_uid):
        raise RecordError("conv_mismatch")
    if msg.reply_to_uid is not None and source_of(msg.reply_to_uid) is not source_of(msg.source_uid):
        raise RecordError("bad_reply_to_uid")
    _check_timestamp(msg.sent_at)
    _check_timestamp(msg.imported_at, required=True)
    if not isinstance(msg.content_digest, str) or not _DIGEST_RE.fullmatch(msg.content_digest):
        raise RecordError("bad_content_digest")
    _check_no_escape(msg.sender_name, msg.sender_id, msg.owner_evidence, msg.media, msg.message_id)
    for participant in msg.recipients:
        _check_participant(participant)
    _check_parts(msg)
