"""Read-only Telethon client construction and the archive sync loop.

Telethon is an optional dependency (``hermes-mordred[telegram]``) and is
imported lazily, so the rest of the extension server runs without it.

Two independent guards keep the client read-only:

1. ``_call`` (every high-level ``await client(request)``) checks the request
   against :mod:`.readonly` before Telethon resolves or queues it;
2. the MTProto sender's ``send`` is wrapped with the same check, catching any
   path that bypasses ``_call`` (connection init, internal helpers).

Cross-DC "exported" senders are refused outright: they exist to download media
from other data centres, which this importer never does.

Telethon's update machinery is disabled: ``_on_login`` normally follows
``updates.GetState`` with ``updates.GetDifference`` to catch up on missed
updates, and the update loop keeps issuing (channel) difference requests. The
importer pulls history explicitly and never consumes updates, so it seeds the
message box from ``GetState`` alone and runs no update loop.

Two record shapes come out of a Telethon message. :func:`convert_message` is
the legacy ``.enc`` row (name, ``out`` flag, text). :func:`convert_import_message`
is the canonical ``mordred.db`` record: the speaker is decided here, from API
identity only (``sender_id``/``from_id``/``out``/``post``/``sender.bot``), and a
forward or a quote becomes its own part with its own author. Both read only
what the history response already carries (``message.forward`` entities
included), so no new MTProto request type is needed. Where the records go is a
:class:`~.history.SyncSink`'s business.
"""

from __future__ import annotations

import asyncio
import datetime
import json
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Final

from ...imports.records import (
    ConversationKind,
    ImportConversation,
    ImportMessage,
    ImportPart,
    OwnerClass,
    PartKind,
    ProvenanceQuality,
    SenderKind,
    Source,
    content_digest,
    part_uid,
    telegram_conv_uid,
    telegram_source_uid,
)
from ..egress import EgressError, resolve_route, socks_proxy
from .readonly import ReadOnlyViolation, RequestPolicy, check_request
from .store import ArchiveIndex, ArchiveStore, StoredMessage, StoreError

if TYPE_CHECKING:
    from .history import SyncSink

# Telegram's MTProto endpoints are raw TCP to data-centre IPs. The hostname is
# only used to pick the gateway proxy (NO_PROXY matching).
_ROUTE_HOST = "telegram.org"
# Sleep through FloodWait errors up to five minutes; longer waits abort the sync
# with ``telegram_rate_limited`` so the operator can retry later.
_FLOOD_SLEEP_SECONDS = 300
# Persist progress this often so an interrupted import resumes, not restarts.
_FLUSH_EVERY = 500
# Persist "already checked up to" positions this often even when no message
# was stored, so an interrupted run does not re-request those chats.
_INDEX_SAVE_EVERY = 25
_MAX_TEXT_CHARS = 16_000


DEFAULT_MAX_GROUP_SIZE = 100
# Default import window: chats active, and messages sent, in the last N days.
DEFAULT_SINCE_DAYS = 3


class TelegramClientError(RuntimeError):
    """Stable, content-free failure code."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class SyncOptions:
    include_channels: bool = True  # broadcast channels (often very large)
    include_archived: bool = False  # the Archived Chats folder is skipped by default
    limit_per_dialog: int | None = None  # first import only: newest N messages
    # Only chats active, and messages sent, in the last N days (None = all history).
    since_days: int | None = DEFAULT_SINCE_DAYS
    # Groups with more members than this are skipped (None = no limit).
    max_group_size: int | None = DEFAULT_MAX_GROUP_SIZE


@dataclass
class SyncProgress:
    dialogs_total: int = 0
    dialogs_done: int = 0
    messages_imported: int = 0
    started_at: int = 0
    finished_at: int = 0


ProgressCallback = Callable[[SyncProgress], None]


def telethon_available() -> bool:
    try:
        import telethon  # noqa: F401
    except ImportError:
        return False
    return True


def _proxy_for_telethon() -> dict[str, Any] | None:
    """Translate the gateway route into Telethon's ``proxy`` dict (or None)."""
    try:
        route = resolve_route(_ROUTE_HOST)
    except EgressError as exc:
        raise TelegramClientError("routing_unavailable") from exc
    if route.socks_proxy_url is not None:
        proxy = socks_proxy(route.socks_proxy_url)
        result: dict[str, Any] = {
            "proxy_type": "socks5",
            "addr": proxy.host,
            "port": proxy.port,
            "rdns": True,
        }
        if proxy.username is not None:
            result["username"] = proxy.username
            result["password"] = proxy.password or ""
        return result
    if route.http_proxy_url is not None:
        from urllib.parse import urlsplit

        parts = urlsplit(route.http_proxy_url)
        if not parts.hostname or parts.port is None:
            raise TelegramClientError("routing_unavailable")
        http_proxy: dict[str, Any] = {"proxy_type": "http", "addr": parts.hostname, "port": parts.port}
        if parts.username is not None:
            http_proxy["username"] = parts.username
            http_proxy["password"] = parts.password or ""
        return http_proxy
    return None


def build_client(api_id: int, api_hash: str, session: str | None, *, policy: RequestPolicy) -> Any:
    """Return a connected-on-demand, allowlist-guarded ``TelegramClient``."""
    try:
        from telethon import TelegramClient
        from telethon.sessions import StringSession
    except ImportError as exc:
        raise TelegramClientError("telegram_not_installed") from exc

    class _ReadOnlyTelegramClient(TelegramClient):  # type: ignore[misc]
        async def _call(
            self, sender: Any, request: Any, ordered: bool = False, flood_sleep_threshold: Any = None
        ) -> Any:
            check_request(request, policy)
            return await super()._call(sender, request, ordered=ordered, flood_sleep_threshold=flood_sleep_threshold)

        async def _on_login(self, user: Any) -> Any:
            from telethon._updates import SessionState
            from telethon.tl.functions.updates import GetStateRequest

            self._mb_entity_cache.set_self_user(user.id, user.bot, user.access_hash)
            self._authorized = True
            state = await self(GetStateRequest())
            self._message_box.load(
                SessionState(0, 0, 0, state.pts, state.qts, int(state.date.timestamp()), state.seq, 0), []
            )
            return user

        async def _update_loop(self) -> None:
            return None

        async def _borrow_exported_sender(self, dc_id: int) -> Any:
            raise ReadOnlyViolation("exported_sender")

        async def _create_exported_sender(self, dc_id: int) -> Any:
            raise ReadOnlyViolation("exported_sender")

    client = _ReadOnlyTelegramClient(
        StringSession(session or ""),
        api_id,
        api_hash,
        proxy=_proxy_for_telethon(),
        use_ipv6=False,
        flood_sleep_threshold=_FLOOD_SLEEP_SECONDS,
        receive_updates=False,
        catch_up=False,
        device_model="Mordred read-only importer",
        app_version="hermes-mordred",
    )
    _guard_sender(client, policy)
    return client


def _guard_sender(client: Any, policy: RequestPolicy) -> None:
    sender = client._sender
    original = sender.send

    def guarded_send(request: Any, ordered: bool = False) -> Any:
        check_request(request, policy)
        return original(request, ordered=ordered)

    sender.send = guarded_send


def save_session(client: Any) -> str:
    from telethon.sessions import StringSession

    return str(StringSession.save(client.session))


# -- message conversion --------------------------------------------------------


def _media_kind(message: Any) -> str | None:
    media = getattr(message, "media", None)
    if media is None:
        return None
    name = type(media).__name__
    for prefix in ("MessageMedia",):
        if name.startswith(prefix):
            name = name[len(prefix) :]
    return name.lower() or "media"


def _display_name(entity: Any) -> str:
    if entity is None:
        return ""
    try:
        from telethon import utils

        return str(utils.get_display_name(entity))
    except Exception:
        return ""


def convert_message(message: Any) -> StoredMessage | None:
    """Convert a Telethon ``Message``; service messages are skipped."""
    if type(message).__name__ != "Message":
        return None
    text = message.message or ""
    if len(text) > _MAX_TEXT_CHARS:
        text = text[:_MAX_TEXT_CHARS]
    reply = getattr(message, "reply_to", None)
    reply_id = getattr(reply, "reply_to_msg_id", None) if reply is not None else None
    date = message.date
    return StoredMessage(
        id=int(message.id),
        date=int(date.timestamp()) if date is not None else 0,
        sender=_display_name(getattr(message, "sender", None)),
        text=text,
        out=bool(getattr(message, "out", False)),
        reply_to=int(reply_id) if isinstance(reply_id, int) else None,
        media=_media_kind(message),
    )


def dialog_kind(dialog: Any) -> str:
    entity = dialog.entity
    if getattr(dialog, "is_user", False):
        return "bot" if getattr(entity, "bot", False) else "user"
    if getattr(dialog, "is_group", False):
        return "group"
    return "channel"


# -- canonical import records (mordred.db) ---------------------------------------------

#: Owner evidence codes. Content-free; a display name never appears in one.
EVIDENCE_FROM_ID_SELF: Final = "api_from_id_eq_self"  # sender_id is the logged-in account
EVIDENCE_OUT: Final = "api_out"  # outgoing message without a from_id (or an outgoing channel post)
EVIDENCE_IDENTITY: Final = "api_identity"  # someone else, identified by a stable API id
EVIDENCE_CHANNEL_POST: Final = "api_channel_post"  # a broadcast post: the person behind it is unknown
EVIDENCE_ANONYMOUS_ADMIN: Final = "api_anonymous_admin"  # from_id is the group itself
EVIDENCE_NO_SENDER: Final = "api_no_sender"  # the response names no sender
#: Appended to the authored part's evidence when the text came through an inline bot.
EVIDENCE_VIA_BOT_SUFFIX: Final = "+via_bot"
EVIDENCE_FWD_SELF: Final = "api_fwd_from_id_eq_self"
EVIDENCE_FWD_IDENTITY: Final = "api_fwd_from_id"
EVIDENCE_FWD_NAME: Final = "fwd_from_name"  # only the name the original sender chose to show
EVIDENCE_FWD_HIDDEN: Final = "fwd_hidden"
EVIDENCE_QUOTE_RESOLVED: Final = "reply_quote_resolved"  # author of the replied-to message
EVIDENCE_QUOTE_UNRESOLVED: Final = "reply_quote_unresolved"

#: Telethon's marked id of a channel is ``-(10**12 + channel_id)``.
_CHANNEL_ID_OFFSET: Final = 1_000_000_000_000
_MAX_TIMESTAMP: Final = 253_402_300_799  # 9999-12-31T23:59:59Z, as ``imports.records``
_MAX_NAME_CHARS: Final = 256
_CONVERSATION_KINDS: Final = {
    "user": ConversationKind.DIRECT,
    "bot": ConversationKind.DIRECT,
    "group": ConversationKind.GROUP,
    "channel": ConversationKind.CHANNEL,
}


@dataclass(frozen=True)
class PartAuthor:
    """Who wrote one part: the fields an :class:`ImportPart` needs about its author."""

    kind: SenderKind
    author_id: str | None
    name: str
    owner_class: OwnerClass
    evidence: str
    quality: ProvenanceQuality

    @classmethod
    def of(cls, part: ImportPart) -> PartAuthor:
        return cls(
            kind=SenderKind(part.author_kind),
            author_id=part.author_id,
            name=part.author_name,
            owner_class=OwnerClass(part.author_owner_class),
            evidence=part.author_evidence,
            quality=ProvenanceQuality(part.provenance_quality),
        )


#: ``resolve_reply(reply_to_msg_id)``: the author of a same-chat message, or ``None`` when unknown.
ReplyResolver = Callable[[int], PartAuthor | None]

_UNKNOWN_AUTHOR: Final = PartAuthor(
    SenderKind.UNKNOWN, None, "", OwnerClass.UNKNOWN, EVIDENCE_QUOTE_UNRESOLVED, ProvenanceQuality.UNKNOWN
)


def _positive_int(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) and value > 0 else None


def _peer(peer: Any) -> tuple[str, int] | None:
    """``("user" | "chat" | "channel", Telethon marked id)`` of a ``Peer*``, else ``None``."""
    if peer is None:
        return None
    user = _positive_int(getattr(peer, "user_id", None))
    if user is not None:
        return "user", user
    channel = _positive_int(getattr(peer, "channel_id", None))
    if channel is not None:
        return "channel", -(_CHANNEL_ID_OFFSET + channel)
    chat = _positive_int(getattr(peer, "chat_id", None))
    if chat is not None:
        return "chat", -chat
    return None


def _timestamp(value: Any) -> int | None:
    """Unix seconds of a datetime, or ``None`` (never the import time)."""
    if value is None:
        return None
    try:
        stamp = int(value.timestamp())
    except (AttributeError, OverflowError, OSError, TypeError, ValueError):
        return None
    return stamp if 0 <= stamp <= _MAX_TIMESTAMP else None


def _clean(text: str) -> str:
    """Imported text never carries an ESC (the record contract refuses it)."""
    return text.replace("\x1b", "�")


def _capped(text: Any) -> str:
    return _clean(text[:_MAX_TEXT_CHARS]) if isinstance(text, str) else ""


def _entity_name(entity: Any) -> str:
    """Display name of a user/chat/channel; plain attributes when Telethon cannot name it."""
    if entity is None:
        return ""
    name = _display_name(entity)
    if not name:
        title = getattr(entity, "title", None)
        parts = [getattr(entity, "first_name", None), getattr(entity, "last_name", None)]
        name = title if isinstance(title, str) else " ".join(p for p in parts if isinstance(p, str) and p)
    return _clean(name.strip())[:_MAX_NAME_CHARS]


@dataclass(frozen=True)
class _Sender:
    kind: SenderKind
    sender_id: str | None
    name: str
    owner_class: OwnerClass
    evidence: str
    quality: ProvenanceQuality


def _sender_kind(message: Any, from_peer: tuple[str, int] | None, sender_id: int | None, out: bool) -> SenderKind:
    if getattr(message, "post", False) is True or (from_peer is not None and from_peer[0] != "user"):
        return SenderKind.CHANNEL
    if getattr(getattr(message, "sender", None), "bot", False) is True:
        return SenderKind.BOT
    return SenderKind.USER if sender_id is not None or out else SenderKind.UNKNOWN


def _owner(
    kind: SenderKind,
    *,
    owner_id: int,
    sender_id: int | None,
    from_peer: tuple[str, int] | None,
    out: bool,
    post: bool,
    chat_id: int,
) -> tuple[OwnerClass, str]:
    """Owner class and evidence code; the first matching rule wins.

    1. ``sender_id == owner_id`` -> owner (``api_from_id_eq_self``);
    2. ``out`` without ``from_id`` -> owner (``api_out``);
    3. a channel identity: ``out`` -> owner (``api_out``); a broadcast post or an
       anonymous group admin (``from_id`` is the chat) -> ``unknown``; another
       channel speaking in a group -> ``other``;
    4. any other stable sender id (users, bots) -> ``other`` (``api_identity``);
    5. no sender at all -> ``unknown``.
    """
    if sender_id is not None and sender_id == owner_id:
        return OwnerClass.ACCOUNT_OWNER, EVIDENCE_FROM_ID_SELF
    if out and from_peer is None:
        return OwnerClass.ACCOUNT_OWNER, EVIDENCE_OUT
    if kind is SenderKind.CHANNEL:
        if out:
            return OwnerClass.ACCOUNT_OWNER, EVIDENCE_OUT
        if post:
            return OwnerClass.UNKNOWN, EVIDENCE_CHANNEL_POST
        if from_peer is not None and from_peer[1] == chat_id:
            return OwnerClass.UNKNOWN, EVIDENCE_ANONYMOUS_ADMIN
        return OwnerClass.OTHER, EVIDENCE_IDENTITY
    if sender_id is not None:
        return OwnerClass.OTHER, EVIDENCE_IDENTITY
    return OwnerClass.UNKNOWN, EVIDENCE_NO_SENDER


def _sender(message: Any, *, owner_id: int, chat_id: int, direct: bool) -> _Sender:
    """The transport sender of ``message`` (for a forward: the forwarder)."""
    from_peer = _peer(getattr(message, "from_id", None))
    out = getattr(message, "out", False) is True
    post = getattr(message, "post", False) is True
    raw = getattr(message, "sender_id", None)
    sender_id = raw if isinstance(raw, int) and not isinstance(raw, bool) and raw != 0 else None
    if sender_id is None:
        # Telethon's own rule: from_id, else the channel of a post or the peer of an incoming 1:1 message.
        if from_peer is not None:
            sender_id = from_peer[1]
        elif post or (not out and direct):
            sender_id = chat_id
    kind = _sender_kind(message, from_peer, sender_id, out)
    owner_class, evidence = _owner(
        kind, owner_id=owner_id, sender_id=sender_id, from_peer=from_peer, out=out, post=post, chat_id=chat_id
    )
    if sender_id is None and owner_class is OwnerClass.ACCOUNT_OWNER:
        sender_id = owner_id
    known = sender_id is not None
    return _Sender(
        kind=kind,
        sender_id=str(sender_id) if known else None,
        name=_entity_name(getattr(message, "sender", None)),
        owner_class=owner_class,
        evidence=evidence,
        quality=ProvenanceQuality.API_IDENTITY if known else ProvenanceQuality.UNKNOWN,
    )


def _forward_author(message: Any, fwd: Any, owner_id: int) -> PartAuthor:
    """The original author of a forward: stable API id, else the shown name, else unknown."""
    peer = _peer(getattr(fwd, "from_id", None))
    forward = getattr(message, "forward", None)  # Telethon's view; its entities came with the response
    if peer is not None:
        kind_name, marked = peer
        if kind_name == "user":
            entity = getattr(forward, "sender", None)
            kind = SenderKind.BOT if getattr(entity, "bot", False) is True else SenderKind.USER
        else:
            entity = getattr(forward, "chat", None)
            kind = SenderKind.CHANNEL
        name = _entity_name(entity)
        if kind_name == "user" and marked == owner_id:
            return PartAuthor(
                kind, str(marked), name, OwnerClass.ACCOUNT_OWNER, EVIDENCE_FWD_SELF, ProvenanceQuality.API_IDENTITY
            )
        return PartAuthor(
            kind, str(marked), name, OwnerClass.OTHER, EVIDENCE_FWD_IDENTITY, ProvenanceQuality.API_IDENTITY
        )
    for field_name in ("from_name", "post_author"):
        claimed = getattr(fwd, field_name, None)
        if isinstance(claimed, str) and claimed.strip():
            name = _clean(claimed.strip())[:_MAX_NAME_CHARS]
            return PartAuthor(
                SenderKind.USER, None, name, OwnerClass.OTHER, EVIDENCE_FWD_NAME, ProvenanceQuality.SOURCE_CLAIMED
            )
    return PartAuthor(SenderKind.UNKNOWN, None, "", OwnerClass.UNKNOWN, EVIDENCE_FWD_HIDDEN, ProvenanceQuality.UNKNOWN)


def _forward_ref(fwd: Any) -> str | None:
    """``tg:<peer>:<msg>`` of the forwarded original, when the header names it."""
    saved_peer = _peer(getattr(fwd, "saved_from_peer", None))
    saved_msg = _positive_int(getattr(fwd, "saved_from_msg_id", None))
    if saved_peer is not None and saved_msg is not None:
        return telegram_source_uid(saved_peer[1], saved_msg)
    origin = _peer(getattr(fwd, "from_id", None))
    post = _positive_int(getattr(fwd, "channel_post", None))
    if origin is not None and origin[0] == "channel" and post is not None:
        return telegram_source_uid(origin[1], post)
    return None


def _part(source_uid: str, kind: PartKind, ordinal: int, author: PartAuthor, text: str, **extra: Any) -> ImportPart:
    return ImportPart(
        part_uid=part_uid(source_uid, kind),
        source_uid=source_uid,
        ordinal=ordinal,
        part_kind=kind,
        author_kind=author.kind,
        author_id=author.author_id,
        author_name=author.name,
        author_owner_class=author.owner_class,
        author_evidence=author.evidence,
        original_sent_at=extra.get("original_sent_at"),
        original_ref=extra.get("original_ref"),
        text=text,
        provenance_quality=author.quality,
    )


def _quote(
    message: Any, source_uid: str, chat_id: int, resolve_reply: ReplyResolver | None
) -> tuple[str | None, ImportPart | None]:
    """``(reply_to_uid, #q1 part)``; the quote's author is the replied-to message's, else unknown."""
    reply = getattr(message, "reply_to", None)
    if reply is None:
        return None, None
    target = _positive_int(getattr(reply, "reply_to_msg_id", None))
    reply_peer = _peer(getattr(reply, "reply_to_peer_id", None))
    same_chat = reply_peer is None or reply_peer[1] == chat_id
    reply_uid = telegram_source_uid(chat_id, target) if target is not None and same_chat else None
    quote_text = _capped(getattr(reply, "quote_text", None))
    if not quote_text.strip():
        return reply_uid, None
    resolved = None
    if resolve_reply is not None and target is not None and same_chat:
        resolved = resolve_reply(target)
    if resolved is None:
        author = _UNKNOWN_AUTHOR
    else:
        author = PartAuthor(
            resolved.kind,
            resolved.author_id,
            resolved.name,
            resolved.owner_class,
            EVIDENCE_QUOTE_RESOLVED,
            resolved.quality,
        )
    return reply_uid, _part(source_uid, PartKind.QUOTED, 1, author, quote_text, original_ref=reply_uid)


def _primary_part(message: Any, source_uid: str, sender: _Sender, text: str, owner_id: int) -> ImportPart:
    """``#f1`` for a forward (the original author's words), else ``#a`` (the sender's own)."""
    fwd = getattr(message, "fwd_from", None)
    if fwd is not None:
        return _part(
            source_uid,
            PartKind.FORWARDED,
            0,
            _forward_author(message, fwd, owner_id),
            text,
            original_sent_at=_timestamp(getattr(fwd, "date", None)),
            original_ref=_forward_ref(fwd),
        )
    via_bot = _positive_int(getattr(message, "via_bot_id", None)) is not None
    evidence = sender.evidence + (EVIDENCE_VIA_BOT_SUFFIX if via_bot else "")
    author = PartAuthor(sender.kind, sender.sender_id, sender.name, sender.owner_class, evidence, sender.quality)
    return _part(source_uid, PartKind.AUTHORED, 0, author, text)


def convert_import_message(
    message: Any,
    *,
    owner_id: int,
    conv: ImportConversation,
    imported_at: int,
    resolve_reply: ReplyResolver | None = None,
) -> ImportMessage | None:
    """One Telethon ``Message`` as a canonical record; ``None`` for service or empty messages.

    Parts: the sender's own words ``#a``; for a forward ONLY ``#f1`` (Telegram
    forwards carry no comment of their own, so the message text is the
    forwarded text and the message's sender is the forwarder); a quoted reply
    adds ``#q1``. Empty text is kept only when media is present.
    """
    if type(message).__name__ != "Message":
        return None
    msg_id = _positive_int(getattr(message, "id", None))
    if msg_id is None:
        return None
    chat_id = int(conv.conversation_id)
    source_uid = telegram_source_uid(chat_id, msg_id)
    raw_text = getattr(message, "message", None)
    text = _capped(raw_text if isinstance(raw_text, str) else getattr(message, "text", None))
    media = _media_kind(message)
    media = None if media == "empty" else media
    if not text and media is None:
        return None
    sender = _sender(message, owner_id=owner_id, chat_id=chat_id, direct=conv.kind == ConversationKind.DIRECT)
    primary = _primary_part(message, source_uid, sender, text, owner_id)
    reply_uid, quote = _quote(message, source_uid, chat_id, resolve_reply)
    parts = (primary,) if quote is None else (primary, quote)
    digest = json.dumps(
        {"media": media, "parts": [[str(p.part_kind), p.text] for p in parts]},
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    return ImportMessage(
        source_uid=source_uid,
        conv_uid=conv.conv_uid,
        message_id=str(msg_id),
        sent_at=_timestamp(getattr(message, "date", None)),
        imported_at=imported_at,
        sender_kind=sender.kind,
        sender_id=sender.sender_id,
        sender_name=sender.name,
        owner_class=sender.owner_class,
        owner_evidence=sender.evidence,
        reply_to_uid=reply_uid,
        media=media,
        provenance_quality=sender.quality,
        source_revision=_revision(message),
        content_digest=content_digest(digest),
        parts=parts,
    )


def _revision(message: Any) -> str | None:
    """The edit time: an edited message re-imported later replaces the stored copy (``revised``)."""
    edited = _timestamp(getattr(message, "edit_date", None))
    return None if edited is None else str(edited)


def convert_dialog(dialog: Any, *, account: str, archived: bool = False) -> ImportConversation:
    """A Telethon dialog as an (empty) canonical conversation; the sink adds counts and cursor."""
    dialog_id = int(dialog.id)
    return ImportConversation(
        conv_uid=telegram_conv_uid(dialog_id),
        source=Source.TELEGRAM,
        source_account=account,
        conversation_id=str(dialog_id),
        kind=_CONVERSATION_KINDS[dialog_kind(dialog)],
        title=_clean(str(getattr(dialog, "name", None) or ""))[:_MAX_NAME_CHARS],
        participants=(),
        last_message_at=None,
        message_count=0,
        archived=archived,
        sync_cursor=None,
    )


# -- sync ----------------------------------------------------------------------


def _last_activity(dialog: Any) -> float | None:
    date = getattr(dialog, "date", None)
    return date.timestamp() if date is not None else None


async def _group_size(client: Any, dialog: Any) -> int | None:
    """Member count of a group, or None when Telegram will not say."""
    entity = dialog.entity
    count = getattr(entity, "participants_count", None)
    if isinstance(count, int):
        return count
    if type(entity).__name__ != "Channel":
        return None
    try:
        from telethon.tl.functions.channels import GetFullChannelRequest

        full = await client(GetFullChannelRequest(entity))  # read-only, allow-listed
        value = getattr(getattr(full, "full_chat", None), "participants_count", None)
        return value if isinstance(value, int) else None
    except Exception:
        return None


async def _too_large(client: Any, dialog: Any, options: SyncOptions) -> bool:
    if options.max_group_size is None or dialog_kind(dialog) != "group":
        return False
    size = await _group_size(client, dialog)
    # Unknown size counts as large: skipping is the conservative default.
    return size is None or size > options.max_group_size


async def _collect_dialogs(client: Any, options: SyncOptions, cutoff: float | None) -> list[tuple[Any, bool]]:
    """Chats to import: pinned first, then most recently active."""
    seen: set[int] = set()
    dialogs: list[tuple[Any, bool]] = []
    folders = [False, True] if options.include_archived else [False]
    for archived in folders:
        async for dialog in client.iter_dialogs(archived=archived):
            if dialog.id in seen:
                continue
            seen.add(dialog.id)
            if not options.include_channels and dialog_kind(dialog) == "channel":
                continue
            last = _last_activity(dialog)
            if cutoff is not None and last is not None and last < cutoff:
                continue  # nothing in the window; do not even open it
            if await _too_large(client, dialog, options):
                continue  # large groups only on request (--include-large-groups)
            dialogs.append((dialog, archived))
    # Stable: Telegram already lists by recency, so this only lifts pinned chats.
    dialogs.sort(key=lambda pair: not getattr(pair[0], "pinned", False))
    return dialogs


async def _newest(client: Any, sink: SyncSink[Any, Any], handle: Any, entity: Any, limit: int) -> tuple[list[Any], int]:
    """The newest *limit* messages, converted in ascending id order, and the highest message id seen."""
    fetched: list[Any] = []
    seen = 0
    async for message in client.iter_messages(entity, limit=limit):
        seen = max(seen, int(message.id))
        fetched.append(message)
    found: list[Any] = []
    for message in sorted(fetched, key=lambda m: int(m.id)):
        converted = sink.convert(handle, message)
        if converted is not None:
            found.append(converted)
    return found, seen


async def _sync_dialog(
    client: Any,
    sink: SyncSink[Any, Any],
    handle: Any,
    cursor: int,
    entity: Any,
    options: SyncOptions,
    on_batch: Callable[[int], Awaitable[None]],
    cutoff: float | None = None,
) -> int:
    """Import only messages newer than ``cursor``; return the dialog's new cursor.

    The cursor is the highest message id ever *seen* — also service messages
    and empty windows — so nothing is requested twice. Messages are fetched
    oldest-first (so a quote can resolve an earlier message of the same run)
    and handed to the sink every ``_FLUSH_EVERY``, so an interrupted archive
    run resumes where it stopped instead of starting over.
    """

    async def flush(batch: list[Any]) -> None:
        if not batch:
            return
        added = await asyncio.to_thread(sink.write, handle, batch)
        if added:
            await on_batch(added)

    if cutoff is None and cursor == 0 and options.limit_per_dialog is not None:
        # Bounded first import (newest N), stored in one go.
        newest, seen = await _newest(client, sink, handle, entity, options.limit_per_dialog)
        await flush(newest)
        return sink.advance(handle, seen)

    kwargs: dict[str, Any] = {"min_id": cursor, "reverse": True}
    if cutoff is not None:
        # Oldest-first from the window start; older gaps stay for a wider sync.
        kwargs["offset_date"] = datetime.datetime.fromtimestamp(cutoff, tz=datetime.UTC)
    seen = cursor
    batch: list[Any] = []
    async for message in client.iter_messages(entity, **kwargs):
        seen = max(seen, int(message.id))
        converted = sink.convert(handle, message)
        if converted is None:
            continue
        batch.append(converted)
        if len(batch) >= _FLUSH_EVERY:
            await flush(batch)
            batch = []
    await flush(batch)
    return sink.advance(handle, seen)


def _top_message_id(dialog: Any) -> int | None:
    top = getattr(getattr(dialog, "message", None), "id", None)
    return top if isinstance(top, int) else None


async def _sync_dialogs(
    client: Any,
    sink: SyncSink[Any, Any],
    index: ArchiveIndex,
    opts: SyncOptions,
    state: SyncProgress,
    progress: ProgressCallback | None,
    clock: Callable[[], float],
) -> None:
    cutoff = clock() - opts.since_days * 86400 if opts.since_days else None
    dialogs = await _collect_dialogs(client, opts, cutoff)
    state.dialogs_total = len(dialogs)
    unsaved = 0
    if progress is not None:
        progress(state)

    async def on_batch(count: int) -> None:
        state.messages_imported += count
        await asyncio.to_thread(sink.checkpoint, index)
        if progress is not None:
            progress(state)

    for dialog, archived in dialogs:
        handle = sink.open_dialog(dialog, archived=archived)
        cursor = sink.cursor(int(dialog.id)) or 0
        top = _top_message_id(dialog)
        if top is not None and top <= cursor:
            # Up to date: the dialog list already told us there is nothing new.
            state.dialogs_done += 1
            continue
        after = await _sync_dialog(client, sink, handle, cursor, dialog.entity, opts, on_batch, cutoff)
        if after != cursor:
            unsaved += 1
            if unsaved >= _INDEX_SAVE_EVERY:
                await asyncio.to_thread(sink.checkpoint, index)
                unsaved = 0
        state.dialogs_done += 1
        if progress is not None:
            progress(state)


async def sync_archive(
    client: Any,
    store: ArchiveStore,
    *,
    options: SyncOptions | None = None,
    progress: ProgressCallback | None = None,
    clock: Callable[[], float] = time.time,
    sink: SyncSink[Any, Any] | None = None,
) -> SyncProgress:
    """Import every reachable dialog's new messages through *sink* (default: the ``.enc`` archive in *store*).

    The caller owns ``store.locked()`` and the client connection. Secret chats
    never appear: they are end-to-end encrypted to the originating device and
    MTProto does not expose them to other sessions. The account is checked
    before anything is written: a login different from the archive's account
    refuses with ``account_mismatch``, and an index retired to ``mordred.db``
    never falls back to the archive (``import_store_unavailable``).
    """
    opts = options or SyncOptions()
    state = SyncProgress(started_at=int(clock()))
    index = await asyncio.to_thread(store.load_index)
    if sink is None and index.retired_to is not None:
        raise StoreError("import_store_unavailable")
    me = await client.get_me()
    if me is None:
        raise TelegramClientError("telegram_not_logged_in")
    owner_id = int(me.id)
    if index.account_id and index.account_id != owner_id:
        raise StoreError("account_mismatch")
    index.account_id = owner_id
    index.account_label = _display_name(me)
    if sink is None:
        from .history import ArchiveSink

        sink = ArchiveSink(store)
    await asyncio.to_thread(sink.begin, index)
    try:
        await _sync_dialogs(client, sink, index, opts, state, progress, clock)
        index.last_sync = int(clock())
        await asyncio.to_thread(sink.finish, index)
        await asyncio.to_thread(store.save_index, index)
    except BaseException:
        sink.fail()
        raise
    state.finished_at = index.last_sync
    return state


def empty_index() -> ArchiveIndex:
    return ArchiveIndex()
