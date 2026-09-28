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
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any

from ..egress import EgressError, resolve_route, socks_proxy
from .readonly import ReadOnlyViolation, RequestPolicy, check_request
from .store import ArchiveIndex, ArchiveStore, DialogInfo, StoredMessage

# Telegram's MTProto endpoints are raw TCP to data-centre IPs. The hostname is
# only used to pick the gateway proxy (NO_PROXY matching).
_ROUTE_HOST = "telegram.org"
# Sleep through FloodWait errors up to five minutes; longer waits abort the sync
# with ``telegram_rate_limited`` so the operator can retry later.
_FLOOD_SLEEP_SECONDS = 300
# Persist progress this often so an interrupted import resumes, not restarts.
_FLUSH_EVERY = 500
_MAX_TEXT_CHARS = 16_000


class TelegramClientError(RuntimeError):
    """Stable, content-free failure code."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class SyncOptions:
    include_channels: bool = True  # broadcast channels (often very large)
    include_archived: bool = True
    limit_per_dialog: int | None = None  # first import only: newest N messages


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


# -- sync ----------------------------------------------------------------------


async def _collect_dialogs(client: Any, options: SyncOptions) -> list[tuple[Any, bool]]:
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
            dialogs.append((dialog, archived))
    return dialogs


async def _sync_dialog(
    client: Any,
    store: ArchiveStore,
    info: DialogInfo,
    entity: Any,
    options: SyncOptions,
    on_batch: Callable[[int], Awaitable[None]],
) -> None:
    """Import one dialog's new messages. Store I/O runs off the event loop."""

    async def flush(batch: list[StoredMessage]) -> None:
        if not batch:
            return
        added = await asyncio.to_thread(store.append_messages, info.dialog_id, batch)
        if added:
            info.message_count += added
            info.last_message_id = max(info.last_message_id, batch[-1].id)
            info.last_date = max(info.last_date, batch[-1].date)
            await on_batch(added)

    if info.last_message_id == 0 and options.limit_per_dialog is not None:
        # Newest-first, bounded: collect everything, then store in ascending
        # order in one go, so an interrupted first import leaves no gap.
        newest: list[StoredMessage] = []
        async for message in client.iter_messages(entity, limit=options.limit_per_dialog):
            converted = convert_message(message)
            if converted is not None:
                newest.append(converted)
        await flush(sorted(newest, key=lambda m: m.id))
        return

    batch: list[StoredMessage] = []
    async for message in client.iter_messages(entity, min_id=info.last_message_id, reverse=True):
        converted = convert_message(message)
        if converted is None:
            continue
        batch.append(converted)
        if len(batch) >= _FLUSH_EVERY:
            await flush(batch)
            batch = []
    await flush(batch)


async def sync_archive(
    client: Any,
    store: ArchiveStore,
    *,
    options: SyncOptions | None = None,
    progress: ProgressCallback | None = None,
    clock: Callable[[], float] = time.time,
) -> SyncProgress:
    """Import every reachable dialog's new messages into *store*.

    The caller owns ``store.locked()`` and the client connection. Secret chats
    never appear: they are end-to-end encrypted to the originating device and
    MTProto does not expose them to other sessions.
    """
    opts = options or SyncOptions()
    state = SyncProgress(started_at=int(clock()))
    index = await asyncio.to_thread(store.load_index)
    me = await client.get_me()
    if me is None:
        raise TelegramClientError("telegram_not_logged_in")
    index.account_id = int(me.id)
    index.account_label = _display_name(me)

    dialogs = await _collect_dialogs(client, opts)
    state.dialogs_total = len(dialogs)
    if progress is not None:
        progress(state)

    for dialog, archived in dialogs:
        info = index.dialogs.get(dialog.id) or DialogInfo(dialog_id=int(dialog.id), kind=dialog_kind(dialog), title="")
        info.title = str(dialog.name or "")
        info.kind = dialog_kind(dialog)
        info.archived = archived
        index.dialogs[info.dialog_id] = info

        async def on_batch(count: int) -> None:
            state.messages_imported += count
            await asyncio.to_thread(store.save_index, index)
            if progress is not None:
                progress(state)

        await _sync_dialog(client, store, info, dialog.entity, opts, on_batch)
        state.dialogs_done += 1
        if progress is not None:
            progress(state)

    index.last_sync = int(clock())
    await asyncio.to_thread(store.save_index, index)
    state.finished_at = index.last_sync
    return state


def empty_index() -> ArchiveIndex:
    return ArchiveIndex()
