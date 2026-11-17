"""Required E2E guard for Hermes's tool/cron standalone delivery seam.

Protected text goes directly to the platform API: delegating ciphertext back
into Hermes would apply Slack Markdown conversion and platform chunking to the
wire. Ordinary destinations continue through the original Hermes sender.
"""

from __future__ import annotations

import asyncio
import importlib
import inspect
import os
import re
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from functools import wraps
from typing import Any

from . import e2e, egress

_CONTEXT_UNAVAILABLE = "mordred_encrypt_context_unavailable"
_UNAVAILABLE = "mordred_encrypt_unavailable"
_SEND_FAILED = "mordred_encrypt_send_failed"
_SLACK_CHANNEL = re.compile(r"[CGD][A-Z0-9]+")
_SLACK_USER = re.compile(r"U[A-Z0-9]+")
_SNOWFLAKE = re.compile(r"[0-9]{1,20}")
_THREAD_TYPES = frozenset({10, 11, 12})
_PARAMETERS = ("platform", "pconfig", "chat_id", "message", "thread_id", "media_files", "force_document")


class StandaloneGuardRefused(BaseException):
    """Escape Hermes's ordinary plugin-failure containment at startup."""


class _Refused(Exception):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@asynccontextmanager
async def _client(platform: str, pconfig: Any) -> AsyncIterator[tuple[Any, dict[str, Any]]]:
    import aiohttp

    host = "slack.com" if platform == "slack" else "discord.com"
    token = getattr(pconfig, "token", None) or os.getenv(f"{platform.upper()}_BOT_TOKEN", "")
    if not isinstance(token, str) or not token.strip():
        raise _Refused(_CONTEXT_UNAVAILABLE)
    route_kwargs = {"platform_env_var": "DISCORD_PROXY"} if platform == "discord" else {}
    route = await asyncio.to_thread(egress.resolve_route, host, **route_kwargs)
    connector = None
    if route.socks_proxy_url is not None:
        from aiohttp_socks import ProxyConnector

        connector = ProxyConnector.from_url(route.socks_proxy_url, rdns=True)
    headers = {"Authorization": f"{'Bearer' if platform == 'slack' else 'Bot'} {token}"}
    async with aiohttp.ClientSession(
        connector=connector, timeout=aiohttp.ClientTimeout(total=30), trust_env=False
    ) as session:
        yield session, {"headers": headers, "proxy": route.http_proxy_url, "allow_redirects": False}


async def _request(session: Any, options: dict[str, Any], method: str, url: str, payload: Any = None) -> dict[str, Any]:
    kwargs = dict(options)
    if payload is not None:
        kwargs["json"] = payload
    async with session.request(method, url, **kwargs) as response:
        data = await response.json()
        if response.status not in {200, 201} or not isinstance(data, dict):
            raise _Refused(_SEND_FAILED)
        return data


def _key(platform: str, ids: list[str], thread: str | None, media_files: Any) -> bytes | None:
    if not any(e2e.outbound_must_encrypt(platform, cid, thread) for cid in ids):
        return None
    # Reject the WHOLE request before even its text can be posted.
    if media_files:
        raise _Refused("mordred_encrypt_attachments_unsupported")
    for cid in ids:
        kid = e2e.outbound_key_id(platform, cid, thread)
        if kid or e2e.bound_channel_key_ids(platform, cid) or e2e.is_encrypted_thread(platform, cid, thread):
            key = e2e.reply_key(kid)
            if key is None:
                raise _Refused(_UNAVAILABLE)
            return key
    raise _Refused(_UNAVAILABLE)


async def _post_text(
    session: Any,
    options: dict[str, Any],
    platform: str,
    chat: str,
    thread: str | None,
    message: str,
    key: bytes,
    result_chat: str,
) -> dict[str, Any]:
    try:
        chunks = e2e.encrypt_reply(
            key,
            message,
            39000 if platform == "slack" else 2000,
            e2e.SLACK_MENTION_PREFIX_RE if platform == "slack" else e2e.DISCORD_MENTION_PREFIX_RE,
            platform=platform,
            chat_id=chat,
            thread_root=thread,
        )
        message_id = None
        for chunk in chunks:
            if platform == "slack":
                url = "https://slack.com/api/chat.postMessage"
                payload = {"channel": chat, "text": chunk, "mrkdwn": False}
                if thread:
                    payload["thread_ts"] = thread
            else:
                url = f"https://discord.com/api/v10/channels/{chat}/messages"
                payload = {"content": chunk}
            data = await _request(session, options, "POST", url, payload)
            if platform == "slack" and data.get("ok") is not True:
                raise _Refused(_SEND_FAILED)
            message_id = data.get("ts" if platform == "slack" else "id")
            if not isinstance(message_id, str) or not message_id:
                raise _Refused(_SEND_FAILED)
        return {"success": True, "platform": platform, "chat_id": result_chat, "message_id": message_id}
    except Exception:
        # Neither platform responses nor transport exceptions are safe to echo.
        # Already-posted chunks stay encrypted. Never delegate after a failure.
        raise _Refused(_SEND_FAILED) from None


async def _slack(pconfig: Any, chat: str, message: str, thread: str | None, media: Any) -> dict[str, Any] | None:
    if not _SLACK_CHANNEL.fullmatch(chat):
        if not _SLACK_USER.fullmatch(chat):
            raise _Refused(_CONTEXT_UNAVAILABLE)
        # Cron can address a user directly, unlike the tool which resolves DMs
        # before this seam. Check the actual conversation's binding either way.
        async with _client("slack", pconfig) as (session, options):
            data = await _request(
                session, options, "POST", "https://slack.com/api/conversations.open", {"users": [chat]}
            )
            resolved = (data.get("channel") or {}).get("id")
            if data.get("ok") is not True or not isinstance(resolved, str) or not _SLACK_CHANNEL.fullmatch(resolved):
                raise _Refused(_CONTEXT_UNAVAILABLE)
            key = _key("slack", [resolved], thread, media)
            if key is None:
                return None
            return await _post_text(session, options, "slack", resolved, thread, message, key, chat)
    key = _key("slack", [chat], thread, media)
    if key is None:
        return None
    async with _client("slack", pconfig) as (session, options):
        return await _post_text(session, options, "slack", chat, thread, message, key, chat)


async def _discord(pconfig: Any, chat: str, message: str, thread: str | None, media: Any) -> dict[str, Any] | None:
    tid = thread or chat
    if not _SNOWFLAKE.fullmatch(tid) or not _SNOWFLAKE.fullmatch(chat):
        raise _Refused(_CONTEXT_UNAVAILABLE)
    async with _client("discord", pconfig) as (session, options):
        # Resolve EVERY destination before delegation: a previously unknown
        # thread may inherit its parent's binding. Lookup failure is not unbound.
        info = await _request(session, options, "GET", f"https://discord.com/api/v10/channels/{tid}")
        kind = info.get("type")
        parent = info.get("parent_id")
        if info.get("id") != tid or type(kind) is not int:
            raise _Refused(_CONTEXT_UNAVAILABLE)
        if parent is not None and (not isinstance(parent, str) or not _SNOWFLAKE.fullmatch(parent)):
            raise _Refused(_CONTEXT_UNAVAILABLE)
        if kind in _THREAD_TYPES and not parent:
            raise _Refused(_CONTEXT_UNAVAILABLE)
        if thread and (kind not in _THREAD_TYPES or chat not in {tid, parent}):
            raise _Refused(_CONTEXT_UNAVAILABLE)
        ids = list(dict.fromkeys(cid for cid in (tid, chat, parent) if cid))
        key = _key("discord", ids, thread, media)
        if key is None:
            return None
        # Forum/media posts create an as-yet unknown thread: no v3 AAD can be
        # bound to it before posting. Existing forum threads remain supported.
        if kind in {15, 16}:
            raise _Refused(_CONTEXT_UNAVAILABLE)
        return await _post_text(session, options, "discord", tid, thread, message, key, chat)


def install_standalone_guard() -> None:
    """Import and guard the common seam before tool or cron can send.

    Supported Hermes 0.13 and 0.19 use the same signature and look it up at call
    time (including cron's local import). Refuse startup on seam drift instead
    of advertising E2E while retaining an unguarded fallback.
    """
    try:
        module: Any = importlib.import_module("tools.send_message_tool")
        original: Callable[..., Awaitable[Any]] = module._send_to_platform
        if getattr(original, "__mordred_standalone_guard__", False):
            return
        if not inspect.iscoroutinefunction(original):
            raise ValueError
        params = inspect.signature(original).parameters
        if tuple(params) != _PARAMETERS or any(
            p.kind != inspect.Parameter.POSITIONAL_OR_KEYWORD for p in params.values()
        ):
            raise ValueError
        if tuple(p.default for p in params.values()) != (inspect.Parameter.empty,) * 4 + (None, None, False):
            raise ValueError

        module._send_to_platform = _wrap_guard(original)
    except Exception:
        raise StandaloneGuardRefused("mordred_e2e: standalone send guard unavailable; refusing startup") from None


def _wrap_guard(original: Callable[..., Awaitable[Any]]) -> Callable[..., Awaitable[Any]]:
    @wraps(original)
    async def guarded(
        platform: Any,
        pconfig: Any,
        chat_id: Any,
        message: Any,
        thread_id: Any = None,
        media_files: Any = None,
        force_document: bool = False,
    ) -> Any:
        name = getattr(platform, "value", platform)
        if name in {"slack", "discord"}:
            try:
                if not isinstance(chat_id, str) or not chat_id or not isinstance(message, str):
                    raise _Refused(_CONTEXT_UNAVAILABLE)
                if thread_id is not None and (not isinstance(thread_id, str) or not thread_id):
                    raise _Refused(_CONTEXT_UNAVAILABLE)
                handler = _slack if name == "slack" else _discord
                result = await handler(pconfig, chat_id, message, thread_id, media_files)
            except _Refused as exc:
                return {"error": exc.code}
            except Exception:
                return {"error": _CONTEXT_UNAVAILABLE}
            if result is not None:
                return result
        return await original(platform, pconfig, chat_id, message, thread_id, media_files, force_document)

    guarded.__mordred_standalone_guard__ = True  # type: ignore[attr-defined]
    return guarded
