"""Outbound reply re-encryption (SPEC-v2 §4 reply-in-kind), as a plugin.

No hermes-agent hook carries channel/thread context on the *send* path
(``transform_llm_output`` only sees ``response_text``/``session_id``/``platform``),
so the reply-in-kind encryption is applied by wrapping each concrete platform
adapter's ``send`` at plugin load. The wrapper diverts ONLY encrypted-thread
replies to an encrypted send; every other message goes to the original,
unmodified ``send``.

Fail-closed: once a thread is known-encrypted, the wrapper never falls back to
plaintext — a missing key returns a failure (Slack also posts a locked notice),
exactly like the vendored fork's adapter edits.
"""

from __future__ import annotations

import contextlib
import logging
from typing import Any

from . import e2e

logger = logging.getLogger(__name__)

# Adapter class names we've already wrapped (idempotent install).
_patched: set[str] = set()

_LOCKED_NOTICE = "🔒 (暗号化できないため本文を送信できませんでした)"


def _SendResult() -> Any:
    from gateway.platforms.base import SendResult  # lazy: only inside a gateway

    return SendResult


# --- Slack -----------------------------------------------------------------


async def _slack_encrypted_send(self: Any, chat_id: str, content: str, thread_ts: str | None) -> Any:
    SendResult = _SendResult()
    client = self._get_client(chat_id)
    kid = e2e.thread_key_id("slack", chat_id, thread_ts)
    key = e2e.reply_key(kid)
    if key is None:
        kw = {"channel": chat_id, "text": _LOCKED_NOTICE, "mrkdwn": False}
        if thread_ts:
            kw["thread_ts"] = thread_ts
        with contextlib.suppress(Exception):
            await client.chat_postMessage(**kw)
        return SendResult(success=False, error="mordred_encrypt_unavailable")

    chunks = e2e.encrypt_reply(key, content, self.MAX_MESSAGE_LENGTH, e2e.SLACK_MENTION_PREFIX_RE)
    last = None
    for chunk in chunks:
        kw = {"channel": chat_id, "text": chunk, "mrkdwn": False}  # ciphertext: never mrkdwn
        if thread_ts:
            kw["thread_ts"] = thread_ts
        last = await client.chat_postMessage(**kw)

    if thread_ts:
        with contextlib.suppress(Exception):
            await self.stop_typing(chat_id)
    sent_ts = last.get("ts") if last else None
    if sent_ts:
        try:
            self._bot_message_ts.add(sent_ts)
            if thread_ts:
                self._bot_message_ts.add(thread_ts)
        except Exception:
            pass
    return SendResult(success=True, message_id=sent_ts, raw_response={"ts": sent_ts})


def _wrap_slack(cls: Any) -> None:
    orig_send = cls.send

    async def send(self, chat_id, content, reply_to=None, metadata=None):  # type: ignore[no-untyped-def]
        if getattr(self, "_app", None):
            try:
                thread_ts = self._resolve_thread_ts(reply_to, metadata)
                encrypted = e2e.is_encrypted_thread("slack", chat_id, thread_ts)
            except Exception:
                encrypted, thread_ts = False, None
            if encrypted:  # fail-closed: never delegate to the plaintext path
                return await _slack_encrypted_send(self, chat_id, content, thread_ts)
        return await orig_send(self, chat_id, content, reply_to, metadata)

    send.__mordred_wrapped__ = True  # type: ignore[attr-defined]
    cls.send = send


# --- Discord ---------------------------------------------------------------


async def _discord_encrypted_send(self: Any, chat_id: str, content: str, thread_id: str | None, ids: list[str]) -> Any:
    SendResult = _SendResult()
    tid = thread_id or chat_id
    channel = self._client.get_channel(int(tid))
    if not channel:
        channel = await self._client.fetch_channel(int(tid))
    if not channel:
        return SendResult(success=False, error=f"Channel {tid} not found")

    # Include the parent channel id in the key lookup (threads inherit the key).
    parent = None
    try:
        _p = getattr(channel, "parent_id", None) or getattr(getattr(channel, "parent", None), "id", None)
        if _p:
            parent = str(_p)
    except Exception:
        parent = None
    lookup = [x for x in {*ids, parent or ""} if x]

    kid = None
    for cid in lookup:
        kid = e2e.thread_key_id("discord", cid, None)
        if kid:
            break
    key = e2e.reply_key(kid)
    if key is None:
        return SendResult(success=False, error="mordred_encrypt_unavailable")

    mids: list[str] = []
    for chunk in e2e.encrypt_reply(key, content, self.MAX_MESSAGE_LENGTH, e2e.DISCORD_MENTION_PREFIX_RE):
        msg = await channel.send(chunk)
        mids.append(str(msg.id))
    return SendResult(success=True, message_id=mids[0] if mids else None, raw_response={"message_ids": mids})


def _wrap_discord(cls: Any) -> None:
    orig_send = cls.send

    async def send(self, chat_id, content, reply_to=None, metadata=None):  # type: ignore[no-untyped-def]
        if getattr(self, "_client", None):
            thread_id = (metadata or {}).get("thread_id")
            ids = [x for x in {str(chat_id), str(thread_id or "")} if x]
            try:
                encrypted = any(e2e.is_encrypted_thread("discord", x, None) for x in ids)
            except Exception:
                encrypted = False
            if encrypted:  # fail-closed
                return await _discord_encrypted_send(self, chat_id, content, thread_id, ids)
        return await orig_send(self, chat_id, content, reply_to, metadata)

    send.__mordred_wrapped__ = True  # type: ignore[attr-defined]
    cls.send = send


# --- install ---------------------------------------------------------------

_TARGETS = [
    ("slack", "gateway.platforms.slack.adapter", "SlackAdapter", _wrap_slack),
    ("discord", "gateway.platforms.discord.adapter", "DiscordAdapter", _wrap_discord),
    # Some builds ship platform adapters under plugins/platforms/*.
    ("slack", "plugins.platforms.slack.adapter", "SlackAdapter", _wrap_slack),
    ("discord", "plugins.platforms.discord.adapter", "DiscordAdapter", _wrap_discord),
]


_WRAPPERS = {"slack": _wrap_slack, "discord": _wrap_discord}


def wrap_live_adapters(gateway: Any) -> list[str]:
    """Wrap the ``send`` of the adapter classes the gateway ACTUALLY built.

    This is the reliable path. Guessing import paths does not work: the concrete
    Slack/Discord adapters are directory-based plugins loaded into a synthetic
    package (``hermes_plugins.slack_platform.adapter``) that only resolves inside
    a live gateway process, and the path differs between hermes builds. Patching
    a same-named class from some other importable module silently wraps a class
    nobody instantiates, so replies go out through the real, unwrapped adapter —
    in cleartext.

    ``GatewayRunner.adapters`` is ``Dict[Platform, BasePlatformAdapter]`` of the
    live instances, so ``type(adapter)`` is exactly the class that will send.
    Idempotent and cheap: safe to call on every inbound event.
    """
    installed: list[str] = []
    adapters = getattr(gateway, "adapters", None) or {}
    try:
        items = list(adapters.items())
    except Exception:  # noqa: BLE001
        return installed
    for plat, adapter in items:
        try:
            name = str(getattr(plat, "value", plat) or "").lower()
            wrap = _WRAPPERS.get(name)
            if wrap is None or adapter is None:
                continue
            cls = type(adapter)
            send = getattr(cls, "send", None)
            if send is None or getattr(send, "__mordred_wrapped__", False):
                _patched.add(name)
                continue
            wrap(cls)
            _patched.add(name)
            installed.append(name)
            logger.info(
                "mordred_e2e: wrapped %s.%s.send for outbound E2E", cls.__module__, cls.__name__
            )
        except Exception as e:  # noqa: BLE001 — never break dispatch
            logger.debug("mordred_e2e: could not wrap %s: %s", plat, e)
    return installed


def install_outbound_patches() -> list[str]:
    """Best-effort wrap of statically importable adapters (pre-gateway fallback).

    Kept for builds that DO expose the adapters as ordinary modules. The
    authoritative path is :func:`wrap_live_adapters`, driven from the live
    gateway once its adapters exist.
    """
    import importlib

    installed = []
    for platform, module_path, cls_name, wrap in _TARGETS:
        if platform in _patched:
            continue
        try:
            mod = importlib.import_module(module_path)
            cls = getattr(mod, cls_name, None)
            if cls is None:
                continue
            if getattr(cls.send, "__mordred_wrapped__", False):
                continue
            wrap(cls)
            installed.append(platform)
            logger.debug("mordred_e2e: wrapped %s.%s.send for outbound E2E", module_path, cls_name)
        except Exception as e:
            logger.debug("mordred_e2e: outbound wrap skipped for %s (%s): %s", platform, module_path, e)
    return installed
