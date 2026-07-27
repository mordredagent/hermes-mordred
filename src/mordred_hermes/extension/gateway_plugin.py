"""Mordred E2E transport as a pure hermes-agent plugin (no core fork).

The vendored fork wired Slack/Discord/Teams E2E by editing each platform
adapter (inbound decrypt) and ``gateway/run.py`` (start the extension server).
This module replaces the *inbound* half with a single ``pre_gateway_dispatch``
hook so the exact same behaviour runs on a stock ``hermes-agent`` install via
``pip install mordred-hermes`` — no upstream edits, no fork.

``pre_gateway_dispatch`` fires once per incoming ``MessageEvent`` after the
internal-event guard but BEFORE auth/pairing and agent dispatch, and may return:
  * ``{"action": "skip",    "reason": ...}`` — drop the message (no reply)
  * ``{"action": "rewrite", "text": ...}``  — replace ``event.text``, continue

which is exactly what the E2E transport needs:
  * ``🔑REQ/GRANT`` key-exchange control messages (peer-to-peer between
    extensions, SPEC-v2 §5) → skip, so the agent never reacts to them;
  * one complete, context-bound ``🔒ENC:v3`` command → authenticate it, then
    rewrite with decrypted plaintext, so the agent reads cleartext while the
    wire stays encrypted. Legacy versions and arbitrary surrounding plaintext
    are rejected on this gateway boundary;
  * before releasing plaintext, verify and record a live fail-closed outbound
    reply path for the same platform/channel/thread.
"""

from __future__ import annotations

import logging
from typing import Any

from . import e2e

logger = logging.getLogger(__name__)

# Platforms where end-to-end encryption is mandatory across ALL channels:
# an inbound message the plugin cannot decrypt (plaintext, or ciphertext whose
# key we do not hold) is never handed to the agent in cleartext. Instead the
# sender is told to set up / obtain an encryption key (see _notify_needs_key).
_ENFORCE_ENCRYPTION_PLATFORMS = frozenset({"slack", "discord"})

_NEEDS_KEY_NOTICE = (
    "🔒 暗号化されていないメッセージには応答できません。"
    "拡張機能で暗号化キーを設定または取得のうえ、暗号化して再送してください。"
)

# Strong refs to fire-and-forget notice sends: without this the event loop only
# holds a weak reference and may garbage-collect the task mid-flight (RUF006).
_bg_tasks: set[Any] = set()
_INVALID_PROFILE = "\x00mordred-invalid-profile"
_MISSING = object()


def _platform_name(event: Any) -> str:
    """Normalized lowercase platform id ("slack"/"discord"/...) from an event.

    ``source.platform`` may be a ``Platform`` enum or a bare string; ``.value``
    unwraps the enum, ``str`` covers the string case.
    """
    src = getattr(event, "source", None)
    raw = getattr(src, "platform", None) or getattr(event, "platform", None)
    return str(getattr(raw, "value", raw) or "").lower()


def _profile_name(event: Any) -> str | None:
    """Return the multiplex profile stamped on ``event.source``.

    Hermes versions before multiplexing simply omit the field. A malformed or
    hostile profile value gets an impossible sentinel so adapter lookup fails
    closed instead of falling back to the active/default bot.
    """
    try:
        src = getattr(event, "source", None)
        raw = getattr(src, "profile", None)
        if raw is None:
            return None
        if not isinstance(raw, str):
            return _INVALID_PROFILE
        return raw.strip() or None
    except BaseException:
        return _INVALID_PROFILE


async def _safe_send(adapter: Any, chat_id: str, content: str, metadata: dict[str, Any] | None) -> None:
    try:
        await adapter.send(chat_id, content, reply_to=None, metadata=metadata)
    except Exception as exc:
        logger.warning("mordred_e2e: needs-key notice send failed: %s", exc)


def _notify_needs_key(gateway: Any, event: Any, outbound: Any, profile: str | None) -> bool:
    """Reply to the originating channel/thread asking the sender to set up or
    obtain an encryption key. Best-effort; returns True if a send was scheduled.

    The send is scheduled on the running loop (the hook itself is sync and is
    invoked from the gateway's async dispatch path) so returning ``skip`` stays
    non-blocking.
    """
    import asyncio

    src = getattr(event, "source", None)
    chat_id = getattr(src, "chat_id", None) or getattr(event, "chat_id", None)
    adapter = (
        outbound.live_adapter_for(gateway, _platform_name(event), profile)
        if gateway is not None and outbound is not None
        else None
    )
    if adapter is None or not chat_id:
        return False

    thread = getattr(src, "thread_id", None) or getattr(event, "thread_id", None)
    metadata: dict[str, Any] | None = None
    if thread:
        # Slack threads reply via thread_ts; Discord via thread_id.
        metadata = {"thread_ts": thread} if _platform_name(event) == "slack" else {"thread_id": thread}

    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:  # no running loop (e.g. unit test calling the hook directly)
        return False
    task = loop.create_task(_safe_send(adapter, str(chat_id), _NEEDS_KEY_NOTICE, metadata))
    _bg_tasks.add(task)
    task.add_done_callback(_bg_tasks.discard)
    return True


def _thread_ctx(event: Any) -> tuple[str, str, str | None, str | None]:
    """Best-effort platform/channel/thread/parent context from a MessageEvent.

    The platform MUST come from :func:`_platform_name` (which unwraps the
    ``Platform`` enum via ``.value``). ``str(Platform.SLACK)`` is
    ``"Platform.SLACK"``, not ``"slack"`` — marking a thread under that repr
    while the outbound wrappers look it up by the literal ``"slack"`` silently
    disables reply-in-kind, sending the agent's answer in CLEARTEXT into an
    encrypted channel.
    """
    src = getattr(event, "source", None)
    chat_id = getattr(src, "chat_id", None) or getattr(event, "chat_id", "") or ""
    thread = getattr(src, "thread_id", None)
    if thread is None:
        thread = getattr(event, "thread_id", None)
    parent = getattr(src, "parent_chat_id", None)
    if parent is None:
        parent = getattr(event, "parent_chat_id", None)
    thread_root = str(thread) if thread not in (None, "") else None
    parent_chat_id = str(parent) if parent not in (None, "") else None
    return _platform_name(event), str(chat_id), thread_root, parent_chat_id


def _command_aad_ctx(
    event: Any,
    routed_context: tuple[str, str, str | None, str | None],
) -> tuple[str, str, str | None]:
    """Derive the context the sender knew before Discord auto-threading.

    Discord creates a reply thread before ``pre_gateway_dispatch``. The routed
    ``SessionSource`` then points at the new thread even though the extension
    encrypted the command while posting in its parent channel. Both supported
    Hermes generations retain the original Discord message in
    ``event.raw_message``; 0.19 additionally stamps ``auto_thread_created``.

    Reply routing must keep using ``routed_context`` (the new thread), while
    command authentication uses the original parent channel with no thread.
    Ambiguous floor-version thread events without the original raw channel fail
    closed instead of guessing a context.
    """
    platform, chat_id, thread_root, parent_chat_id = routed_context
    if platform != "discord":
        return platform, chat_id, thread_root

    src = getattr(event, "source", None)
    explicit_auto = getattr(src, "auto_thread_created", _MISSING)
    if explicit_auto is not _MISSING and not isinstance(explicit_auto, bool):
        raise ValueError("invalid Discord auto-thread marker")

    raw_message = getattr(event, "raw_message", None)
    raw_channel = getattr(raw_message, "channel", None)
    raw_channel_value = getattr(raw_channel, "id", None)
    raw_channel_id = str(raw_channel_value) if raw_channel_value not in (None, "") else None

    parent = parent_chat_id or ""
    routed_thread = bool(parent and thread_root and chat_id == thread_root)
    inferred_auto = bool(routed_thread and raw_channel_id == parent and raw_channel_id != chat_id)

    if explicit_auto is True:
        if not inferred_auto:
            raise ValueError("inconsistent Discord auto-thread context")
        return platform, parent, None
    if explicit_auto is False and inferred_auto:
        raise ValueError("inconsistent Discord auto-thread marker")
    if inferred_auto:
        return platform, parent, None

    if routed_thread and explicit_auto is _MISSING:
        if raw_channel_id is None:
            raise ValueError("ambiguous Discord thread context")
        if raw_channel_id != chat_id:
            raise ValueError("inconsistent Discord thread context")

    return platform, chat_id, thread_root


def _rewrite_encrypted(
    context: tuple[str, str, str | None, str | None],
    gateway: Any,
    outbound: Any,
    decrypted: str,
    kid: str | None,
    replay: e2e.ReplayClaim | None,
    profile: str | None,
) -> dict[str, Any]:
    """Authorize outbound encryption before releasing decrypted text."""
    try:
        platform, chat_id, thread, _parent_chat_id = context
        if not platform or not chat_id or not kid:
            logger.error("mordred_e2e: refusing encrypted message because reply context is incomplete")
            return {"action": "skip", "reason": "mordred-outbound-encryption-unavailable"}
        if gateway is None or outbound is None or not outbound.live_adapter_is_wrapped(gateway, platform, profile):
            logger.error(
                "mordred_e2e: refusing encrypted %s message because its live outbound adapter is not wrapped",
                platform,
            )
            return {"action": "skip", "reason": "mordred-outbound-encryption-unavailable"}

        # Remember this conversation is encrypted so the reply re-encrypts
        # (§4). A context/registry failure must also stop before plaintext
        # reaches the agent.
        if not e2e.mark_encrypted_thread(platform, chat_id, thread, kid):
            logger.error("mordred_e2e: refusing encrypted message because reply context was not recorded")
            return {"action": "skip", "reason": "mordred-outbound-encryption-unavailable"}
    except BaseException:
        logger.error("mordred_e2e: encrypted outbound verification failed")
        return {"action": "skip", "reason": "mordred-outbound-encryption-unavailable"}

    # Replay state is committed only after the reply path and conversation
    # registry are ready. A transient unwrappable adapter must not consume a
    # legitimate command that was never released to the agent.
    try:
        if replay is None:
            raise ValueError("missing replay claim")
        if not e2e.claim_gateway_replay(replay):
            logger.warning("mordred_e2e: refusing replayed encrypted envelope")
            return {"action": "skip", "reason": "mordred-replayed-encrypted-envelope"}
    except BaseException:
        logger.error("mordred_e2e: encrypted replay-state verification failed")
        return {"action": "skip", "reason": "mordred-invalid-encrypted-envelope"}
    return {"action": "rewrite", "text": decrypted}


def pre_gateway_dispatch(
    event: Any = None,
    gateway: Any = None,
    session_store: Any = None,
    **_kw: Any,
) -> dict[str, Any] | None:
    """Decrypt inbound ciphertext / drop key-exchange, before the agent."""
    # The concrete platform adapters are directory-based plugins that only exist
    # once the gateway is up, so register() cannot reach them by import path.
    # Wrap the LIVE adapter classes here (idempotent) — otherwise the reply goes
    # out through the real, unwrapped send in cleartext.
    outbound = None
    profile = _profile_name(event)
    if gateway is not None:
        try:
            from . import outbound as outbound_module

            outbound_module.wrap_live_adapters(gateway, profile)
            outbound = outbound_module
        except BaseException:
            logger.warning("mordred_e2e: live adapter wrap failed")

    text = getattr(event, "text", None)
    if not isinstance(text, str) or not text:
        return None

    # 🔑REQ/GRANT are peer-to-peer between extensions — the agent must not see them.
    if e2e.is_key_exchange(text):
        return {"action": "skip", "reason": "mordred-key-exchange"}

    # Treat the whole wire value as one authenticated envelope. Only a
    # platform-valid leading mention prefix, one fully authenticated v3 token,
    # and trailing whitespace are accepted. In particular, never decrypt a
    # valid token embedded beside attacker-controlled plaintext.
    try:
        context = _thread_ctx(event)
        platform, chat_id, thread_root = _command_aad_ctx(event, context)
        parent_chat_id = context[3]
        decrypted, kid, replay = e2e.decrypt_gateway_envelope(
            text,
            platform,
            chat_id=chat_id,
            thread_root=thread_root,
            parent_chat_id=parent_chat_id,
        )
    except e2e.InvalidEncryptedEnvelope:
        logger.warning("mordred_e2e: refusing malformed or unauthenticated encrypted envelope")
        return {"action": "skip", "reason": "mordred-invalid-encrypted-envelope"}
    except BaseException:
        logger.error("mordred_e2e: encrypted envelope verification failed")
        return {"action": "skip", "reason": "mordred-invalid-encrypted-envelope"}

    if decrypted is not None:
        # Decrypting commits the agent to producing a reply for an encrypted
        # channel. Check/record the outbound path before plaintext is released.
        return _rewrite_encrypted(context, gateway, outbound, decrypted, kid, replay, profile)

    # Nothing decrypted → the agent would otherwise read this as cleartext.
    # On platforms with mandatory E2E (Slack/Discord, all channels), refuse to
    # answer in cleartext: tell the sender to set up / obtain an encryption key
    # and skip, so the agent never processes the plaintext.
    if _platform_name(event) in _ENFORCE_ENCRYPTION_PLATFORMS:
        _notify_needs_key(gateway, event, outbound, profile)
        return {"action": "skip", "reason": "mordred-encryption-required"}

    return None


def register(ctx: Any) -> None:
    """Plugin entry point (``hermes_agent.plugins`` group).

    Wires the full E2E transport with no core fork:
      * inbound decrypt / key-exchange drop  → ``pre_gateway_dispatch`` hook
      * outbound reply re-encryption         → platform ``send`` wrappers
    The browser-extension WebSocket server ships as the standalone
    ``hermes-mordred extension serve`` command (``extension.api``); it does not
    need the gateway process.
    """
    from ..privacy_check.hooks import check_plugin_integrity

    ctx.register_hook("on_session_start", check_plugin_integrity)
    ctx.register_hook("pre_gateway_dispatch", pre_gateway_dispatch)
    logger.debug("mordred_e2e: registered pre_gateway_dispatch hook")

    # Outbound: wrap each installed platform adapter's send (best-effort).
    try:
        from . import outbound

        installed = outbound.install_outbound_patches()
        if installed:
            logger.debug("mordred_e2e: outbound E2E wrapped for %s", ", ".join(installed))
    except Exception as e:
        logger.warning("mordred_e2e: outbound patch install failed: %s", e)
