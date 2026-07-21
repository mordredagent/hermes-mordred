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
  * ``🔒ENC:v1/v2`` ciphertext → rewrite with the decrypted plaintext, so the
    agent reads cleartext while the wire stays encrypted.

PoC scope: inbound decrypt + key-exchange drop. Outbound reply re-encryption
(``transform_llm_output``) and the extension WebSocket server startup
(``register_platform``) land in the next phases.
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


def _platform_name(event: Any) -> str:
    """Normalized lowercase platform id ("slack"/"discord"/...) from an event.

    ``source.platform`` may be a ``Platform`` enum or a bare string; ``.value``
    unwraps the enum, ``str`` covers the string case.
    """
    src = getattr(event, "source", None)
    raw = getattr(src, "platform", None) or getattr(event, "platform", None)
    return str(getattr(raw, "value", raw) or "").lower()


async def _safe_send(adapter: Any, chat_id: str, content: str, metadata: dict[str, Any] | None) -> None:
    try:
        await adapter.send(chat_id, content, reply_to=None, metadata=metadata)
    except Exception as exc:
        logger.warning("mordred_e2e: needs-key notice send failed: %s", exc)


def _notify_needs_key(gateway: Any, event: Any) -> bool:
    """Reply to the originating channel/thread asking the sender to set up or
    obtain an encryption key. Best-effort; returns True if a send was scheduled.

    The send is scheduled on the running loop (the hook itself is sync and is
    invoked from the gateway's async dispatch path) so returning ``skip`` stays
    non-blocking.
    """
    import asyncio

    src = getattr(event, "source", None)
    platform = getattr(src, "platform", None)
    chat_id = getattr(src, "chat_id", None) or getattr(event, "chat_id", None)
    adapters = getattr(gateway, "adapters", None)
    adapter = adapters.get(platform) if (platform is not None and isinstance(adapters, dict)) else None
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


def _thread_ctx(event: Any) -> tuple[str, str, str | None]:
    """Best-effort (platform, chat_id, thread_root) from a MessageEvent.

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
    return _platform_name(event), str(chat_id), thread


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
    if gateway is not None:
        try:
            from . import outbound

            outbound.wrap_live_adapters(gateway)
        except Exception as e:  # noqa: BLE001 — never break dispatch
            logger.debug("mordred_e2e: live adapter wrap failed: %s", e)

    text = getattr(event, "text", None)
    if not isinstance(text, str) or not text:
        return None

    # 🔑REQ/GRANT are peer-to-peer between extensions — the agent must not see them.
    if e2e.is_key_exchange(text):
        return {"action": "skip", "reason": "mordred-key-exchange"}

    # Decrypt any 🔒ENC tokens using the local channel keyring (per-token key
    # selection by keyId). Fail-open: on any error, decrypt_inbound_keyed
    # returns (None, None) and we leave the message untouched.
    decrypted, kid = e2e.decrypt_inbound_keyed(text)
    if decrypted is not None and decrypted != text:
        # Remember this conversation is encrypted so the reply re-encrypts (§4).
        platform, chat_id, thread = _thread_ctx(event)
        if chat_id:
            e2e.mark_encrypted_thread(platform, chat_id, thread, kid)
        return {"action": "rewrite", "text": decrypted}

    # Nothing decrypted → the agent would otherwise read this as cleartext.
    # On platforms with mandatory E2E (Slack/Discord, all channels), refuse to
    # answer in cleartext: tell the sender to set up / obtain an encryption key
    # and skip, so the agent never processes the plaintext.
    if _platform_name(event) in _ENFORCE_ENCRYPTION_PLATFORMS:
        _notify_needs_key(gateway, event)
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
