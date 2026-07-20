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
from typing import Any, Optional

from . import e2e

logger = logging.getLogger(__name__)


def _thread_ctx(event: Any) -> tuple[str, str, Optional[str]]:
    """Best-effort (platform, chat_id, thread_root) from a MessageEvent."""
    src = getattr(event, "source", None)
    platform = getattr(src, "platform", None) or getattr(event, "platform", "") or ""
    chat_id = getattr(src, "chat_id", None) or getattr(event, "chat_id", "") or ""
    thread = getattr(src, "thread_id", None)
    if thread is None:
        thread = getattr(event, "thread_id", None)
    return str(platform), str(chat_id), thread


def pre_gateway_dispatch(
    event: Any = None,
    gateway: Any = None,
    session_store: Any = None,
    **_kw: Any,
) -> Optional[dict]:
    """Decrypt inbound ciphertext / drop key-exchange, before the agent."""
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
    except Exception as e:  # noqa: BLE001 — never break plugin load
        logger.warning("mordred_e2e: outbound patch install failed: %s", e)
