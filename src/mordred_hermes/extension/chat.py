"""Bridge the Mordred extension chat to the real Hermes agent.

Produces a streaming ``chat_handler`` for ``mordred_hermes.extension.api`` that runs
the actual :class:`AIAgent` — the same agent class the messaging platforms use,
so extension chat passes through every Mordred hook (``pre_llm_call``,
``mordred_llm_guard``, network guard, tools). This is what makes the extension
a first-class Hermes client rather than a side channel (SPEC §2.1).

``run_conversation`` is synchronous and streams via a callback from a worker
thread; we marshal those deltas onto the event loop through a queue and re-yield
them from an async generator.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import AsyncIterator, Callable
from typing import Any

logger = logging.getLogger(__name__)

# One conversation for the extension popup. Multi-account is out of scope (§1.1).
_EXT_SESSION_ID = "mordred-extension"


def make_gateway_chat_handler(runner: Any) -> Callable[[str, dict[str, Any]], AsyncIterator[str]]:
    """Return an async-generator chat handler bound to a live GatewayRunner."""
    state: dict[str, Any] = {"agent": None, "sig": None, "history": []}
    lock = asyncio.Lock()

    async def handler(content: str, context: dict[str, Any]) -> AsyncIterator[str]:
        from . import history as extension_history

        # Serialize turns so concurrent messages can't corrupt history.
        async with lock:
            message = _augment_with_context(content, context)
            try:
                agent = _ensure_agent(runner, state)
            except Exception as exc:
                logger.exception("extension chat: agent build failed")
                raise RuntimeError(f"agent_unavailable: {exc}") from exc

            loop = asyncio.get_running_loop()
            queue: asyncio.Queue[Any] = asyncio.Queue()
            done = object()

            def stream_cb(delta: str) -> None:
                if delta:
                    loop.call_soon_threadsafe(queue.put_nowait, delta)

            # Encrypted-at-rest history is the source of truth: it persists across
            # restarts and is shared by every paired surface (§ chat persistence).
            history = extension_history.load_messages()

            def run() -> Any:
                return agent.run_conversation(message, conversation_history=history, stream_callback=stream_cb)

            fut = loop.run_in_executor(None, run)
            fut.add_done_callback(lambda _f: loop.call_soon_threadsafe(queue.put_nowait, done))

            streamed_any = False
            while True:
                item = await queue.get()
                if item is done:
                    break
                streamed_any = True
                yield item

            result = await fut  # propagate any exception from the agent run
            final = _persist_and_final(result, extension_history, streamed_any)
            if final:
                yield final

    return handler


def _persist_and_final(result: Any, extension_history: Any, streamed_any: bool) -> str:
    """Persist the run's message history and return the final response to emit
    when nothing was streamed. Returns "" when there's nothing left to yield."""
    if not isinstance(result, dict):
        return ""
    msgs = result.get("messages")
    if isinstance(msgs, list):
        extension_history.save_messages(msgs)
    if streamed_any:
        return ""
    return result.get("final_response") or ""


def _augment_with_context(content: str, context: dict[str, Any]) -> str:
    parts = []
    url = context.get("url")
    selection = context.get("selection")
    if url:
        parts.append(f"[active browser tab: {url}]")
    if selection:
        parts.append(f"[selected text on page]\n{selection}")
    parts.append(content)
    return "\n\n".join(parts)


def _ensure_agent(runner: Any, state: dict[str, Any]) -> Any:
    """Build (or reuse) the extension's AIAgent via the gateway's own routing."""
    from gateway.run import _resolve_gateway_model, _resolve_runtime_agent_kwargs
    from run_agent import AIAgent

    model = _resolve_gateway_model(None)
    runtime = _resolve_runtime_agent_kwargs()
    if not model and runtime.get("provider"):
        try:
            from hermes_cli.models import get_default_model_for_provider

            model = get_default_model_for_provider(runtime["provider"])
        except Exception:
            pass

    sig = (model, tuple(sorted((k, str(v)) for k, v in runtime.items() if k != "api_key")))
    if state["agent"] is not None and state["sig"] == sig:
        return state["agent"]

    agent = AIAgent(
        model=model,
        **runtime,
        max_iterations=int(getattr(runner, "_max_iterations", 0) or 90),
        quiet_mode=True,
        verbose_logging=False,
        session_id=_EXT_SESSION_ID,
        platform="extension",
        gateway_session_key=_EXT_SESSION_ID,
        session_db=getattr(runner, "_session_db", None),
        fallback_model=getattr(runner, "_fallback_model", None),
    )
    state["agent"] = agent
    state["sig"] = sig
    state["history"] = []
    logger.info("extension chat: built agent (model=%s)", model or "<provider-default>")
    return agent
