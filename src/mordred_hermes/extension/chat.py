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
import threading
from collections.abc import AsyncIterator, Callable
from typing import Any

logger = logging.getLogger(__name__)

# One conversation for the extension popup. Multi-account is out of scope (§1.1).
_EXT_SESSION_ID = "mordred-extension"

# Streaming-queue bound: real backpressure instead of unbounded memory growth
# when the agent emits deltas faster than the websocket drains them.
_QUEUE_MAXSIZE = 256
# How long the agent's worker thread waits for queue space before dropping a
# delta — a guard against a dead event loop, not a normal-operation path.
_PUT_TIMEOUT = 60.0
# Wall-clock budget for one whole turn (streaming plus consumer drain time,
# not an agent-idle timeout): turns may legitimately run for minutes, but a
# hung turn must not hold the shared lock forever and block every client.
_DEFAULT_TURN_TIMEOUT = 900.0

# Keep strong references to detached-turn drainer tasks (RUF006): a task held
# only by the event loop can be garbage-collected mid-flight.
_background_tasks: set[asyncio.Task[None]] = set()


def make_gateway_chat_handler(
    runner: Any, *, turn_timeout: float = _DEFAULT_TURN_TIMEOUT
) -> Callable[[str, dict[str, Any]], AsyncIterator[str]]:
    """Return an async-generator chat handler bound to a live GatewayRunner."""
    state: dict[str, Any] = {"agent": None, "sig": None, "history": [], "turn": 0}
    lock = asyncio.Lock()

    async def handler(content: str, context: dict[str, Any]) -> AsyncIterator[str]:
        from . import history as extension_history

        # Serialize turns so concurrent messages can't corrupt history.
        async with lock:
            state["turn"] = turn = state["turn"] + 1
            message = _augment_with_context(content, context)
            try:
                agent = _ensure_agent(runner, state)
            except Exception as exc:
                logger.exception("extension chat: agent build failed")
                raise RuntimeError(f"agent_unavailable: {exc}") from exc

            loop = asyncio.get_running_loop()
            # Encrypted-at-rest history is the source of truth: it persists across
            # restarts and is shared by every paired surface (§ chat persistence).
            history = extension_history.load_messages()
            fut, queue, done = _spawn_turn(agent, message, history, loop)

            deadline = loop.time() + turn_timeout
            streamed_any = False
            try:
                while (item := await _next_item(queue, deadline, loop)) is not done:
                    streamed_any = True
                    yield item
            except TimeoutError:
                _abandon_turn(state, queue, done, fut, extension_history, history)
                logger.warning(
                    "extension chat: turn %d timed out after %.0fs; agent will be rebuilt", turn, turn_timeout
                )
                raise RuntimeError(f"turn_timeout: no completion within {turn_timeout:.0f}s") from None
            except GeneratorExit:
                # Consumer closed us mid-stream (client disconnected). The
                # worker thread can't be killed, so the turn finishes detached:
                # its reply stays recoverable via history_get after reconnect.
                _abandon_turn(state, queue, done, fut, extension_history, history)
                logger.info("extension chat: client disconnected mid-turn %d; turn continues detached", turn)
                raise

            result = await fut  # propagate any exception from the agent run
            final = _persist_and_final(result, extension_history, streamed_any, history)
            if final:
                yield final

    return handler


def _spawn_turn(
    agent: Any, message: str, history: list[Any], loop: asyncio.AbstractEventLoop
) -> tuple[asyncio.Future[Any], asyncio.Queue[Any], object]:
    """Run one agent turn on a worker thread, streaming deltas into a bounded
    queue. The returned ``done`` sentinel is enqueued when the run finishes."""
    queue: asyncio.Queue[Any] = asyncio.Queue(maxsize=_QUEUE_MAXSIZE)
    done = object()
    gave_up = threading.Event()

    def stream_cb(delta: str) -> None:
        if not delta or gave_up.is_set():
            return
        # Block the agent's worker thread (never the event loop) until the
        # consumer drains — bounded queue = real backpressure.
        f = asyncio.run_coroutine_threadsafe(queue.put(delta), loop)
        try:
            f.result(timeout=_PUT_TIMEOUT)
        except Exception:
            f.cancel()
            # A timed-out put means the loop is wedged, not merely slow —
            # give up on streaming instead of stalling the worker thread
            # _PUT_TIMEOUT per remaining delta.
            gave_up.set()

    def run() -> Any:
        return agent.run_conversation(message, conversation_history=history, stream_callback=stream_cb)

    fut = loop.run_in_executor(None, run)
    # put() (vs put_nowait) so a momentarily-full queue can't drop the
    # sentinel; the callback runs on the loop thread.
    fut.add_done_callback(lambda _f: loop.create_task(queue.put(done)))
    return fut, queue, done


async def _next_item(queue: asyncio.Queue[Any], deadline: float, loop: asyncio.AbstractEventLoop) -> Any:
    """Next streamed item, or ``TimeoutError`` once ``deadline`` passes."""
    remaining = deadline - loop.time()
    if remaining <= 0:
        raise TimeoutError
    return await asyncio.wait_for(queue.get(), timeout=remaining)


def _abandon_turn(
    state: dict[str, Any],
    queue: asyncio.Queue[Any],
    done: object,
    fut: asyncio.Future[Any],
    extension_history: Any,
    history_base: list[Any],
) -> None:
    """Detach a turn whose consumer is gone (timeout or client disconnect).

    Nothing can cancel ``run_conversation`` mid-flight, so instead: force a
    fresh agent for the next turn (the detached thread keeps the old object),
    keep draining the queue so ``stream_cb`` never wedges the worker thread on
    a full queue, and persist the finished history once the run completes —
    ``_persist_and_final`` merges instead of overwriting if a newer turn moved
    the store meanwhile, so neither exchange is lost.
    """
    state["agent"] = None
    state["sig"] = None

    async def _drain() -> None:
        while await queue.get() is not done:
            pass

    task = asyncio.ensure_future(_drain())
    _background_tasks.add(task)
    task.add_done_callback(_background_tasks.discard)

    def _persist_detached(f: asyncio.Future[Any]) -> None:
        if f.cancelled():
            return
        exc = f.exception()
        if exc is not None:
            logger.warning("extension chat: detached turn failed: %s", exc)
            return
        try:
            _persist_and_final(f.result(), extension_history, True, history_base)
        except Exception:
            logger.exception("extension chat: failed to persist detached turn history")

    fut.add_done_callback(_persist_detached)


def _persist_and_final(result: Any, extension_history: Any, streamed_any: bool, history_base: list[Any]) -> str:
    """Persist the run's message history and return the final response to emit
    when nothing was streamed. Returns "" when there's nothing left to yield.

    ``history_base`` is the history the turn started from. In the usual,
    uncontended case the store still equals it and the turn's transcript is
    saved verbatim. If the store moved while the turn ran (a detached turn
    finished late, or this turn was itself detached and superseded), a plain
    overwrite would drop the other turn's exchange — append only this turn's
    new messages instead.
    """
    if not isinstance(result, dict):
        return ""
    msgs = result.get("messages")
    if isinstance(msgs, list):
        current = extension_history.load_messages()
        if current == history_base:
            extension_history.save_messages(msgs)
        else:
            extension_history.save_messages([*current, *msgs[len(history_base) :]])
            logger.info("extension chat: merged turn history over a concurrent update")
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
