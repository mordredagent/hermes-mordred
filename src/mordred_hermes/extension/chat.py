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

from ..recall.turn_context import set_note_after_block
from . import answer_guard

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

# The extension chat's toolsets when ``platform_toolsets`` has no ``extension`` entry:
# the user's memory and lookups, nothing that acts on the machine. Every registered
# tool (terminal, files, browser, messaging, ...) used to be offered, which buried a
# small local model's prompt (16k tokens) and the memory Mordred adds to each turn
# (mordred_hermes.recall.turn_context), after which the session is a reader session
# where those tools are refused anyway.
# Skills are not offered either: their three tools were 1.3k of a 3.5k-token prompt
# for a 2B model, which called them for unrelated questions.
DEFAULT_TOOLSETS: tuple[str, ...] = ("mordred_recall", "mordred_telegram", "mordred_activity", "web")

# Appended to Hermes's system prompt for the extension chat. Written for any
# language: the reply follows the user's, and nothing here assumes one.
EXTENSION_RULES = """How to answer in this chat:
- Reply in the language of the user's latest message.
- You can act only through the tools listed. When asked for something none of them does \
(running commands, changing files, sending messages, ...), say plainly that you cannot do it \
here. Never write output, results or confirmations for something no tool did.
- Answer from this conversation, the memory and the tool results you were given. If none of \
them holds the answer, say you could not find it; do not guess names, numbers or dates.
- Keep the answer short."""

# Corrections asked of the model per turn when its answer fails a check
# (mordred_hermes.extension.answer_guard): each one is a short extra model call.
MAX_REPAIRS = 2

# The model is sent the last turns only. A small local model loses the question in a
# long transcript (21-25k tokens per turn on a dev Hermes, most of it history); the
# store keeps every turn, they are just not sent.
HISTORY_TURNS = 6

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
            sent = model_history(history)
            plan = answer_guard.plan_turn(content, getattr(agent, "valid_tool_names", None) or (), sent)
            note = answer_guard.note(plan)
            set_note_after_block(_EXT_SESSION_ID, note)
            fut, queue, done = _spawn_turn(agent, message + note, sent, loop, persist=message)

            deadline = loop.time() + turn_timeout
            # The answer is checked before it is shown, so it is collected, not streamed.
            parts: list[str] = []
            try:
                while (item := await _next_item(queue, deadline, loop)) is not done:
                    parts.append(item)
            except TimeoutError:
                _abandon_turn(state, queue, done, fut, extension_history, history, sent)
                logger.warning(
                    "extension chat: turn %d timed out after %.0fs; agent will be rebuilt", turn, turn_timeout
                )
                raise RuntimeError(f"turn_timeout: no completion within {turn_timeout:.0f}s") from None
            except (GeneratorExit, asyncio.CancelledError):
                # The consumer is gone (client disconnected, its task cancelled). The
                # worker thread can't be killed, so the turn finishes detached: its
                # reply stays recoverable via history_get after reconnect (unchecked:
                # a correction needs the model, and nobody is waiting for it).
                _abandon_turn(state, queue, done, fut, extension_history, history, sent)
                logger.info("extension chat: client disconnected mid-turn %d; turn continues detached", turn)
                raise

            result = await fut  # propagate any exception from the agent run
            answer = (result.get("final_response") if isinstance(result, dict) else "") or "".join(parts)
            try:
                checked = await _checked_answer(
                    agent, plan, content, answer, result, sent, loop, deadline, page=bool(context.get("selection"))
                )
            except asyncio.CancelledError:
                # Gone while a correction ran: keep the turn as the model first answered it.
                _persist_and_final(result, extension_history, False, history, sent)
                raise
            if isinstance(result, dict) and checked != (result.get("final_response") or ""):
                # A corrected answer, or one only the stream carried.
                result = _with_answer(result, checked)
            final = _persist_and_final(result, extension_history, False, history, sent)
            if final:
                yield final

    return handler


def _spawn_turn(
    agent: Any, message: str, history: list[Any], loop: asyncio.AbstractEventLoop, persist: str | None = None
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
        return agent.run_conversation(
            message, conversation_history=history, stream_callback=stream_cb, persist_user_message=persist
        )

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


async def _checked_answer(
    agent: Any,
    plan: Any,
    question: str,
    answer: str,
    result: Any,
    sent: list[Any],
    loop: asyncio.AbstractEventLoop,
    deadline: float,
    *,
    page: bool = False,
) -> str:
    """``answer`` after the guard's checks: corrected by the model, else repaired in Python.

    The model sees the question as it did the first time (with the memory block, from
    the turn's ``api_content``) followed by its answer and what to fix, and nothing of
    the earlier conversation. A correction is kept only when it has fewer problems than
    the answer it replaces.
    """
    turn_msgs = result.get("messages") if isinstance(result, dict) else None
    asked = _turn_user_message(turn_msgs, question)
    api_copy = str(asked.get("api_content") or "")
    tools = _tool_texts(turn_msgs)
    if (
        not plan.action
        and answers_from_sources_only(agent)
        and not answer_guard.has_source(question, plan, memory_entries(api_copy), tools, page, bool(sent))
    ):
        # A small local model with nothing to answer from answers from what it half knows.
        logger.info("extension chat: nothing to answer from; saying so instead of the model's answer")
        return answer_guard.no_source_reply(plan)
    sources = [question, *(_text(m) for m in sent), api_copy, *tools]
    problems = answer_guard.review(answer, plan, sources)
    for attempt in range(MAX_REPAIRS):
        if not problems or loop.time() >= deadline:
            break
        logger.info("extension chat: answer fails %s; asking for a correction", [p.kind for p in problems])
        # Only this exchange: the question as first sent (memory block included) and the
        # answer. A long conversation here made a 2B model translate an older message.
        shown = {k: v for k, v in asked.items() if k in ("role", "content", "api_content")}
        fut, queue, done = _spawn_turn(
            agent,
            answer_guard.repair_request(problems, plan, attempt),
            [shown, {"role": "assistant", "content": answer}],
            loop,
        )
        try:
            while await _next_item(queue, deadline, loop) is not done:
                pass
            fixed = await fut
        except TimeoutError:
            break
        text = (fixed.get("final_response") if isinstance(fixed, dict) else "") or ""
        # Drop sentences about the answer ("this is the translation") the request was echoed into.
        text = answer_guard.without_meta(text) or text
        if not text.strip():
            break
        found = answer_guard.review(text, plan, sources)
        if any(p.kind == "number" for p in found):
            # A correction may fix the language and miscopy a number; fix the number here.
            text = answer_guard.fix_numbers(text, found)
            found = answer_guard.review(text, plan, sources)
        if len(found) < len(problems):
            answer, problems = text, found
    return answer_guard.last_resort(answer, problems, plan) if problems else answer


def answers_from_sources_only(agent: Any) -> bool:
    """Whether the chat's model is a local one, which answers only from the user's sources.

    A small model on this machine (a loopback server) knows too little to answer
    general questions; a larger model the user chose ("upgrade the chat AI") does.
    """
    from urllib.parse import urlparse

    host = urlparse(str(getattr(agent, "base_url", "") or "")).hostname or ""
    return host in {"127.0.0.1", "localhost", "::1"} or host.endswith(".localhost")


def memory_entries(api_copy: str) -> str:
    """The memory block's entries in the model's copy of the question (without its header)."""
    from ..recall.turn_context import FOOTER

    start = api_copy.find("[Mordred memory")
    if start < 0:
        return ""
    end = api_copy.find(FOOTER, start)
    block = api_copy[start : end if end >= 0 else len(api_copy)]
    return block.split("\n", 1)[1] if "\n" in block else ""


def _turn_user_message(msgs: Any, question: str) -> dict[str, Any]:
    """This turn's user message in the run's transcript (it carries ``api_content``)."""
    for msg in reversed(msgs if isinstance(msgs, list) else []):
        if isinstance(msg, dict) and msg.get("role") == "user":
            return msg
    return {"role": "user", "content": question}


def _tool_texts(msgs: Any) -> list[str]:
    return [
        _text(m) for m in (msgs if isinstance(msgs, list) else []) if isinstance(m, dict) and m.get("role") == "tool"
    ]


def _with_answer(result: dict[str, Any], answer: str) -> dict[str, Any]:
    """``result`` with its final answer (and the transcript's last reply) replaced by ``answer``."""
    msgs = list(result.get("messages") or [])
    for i in range(len(msgs) - 1, -1, -1):
        if isinstance(msgs[i], dict) and msgs[i].get("role") == "assistant" and not msgs[i].get("tool_calls"):
            msgs[i] = {**msgs[i], "content": answer}
            break
    return {**result, "messages": msgs, "final_response": answer}


def _abandon_turn(
    state: dict[str, Any],
    queue: asyncio.Queue[Any],
    done: object,
    fut: asyncio.Future[Any],
    extension_history: Any,
    history_base: list[Any],
    sent: list[Any] | None = None,
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
            _persist_and_final(f.result(), extension_history, True, history_base, sent)
        except Exception:
            logger.exception("extension chat: failed to persist detached turn history")

    fut.add_done_callback(_persist_detached)


def _messages_added_this_turn(history_base: list[Any], msgs: list[Any]) -> list[Any]:
    """The messages ``msgs`` adds beyond its shared prefix with ``history_base``.

    Used only on the concurrent-merge path (the store moved while the turn ran).
    The old code sliced ``msgs[len(history_base):]``, which assumes ``msgs``
    begins with EXACTLY ``history_base`` — a real ``AIAgent`` that prepends a
    system message or compresses history breaks that, silently dropping the
    turn's user+assistant exchange or duplicating it. Taking the tail after the
    longest common prefix degrades safely: in the normal case
    (``msgs == history_base + new``) it is identical to the old slice, and when
    the prefix diverges it never DROPS the turn's new messages (the worse
    failure) — at most it re-appends a few already-present ones.
    """
    common = 0
    # strict=False: the two are expected to differ in length (base is meant to
    # be a prefix of msgs); we only walk the shared span to find the divergence.
    for base_msg, msg in zip(history_base, msgs, strict=False):
        if base_msg != msg:
            break
        common += 1
    return msgs[common:]


def model_history(history: list[Any]) -> list[Any]:
    """What the model is sent of ``history``: the last :data:`HISTORY_TURNS` exchanges.

    Earlier turns keep their words only: their tool calls and tool results are
    left out, and a search screen's block stays only in the newest message that
    has one (the one a follow-up is about).
    """
    from ..recall.turn_context import strip_search_block

    starts = [i for i, m in enumerate(history) if isinstance(m, dict) and m.get("role") == "user"]
    if not starts:
        return []
    window = history[starts[-HISTORY_TURNS] if len(starts) > HISTORY_TURNS else starts[0] :]
    with_search = [
        i for i, m in enumerate(window) if m.get("role") == "user" and strip_search_block(_text(m)) != _text(m)
    ]
    out: list[Any] = []
    for i, msg in enumerate(window):
        role = msg.get("role")
        if role == "user":
            content = msg.get("content")
            if isinstance(content, str) and with_search and i != with_search[-1]:
                content = strip_search_block(content)
            out.append({"role": "user", "content": content})
        elif role == "assistant" and _text(msg).strip():
            out.append({"role": "assistant", "content": msg.get("content")})
    return out


def _text(msg: dict[str, Any]) -> str:
    content = msg.get("content")
    return content if isinstance(content, str) else ""


def _persist_and_final(
    result: Any, extension_history: Any, streamed_any: bool, history_base: list[Any], sent: list[Any] | None = None
) -> str:
    """Persist the run's message history and return the final response to emit
    when nothing was streamed. Returns "" when there's nothing left to yield.

    ``history_base`` is the history the turn started from. In the usual,
    uncontended case the store still equals it and the turn's transcript is
    saved verbatim. If the store moved while the turn ran (a detached turn
    finished late, or this turn was itself detached and superseded), a plain
    overwrite would drop the other turn's exchange — append only this turn's
    new messages instead. ``sent`` is the part of the history the model was
    given (:func:`model_history`); the store keeps all of it.
    """
    if not isinstance(result, dict):
        return ""
    msgs = result.get("messages")
    if isinstance(msgs, list):
        current = extension_history.load_messages()
        if current == history_base and sent is None:
            extension_history.save_messages(msgs)
        else:
            # Only this turn's messages are added: to the whole history when the model
            # was sent a window of it, to the newer store when another turn moved it.
            added = _messages_added_this_turn(history_base if sent is None else sent, msgs)
            moved = current != history_base
            extension_history.save_messages([*(current if moved else history_base), *added])
            if moved:
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


def extension_toolsets() -> list[str]:
    """The toolsets offered to the extension chat: ``platform_toolsets.extension``, else :data:`DEFAULT_TOOLSETS`."""
    try:
        from hermes_cli.config import load_config
        from hermes_cli.tools_config import _get_platform_tools

        config = load_config()
        named = config.get("platform_toolsets")
        if isinstance(named, dict) and "extension" in named:
            return sorted(_get_platform_tools(config, "extension"))
    except Exception:
        logger.warning("extension chat: platform_toolsets unreadable; using the default toolsets")
    return list(DEFAULT_TOOLSETS)


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
        except Exception:  # noqa: S110 - optional default-model lookup; absence handled below
            pass

    toolsets = extension_toolsets()
    sig = (model, tuple(sorted((k, str(v)) for k, v in runtime.items() if k != "api_key")), tuple(toolsets))
    if state["agent"] is not None and state["sig"] == sig:
        return state["agent"]

    agent = AIAgent(
        model=model,
        **runtime,
        enabled_toolsets=toolsets,
        max_iterations=int(getattr(runner, "_max_iterations", 0) or 90),
        quiet_mode=True,
        verbose_logging=False,
        session_id=_EXT_SESSION_ID,
        platform="extension",
        ephemeral_system_prompt=EXTENSION_RULES,
        gateway_session_key=_EXT_SESSION_ID,
        session_db=getattr(runner, "_session_db", None),
        fallback_model=getattr(runner, "_fallback_model", None),
    )
    state["agent"] = agent
    state["sig"] = sig
    state["history"] = []
    logger.info(
        "extension chat: built agent (model=%s, toolsets=%s)", model or "<provider-default>", ",".join(toolsets)
    )
    return agent
