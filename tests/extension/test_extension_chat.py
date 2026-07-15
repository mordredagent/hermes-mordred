"""Chat bridge: the async-generator handler must stream agent deltas and carry
conversation history across turns. We stub the agent so no LLM is needed."""

from __future__ import annotations

import asyncio

import pytest

from mordred_hermes.extension import extension_chat, extension_history


@pytest.fixture(autouse=True)
def _mem_history(monkeypatch):
    """In-memory history store so chat persistence is testable without a pairing."""
    store: dict[str, list] = {"messages": []}
    monkeypatch.setattr(extension_history, "load_messages", lambda: list(store["messages"]))
    monkeypatch.setattr(extension_history, "save_messages", lambda m: store.update(messages=list(m)))
    return store


class _FakeAgent:
    def __init__(self):
        self.seen_histories = []

    def run_conversation(self, message, conversation_history=None, stream_callback=None):
        self.seen_histories.append(list(conversation_history or []))
        if stream_callback:
            for piece in ("Hello ", "from ", "agent"):
                stream_callback(piece)
        new_history = [
            *list(conversation_history or []),
            {"role": "user", "content": message},
            {"role": "assistant", "content": "Hello from agent"},
        ]
        return {"final_response": "Hello from agent", "messages": new_history, "completed": True}


async def _collect(agen):
    out = []
    async for chunk in agen:
        out.append(chunk)
    return out


def test_chat_streams_and_keeps_history(monkeypatch):
    fake = _FakeAgent()
    monkeypatch.setattr(extension_chat, "_ensure_agent", lambda runner, state: fake)
    handler = extension_chat.make_gateway_chat_handler(runner=object())

    async def scenario():
        first = await _collect(handler("hi", {}))
        second = await _collect(handler("again", {}))
        return first, second

    first, second = asyncio.run(scenario())
    assert "".join(first) == "Hello from agent"
    # Second turn must have received the accumulated history from the first.
    assert len(fake.seen_histories[1]) == 2
    assert "".join(second) == "Hello from agent"


def test_chat_falls_back_to_final_when_no_stream(monkeypatch):
    class _NoStream:
        def run_conversation(self, message, conversation_history=None, stream_callback=None):
            return {"final_response": "done", "messages": [], "completed": True}

    monkeypatch.setattr(extension_chat, "_ensure_agent", lambda runner, state: _NoStream())
    handler = extension_chat.make_gateway_chat_handler(runner=object())
    out = asyncio.run(_collect(handler("x", {})))
    assert out == ["done"]


def test_context_augmentation():
    msg = extension_chat._augment_with_context("summarize", {"url": "https://example.com", "selection": "hi"})
    assert "https://example.com" in msg
    assert "hi" in msg
    assert msg.endswith("summarize")


def test_turn_timeout_releases_lock(monkeypatch):
    """A hung agent turn must raise turn_timeout instead of holding the shared
    lock forever, and the next turn must be able to run immediately."""
    import threading

    release = threading.Event()

    class _Slow:
        def run_conversation(self, message, conversation_history=None, stream_callback=None):
            release.wait(timeout=10)
            return {"final_response": "late", "messages": [], "completed": True}

    monkeypatch.setattr(extension_chat, "_ensure_agent", lambda r, s: _Slow())
    handler = extension_chat.make_gateway_chat_handler(runner=object(), turn_timeout=0.2)

    async def scenario():
        loop = asyncio.get_running_loop()
        t0 = loop.time()
        with pytest.raises(RuntimeError, match="turn_timeout"):
            async for _ in handler("first", {}):
                pass
        elapsed = loop.time() - t0
        release.set()  # let the detached thread finish
        second = await asyncio.wait_for(_collect(handler("second", {})), timeout=5)
        return elapsed, second

    elapsed, second = asyncio.run(scenario())
    assert elapsed < 2, f"timeout took {elapsed:.1f}s — lock held too long"
    assert second == ["late"]


def test_disconnect_detaches_turn_and_persists_history(monkeypatch, _mem_history):
    """Closing the consumer mid-stream (client disconnect) must not lose the
    finished turn: its history is persisted for history_get after reconnect."""
    import threading

    gate = threading.Event()

    class _TwoPhase:
        def run_conversation(self, message, conversation_history=None, stream_callback=None):
            stream_callback("first-half")
            gate.wait(timeout=10)
            stream_callback("second-half")
            msgs = [
                {"role": "user", "content": message},
                {"role": "assistant", "content": "first-halfsecond-half"},
            ]
            return {"final_response": "first-halfsecond-half", "messages": msgs, "completed": True}

    monkeypatch.setattr(extension_chat, "_ensure_agent", lambda r, s: _TwoPhase())
    handler = extension_chat.make_gateway_chat_handler(runner=object())

    async def scenario():
        agen = handler("hi", {})
        first = await agen.__anext__()
        await agen.aclose()  # client disconnected mid-stream
        gate.set()  # detached turn now runs to completion
        for _ in range(100):
            if _mem_history["messages"]:
                break
            await asyncio.sleep(0.02)
        return first, list(_mem_history["messages"])

    first, persisted = asyncio.run(scenario())
    assert first == "first-half"
    assert persisted, "detached turn's history was never persisted"
    assert persisted[-1]["content"] == "first-halfsecond-half"


def test_stream_backpressure_bounded_queue(monkeypatch):
    """With a tiny queue bound, a flood of deltas must still arrive complete
    and in order (producer blocks instead of growing memory or dropping)."""
    monkeypatch.setattr(extension_chat, "_QUEUE_MAXSIZE", 4)
    n = 200

    class _Flood:
        def run_conversation(self, message, conversation_history=None, stream_callback=None):
            for i in range(n):
                stream_callback(f"d{i};")
            return {"final_response": "", "messages": [], "completed": True}

    # Spy on the queue to prove the bound holds while the flood is in flight.
    depths: list[int] = []
    orig_spawn = extension_chat._spawn_turn

    def spy_spawn(agent, message, history, loop):
        fut, queue, done = orig_spawn(agent, message, history, loop)
        orig_get = queue.get

        async def get_spy():
            depths.append(queue.qsize())
            return await orig_get()

        queue.get = get_spy  # type: ignore[method-assign]
        return fut, queue, done

    monkeypatch.setattr(extension_chat, "_spawn_turn", spy_spawn)
    monkeypatch.setattr(extension_chat, "_ensure_agent", lambda r, s: _Flood())
    handler = extension_chat.make_gateway_chat_handler(runner=object())
    out = asyncio.run(_collect(handler("x", {})))
    assert out == [f"d{i};" for i in range(n)]
    assert depths and max(depths) <= 4, f"queue grew past its bound: {max(depths)}"


def test_detached_turn_merges_with_superseding_turn(monkeypatch, _mem_history):
    """Reconnect race: the client vanishes mid-turn, reconnects, and completes
    a NEW turn while the detached one is still running. When the detached turn
    finally finishes, neither exchange may be lost from the persisted history."""
    import threading

    gate = threading.Event()

    def _msgs(base, message, answer):
        return [
            *list(base or []),
            {"role": "user", "content": message},
            {"role": "assistant", "content": answer},
        ]

    class _SlowFirst:
        def run_conversation(self, message, conversation_history=None, stream_callback=None):
            stream_callback("slow-chunk")
            gate.wait(timeout=10)
            return {
                "final_response": "slow-answer",
                "messages": _msgs(conversation_history, message, "slow-answer"),
                "completed": True,
            }

    class _Fast:
        def run_conversation(self, message, conversation_history=None, stream_callback=None):
            stream_callback("fast-chunk")
            return {
                "final_response": "fast-answer",
                "messages": _msgs(conversation_history, message, "fast-answer"),
                "completed": True,
            }

    agents = [_SlowFirst(), _Fast()]
    monkeypatch.setattr(extension_chat, "_ensure_agent", lambda r, s: agents.pop(0))
    handler = extension_chat.make_gateway_chat_handler(runner=object())

    async def scenario():
        agen = handler("first", {})
        assert await agen.__anext__() == "slow-chunk"
        await agen.aclose()  # client vanishes; turn 1 detaches
        second = await _collect(handler("second", {}))  # reconnected client's turn wins the race
        gate.set()  # detached turn 1 finishes only now
        for _ in range(100):
            if len(_mem_history["messages"]) >= 4:
                break
            await asyncio.sleep(0.02)
        return second, list(_mem_history["messages"])

    second, persisted = asyncio.run(scenario())
    assert second == ["fast-chunk"]
    contents = [m["content"] for m in persisted]
    assert "fast-answer" in contents, "superseding turn's exchange lost"
    assert "slow-answer" in contents, "detached turn's exchange lost"


def test_messages_added_this_turn_normal_case_is_the_tail():
    """msgs == history_base + new: identical to the old positional slice."""
    base = [{"role": "user", "content": "a"}, {"role": "assistant", "content": "b"}]
    new = [{"role": "user", "content": "c"}, {"role": "assistant", "content": "d"}]
    assert extension_chat._messages_added_this_turn(base, [*base, *new]) == new


def test_messages_added_this_turn_never_drops_when_prefix_diverges():
    """A real agent that PREPENDS a system message (or compresses history) makes
    msgs NOT start with history_base. The old slice would silently drop the
    turn's user+assistant exchange; the common-prefix helper must not — it
    returns everything from the first divergence, so no new message is lost."""
    base = [{"role": "user", "content": "a"}, {"role": "assistant", "content": "b"}]
    prepended = [{"role": "system", "content": "sys"}, *base, {"role": "user", "content": "c"}]
    added = extension_chat._messages_added_this_turn(base, prepended)
    # The turn's genuinely-new message survives (drop was the dangerous failure).
    assert {"role": "user", "content": "c"} in added
    # And the old slice would have dropped it: msgs[len(base):] == [msgs[2], msgs[3]]
    assert prepended[len(base) :] != added


def test_messages_added_this_turn_identical_returns_empty():
    base = [{"role": "user", "content": "a"}]
    assert extension_chat._messages_added_this_turn(base, list(base)) == []


def test_messages_added_this_turn_empty_base_returns_all():
    msgs = [{"role": "user", "content": "a"}, {"role": "assistant", "content": "b"}]
    assert extension_chat._messages_added_this_turn([], msgs) == msgs
