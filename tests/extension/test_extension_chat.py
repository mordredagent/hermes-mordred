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
