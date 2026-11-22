"""Chat bridge: the async-generator handler must stream agent deltas and carry
conversation history across turns. We stub the agent so no LLM is needed."""

# ruff: noqa: RUF001 - messages as users type them, with full-width punctuation

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

    def run_conversation(self, message, conversation_history=None, stream_callback=None, persist_user_message=None):
        # Like Hermes: the returned history holds the words as typed, not the model's copy.
        message = persist_user_message if persist_user_message is not None else message
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
        def run_conversation(self, message, conversation_history=None, stream_callback=None, persist_user_message=None):
            # Like Hermes: the returned history holds the words as typed, not the model's copy.
            message = persist_user_message if persist_user_message is not None else message
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
        def run_conversation(self, message, conversation_history=None, stream_callback=None, persist_user_message=None):
            # Like Hermes: the returned history holds the words as typed, not the model's copy.
            message = persist_user_message if persist_user_message is not None else message
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
    """Cancelling the consumer mid-turn (client disconnect) must not lose the
    finished turn: its history is persisted for history_get after reconnect."""
    import threading

    gate = threading.Event()

    class _TwoPhase:
        def run_conversation(self, message, conversation_history=None, stream_callback=None, persist_user_message=None):
            # Like Hermes: the returned history holds the words as typed, not the model's copy.
            message = persist_user_message if persist_user_message is not None else message
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
        consumer = asyncio.ensure_future(_collect(handler("hi", {})))
        await asyncio.sleep(0.1)  # the turn is running and has produced "first-half"
        consumer.cancel()  # client disconnected mid-turn
        with pytest.raises(asyncio.CancelledError):
            await consumer
        gate.set()  # detached turn now runs to completion
        for _ in range(100):
            if _mem_history["messages"]:
                break
            await asyncio.sleep(0.02)
        return list(_mem_history["messages"])

    persisted = asyncio.run(scenario())
    assert persisted, "detached turn's history was never persisted"
    assert persisted[-1]["content"] == "first-halfsecond-half"


def test_stream_backpressure_bounded_queue(monkeypatch):
    """With a tiny queue bound, a flood of deltas must still arrive complete
    and in order (producer blocks instead of growing memory or dropping). The
    answer is checked before it is shown, so it arrives as one piece."""
    monkeypatch.setattr(extension_chat, "_QUEUE_MAXSIZE", 4)
    n = 200

    class _Flood:
        def run_conversation(self, message, conversation_history=None, stream_callback=None, persist_user_message=None):
            # Like Hermes: the returned history holds the words as typed, not the model's copy.
            message = persist_user_message if persist_user_message is not None else message
            for i in range(n):
                stream_callback(f"d{i};")
            return {"final_response": "", "messages": [], "completed": True}

    # Spy on the queue to prove the bound holds while the flood is in flight.
    depths: list[int] = []
    orig_spawn = extension_chat._spawn_turn

    def spy_spawn(agent, message, history, loop, persist=None):
        fut, queue, done = orig_spawn(agent, message, history, loop, persist)
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
    assert out == ["".join(f"d{i};" for i in range(n))]
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
        def run_conversation(self, message, conversation_history=None, stream_callback=None, persist_user_message=None):
            # Like Hermes: the returned history holds the words as typed, not the model's copy.
            message = persist_user_message if persist_user_message is not None else message
            stream_callback("slow-chunk")
            gate.wait(timeout=10)
            return {
                "final_response": "slow-answer",
                "messages": _msgs(conversation_history, message, "slow-answer"),
                "completed": True,
            }

    class _Fast:
        def run_conversation(self, message, conversation_history=None, stream_callback=None, persist_user_message=None):
            # Like Hermes: the returned history holds the words as typed, not the model's copy.
            message = persist_user_message if persist_user_message is not None else message
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
        consumer = asyncio.ensure_future(_collect(handler("first", {})))
        await asyncio.sleep(0.1)  # turn 1 is running
        consumer.cancel()  # client vanishes; turn 1 detaches
        with pytest.raises(asyncio.CancelledError):
            await consumer
        second = await _collect(handler("second", {}))  # reconnected client's turn wins the race
        gate.set()  # detached turn 1 finishes only now
        for _ in range(100):
            if len(_mem_history["messages"]) >= 4:
                break
            await asyncio.sleep(0.02)
        return second, list(_mem_history["messages"])

    second, persisted = asyncio.run(scenario())
    assert second == ["fast-answer"]
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


def test_the_extension_chat_offers_its_configured_toolsets_else_memory_and_lookups(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import hermes_cli.config as hermes_config
    import hermes_cli.tools_config as tools_config

    monkeypatch.setattr(hermes_config, "load_config", lambda: {"model": {}})
    assert extension_chat.extension_toolsets() == list(extension_chat.DEFAULT_TOOLSETS)
    assert "terminal" not in extension_chat.DEFAULT_TOOLSETS and "mordred_recall" in extension_chat.DEFAULT_TOOLSETS
    assert "skills" not in extension_chat.DEFAULT_TOOLSETS

    configured = {"platform_toolsets": {"extension": ["web"]}}
    monkeypatch.setattr(hermes_config, "load_config", lambda: configured)
    monkeypatch.setattr(tools_config, "_get_platform_tools", lambda config, platform: {"web", "skills"})
    assert extension_chat.extension_toolsets() == ["skills", "web"]


def _search(words: str, question: str) -> str:
    return f"[Mordred search: {words}]\nResults shown:\n- 2026-11-08 a headline\n[/Mordred search]\n\n{question}"


def test_the_model_is_sent_the_last_turns_only_and_the_store_keeps_every_turn(monkeypatch, _mem_history):
    turns = []
    for i in range(8):
        question = _search(f"w{i}", f"q{i}") if i in (5, 6) else f"q{i}"
        turns.append({"role": "user", "content": question})
        if i == 6:  # a turn that used a tool
            turns.append({"role": "assistant", "content": "", "tool_calls": [{"id": "c", "function": {"name": "t"}}]})
            turns.append({"role": "tool", "tool_call_id": "c", "content": "tool output"})
        turns.append({"role": "assistant", "content": f"a{i}"})
    _mem_history["messages"] = list(turns)
    fake = _FakeAgent()
    monkeypatch.setattr(extension_chat, "_ensure_agent", lambda runner, state: fake)
    handler = extension_chat.make_gateway_chat_handler(runner=object())

    asyncio.run(_collect(handler("next", {})))

    sent = fake.seen_histories[0]
    users = [m["content"] for m in sent if m["role"] == "user"]
    assert len(users) == extension_chat.HISTORY_TURNS
    assert users[0] == "q2"
    # Earlier turns keep their words: no tool traffic, a search block only in the newest such message.
    assert {m["role"] for m in sent} == {"user", "assistant"}
    assert "tool output" not in str(sent)
    assert users[3] == "q5" and users[4].startswith("[Mordred search: w6]")
    # The store keeps all of it and adds this turn.
    assert _mem_history["messages"] == [
        *turns,
        {"role": "user", "content": "next"},
        {"role": "assistant", "content": "Hello from agent"},
    ]


def test_the_extension_chat_gets_its_answering_rules(monkeypatch):
    import gateway.run as gateway_run
    import run_agent

    built = {}

    class _Agent:
        def __init__(self, **kwargs):
            built.update(kwargs)

    monkeypatch.setattr(run_agent, "AIAgent", _Agent)
    monkeypatch.setattr(gateway_run, "_resolve_gateway_model", lambda _m: "m")
    monkeypatch.setattr(gateway_run, "_resolve_runtime_agent_kwargs", lambda: {"provider": "custom"})
    extension_chat._ensure_agent(object(), {"agent": None, "sig": None})

    rules = built["ephemeral_system_prompt"]
    assert rules == extension_chat.EXTENSION_RULES
    # Language-neutral: the reply follows the user's language, none is named.
    assert "language of the user's latest message" in rules
    assert not any(name in rules for name in ("Japanese", "English", "日本語"))


def test_the_model_is_told_the_reply_language_after_the_question_and_the_store_is_not(monkeypatch, _mem_history):
    calls = []

    class _Agent(_FakeAgent):
        def run_conversation(self, message, persist_user_message=None, **kwargs):
            calls.append((message, persist_user_message))
            return super().run_conversation(message, persist_user_message=persist_user_message, **kwargs)

    monkeypatch.setattr(extension_chat, "_ensure_agent", lambda runner, state: _Agent())
    handler = extension_chat.make_gateway_chat_handler(runner=object())

    asyncio.run(_collect(handler("¿Cuánto costó?", {})))

    (sent, stored), *_ = calls
    assert sent.startswith("¿Cuánto costó?\n\n") and "(Reply in Spanish.)" in sent
    assert stored == "¿Cuánto costó?"
    assert _mem_history["messages"][0] == {"role": "user", "content": "¿Cuánto costó?"}


class _Scripted:
    """Answers each run with the next of ``answers``; records what it was sent."""

    def __init__(self, answers):
        self.answers = list(answers)
        self.calls = []
        self.valid_tool_names = {"mordred_memory_search"}

    def run_conversation(self, message, conversation_history=None, stream_callback=None, persist_user_message=None):
        self.calls.append((message, list(conversation_history or [])))
        answer = self.answers.pop(0)
        stored = persist_user_message if persist_user_message is not None else message
        msgs = [
            *list(conversation_history or []),
            {"role": "user", "content": stored, "api_content": message},
            {"role": "assistant", "content": answer},
        ]
        return {"final_response": answer, "messages": msgs, "completed": True}


def test_an_answer_in_the_wrong_language_is_corrected_before_it_is_shown(monkeypatch, _mem_history):
    agent = _Scripted(["The research budget is 2.4 million yen.", "El presupuesto es de 240 万 yenes."])
    monkeypatch.setattr(extension_chat, "_ensure_agent", lambda r, s: agent)
    handler = extension_chat.make_gateway_chat_handler(runner=object())

    out = asyncio.run(_collect(handler("¿Cuál es el presupuesto de investigación?", {})))

    assert out == ["El presupuesto es de 240 万 yenes."]
    (first, _), (fix, fix_history) = agent.calls
    assert "(Reply in Spanish.)" in first
    assert fix.startswith("[Mordred check]") and "in Spanish" in fix
    # The correction sees only this exchange: the question as first sent and the answer it replaces.
    assert fix_history == [
        {"role": "user", "content": "¿Cuál es el presupuesto de investigación?", "api_content": first},
        {"role": "assistant", "content": "The research budget is 2.4 million yen."},
    ]
    # The store keeps the question as typed and the corrected answer, not the correction request.
    assert _mem_history["messages"] == [
        {"role": "user", "content": "¿Cuál es el presupuesto de investigación?", "api_content": first},
        {"role": "assistant", "content": "El presupuesto es de 240 万 yenes."},
    ]


def test_a_claimed_action_that_survives_correction_becomes_a_plain_decline(monkeypatch, _mem_history):
    shown = "```\ntotal 3\nnotes.txt\n```"
    agent = _Scripted([f"```bash\nls\n```\n{shown}", shown, shown])
    monkeypatch.setattr(extension_chat, "_ensure_agent", lambda r, s: agent)
    handler = extension_chat.make_gateway_chat_handler(runner=object())

    out = asyncio.run(_collect(handler("ls コマンドを実行して結果を見せて", {})))

    assert len(agent.calls) == 1 + extension_chat.MAX_REPAIRS  # every correction was asked for, none helped
    assert out == [guard_cannot("ja")]
    assert _mem_history["messages"][-1]["content"] == guard_cannot("ja")


def test_a_good_answer_is_shown_as_is_with_one_model_call(monkeypatch, _mem_history):
    agent = _Scripted(["Kestrel 基板は 3 枚発注しました。"])
    monkeypatch.setattr(extension_chat, "_ensure_agent", lambda r, s: agent)
    handler = extension_chat.make_gateway_chat_handler(runner=object())

    assert asyncio.run(_collect(handler("Kestrel 基板は何枚発注した？", {}))) == ["Kestrel 基板は 3 枚発注しました。"]
    assert len(agent.calls) == 1


def guard_cannot(lang):
    from mordred_hermes.extension import answer_guard

    return answer_guard._CANNOT[lang]


def test_a_correction_that_fixes_the_language_and_miscopies_a_number_is_kept_with_the_number_fixed(
    monkeypatch, _mem_history
):
    agent = _Scripted(["来年度の研究予算は 240 万円です。", "El presupuesto fue de 240 millones de yenes."])
    monkeypatch.setattr(extension_chat, "_ensure_agent", lambda r, s: agent)
    handler = extension_chat.make_gateway_chat_handler(runner=object())

    out = asyncio.run(_collect(handler("¿Cuál es el presupuesto de investigación acordado? (240 万円)", {})))

    assert out == ["El presupuesto fue de 2,400,000 de yenes."]


class _Local(_Scripted):
    base_url = "http://127.0.0.1:8082/v1"


def test_a_local_model_with_nothing_to_answer_from_says_so(monkeypatch, _mem_history):
    from mordred_hermes.extension import answer_guard

    agent = _Local(["インドの首都はダラビドです。"])
    monkeypatch.setattr(extension_chat, "_ensure_agent", lambda r, s: agent)
    handler = extension_chat.make_gateway_chat_handler(runner=object())

    out = asyncio.run(_collect(handler("インドの首都はニューデリーでは？", {})))

    assert out == [answer_guard._NO_SOURCE["ja"]]
    assert len(agent.calls) == 1
    assert _mem_history["messages"][-1]["content"] == answer_guard._NO_SOURCE["ja"]


def test_a_local_model_answers_from_the_memory_it_was_given(monkeypatch, _mem_history):
    class _WithMemory(_Local):
        def run_conversation(self, message, **kwargs):
            block = "\n\n[Mordred memory — header]\n- Kestrel 基板を 3 枚発注\n[/Mordred memory]"
            return super().run_conversation(message + block, **kwargs)

    agent = _WithMemory(["Kestrel 基板は 3 枚発注しました。"])
    monkeypatch.setattr(extension_chat, "_ensure_agent", lambda r, s: agent)
    handler = extension_chat.make_gateway_chat_handler(runner=object())

    assert asyncio.run(_collect(handler("Kestrel 基板は何枚発注した？", {}))) == ["Kestrel 基板は 3 枚発注しました。"]


def test_a_remote_model_answers_general_questions(monkeypatch, _mem_history):
    agent = _Scripted(["インドの首都はニューデリーです。"])
    agent.base_url = "https://api.venice.ai/api/v1"
    monkeypatch.setattr(extension_chat, "_ensure_agent", lambda r, s: agent)
    handler = extension_chat.make_gateway_chat_handler(runner=object())

    assert asyncio.run(_collect(handler("インドの首都は？", {}))) == ["インドの首都はニューデリーです。"]
