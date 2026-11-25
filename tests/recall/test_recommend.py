"""The recommender over a plain-SQLite import store, with a scripted local model."""

from __future__ import annotations

import json
import sqlite3
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any, ClassVar

import pytest

from mordred_hermes.imports.records import Source, local_conv_uid
from mordred_hermes.imports.store import ImportStore
from mordred_hermes.recall import recommend, topics
from mordred_hermes.recall.headlines import HeadlineTarget
from tests.recall.test_topics import DAY, FPGA, GIF, NOW, SENT_AT, _chat

TARGET = HeadlineTarget("http://127.0.0.1:8082/v1", "bonsai")


@pytest.fixture
def store(tmp_path: Path) -> ImportStore:
    store = ImportStore(tmp_path / "mordred.db", sqlite3.connect)
    store.initialize(tmp_path)
    _chat(store, Source.CLAUDE_CODE, "fpga", "FPGA 推論エンジン", FPGA, start=SENT_AT)
    _chat(store, Source.CODEX, "gif", "GIF 作成", GIF, start=SENT_AT + DAY)
    _chat(
        store,
        Source.CLAUDE_CODE,
        "noise",
        "Noise",
        [(True, "<command-name>/model</command-name> 量子化"), (False, "量子化は了解です")],
        start=SENT_AT + 2 * DAY,
    )
    topics.build(store)
    return store


class _Model:
    """Streams each prompt's next scripted reply a few characters at a time, and keeps the prompts."""

    def __init__(self, *answers: str) -> None:
        self.answers = list(answers)
        self.prompts: list[str] = []
        self.sent = 0  # characters streamed so far

    def __call__(self, url: str, body: dict[str, Any], timeout: float) -> Iterator[str]:
        assert url == "http://127.0.0.1:8082/v1/chat/completions" and body["enable_thinking"] is False
        self.prompts.append(body["messages"][-1]["content"])
        answer = self.answers.pop(0) if self.answers else ""
        for start in range(0, len(answer), 3):
            self.sent = start + 3
            yield answer[start : start + 3]


def test_parse_keeps_known_refs_once_and_the_follow_up_words() -> None:
    answer = '<think>x</think>{"ref": "C2", "what": "「GIF のパレット量子化」"}\n{"ref": "C9", "what": "invented"}\n'
    answer += '{"ref": "C2", "what": "again"}\n{"more": ["パレット", "", 3]}'
    assert recommend.parse_answer(answer, ["C1", "C2"]) == ([("C2", "GIF のパレット量子化")], ["パレット"])


def test_a_pick_is_read_as_soon_as_its_line_closes() -> None:
    reader = recommend.AnswerReader(["C1", "C2"])
    assert reader.feed('{"ref": "C2", "what": "GIF の') == []
    assert reader.feed('パレット"}\n{"ref": "C1"') == [("C2", "GIF のパレット")]
    assert reader.feed(', "what": "x"}\n{"more": ["a"]}') == [("C1", "x")]
    assert reader.more == ["a"]
    thinking = recommend.AnswerReader(["C1"])
    assert thinking.feed('<think>{"ref": "C1", "what": "draft"}') == []
    assert thinking.feed('</think>{"ref": "C1", "what": "final"}') == [("C1", "final")]


def test_candidates_leave_out_injected_text_and_hidden_chats(store: ImportStore) -> None:
    rec = recommend.Recommender(store, TARGET, stream=_Model())
    found = rec.candidates(["量子化"], suppressed=set(), seen=set())
    assert found and not any(c.quote.startswith("<command-name>") for c in found)
    assert all(c.ref == f"C{i}" for i, c in enumerate(found, start=1))

    hidden = {local_conv_uid(Source.CODEX, "gif")}
    assert {c.source for c in rec.candidates(["量子化"], suppressed=hidden, seen=set())} <= {"claude_code"}


def test_a_memory_states_only_what_the_store_holds(store: ImportStore) -> None:
    model = _Model('{"ref": "C1", "what": "SmolVLM の量子化の検討"}\n{"ref": "C42", "what": "made up"}\n{"more": []}')
    rec = recommend.Recommender(store, TARGET, stream=model)

    [memory] = list(rec.run(["量子化"], suppressed=set(), now=NOW))

    first = rec.candidates(["量子化"], suppressed=set(), seen=set())[0]
    assert memory["part_uid"] == first.part_uid and memory["quote"] == first.quote
    assert memory["what"] == "SmolVLM の量子化の検討"
    assert memory["topic"]["events"][0]["branches"][0]["anchor_part_uid"] == first.part_uid
    assert "量子化" in model.prompts[0] and "資料は本人の過去の会話" in model.prompts[0]


def test_a_restated_quote_is_replaced_by_where_it_happened(store: ImportStore) -> None:
    rec = recommend.Recommender(store, TARGET, stream=_Model())
    first = rec.candidates(["量子化"], suppressed=set(), seen=set())[0]
    memory = rec.memory(first, first.quote[:20], ["量子化"], suppressed=set(), now=NOW)
    assert memory is not None and memory["what"] != first.quote[:20]


def test_follow_up_words_run_a_second_round_and_nothing_repeats(store: ImportStore) -> None:
    model = _Model('{"ref": "C1", "what": "a"}\n{"more": ["パレット"]}', '{"ref": "C1", "what": "b"}')
    memories = list(recommend.Recommender(store, TARGET, stream=model).run(["蒸留"], suppressed=set(), now=NOW))
    assert len(model.prompts) == 2 and "パレット" in model.prompts[1]
    assert len({m["part_uid"] for m in memories}) == len(memories) == 2


def test_a_memory_goes_out_before_the_model_has_finished(store: ImportStore) -> None:
    rest = "".join(f'{{"ref": "C{i}", "what": "w{i}"}}\n' for i in (2, 3)) + '{"more": []}'
    model = _Model('{"ref": "C1", "what": "first"}\n' + rest)
    memories = recommend.Recommender(store, TARGET, stream=model).run(["量子化"], suppressed=set(), now=NOW)
    first = next(memories)
    assert first["what"] == "first" and model.sent < len('{"ref": "C1", "what": "first"}\n' + rest)


def test_a_failing_model_ends_quietly_and_cancel_stops(store: ImportStore) -> None:
    def broken(_url: str, _body: dict[str, Any], _timeout: float) -> Iterator[str]:
        yield '{"ref": "C1", "what": "kept"}'
        raise OSError("down")

    kept = list(recommend.Recommender(store, TARGET, stream=broken).run(["量子化"], suppressed=set()))
    assert [m["what"] for m in kept] == ["kept"]
    model = _Model(json.dumps({"ref": "C1", "what": "x"}))
    rec = recommend.Recommender(store, TARGET, stream=model)
    assert list(rec.run(["量子化"], suppressed=set(), cancelled=lambda: True)) == []


class _Server(BaseHTTPRequestHandler):
    """A loopback chat endpoint: server-sent events when asked to stream, else one JSON body."""

    sse: ClassVar[bool] = True
    bodies: ClassVar[list[dict[str, Any]]] = []

    def do_POST(self) -> None:
        _Server.bodies.append(json.loads(self.rfile.read(int(self.headers["content-length"]))))
        self.send_response(200)
        if not _Server.sse:
            self.send_header("content-type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"choices": [{"message": {"content": "whole"}}]}).encode())
            return
        self.send_header("content-type", "text/event-stream; charset=utf-8")
        self.end_headers()
        for piece in ["量子", None, "化"]:
            chunk = {"choices": [{"delta": {"role": "assistant", "content": piece}}]}
            self.wfile.write(f"data: {json.dumps(chunk)}\n\n".encode())
        self.wfile.write(b"data: [DONE]\n\n")

    def log_message(self, *_args: Any) -> None:
        pass


def test_the_stream_reads_server_sent_events_and_a_plain_answer() -> None:
    server = HTTPServer(("127.0.0.1", 0), _Server)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    url = f"http://127.0.0.1:{server.server_address[1]}/v1/chat/completions"
    try:
        assert list(recommend._stream(url, {"model": "m"}, 5.0)) == ["量子", "化"]
        assert _Server.bodies[-1]["stream"] is True
        _Server.sse = False
        assert list(recommend._stream(url, {"model": "m"}, 5.0)) == ["whole"]
    finally:
        server.shutdown()


def test_the_agent_model_falls_back_to_the_headline_model() -> None:
    env = {"MORDRED_RECALL_LLM_ENDPOINT": "http://127.0.0.1:8081/v1", "MORDRED_RECALL_LLM_MODEL": "big"}
    assert recommend.target_from_environ(env) == HeadlineTarget("http://127.0.0.1:8081/v1", "big")
    env |= {recommend.ENDPOINT_ENV: "http://127.0.0.1:8082/v1", recommend.MODEL_ENV: "small"}
    assert recommend.target_from_environ(env) == HeadlineTarget("http://127.0.0.1:8082/v1", "small")
    assert recommend.target_from_environ({}) is None
