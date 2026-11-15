"""``recall_query`` / ``recall_open`` / ``recall_dismiss`` on the /ext gateway.

The selection must arrive sealed with K_extchat and every result leaves sealed;
refusals are content-free codes. The service is a fake: store behaviour is
covered in ``tests/recall``.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any

from mordred_hermes.extension import api as extension_api
from mordred_hermes.extension.crypto import decrypt_message, encrypt_message_v2, hkdf_subkey, key_id
from mordred_hermes.recall.service import RecallError
from tests.extension._trust_helpers import authenticate

_AES = b"\x02" * 32
_EK = hkdf_subkey(_AES, "mordred-extchat-v1", "extchat")


class _FakeWS:
    def __init__(self) -> None:
        self.closed = False
        self.sent: list[dict[str, Any]] = []

    async def send_str(self, data: str) -> None:
        self.sent.append(json.loads(data))


async def _no_chat(_content: str, _context: dict[str, Any]) -> Any:
    if False:
        yield ""


class _FakeRecall:
    def __init__(self, fail: str | None = None) -> None:
        self.fail = fail
        self.calls: list[tuple[str, Any]] = []

    def _check(self) -> None:
        if self.fail == "boom":
            raise RuntimeError("secret store text")
        if self.fail is not None:
            raise RecallError(self.fail)

    def query(self, text: str, *, limit: int = 8, words: bool = False) -> dict[str, Any]:
        self.calls.append(("query_words" if words else "query", (text, limit)))
        self._check()
        return {"query": text, "confidence": "high", "cards": [{"uid": "tg:-1:1#a", "excerpt": "経費精算は27日"}]}

    def open(self, part_uid: str, *, before: int = 2, after: int = 2) -> list[dict[str, Any]]:
        self.calls.append(("open", (part_uid, before, after)))
        self._check()
        return [{"part_uid": part_uid, "text": "前後の発言", "anchor": True}]

    def dismiss(self, conv_uid: str) -> None:
        self.calls.append(("dismiss", conv_uid))
        self._check()

    def restore(self, conv_uid: str) -> None:
        self.calls.append(("restore", conv_uid))
        self._check()

    def hidden(self) -> list[dict[str, Any]]:
        self.calls.append(("hidden", None))
        self._check()
        return [{"conv_uid": "tg:-1", "until": 2, "hidden_at": 1, "source": "telegram", "title": "総務チャット"}]


def _conn(svc: Any, *, page: bool = False) -> Any:
    conn = extension_api._Connection(_FakeWS(), _no_chat, recall_service=svc, page_token="p" if page else None)
    if page:
        conn.authed = True
        conn._page_authenticated = True
    else:
        authenticate(conn, _EK)
    return conn


def _dispatch(conn: Any, payload: dict[str, Any]) -> list[dict[str, Any]]:
    asyncio.run(conn.dispatch(json.dumps(payload)))
    return list(conn.ws.sent)


def _sealed(text: str) -> str:
    return encrypt_message_v2(_EK, text, key_id(_EK))


def test_query_decrypts_the_selection_and_seals_the_cards() -> None:
    svc = _FakeRecall()
    [frame] = _dispatch(_conn(svc), {"id": "q", "type": "recall_query", "text": _sealed("経費精算"), "limit": 5})
    assert svc.calls == [("query", ("経費精算", 5))]
    assert frame["type"] == "recall_result" and frame["ok"] is True and frame["id"] == "q"
    assert "経費精算" not in json.dumps(frame, ensure_ascii=False)
    payload = json.loads(decrypt_message(_EK, frame["content"]))
    assert payload["cards"][0]["excerpt"] == "経費精算は27日"


def test_query_refuses_a_plaintext_selection_without_touching_the_store() -> None:
    svc = _FakeRecall()
    [frame] = _dispatch(_conn(svc), {"id": "q", "type": "recall_query", "text": "経費精算"})
    assert frame == {"id": "q", "type": "recall_result", "ok": False, "error": "invalid_request"}
    assert svc.calls == []


def test_query_rejects_bad_limits_and_undecryptable_text() -> None:
    svc = _FakeRecall()
    for limit in (0, 21, True, "8"):
        [frame] = _dispatch(_conn(svc), {"id": "q", "type": "recall_query", "text": _sealed("x"), "limit": limit})
        assert frame["error"] == "invalid_request"
    other = hkdf_subkey(b"\x03" * 32, "mordred-extchat-v1", "extchat")
    foreign = encrypt_message_v2(other, "x", key_id(other))
    [frame] = _dispatch(_conn(svc), {"id": "q", "type": "recall_query", "text": foreign})
    assert frame["error"] == "undecryptable"
    assert svc.calls == []


def test_store_failures_become_codes_without_content() -> None:
    [frame] = _dispatch(
        _conn(_FakeRecall("import_store_unavailable")), {"id": "q", "type": "recall_query", "text": _sealed("x")}
    )
    assert frame == {"id": "q", "type": "recall_result", "ok": False, "error": "import_store_unavailable"}
    [frame] = _dispatch(_conn(_FakeRecall("boom")), {"id": "o", "type": "recall_open", "part_uid": "tg:-1:1#a"})
    assert frame == {"id": "o", "type": "recall_opened", "ok": False, "error": "recall_unavailable"}


def test_open_seals_the_context_and_bounds_the_window() -> None:
    svc = _FakeRecall()
    [frame] = _dispatch(
        _conn(svc), {"id": "o", "type": "recall_open", "part_uid": "mail:work:<a@example.com>#a", "before": 1}
    )
    assert svc.calls == [("open", ("mail:work:<a@example.com>#a", 1, 2))]
    assert json.loads(decrypt_message(_EK, frame["content"]))["parts"][0]["text"] == "前後の発言"
    for bad in ({"part_uid": ""}, {"part_uid": "a\nb"}, {"part_uid": "x", "after": 6}, {"part_uid": 3}):
        [frame] = _dispatch(_conn(svc), {"id": "o", "type": "recall_open", **bad})
        assert frame["error"] == "invalid_request"
    assert len(svc.calls) == 1


def test_dismiss_acknowledges() -> None:
    svc = _FakeRecall()
    [frame] = _dispatch(_conn(svc), {"id": "d", "type": "recall_dismiss", "conv_uid": "tg:-1"})
    assert frame == {"id": "d", "type": "recall_dismissed", "ok": True}
    assert svc.calls == [("dismiss", "tg:-1")]


def test_page_sessions_cannot_recall() -> None:
    svc = _FakeRecall()
    for payload in (
        {"id": "q", "type": "recall_query", "text": _sealed("x")},
        {"id": "o", "type": "recall_open", "part_uid": "tg:-1:1#a"},
        {"id": "d", "type": "recall_dismiss", "conv_uid": "tg:-1"},
        {"id": "r", "type": "recall_restore", "conv_uid": "tg:-1"},
        {"id": "h", "type": "recall_hidden"},
    ):
        conn = _conn(svc, page=True)
        [frame] = _dispatch(conn, payload)
        assert frame == {"id": payload["id"], "type": "error", "reason": "page_session_forbidden"}
    assert svc.calls == []


def test_word_mode_reaches_the_word_search_and_bad_modes_are_refused() -> None:
    svc = _FakeRecall()
    payload = {"id": "q", "type": "recall_query", "text": _sealed("経費 締め切り"), "mode": "words"}
    [frame] = _dispatch(_conn(svc), payload)
    assert frame["ok"] is True and svc.calls == [("query_words", ("経費 締め切り", 8))]
    [bad] = _dispatch(_conn(_FakeRecall()), {**payload, "mode": "regex"})
    assert bad == {"id": "q", "type": "recall_result", "ok": False, "error": "invalid_request"}


class _FakeEvents(_FakeRecall):
    def events(self, text: str, *, limit: int = 5, headlines: bool = True, selection: bool = False) -> dict[str, Any]:
        self.calls.append(("events", (text, limit, headlines, selection)))
        self._check()
        return {"query": text, "headlines": "local", "events": [{"headline": "SmolVLM の量子化を進めている"}]}


def test_events_decrypt_the_words_and_seal_the_result() -> None:
    svc = _FakeEvents()
    payload = {"id": "e", "type": "recall_events", "text": _sealed("量子化"), "limit": 3, "headlines": False}
    [frame] = _dispatch(_conn(svc), payload)
    assert svc.calls == [("events", ("量子化", 3, False, False))]
    assert frame["type"] == "recall_events_result" and frame["ok"] is True and frame["id"] == "e"
    assert "量子化" not in json.dumps(frame, ensure_ascii=False)
    assert json.loads(decrypt_message(_EK, frame["content"]))["events"][0]["headline"].startswith("SmolVLM")


def test_events_refuse_plaintext_and_bad_options_without_touching_the_store() -> None:
    svc = _FakeEvents()
    bad: list[dict[str, Any]] = [
        {"text": "量子化"},
        {"text": _sealed("x"), "limit": 0},
        {"text": _sealed("x"), "limit": 11},
        {"text": _sealed("x"), "limit": True},
        {"text": _sealed("x"), "headlines": "yes"},
        {"text": _sealed("x"), "mode": "regex"},
    ]
    for extra in bad:
        [frame] = _dispatch(_conn(svc), {"id": "e", "type": "recall_events", **extra})
        assert frame == {"id": "e", "type": "recall_events_result", "ok": False, "error": "invalid_request"}
    assert svc.calls == []


def test_a_selection_reaches_the_event_search_as_a_selection() -> None:
    svc = _FakeEvents()
    payload = {"id": "e", "type": "recall_events", "text": _sealed("量子化のコードを確認します"), "mode": "selection"}
    [frame] = _dispatch(_conn(svc), payload)
    assert frame["ok"] is True
    assert svc.calls == [("events", ("量子化のコードを確認します", 5, True, True))]


def test_events_report_store_failures_as_codes() -> None:
    for fail, code in (("import_store_unavailable", "import_store_unavailable"), ("boom", "recall_unavailable")):
        [frame] = _dispatch(_conn(_FakeEvents(fail)), {"id": "e", "type": "recall_events", "text": _sealed("x")})
        assert frame == {"id": "e", "type": "recall_events_result", "ok": False, "error": code}


def test_restore_acknowledges_and_refuses_a_bad_id() -> None:
    svc = _FakeRecall()
    [frame] = _dispatch(_conn(svc), {"id": "r", "type": "recall_restore", "conv_uid": "tg:-1"})
    assert frame == {"id": "r", "type": "recall_restored", "ok": True}
    [bad] = _dispatch(_conn(svc), {"id": "r", "type": "recall_restore", "conv_uid": "a\nb"})
    assert bad == {"id": "r", "type": "recall_restored", "ok": False, "error": "invalid_request"}
    assert svc.calls == [("restore", "tg:-1")]


def test_hidden_conversations_leave_sealed() -> None:
    svc = _FakeRecall()
    [frame] = _dispatch(_conn(svc), {"id": "h", "type": "recall_hidden"})
    assert frame["type"] == "recall_hidden_result" and frame["ok"] is True
    assert "総務チャット" not in json.dumps(frame, ensure_ascii=False)
    [hidden] = json.loads(decrypt_message(_EK, frame["content"]))["hidden"]
    assert hidden["conv_uid"] == "tg:-1" and hidden["title"] == "総務チャット"


class _FakeRecommend(_FakeRecall):
    def recommend(self, text: str, *, selection: bool = False, on_item: Any, cancelled: Any) -> int:
        self.calls.append(("recommend", (text, selection)))
        self._check()
        for n in range(2):
            on_item({"part_uid": f"claude:a:{n}#a", "quote": "量子化なしの生徒", "what": "蒸留の検討"})
        return 2


def _stream(conn: Any, payload: dict[str, Any]) -> list[dict[str, Any]]:
    """Dispatch, then wait for the recommendation the frame started."""

    async def run() -> None:
        await conn.dispatch(json.dumps(payload))
        await asyncio.gather(*(task for task, _stop in list(conn._recall_recommends.values())))

    asyncio.run(run())
    return list(conn.ws.sent)


def test_recommendations_stream_sealed_and_end() -> None:
    svc = _FakeRecommend()
    payload = {"id": "m", "type": "recall_recommend", "text": _sealed("量子化"), "mode": "selection"}
    *items, end = _stream(_conn(svc), payload)
    assert svc.calls == [("recommend", ("量子化", True))]
    assert [frame["type"] for frame in items] == ["recall_recommend_item"] * 2
    assert "量子化" not in json.dumps(items, ensure_ascii=False)
    assert json.loads(decrypt_message(_EK, items[0]["content"]))["what"] == "蒸留の検討"
    assert end == {"id": "m", "type": "recall_recommend_end", "ok": True}


def test_recommendations_report_a_missing_model_and_refuse_plaintext() -> None:
    svc = _FakeRecommend(fail="recall_agent_unavailable")
    [end] = _stream(_conn(svc), {"id": "m", "type": "recall_recommend", "text": _sealed("量子化")})
    assert end == {"id": "m", "type": "recall_recommend_end", "ok": False, "error": "recall_agent_unavailable"}
    [bad] = _stream(_conn(_FakeRecommend()), {"id": "m", "type": "recall_recommend", "text": "量子化"})
    assert bad == {"id": "m", "type": "recall_recommend_end", "ok": False, "error": "invalid_request"}


def test_page_sessions_cannot_ask_for_recommendations() -> None:
    svc = _FakeRecommend()
    [frame] = _dispatch(_conn(svc, page=True), {"id": "m", "type": "recall_recommend", "text": _sealed("x")})
    assert frame == {"id": "m", "type": "error", "reason": "page_session_forbidden"}
    assert svc.calls == []
