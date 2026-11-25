"""The selection translator: the prompt it sends, the streamed answer it keeps, and its refusals."""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

import pytest

from mordred_hermes.recall import translate as tr
from mordred_hermes.recall.headlines import HeadlineTarget

_TARGET = HeadlineTarget("http://127.0.0.1:8082/v1", "small")


def _fake_stream(pieces: list[str], calls: list[tuple[str, dict[str, Any]]]) -> Any:
    def stream(url: str, body: dict[str, Any], _timeout: float) -> Iterator[str]:
        calls.append((url, body))
        yield from pieces

    return stream


def test_pieces_stream_through_and_the_whole_translation_returns() -> None:
    calls: list[tuple[str, dict[str, Any]]] = []
    got: list[str] = []
    whole = tr.translate(
        "The meeting is on Thursday.",
        "ja",
        target=_TARGET,
        on_piece=got.append,
        stream=_fake_stream(["  会議は", "木曜日", "です。"], calls),
    )
    assert whole == "会議は木曜日です。"
    assert got == ["会議は", "木曜日", "です。"]
    [(url, body)] = calls
    assert url == "http://127.0.0.1:8082/v1/chat/completions"
    assert body["model"] == "small" and body["chat_template_kwargs"] == {"enable_thinking": False}
    user = body["messages"][-1]["content"]
    assert "日本語" in user and "<text>\nThe meeting is on Thursday.\n</text>" in user


def test_other_languages_get_the_english_prompt_with_the_language_named() -> None:
    [system, user] = tr.messages("会議は木曜日です。", "de-AT")
    assert system["content"] == "You are a translator."
    assert "into natural German" in user["content"] and "会議は木曜日です。" in user["content"]
    assert "Traditional Chinese" in tr.messages("x", "zh-TW")[1]["content"]
    assert "Simplified Chinese" in tr.messages("x", "zh-CN")[1]["content"]


def test_thinking_is_left_out_of_the_translation() -> None:
    got: list[str] = []
    whole = tr.translate(
        "x",
        "ja",
        target=_TARGET,
        on_piece=got.append,
        stream=_fake_stream(["<thi", "nk>plan the answer", "</think>\n", "訳文"], []),
    )
    assert whole == "訳文" and "".join(got) == "訳文"


def test_the_selection_is_cut_to_the_extension_limit() -> None:
    calls: list[tuple[str, dict[str, Any]]] = []
    tr.translate("a" * 5000, "ja", target=_TARGET, on_piece=lambda _p: None, stream=_fake_stream(["訳"], calls))
    assert "a" * tr.MAX_CHARS + "\n</text>" in calls[0][1]["messages"][-1]["content"]
    assert "a" * (tr.MAX_CHARS + 1) not in calls[0][1]["messages"][-1]["content"]


@pytest.mark.parametrize(
    ("kwargs", "code"),
    [
        ({"target": None}, "recall_agent_unavailable"),
        ({"text": "   "}, "invalid_request"),
        ({"language": "Japanese!"}, "invalid_request"),
        ({"pieces": []}, "recall_translate_empty"),
    ],
)
def test_refusals_are_content_free_codes(kwargs: dict[str, Any], code: str) -> None:
    pieces = kwargs.pop("pieces", ["訳"])
    args: dict[str, Any] = {"text": "secret page text", "language": "ja", "target": _TARGET, **kwargs}
    with pytest.raises(tr.TranslateError) as caught:
        tr.translate(
            args["text"],
            args["language"],
            target=args["target"],
            on_piece=lambda _p: None,
            stream=_fake_stream(pieces, []),
        )
    assert caught.value.code == code
    assert "secret" not in str(caught.value)


def test_a_failing_model_is_reported_and_its_response_closed() -> None:
    closed: list[bool] = []

    class _Broken:
        def __iter__(self) -> _Broken:
            return self

        def __next__(self) -> str:
            raise OSError("connection reset")

        def close(self) -> None:
            closed.append(True)

    with pytest.raises(tr.TranslateError) as caught:
        tr.translate("x", "ja", target=_TARGET, on_piece=lambda _p: None, stream=lambda *_a: _Broken())
    assert caught.value.code == "recall_agent_failed"
    assert closed == [True]


def test_cancelling_stops_reading() -> None:
    got: list[str] = []
    tr.translate(
        "x",
        "ja",
        target=_TARGET,
        on_piece=got.append,
        cancelled=lambda: len(got) >= 1,
        stream=_fake_stream(["一", "二", "三"], []),
    )
    assert got == ["一"]


def test_translate_selection_uses_the_agent_model_and_refuses_a_remote_one(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("MORDRED_RECALL_LLM_ENDPOINT", raising=False)
    monkeypatch.delenv("MORDRED_RECALL_LLM_MODEL", raising=False)
    monkeypatch.setenv("MORDRED_RECALL_AGENT_ENDPOINT", "https://example.com/v1")
    monkeypatch.setenv("MORDRED_RECALL_AGENT_MODEL", "small")
    assert tr.translate_selection("x", "ja", on_piece=lambda _p: None) == "recall_agent_unavailable"
    monkeypatch.delenv("MORDRED_RECALL_AGENT_ENDPOINT")
    assert tr.translate_selection("x", "ja", on_piece=lambda _p: None) == "recall_agent_unavailable"


@pytest.mark.parametrize(
    ("tag", "ok"), [("ja", True), ("en-US", True), ("zh-Hant", True), ("日本語", False), ("", False), (3, False)]
)
def test_language_tags(tag: object, ok: bool) -> None:
    assert tr.valid_language(tag) is ok
