"""Body extraction: plain preferred, HTML conversion, attachment kinds, attached messages."""

from __future__ import annotations

import time
from collections import Counter
from pathlib import Path

import pytest

from mordred_hermes.imports.mail import body as body_mod
from mordred_hermes.imports.mail.body import MAX_OPEN_TAGS, HtmlToText, extract_body, html_to_text
from mordred_hermes.imports.mail.normalize import parse_mail
from mordred_hermes.imports.mail.segment import segment_body
from mordred_hermes.imports.records import PartKind

FIXTURES = Path(__file__).parent / "fixtures" / "mail"


def body_of(raw: bytes, stats: Counter[str] | None = None):  # type: ignore[no-untyped-def]
    return extract_body(parse_mail(raw), stats if stats is not None else Counter())


def test_html_only_fixture_drops_script_style_title_and_prefixes_quotes() -> None:
    result = body_of((FIXTURES / "html_only.eml").read_bytes())
    assert result.html_only
    for hidden in ("CANARY-HTML-SCRIPT", "CANARY-HTML-STYLE", "CANARY-HTML-TITLE"):
        assert hidden not in result.text
    lines = result.text.split("\n")
    assert lines[0] == "Here is my answer. CANARY-HTML-A"
    assert "Second line & more." in lines
    assert "On Mon, Oct 5, 2026 at 10:00 AM Hanako Suzuki <hanako@example.org> wrote:" in lines
    assert "> Original question. CANARY-HTML-Q" in lines
    assert "> > Deeper quote without attribution. CANARY-HTML-DEEP" in lines


def test_outlook_reply_div_quotes_the_rest_of_the_message() -> None:
    html = (
        '<div>Thanks, agreed.</div><hr><div id="divRplyFwdMsg"><b>From:</b> Taro Yamada &lt;taro@example.net&gt;<br>'
        "<b>Sent:</b> Monday, October 5, 2026 10:00 AM<br><b>To:</b> Owner<br><b>Subject:</b> Plan</div>"
        "<div>Original plan text.</div>"
    )
    text = html_to_text(html)
    assert text.split("\n")[0] == "Thanks, agreed."
    assert "> Original plan text." in text
    segments = segment_body(text, tz_offset_minutes=540).segments
    assert [(segment.kind, segment.text) for segment in segments] == [
        (PartKind.AUTHORED, "Thanks, agreed."),
        (PartKind.QUOTED, "Original plan text."),
    ]
    assert segments[1].attribution is not None
    assert segments[1].attribution.address == "taro@example.net"


def test_outlook_border_div_and_japanese_labels() -> None:
    html = (
        '<p>了解です。</p><div style="border:none;border-top:solid #E1E1E1 1.0pt;padding:3.0pt 0in 0in 0in">'
        "<p><b>差出人:</b> 山田太郎 &lt;taro@example.net&gt;<br><b>送信日時:</b> 2026年10月5日 10:00<br>"
        "<b>宛先:</b> 佐々木 葵<br><b>件名:</b> 予定</p></div><p>元の本文です。</p>"
    )
    segments = segment_body(html_to_text(html), tz_offset_minutes=540).segments
    assert [segment.kind for segment in segments] == [PartKind.AUTHORED, PartKind.QUOTED]
    assert segments[1].text == "元の本文です。"
    assert segments[1].attribution is not None
    assert segments[1].attribution.name == "山田太郎"


def test_html_blocks_breaks_and_preformatted_text() -> None:
    text = html_to_text("<p>one</p><p>two<br>three</p><pre>  keep   spaces\nline</pre><ul><li>a</li><li>b</li></ul>")
    assert text.split("\n") == ["one", "", "two", "three", "  keep   spaces", "line", "a", "b"]


def test_multipart_alternative_prefers_plain_and_skips_the_html_twin() -> None:
    raw = (
        b'Content-Type: multipart/alternative; boundary="b"\n\n--b\nContent-Type: text/plain; charset=UTF-8\n\n'
        b"plain body\n--b\nContent-Type: text/html; charset=UTF-8\n\n<p>html body</p>\n--b--\n"
    )
    result = body_of(raw)
    assert (result.text.strip(), result.html_only, result.attachments) == ("plain body", False, ())


def test_attachment_kinds_never_names_and_rfc822_becomes_forwarded() -> None:
    result = body_of((FIXTURES / "rfc822_attachment.eml").read_bytes())
    assert sorted(result.attachments) == ["document", "image", "rfc822"]
    assert "CANARY-RFC-FILENAME" not in repr(result)
    assert "CANARY-RFC-IMAGE" not in repr(result) and "CANARY-RFC-DOC" not in repr(result)
    (forwarded,) = result.forwarded
    assert forwarded.depth == 1
    assert forwarded.text.strip() == "Inner message body. CANARY-RFC-INNER"
    assert forwarded.headers.sender is not None
    assert forwarded.headers.sender.address == "ichiro@example.net"


def _wrapped(level: int) -> bytes:
    inner = f"Message-ID: <l{level}@example.net>\nFrom: L{level} <l{level}@example.net>\nSubject: s\n\nlevel {level}\n"
    data = inner.encode()
    for depth in range(level - 1, -1, -1):
        boundary = f"b{depth}".encode()
        data = (
            b"From: L"
            + str(depth).encode()
            + b' <l@example.net>\nContent-Type: multipart/mixed; boundary="'
            + boundary
            + b'"\n\n--'
            + boundary
            + b"\nContent-Type: text/plain\n\nlevel "
            + str(depth).encode()
            + b"\n--"
            + boundary
            + b"\nContent-Type: message/rfc822\n\n"
            + data
            + b"\n--"
            + boundary
            + b"--\n"
        )
    return data


def test_attached_messages_are_forwarded_up_to_depth_two() -> None:
    result = body_of(_wrapped(3))
    assert [mail.depth for mail in result.forwarded] == [1, 2]
    assert [mail.text.strip() for mail in result.forwarded] == ["level 1", "level 2"]


def test_body_is_bounded_before_segmentation(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(body_mod, "MAX_BODY_BYTES", 32)
    result = body_of(b"Content-Type: text/plain; charset=UTF-8\n\n" + "あ".encode() * 40)
    assert result.truncated
    assert len(result.text.encode()) <= 32


def test_unknown_charset_falls_back_and_counts() -> None:
    stats: Counter[str] = Counter()
    result = body_of(
        b"Content-Type: text/plain; charset=x-unknown\nContent-Transfer-Encoding: 8bit\n\n" + "日本".encode(), stats
    )
    assert result.text == "日本"
    assert stats["charset_fallback"] == 1


def test_iso2022jp_body_with_nec_specials_decodes_via_cp932() -> None:
    stats: Counter[str] = Counter()
    result = body_of((FIXTURES / "iso2022jp_ext.eml").read_bytes(), stats)
    assert "①の件、了解しました。㈱サンプルの資料です。" in result.text
    assert stats["charset_fallback"] >= 1


def test_control_characters_are_replaced() -> None:
    result = body_of(b"Content-Type: text/plain\n\nbell\x07 esc\x1b[31m red\r\n")
    assert "\x1b" not in result.text and "\x07" not in result.text
    assert result.text.startswith("bell� esc�[31m red")


def test_parser_defects_are_counted_by_class_name() -> None:
    stats: Counter[str] = Counter()
    body_of(b'Content-Type: multipart/mixed; boundary="never"\n\nno boundary here\n', stats)
    assert any(key.startswith("defect:") for key in stats)


def test_html_body_is_cut_before_conversion_and_converted_in_linear_time(monkeypatch: pytest.MonkeyPatch) -> None:
    cap = 128 * 1024
    monkeypatch.setattr(body_mod, "MAX_BODY_BYTES", cap)
    fed: list[int] = []
    original_feed = HtmlToText.feed

    def feed(self: HtmlToText, data: str) -> None:
        fed.append(len(data.encode()))
        original_feed(self, data)

    monkeypatch.setattr(HtmlToText, "feed", feed)
    # Unclosed opens plus end tags that match nothing: a stack scan per end tag was quadratic.
    unit = "<b>" * 1000 + "</i>" * 1000 + "<p>text</p>"
    html = unit * (1024 * 1024 // len(unit) + 1)
    raw = b"Content-Type: text/html; charset=UTF-8\n\n" + html.encode()
    assert len(raw) > 1024 * 1024
    started = time.perf_counter()
    result = body_of(raw)
    elapsed = time.perf_counter() - started
    assert elapsed < 2.0
    assert result.html_only and result.truncated
    assert fed and sum(fed) <= 4 * cap  # cut to 4 * MAX_BODY_BYTES before the parser saw it
    assert result.text.startswith("text\n")
    assert len(result.text.encode()) <= cap


def test_converted_output_is_bounded_and_flags_truncation() -> None:
    parser = HtmlToText(max_chars=100)
    parser.feed("<p>" + "word " * 50 + "</p>" + "<p>more</p>" * 100)
    text = parser.text()
    assert parser.truncated
    assert "more" not in text and len(text) < 300
    # Outlook header blocks never close their quote level, but prefixes stop growing.
    outlook = html_to_text('<div id="divRplyFwdMsg">h</div>x' * 100)
    assert max(len(line) for line in outlook.split("\n")) <= len("> " * 32 + "x")


def test_deep_nesting_is_bounded_and_still_produces_text() -> None:
    assert html_to_text("<div>" * 10_000 + "deep text" + "</div>" * 10_000 + "after").split("\n") == [
        "deep text",
        "after",
    ]
    quoted = html_to_text("<blockquote>" * 10_000 + "q" + "</blockquote>" * 10_000 + "after").split("\n")
    assert quoted == ["> " * 32 + "q", "after"]
    # Too deep to track, a skip tag still hides its text until it (or an outer element) closes.
    deep = "<span>" * MAX_OPEN_TAGS
    assert html_to_text(deep + "<style>hidden</style>shown") == "shown"
    assert html_to_text(deep + "<head>hidden</span>shown") == "shown"
    assert html_to_text("</b></div>stray<p>end tags</p>") == "stray\nend tags"
