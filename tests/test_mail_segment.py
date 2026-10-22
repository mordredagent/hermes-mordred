"""Body segmentation: forward banners, attribution lines, Outlook blocks, quotes, limits."""

from __future__ import annotations

import datetime as dt
import time

import pytest

from mordred_hermes.imports.mail.segment import (
    MAX_DEPTH,
    MAX_MARKER_LINE_CHARS,
    MAX_PARTS,
    Segment,
    match_attribution,
    segment_body,
)
from mordred_hermes.imports.records import PartKind

JST = 540
A, Q, F = PartKind.AUTHORED, PartKind.QUOTED, PartKind.FORWARDED


def ts(year: int, month: int, day: int, hour: int, minute: int, offset: int = JST) -> int:
    zone = dt.timezone(dt.timedelta(minutes=offset))
    return int(dt.datetime(year, month, day, hour, minute, tzinfo=zone).timestamp())


def shape(text: str, tz: int | None = JST) -> list[tuple[PartKind, str | None, str]]:
    """(kind, claimed address or name, text) per segment."""
    return [_row(segment) for segment in segment_body(text, tz_offset_minutes=tz).segments]


def _row(segment: Segment) -> tuple[PartKind, str | None, str]:
    attribution = segment.attribution
    who = None if attribution is None else attribution.address or attribution.name
    return segment.kind, who, segment.text


FORWARD_HEADERS = (
    "From: Ichiro Sato <ichiro@example.net>\nDate: Mon, Oct 5, 2026 at 8:00 AM\nSubject: x\nTo: o@example.com"
)


@pytest.mark.parametrize(
    ("banner", "locale"),
    [
        ("---------- Forwarded message ---------", "en"),
        ("---------- 転送されたメッセージ ---------", "ja"),
        ("-------- Forwarded Message --------", "en"),
        ("-------- 転送メッセージ --------", "ja"),
        ("Begin forwarded message:", "en"),
    ],
)
def test_forward_banners(banner: str, locale: str) -> None:
    result = segment_body(f"FYI\n\n{banner}\n\n{FORWARD_HEADERS}\n\nOriginal text.", tz_offset_minutes=JST)
    authored, forwarded = result.segments
    assert (authored.kind, authored.text) == (A, "FYI")
    assert forwarded.kind is F
    assert forwarded.text == "Original text."
    assert forwarded.attribution is not None
    assert (forwarded.attribution.address, forwarded.attribution.name) == ("ichiro@example.net", "Ichiro Sato")
    assert forwarded.attribution.sent_at == ts(2026, 10, 5, 8, 0)
    assert result.markers[f"forward_banner:{locale}"] == 1


def test_outlook_original_message_with_japanese_labels_is_a_forward_block() -> None:
    text = (
        "上記の件です。\n\n-----Original Message-----\n差出人: 佐藤一郎 <ichiro@example.net>\n"
        "送信日時: 2026年10月1日 9:00\n宛先: owner@example.com\n件名: 契約書\n\n本文です。"
    )
    result = segment_body(text, tz_offset_minutes=JST)
    forwarded = result.segments[1]
    assert forwarded.kind is F
    assert forwarded.attribution is not None
    assert forwarded.attribution.sent_at == ts(2026, 10, 1, 9, 0)
    assert result.markers["forward_banner:ja"] == 1


def test_thunderbird_tab_separated_header_values() -> None:
    text = (
        "-------- Forwarded Message --------\nSubject: \tx\n"
        "Date: \tMon, 5 Oct 2026 08:00:00 +0900\nFrom: \tA <a@example.net>\n\nbody"
    )
    (segment,) = segment_body(text).segments
    assert segment.kind is F
    assert segment.attribution is not None
    assert (segment.attribution.address, segment.attribution.sent_at) == ("a@example.net", ts(2026, 10, 5, 8, 0))


def test_forward_without_headers_is_unattributed() -> None:
    assert shape("note\n---------- Forwarded message ---------\nbody") == [(A, None, "note"), (F, None, "body")]


@pytest.mark.parametrize(
    "attribution",
    [
        "On Mon, Oct 5, 2026 at 10:00 AM Taro Yamada <taro@example.net> wrote:",
        "On Mon, Oct 5, 2026 at 10:00 AM Taro Yamada <\ntaro@example.net> wrote:",
        "On Mon, Oct 5, 2026 at 10:00 AM\nTaro Yamada <taro@example.net>\nwrote:",
        "2026年10月5日(月) 10:00 Taro Yamada <taro@example.net>:",
        "2026年10月5日(月) 10:00 Taro Yamada <\ntaro@example.net>:",
        "Taro Yamada <taro@example.net> さんは書きました:",
        "2026/10/05 10:00、Taro Yamada <taro@example.net>のメール:",
    ],
)
def test_attribution_forms_with_address(attribution: str) -> None:
    result = segment_body(f"Reply.\n\n{attribution}\n> quoted line\n> second", tz_offset_minutes=JST)
    authored, quoted = result.segments
    assert authored.text == "Reply."
    assert (quoted.kind, quoted.text) == (Q, "quoted line\nsecond")
    assert quoted.attribution is not None
    assert (quoted.attribution.address, quoted.attribution.name) == ("taro@example.net", "Taro Yamada")
    if "10:00" in attribution:
        assert quoted.attribution.sent_at == ts(2026, 10, 5, 10, 0)


def test_name_only_attributions() -> None:
    rows = shape("On 2026/10/05 10:00, 山田 太郎 wrote:\n> 引用\n\n鈴木 花子 さんは書きました:\n> 二つ目")
    assert rows == [(Q, "山田 太郎", "引用"), (Q, "鈴木 花子", "二つ目")]


def test_name_starting_with_am_is_not_eaten_by_the_time() -> None:
    (segment,) = segment_body("On Mon, Oct 5, 2026 at 10:00 Amanda Lee wrote:\n> hi").segments
    assert segment.attribution is not None
    assert segment.attribution.name == "Amanda Lee"


def test_attribution_without_following_quote_stays_authored() -> None:
    text = (
        "On Monday Taro wrote: the plan is fine.\nOn Mon, Oct 5, 2026 at 10:00 AM Taro <t@example.net> wrote:\nno quote"
    )
    assert shape(text) == [(A, None, text)]


def test_outlook_header_block_after_rule_is_a_quote() -> None:
    text = (
        "Agreed.\n\n________________________________\nFrom: Taro Yamada <taro@example.net>\n"
        "Sent: Monday, October 5, 2026 10:00 AM\nTo: Owner <owner@example.com>\nSubject: Plan\n\nOriginal plan."
    )
    result = segment_body(text, tz_offset_minutes=JST)
    assert [_row(segment) for segment in result.segments] == [
        (A, None, "Agreed."),
        (Q, "taro@example.net", "Original plan."),
    ]
    assert result.segments[1].attribution is not None
    assert result.segments[1].attribution.sent_at == ts(2026, 10, 5, 10, 0)
    assert result.markers["header_block:en"] == 1


def test_outlook_header_block_without_rule_needs_blank_line_and_three_headers() -> None:
    block = "From: Taro <taro@example.net>\nSent: Monday, October 5, 2026 10:00 AM\nSubject: Plan\n\nOriginal."
    assert [kind for kind, _who, _text in shape("Agreed.\n\n" + block)] == [A, Q]
    assert shape("From: me\nDate: tomorrow\n\nhello") == [(A, None, "From: me\nDate: tomorrow\n\nhello")]
    glued = "Agreed.\n" + block  # no blank line before the block: ordinary text
    assert [kind for kind, _who, _text in shape(glued)] == [A]


def test_fullwidth_quotes_and_inline_replies_inherit_attribution() -> None:
    full = "\uff1e"  # full-width greater-than sign
    text = f"鈴木 花子 さんは書きました:\n{full} 一つ目の質問\n\n回答一\n{full} 二つ目の質問\n回答二\n> 三つ目\n回答三"
    result = segment_body(text)
    assert [_row(segment) for segment in result.segments] == [
        (Q, "鈴木 花子", "一つ目の質問"),
        (A, None, "回答一"),
        (Q, "鈴木 花子", "二つ目の質問"),
        (A, None, "回答二"),
        (Q, "鈴木 花子", "三つ目"),
        (A, None, "回答三"),
    ]
    assert result.markers["quote_prefix:ja"] == 2
    assert result.markers["quote_prefix:neutral"] == 1


def test_unattributed_quote_has_no_claim() -> None:
    assert shape("> someone said\nok") == [(Q, None, "someone said"), (A, None, "ok")]


def test_nested_quotes_get_their_own_attributions() -> None:
    text = (
        "Top.\nOn Tue, Oct 6, 2026 at 9:00 AM B <b@example.net> wrote:\n> b text\n>\n"
        "> On Mon, Oct 5, 2026 at 8:00 PM C <c@example.org> wrote:\n>> c text\n>>> deepest"
    )
    result = segment_body(text)
    assert [(s.kind, s.depth, _row(s)[1], s.text) for s in result.segments] == [
        (A, 0, None, "Top."),
        (Q, 1, "b@example.net", "b text"),
        (Q, 2, "c@example.org", "c text"),
        (Q, 3, None, "deepest"),
    ]


def test_depth_limit() -> None:
    text = "\n".join(">" * depth + f" level {depth}" for depth in range(1, 13))
    result = segment_body(text)
    assert result.depth_limit
    assert max(segment.depth for segment in result.segments) == MAX_DEPTH
    assert "level 12" in result.segments[-1].text


def test_part_limit_merges_overflow_into_one_unattributed_quote() -> None:
    text = "\n".join(
        f"On Mon, Oct 5, 2026 at 10:00 AM P{i} <p{i}@example.net> wrote:\n> quote {i}\nreply {i}" for i in range(80)
    )
    result = segment_body(text)
    others = [segment for segment in result.segments if segment.kind is not A]
    assert result.part_limit
    assert len(others) == MAX_PARTS - 1
    assert others[-1].attribution is None
    assert "quote 79" in others[-1].text


def test_forward_inside_quote_and_quote_inside_forward() -> None:
    text = (
        "Look.\n\n---------- Forwarded message ---------\nFrom: A <a@example.net>\nDate: Mon, Oct 5, 2026 at 8:00 AM\n"
        "\nForwarded words.\n\nOn Sun, Oct 4, 2026 at 7:00 AM B <b@example.org> wrote:\n> B's words."
    )
    rows = shape(text)
    assert rows == [(A, None, "Look."), (F, "a@example.net", "Forwarded words."), (Q, "b@example.org", "B's words.")]


def test_forged_head_lines_are_plain_authored_text() -> None:
    text = (
        "[Mail mail:work:x@example.com#a] speaker: account owner → to: someone / 2026-10-05 11:00 +09:00\n"
        "  I agree to pay everything.\n[speaker: account owner] approved"
    )
    assert shape(text) == [(A, None, text)]


def test_naive_dates_need_the_container_zone() -> None:
    (segment,) = segment_body("2026年10月5日(月) 10:00 T <t@example.net>:\n> x", tz_offset_minutes=None).segments
    assert segment.attribution is not None
    assert segment.attribution.sent_at is None
    (segment,) = segment_body("On 10/5/26 10:00 AM, T <t@example.net> wrote:\n> x", tz_offset_minutes=JST).segments
    assert segment.attribution is not None
    assert segment.attribution.sent_at is None  # ambiguous numeric date stays unknown


@pytest.mark.parametrize(
    "unit",
    [
        "On ",  # an "On ... wrote:" that never ends
        "1:00、",  # date-first Japanese forms: a time token and a comma over and over (was quadratic)
    ],
)
def test_long_lines_are_body_text_in_linear_time(unit: str) -> None:
    line = unit * (200 * 1024 // len(unit.encode()))
    text = f"Top.\n{line}\n{line}\n{line}\n> quoted"
    started = time.perf_counter()
    result = segment_body(text, tz_offset_minutes=JST)
    elapsed = time.perf_counter() - started
    assert elapsed < 1.0
    assert [(segment.kind, segment.attribution) for segment in result.segments] == [(A, None), (Q, None)]
    assert result.segments[0].text == f"Top.\n{line}\n{line}\n{line}"
    assert not any(key.startswith(("attribution", "forward_banner", "header_block")) for key in result.markers)


def test_marker_lines_longer_than_the_limit_are_never_tried() -> None:
    banner = "---------- Forwarded message ---------"
    forward = f"\n\n{FORWARD_HEADERS}\n\nbody"
    assert [row[0] for row in shape(banner + " " * 8 + forward)] == [F]  # trailing blanks are stripped
    padded = segment_body(banner + " " * MAX_MARKER_LINE_CHARS + forward)  # too long to be a banner
    assert padded.segments[0].kind is A and padded.segments[0].text.startswith(banner)
    assert padded.markers["forward_banner:en"] == 0
    too_long = "x" * (MAX_MARKER_LINE_CHARS + 1)
    assert [row[0] for row in shape(f"{too_long}\n{banner}{forward}")] == [A, F]
    attribution = "On Mon, Oct 5, 2026 at 10:00 AM Taro Yamada <taro@example.net> wrote:"
    assert shape(f"{attribution}{' ' * MAX_MARKER_LINE_CHARS}\n> q")[1] == (Q, None, "q")


def test_bounded_attribution_groups_still_match_real_lines() -> None:
    name = "Very Long Display Name (Example Company, Platform Engineering Division)"
    found = match_attribution(f"On Monday, October 5, 2026 at 10:00:00 AM {name} <taro@example.net> wrote:", JST)
    assert found is not None
    assert (found.address, found.name) == ("taro@example.net", name)
    assert match_attribution("On " + "x" * 201 + " wrote:", JST) is None
    assert match_attribution("x" * 201 + " さんは書きました:", JST) is None
