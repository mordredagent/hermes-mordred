"""Header decoding: RFC 2047 with Japanese fallbacks, addresses, dates, ids, Gmail labels."""

from __future__ import annotations

import base64
from collections import Counter
from email import policy
from email.parser import BytesParser
from pathlib import Path

import pytest

from mordred_hermes.imports.mail.headers import (
    Address,
    decode_words,
    normalize_message_id,
    parse_headers,
    parse_labels,
    split_message_ids,
)

FIXTURES = Path(__file__).parent / "fixtures" / "mail"


def _headers(raw: bytes, stats: Counter[str] | None = None):  # type: ignore[no-untyped-def]
    msg = BytesParser(policy=policy.default).parsebytes(raw, headersonly=True)
    return parse_headers(msg, stats if stats is not None else Counter())


def _b(text: str, charset: str = "UTF-8", codec: str = "utf-8") -> str:
    return f"=?{charset}?B?{base64.b64encode(text.encode(codec)).decode()}?="


def test_iso2022jp_extended_characters_fall_back_and_are_counted() -> None:
    stats: Counter[str] = Counter()
    headers = _headers((FIXTURES / "iso2022jp_ext.eml").read_bytes(), stats)
    assert headers.subject == "ｱﾝｹｰﾄ のお願い"  # half-width katakana: iso2022_jp_ext
    assert headers.from_ == (Address("髙橋 一郎", "takahashi@example.org"),)  # IBM extension: cp932
    assert stats["charset_fallback"] == 2


def test_plain_iso2022jp_needs_no_fallback() -> None:
    stats: Counter[str] = Counter()
    assert decode_words(_b("見積もり", "ISO-2022-JP", "iso2022_jp"), stats) == "見積もり"
    assert not stats


def test_adjacent_encoded_words_are_joined_before_decoding() -> None:
    data = "見積もり".encode()
    first, second = base64.b64encode(data[:4]).decode(), base64.b64encode(data[4:]).decode()
    value = f"=?UTF-8?B?{first}?=\r\n =?UTF-8?B?{second}?= tail"
    assert decode_words(value, Counter()) == "見積もり tail"


def test_q_encoding_and_mixed_text() -> None:
    assert decode_words("Re: =?utf-8?Q?caf=C3=A9_bar?= now", Counter()) == "Re: café bar now"


def test_bad_encoded_word_is_kept_and_counted() -> None:
    stats: Counter[str] = Counter()
    assert decode_words("=?utf-8?B?***?=", stats) == "=?utf-8?B?***?="
    assert stats["bad_encoded_word"] == 1


def test_raw_eight_bit_headers_are_recovered() -> None:
    stats: Counter[str] = Counter()
    raw = b"Subject: " + "件名".encode() + b"\nFrom: " + "鈴木".encode("cp932") + b" <s@example.org>\n\n"
    headers = _headers(raw, stats)
    assert headers.subject == "件名"
    assert headers.from_ == (Address("鈴木", "s@example.org"),)
    assert stats["charset_fallback"] == 1  # the Shift_JIS name, not the UTF-8 subject


def test_address_lists_split_on_raw_value_so_decoded_commas_are_safe() -> None:
    raw = f"To: {_b('Yamada, Taro')} <Taro@Example.NET>, b@example.org, Undisclosed:;\n\n".encode()
    headers = _headers(raw)
    assert headers.to[:2] == (Address("Yamada, Taro", "taro@example.net"), Address("", "b@example.org"))


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("Mon, 05 Oct 2026 10:00:00 +0900", (1791162000, 540)),
        ("Mon, 05 Oct 2026 01:00:00 -0000", (1791162000, None)),
        ("not a date", (None, None)),
        ("", (None, None)),
    ],
)
def test_date_header(value: str, expected: tuple[int | None, int | None]) -> None:
    headers = _headers(f"Date: {value}\n\n".encode())
    assert (headers.date, headers.tz_offset_minutes) == expected


def test_missing_date_is_none_never_now() -> None:
    headers = _headers((FIXTURES / "missing_date.eml").read_bytes())
    assert headers.date is None
    assert headers.message_id is None


def test_message_id_normalisation_lowercases_only_the_domain() -> None:
    assert normalize_message_id("  <AbC.Def@Mail.Example.COM>  ") == "AbC.Def@mail.example.com"
    assert normalize_message_id("bare-ID@Example.org") == "bare-ID@example.org"
    assert normalize_message_id("<>") is None
    assert normalize_message_id("") is None
    assert normalize_message_id(None) is None
    assert normalize_message_id("<" + "x" * 600 + "@example.org>") is None


def test_references_keep_root_and_nearest_parents() -> None:
    ids = " ".join(f"<m{i}@Example.org>" for i in range(80))
    refs = split_message_ids(ids)
    assert refs[0] == "m0@example.org"
    assert refs[-1] == "m79@example.org"
    assert len(refs) == 50


def test_gmail_labels_respect_quotes_and_encoded_words() -> None:
    value = 'Inbox,"Category: Updates",=?UTF-8?Q?=E9=80=81=E4=BF=A1=E6=B8=88=E3=81=BF?=,"a,b",Inbox'
    assert parse_labels(value, Counter()) == ("Inbox", "Category: Updates", "送信済み", "a,b")
    assert parse_labels(None, Counter()) == ()


def test_gmail_thread_id_must_be_digits() -> None:
    assert _headers(b"X-GM-THRID: 1790000000000000001\n\n").gm_thread_id == "1790000000000000001"
    assert _headers(b"X-GM-THRID: abc\n\n").gm_thread_id is None


def test_takeout_headers() -> None:
    raw = (FIXTURES / "takeout_small.mbox").read_bytes().split(b"\n\nFrom 1790")[1]
    headers = _headers(raw.split(b"\n", 1)[1])
    assert headers.labels == ("Sent",)
    assert headers.in_reply_to == ("a1@mail.example.net",)
    assert headers.subject == "Re: 見積もりの件 SUBJCANARY-A"
    assert headers.sender == Address("佐々木 葵", "owner@example.com")
