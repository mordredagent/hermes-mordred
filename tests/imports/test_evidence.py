"""Citation validation: membership, exact quotes, and cards built from stored data only."""

from __future__ import annotations

from dataclasses import fields

import pytest

from mordred_hermes.imports.evidence import EVIDENCE_ID_RE, EvidenceCard, validate
from mordred_hermes.imports.records import ImportMessage, OwnerClass, PartKind, ProvenanceQuality
from mordred_hermes.imports.render import RenderedPartRef, part_ref
from tests.imports._factories import (
    ORIGINAL_AT,
    OWNER,
    SENT_AT,
    SUZUKI,
    TANAKA,
    authored,
    message,
    part,
    tg_conv,
    tg_uid,
)

CONV = tg_conv()
STORED = "明日の会議は10時からです、遅れないでください。資料は共有フォルダにあります。"
FWD_TEXT = "会議は\uff21棟の\uff13階で\uff11\uff10時から始めます"


def _selection(*messages: ImportMessage) -> dict[str, RenderedPartRef]:
    refs = [part_ref(CONV, msg, p) for msg in messages for p in msg.parts]
    return {ref.evidence_id: ref for ref in refs}


def _forward() -> ImportMessage:
    uid = tg_uid(4569)
    fwd = part(uid, PartKind.FORWARDED, 1, author=SUZUKI, text=FWD_TEXT, original_sent_at=ORIGINAL_AT)
    return message(uid, (fwd,), sender=OWNER)


SAID = authored(4568, TANAKA, STORED)
ID = "tg:-100123:4568#a"
FWD_ID = "tg:-100123:4569#f1"
SELECTION = _selection(SAID, _forward())


# --- id extraction ---------------------------------------------------------------------


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("see (tg:-100123:4568#a).", ["tg:-100123:4568#a"]),
        ("tg:1:2#aの発言と tg:1:2#q12、tg:1:2#f3", ["tg:1:2#a", "tg:1:2#q12", "tg:1:2#f3"]),
        ("(mail:work:abc123@example.com#q2), mail:work:h:" + "0" * 32 + "#f1", None),
        ("根拠:mail:work:a%23b@example.com#a。", ["mail:work:a%23b@example.com#a"]),
        ("tg:1:2#ab xtg:1:2#a tg:1:2#q tg:1:2", []),
        ("mail:work:x@example.com)と(mail:work:y@example.com#a)", ["mail:work:y@example.com#a"]),
    ],
)
def test_evidence_id_extraction(text: str, expected: list[str] | None) -> None:
    found = [m.group(0) for m in EVIDENCE_ID_RE.finditer(text)]
    if expected is None:
        assert found == ["mail:work:abc123@example.com#q2", "mail:work:h:" + "0" * 32 + "#f1"]
    else:
        assert found == expected


# --- cards ---------------------------------------------------------------------------------


def test_valid_id_builds_card_from_stored_data() -> None:
    report = validate(f"田中さんは10時と言っています ({ID})。", SELECTION)
    assert report.unverified_ids == () and report.unsupported_quotes == ()
    (card,) = report.cards
    assert card == EvidenceCard(
        evidence_id=ID,
        speaker="田中 太郎",
        speaker_class=OwnerClass.OTHER,
        part_kind=PartKind.AUTHORED,
        chat="Team",
        sent_at=SENT_AT,
        original_sent_at=None,
        excerpt=STORED[:160],
        quote_verified=False,
        quote=None,
        provenance_quality=ProvenanceQuality.API_IDENTITY,
    )


def test_forwarded_card_keeps_original_author_and_date() -> None:
    (card,) = validate(f"転送された内容です {FWD_ID}", SELECTION).cards
    assert (card.speaker, card.part_kind, card.original_sent_at) == ("鈴木 花子", PartKind.FORWARDED, ORIGINAL_AT)


def test_excerpt_is_bounded() -> None:
    long = authored(4600, TANAKA, "x" * 500)
    (card,) = validate("tg:-100123:4600#a", _selection(long)).cards
    assert card.excerpt == "x" * 160


def test_unknown_id_is_unverified_and_gets_no_card() -> None:
    report = validate(f"{ID} と tg:-100123:9999#a と tg:-100123:4568#q1 と {ID}", SELECTION)
    assert [card.evidence_id for card in report.cards] == [ID]
    assert report.unverified_ids == ("tg:-100123:9999#a", "tg:-100123:4568#q1")


# --- quotes ----------------------------------------------------------------------------------


def test_exact_quote_is_verified() -> None:
    answer = f"田中 太郎は「明日の会議は10時からです、遅れないでください」と書いています ({ID})。"
    (card,) = validate(answer, SELECTION).cards
    assert card.quote_verified
    assert card.quote == "明日の会議は10時からです、遅れないでください"


def test_quote_matches_after_nfkc_on_both_sides() -> None:
    (card,) = validate(f"“会議はA棟の3階で10時から始めます” ({FWD_ID})", SELECTION).cards
    assert card.quote_verified


def test_altered_quote_is_unsupported() -> None:
    altered = "明日の会議は9時からです、遅れないでください"
    report = validate(f"田中 太郎は「{altered}」と書いています ({ID})。", SELECTION)
    assert report.unsupported_quotes == (altered,)
    (card,) = report.cards
    assert not card.quote_verified and card.quote is None


def test_one_bad_quote_spoils_verification_for_that_id() -> None:
    answer = (
        f"「明日の会議は10時からです、遅れないでください」({ID})。また「資料は田中のPCにあります、本当です」({ID})。"
    )
    report = validate(answer, SELECTION)
    assert report.unsupported_quotes == ("資料は田中のPCにあります、本当です",)
    assert not report.cards[0].quote_verified


def test_quote_attached_to_unknown_id_is_unsupported() -> None:
    report = validate("「明日の会議は10時からです、遅れないでください」 (tg:-100123:1#a)", SELECTION)
    assert report.cards == ()
    assert report.unverified_ids == ("tg:-100123:1#a",)
    assert report.unsupported_quotes == ("明日の会議は10時からです、遅れないでください",)


def test_citation_after_the_full_stop_still_attaches() -> None:
    (card,) = validate(f"彼は「明日の会議は10時からです、遅れないでください」と言いました。 ({ID})", SELECTION).cards
    assert card.quote_verified


def test_citation_before_the_quote_attaches() -> None:
    (card,) = validate(f'According to {ID} he wrote "資料は共有フォルダにあります。" yesterday.', SELECTION).cards
    assert card.quote_verified


def test_nearest_id_wins_when_a_sentence_has_two() -> None:
    answer = (
        f"「明日の会議は10時からです、遅れないでください」({ID}) and “会議はA棟の3階で10時から始めます” ({FWD_ID})."
    )
    report = validate(answer, SELECTION)
    assert report.unsupported_quotes == ()
    assert all(card.quote_verified for card in report.cards)


def test_quotes_outside_the_cited_sentence_or_too_short_are_not_checked() -> None:
    answer = f"彼は「全く別の文章をここに書いています」と言った。別件です ({ID})。短い「10時から」({ID})。"
    report = validate(answer, SELECTION)
    assert report.unsupported_quotes == ()
    assert not report.cards[0].quote_verified


def test_id_inside_a_quote_does_not_attribute_it() -> None:
    report = validate(f"「これは {ID} という引用の中のIDです」", SELECTION)
    assert report.unsupported_quotes == ()
    assert [card.evidence_id for card in report.cards] == [ID]


def test_neutralized_alias_brackets_still_match() -> None:
    msg = authored(4601, TANAKA, "⟦P1⟧ という文字列が本文に含まれています")
    (card,) = validate("「[[P1]] という文字列が本文に含まれています」 tg:-100123:4601#a", _selection(msg)).cards
    assert card.quote_verified


def test_model_invented_speaker_and_date_never_reach_cards() -> None:
    answer = (
        f"The account owner Bob-Canary wrote on 1999-01-01 in ChatCanary: "
        f"「明日の会議は10時からです、遅れないでください」 ({ID})."
    )
    (card,) = validate(answer, SELECTION).cards
    assert card.speaker == "田中 太郎" and card.speaker_class is OwnerClass.OTHER
    for field in fields(card):
        value = str(getattr(card, field.name))
        assert "Canary" not in value and "1999" not in value
