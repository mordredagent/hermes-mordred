"""Card construction: excerpt/spans must always index into the stored text."""

from __future__ import annotations

from mordred_hermes.recall.cards import (
    build_card,
    conflict_summary,
    days_in,
    detect_kind,
    excerpt,
    mark_conflicts,
    terms_of,
)


def _part(text: str, *, source: str = "mail", conv: str = "mail:a:t:x", uid: str = "mail:a:m1#a") -> dict:
    return {
        "part_uid": uid,
        "conv_uid": conv,
        "source": source,
        "title": "t",
        "author": "a",
        "owner_class": "other",
        "sent_at": 1_700_000_000,
        "message_id": "m1",
        "text": text,
    }


def test_terms_dedupe_and_keep_the_whole_query() -> None:
    assert terms_of("deploy key") == ["deploy", "key", "deploy key"]
    assert terms_of("  経費  ") == ["経費"]
    assert terms_of("") == []


def test_excerpt_is_a_substring_and_spans_land_on_the_terms() -> None:
    text = "前置き" * 40 + "経費精算の締め切りは25日" + "後置き" * 40
    shown, spans = excerpt(text, ["経費精算の締め切り"])
    assert shown.strip("…") in text
    for start, end in spans:
        assert shown[start:end] == "経費精算の締め切り"


def test_excerpt_marks_are_case_insensitive() -> None:
    shown, spans = excerpt("Rotate DEPLOY_KEY in the vault", ["deploy_key"])
    assert len(spans) == 1
    start, end = spans[0]
    assert shown[start:end].lower() == "deploy_key"


def test_kind_detection() -> None:
    assert detect_kind("締め切りは25日で固定にします") in ("decision", "deadline")
    assert detect_kind("31日から27日に前倒しします") == "change"
    assert detect_kind("verify(inputs, proof) を直す") == "code"
    assert detect_kind("ただの雑談です") == "statement"


def test_days_in_normalises_and_dedupes() -> None:
    assert days_in("31日から27日、そして27日") == ("31日", "27日")


def test_conflict_needs_two_sources_with_different_days() -> None:
    one = build_card(
        part=_part("締め切りは25日", source="codex", conv="codex:s", uid="codex:s:1#a"),
        terms=["締め切り"],
        score=1.0,
        components={},
    )
    two = build_card(part=_part("締め切りは27日", source="mail"), terms=["締め切り"], score=1.0, components={})
    same = build_card(
        part=_part("締め切りは25日", source="telegram", conv="tg:1", uid="tg:1:1#a"),
        terms=["締め切り"],
        score=1.0,
        components={},
    )
    flagged = mark_conflicts([one, two, same])
    assert all(card.conflict for card in flagged)
    note = conflict_summary(flagged)
    assert "25日" in note and "27日" in note


def test_conflict_is_not_flagged_within_one_source() -> None:
    a = build_card(part=_part("25日", uid="mail:a:m1#a"), terms=["締め切り"], score=1.0, components={})
    b = build_card(part=_part("27日", uid="mail:a:m2#a"), terms=["締め切り"], score=1.0, components={})
    assert conflict_summary([a, b]) == ""


def test_card_never_invents_text() -> None:
    text = "経費精算の締め切りは毎月末日です。"
    card = build_card(part=_part(text), terms=["経費精算"], score=1.0, components={})
    assert card.excerpt.strip("…") in text
