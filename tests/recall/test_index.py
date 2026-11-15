"""RecallIndex over a plain-SQLite import store (synthetic data, no SQLCipher)."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from mordred_hermes.imports.records import ImportConversation, ImportMessage
from mordred_hermes.imports.store import ImportStore
from mordred_hermes.recall.index import RecallIndex
from mordred_hermes.recall.service import RecallError, RecallService
from tests.imports._factories import (
    MAIL_CONV_UID,
    OWNER,
    SENT_AT,
    SUZUKI,
    TANAKA,
    TG_CONV_UID,
    authored,
    mail_conv,
    mail_uid,
    message,
    part,
    tg_conv,
)

NOW = SENT_AT + 86400


def _commit(store: ImportStore, conv: ImportConversation, messages: list[ImportMessage]) -> None:
    run = store.run_begin(conv.source)
    result = store.write_thread(run, messages, conversation=conv)
    store.run_commit(run, {"inserted": result.inserted})


def _mail(message_id: str, text: str, *, sent_at: int) -> ImportMessage:
    uid = mail_uid(message_id)
    return message(uid, (part(uid, author=TANAKA, text=text),), conv_uid=MAIL_CONV_UID, sent_at=sent_at)


@pytest.fixture
def store(tmp_path: Path) -> ImportStore:
    store = ImportStore(tmp_path / "mordred.db", sqlite3.connect)
    store.initialize(tmp_path)
    _commit(
        store,
        tg_conv(),
        [
            authored(1, TANAKA, "経費精算の締め切りは27日に前倒しします。", sent_at=SENT_AT - 300),
            authored(2, OWNER, "了解です", sent_at=SENT_AT - 200),
            authored(3, SUZUKI, "領収書の添付も忘れずに", sent_at=SENT_AT - 100),
        ],
    )
    _commit(store, mail_conv(), [_mail("m1@example.com", "経費精算は25日締めで固定します。", sent_at=SENT_AT)])
    return store


def test_search_returns_cards_from_both_sources_with_a_conflict_note(store: ImportStore) -> None:
    result = RecallIndex(store).search("経費精算の締め切りを確認したい", now=NOW)
    assert {card.source for card in result.cards} == {"telegram", "mail"}
    assert result.confidence in {"high", "low"}
    assert "日付が一致しません" in result.conflict_note
    assert all(card.conflict for card in result.cards if card.days)


def test_cards_quote_stored_text_only(store: ImportStore) -> None:
    for card in RecallIndex(store).search("経費精算", now=NOW).cards:
        stored = card.excerpt.strip("…")
        assert stored in {"経費精算の締め切りは27日に前倒しします。", "経費精算は25日締めで固定します。"}
        for start, end in card.spans:
            assert card.excerpt[start:end].casefold() == "経費精算"


def test_unknown_selection_is_silent(store: ImportStore) -> None:
    result = RecallIndex(store).search("量子コンピュータの冷却装置", now=NOW)
    assert result.cards == []
    assert result.confidence == "none"


def test_open_returns_the_anchor_with_its_neighbours(store: ImportStore) -> None:
    anchor = next(c for c in RecallIndex(store).search("前倒し", now=NOW).cards if c.conv_uid == TG_CONV_UID)
    parts = RecallIndex(store).open(anchor.part_uid, before=1, after=1)
    assert [p["anchor"] for p in parts] == [True, False]
    assert parts[1]["text"] == "了解です"
    assert RecallIndex(store).open("tg:-1:999#a") == []


def test_dismissed_conversation_disappears_for_a_week(store: ImportStore) -> None:
    index = RecallIndex(store)
    index.dismiss(MAIL_CONV_UID, now=NOW)
    assert {c.source for c in index.search("経費精算", now=NOW + 3600).cards} == {"telegram"}
    assert "mail" in {c.source for c in index.search("経費精算", now=NOW + 8 * 86400).cards}


def test_a_hidden_conversation_is_listed_and_can_be_shown_again(store: ImportStore) -> None:
    index = RecallIndex(store)
    assert index.hidden(NOW) == []
    index.dismiss(MAIL_CONV_UID, now=NOW)

    [hidden] = index.hidden(NOW + 3600)
    assert hidden["conv_uid"] == MAIL_CONV_UID and hidden["source"] == "mail"
    assert hidden["hidden_at"] == int(NOW) and hidden["until"] == int(NOW) + 7 * 86400
    assert index.hidden(NOW + 8 * 86400) == []

    index.restore(MAIL_CONV_UID)
    assert index.hidden(NOW + 3600) == []
    assert "mail" in {c.source for c in index.search("経費精算", now=NOW + 3600).cards}
    index.restore(MAIL_CONV_UID)  # restoring what is not hidden does nothing


def test_service_maps_a_refused_store_to_a_content_free_code(tmp_path: Path) -> None:
    from mordred_hermes.imports.store import ImportRefused

    def refuse(_home: Path) -> ImportStore:
        raise ImportRefused("not_armed")

    with pytest.raises(RecallError) as caught:
        RecallService(opener=refuse, home=tmp_path).query("経費精算")
    assert caught.value.code == "import_store_unavailable"


def test_service_maps_a_busy_store_to_store_busy(tmp_path: Path) -> None:
    """A store held by another connection (a topics rebuild) is a passing state the client retries."""
    from mordred_hermes.imports.store import ImportRefused

    def busy(_home: Path) -> ImportStore:
        raise ImportRefused("busy")

    class HeldStore:
        def connection(self) -> object:
            raise ImportRefused("busy")

    with pytest.raises(RecallError) as at_open:
        RecallService(opener=busy, home=tmp_path).query("経費精算")
    with pytest.raises(RecallError) as mid_query:
        RecallService(opener=lambda _home: HeldStore(), home=tmp_path).conversation("p1")  # type: ignore[arg-type,return-value]
    assert (at_open.value.code, mid_query.value.code) == ("store_busy", "store_busy")


def test_service_cuts_the_selection(store: ImportStore, tmp_path: Path) -> None:
    result = RecallService(opener=lambda _home: store, home=tmp_path).query("経" * 5000)
    assert len(result["query"]) == 4000


def test_word_search_ands_every_word_as_typed(store: ImportStore) -> None:
    index = RecallIndex(store)
    both = index.search_words("経費精算 前倒し", now=NOW)
    assert {card.source for card in both.cards} == {"telegram"}
    assert both.derived.queries == ("経費精算 前倒し",)
    # A hiragana word is searched as typed (selection recall drops it); a word matches whole
    # terms only, so one kanji does not match inside 固定.
    assert [c.source for c in index.search_words("了解です", now=NOW).cards] == ["telegram"]
    assert {c.source for c in index.search_words("固定 経費精算", now=NOW).cards} == {"mail"}
    assert index.search_words("固 経費精算", now=NOW).cards == []
    assert index.search_words("経費精算 存在しない語", now=NOW).cards == []


def test_word_search_of_nothing_is_empty(store: ImportStore) -> None:
    result = RecallIndex(store).search_words(" 　 ", now=NOW)
    assert (result.cards, result.confidence, result.derived.queries) == ([], "none", ())


def test_a_conversation_is_read_whole_around_its_part(store: ImportStore) -> None:
    _commit(
        store,
        mail_conv(),
        [
            _mail("m2@example.com", "二通目、領収書は来週まとめます。", sent_at=SENT_AT + 60),
            _mail("m3@example.com", "三通目、了解しました。", sent_at=SENT_AT + 120),
        ],
    )
    index = RecallIndex(store)
    anchor = next(c for c in index.search("領収書", now=NOW).cards if c.conv_uid == MAIL_CONV_UID)
    whole = index.conversation(anchor.part_uid, max_chars=10_000)
    assert [p["text"][:3] for p in whole["parts"]] == ["経費精", "二通目", "三通目"]
    assert [p["anchor"] for p in whole["parts"]] == [False, True, False]
    assert (whole["omitted_before"], whole["omitted_after"]) == (0, 0)

    # Too long for the budget: the parts nearest the match are kept, and the rest counted.
    cut = index.conversation(anchor.part_uid, max_chars=len("二通目、領収書は来週まとめます。") + 12)
    assert [p["anchor"] for p in cut["parts"]] == [True, False]
    assert (cut["omitted_before"], cut["omitted_after"]) == (1, 0)


def test_a_telegram_conversation_is_never_read(store: ImportStore) -> None:
    tg = next(c for c in RecallIndex(store).search("前倒し", now=NOW).cards if c.conv_uid == TG_CONV_UID)
    assert RecallIndex(store).conversation(tg.part_uid, max_chars=10_000)["parts"] == []
    assert RecallIndex(store).conversation("tg:-1:999#a", max_chars=10_000)["parts"] == []
