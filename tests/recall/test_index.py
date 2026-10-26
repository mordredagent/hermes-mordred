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


def test_service_maps_a_refused_store_to_a_content_free_code(tmp_path: Path) -> None:
    from mordred_hermes.imports.store import ImportRefused

    def refuse(_home: Path) -> ImportStore:
        raise ImportRefused("not_armed")

    with pytest.raises(RecallError) as caught:
        RecallService(opener=refuse, home=tmp_path).query("経費精算")
    assert caught.value.code == "import_store_unavailable"


def test_service_cuts_the_selection(store: ImportStore, tmp_path: Path) -> None:
    result = RecallService(opener=lambda _home: store, home=tmp_path).query("経" * 5000)
    assert len(result["query"]) == 4000
