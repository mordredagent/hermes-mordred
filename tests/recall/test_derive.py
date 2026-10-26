"""Deriving a summary and keywords from a page selection."""

from __future__ import annotations

from mordred_hermes.recall.derive import MAX_SELECTION, derive

PARAGRAPH = (
    "経費精算の締め切りについて確認したい。先月の分がまだ未提出で、領収書の添付も忘れていた。"
    "総務の田中さんからは、1月分は31日必着、システム移行のため27日に前倒しすると連絡が来ている。"
    "リマインダーは毎月20日に設定する予定。"
)


def test_keywords_are_the_things_worth_searching() -> None:
    result = derive(PARAGRAPH)
    assert "経費精算" in result.keywords
    assert "27日" in result.keywords
    assert result.queries
    assert all(len(query) >= 2 for query in result.queries)


def test_summary_is_the_keyword_rich_sentence() -> None:
    result = derive(PARAGRAPH)
    assert result.summary.startswith("総務の田中さんからは")
    assert result.summary.endswith("。")


def test_selection_is_cut_at_a_thousand_characters() -> None:
    long_text = "経費精算の締め切りは25日です。" * 200
    result = derive(long_text)
    assert MAX_SELECTION == 1000
    assert result.chars > MAX_SELECTION
    assert result.truncated is True
    # Keywords come from the kept prefix only.
    assert all(len(query) <= MAX_SELECTION for query in result.queries)


def test_queries_are_never_the_whole_sentence() -> None:
    # A sentence would AND its own terms and match nothing.
    result = derive(PARAGRAPH)
    assert result.summary not in result.queries
    assert all(len(query) <= 40 for query in result.queries)


def test_falls_back_when_nothing_word_like_survives() -> None:
    result = derive("!!! ??? ... ---")
    assert result.keywords == ()
    assert result.queries == ("!!! ??? ... ---",)


def test_empty_selection_has_no_queries() -> None:
    result = derive("   ")
    assert result.queries == ()
    assert result.summary == ""


def test_deduplicates_and_orders_by_weight() -> None:
    result = derive("経費精算 経費精算 経費精算 締め切り")
    assert result.keywords[0] == "経費精算"
    assert len(result.keywords) == len(set(result.keywords))
