"""Deriving a summary and keywords from a page selection."""

from __future__ import annotations

from collections.abc import Sequence

from mordred_hermes.recall.derive import MAX_SELECTION, derive, keywords_of, selection_words

PARAGRAPH = (
    "経費精算の締め切りについて確認したい。先月の分がまだ未提出で、領収書の添付も忘れていた。"
    "総務の田中さんからは、1月分は31日必着、システム移行のため27日に前倒しすると連絡が来ている。"
    "リマインダーは毎月20日に設定する予定。"
)


def test_keywords_are_the_things_worth_searching() -> None:
    result = derive(PARAGRAPH)
    assert {"経費精算", "締め切り"} <= set(result.keywords)
    assert result.queries
    assert all(len(query) >= 2 for query in result.queries)


def test_keywords_are_whole_morphemes_with_numbers_and_formal_nouns_split_off() -> None:
    every = keywords_of(PARAGRAPH, limit=100)
    assert {"27日", "31日", "20日", "毎月", "必着", "前倒し", "田中"} <= set(every)
    assert not {"ため27日", "31日必着", "毎月20日", "田中さん", "確認"} & set(every)
    assert keywords_of("Use AI privately") == ["privately", "AI"]  # "use" is a stop word


def test_corpus_frequencies_rank_rare_keywords_first_and_drop_absent_ones() -> None:
    counts = {"経費精算": 40, "27日": 2, "締め切り": 300}

    def frequencies(words: Sequence[str]) -> tuple[dict[str, int], int]:
        return {word: counts.get(word, 0) for word in words}, 1000

    kept = keywords_of(PARAGRAPH, frequencies=frequencies)
    assert kept == ["27日", "経費精算", "締め切り"]  # everything else is absent from the corpus


def test_summary_is_the_keyword_rich_sentence() -> None:
    result = derive(PARAGRAPH)
    assert result.summary in PARAGRAPH and result.summary.endswith("。")
    richest = max(sum(word in sentence for word in result.keywords) for sentence in PARAGRAPH.split("。"))
    assert sum(word in result.summary for word in result.keywords) == richest


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


def test_selection_words_are_the_nouns_in_reading_order() -> None:
    text = "SQLCipher は SQLite のデータベースを暗号化する拡張で、WAL ファイルも大切な鍵で十分に守られます。"
    words = selection_words(text)
    assert words[:3] == ["SQLCipher", "SQLite", "データベース"]
    assert "暗号化" in words and "WAL" in words
    # Verbs (守る) and adjectival nouns standing alone (大切, 十分) say how, not what about.
    assert not any(word.startswith("守") for word in words) and {"大切", "十分"}.isdisjoint(words)


def test_english_function_words_are_not_selection_words() -> None:
    words = selection_words("FRI is the low degree test used by STARKs to check the folding between rounds.")
    assert {"is", "to", "by", "between"}.isdisjoint(words)
    assert {"FRI", "STARKs", "folding"} <= set(words)
