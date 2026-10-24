"""``activity.matching``: term extraction (with CJK bigrams) and the bounded per-session budget."""

from __future__ import annotations

from mordred_hermes.activity.matching import MAX_SESSIONS, SessionBudget, terms


def test_terms_fold_case_and_drop_short_words_and_stopwords() -> None:
    assert terms("Export the Monthly FINANCE report for May 7") == {
        "export",
        "monthly",
        "finance",
        "report",
        "may",
        "7",
    }
    assert terms("an to of is when like task operating") == set()


def test_terms_keep_digits_and_split_on_punctuation() -> None:
    assert terms("app.example.com/reports?id=42") == {"app", "example", "com", "reports", "42"}
    assert terms("snake_case words") == {"snake", "case", "words"}


def test_cjk_runs_become_bigrams_and_match_across_phrasings() -> None:
    stored = terms("月次の経理レポートを出力する")
    assert {"経理", "レポ", "出力"} <= stored
    assert stored & terms("経理レポートの出力")
    assert not stored & terms("歯医者の予約")


def test_a_single_cjk_character_is_one_term() -> None:
    assert terms("表 report") == {"表", "report"}


def test_session_budget_charges_chars_and_shown_items_per_session() -> None:
    budget = SessionBudget()
    assert budget.snapshot("s1") == (0, frozenset())

    budget.charge("s1", 120, [("item-1", 1)])
    budget.charge("s1", 30, [("item-2", 3), ("item-1", 1)])

    assert budget.snapshot("s1") == (150, frozenset({("item-1", 1), ("item-2", 3)}))
    assert budget.snapshot("s2") == (0, frozenset())


def test_session_budget_is_bounded() -> None:
    budget = SessionBudget(max_sessions=2)
    budget.charge("a", 10, [("l", 1)])
    budget.charge("b", 10, [])
    budget.charge("c", 10, [])

    assert budget.snapshot("a") == (0, frozenset())
    assert MAX_SESSIONS == 256
