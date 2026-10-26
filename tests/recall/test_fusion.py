"""Scoring components and the confidence gate."""

from __future__ import annotations

import math

from mordred_hermes.recall import fusion


def test_lexical_is_bounded_and_zero_for_the_like_path() -> None:
    assert fusion.lexical_component(0.0) == 0.0
    assert fusion.lexical_component(-4.0) == 1.0
    assert fusion.lexical_component(-100.0) == 1.0
    assert 0.0 < fusion.lexical_component(-2.0) < 1.0


def test_coverage_is_case_insensitive_and_partial() -> None:
    assert fusion.coverage_component(["deploy", "key"], "DEPLOY_KEY") == 1.0
    assert fusion.coverage_component(["deploy", "key", "deploy key"], "DEPLOY_KEY") == 2 / 3
    assert fusion.coverage_component(["x"], "nothing") == 0.0
    assert fusion.coverage_component([], "anything") == 0.0


def test_questions_are_penalised_only_at_the_opening() -> None:
    assert fusion.assertion_component("締め切りはいつ\uff1f") == 0.0
    assert fusion.assertion_component("How do I rotate it?") == 0.0
    assert fusion.assertion_component("締め切りは25日です。") == 1.0
    # A statement that quotes a question later is not penalised.
    text = "結論として25日で固定します。" + "補足" * 30 + "これは何か\uff1f"
    assert fusion.assertion_component(text) == 1.0


def test_recency_halves_at_the_half_life() -> None:
    now = 1_000_000_000.0
    assert fusion.recency_component(None, now) == 0.0
    assert fusion.recency_component(int(now), now) == 1.0
    assert math.isclose(fusion.recency_component(int(now - 180 * 86400), now), 0.5, rel_tol=1e-6)


def test_score_weights_sum_to_one() -> None:
    assert math.isclose(sum(fusion.WEIGHTS.values()), 1.0)


def test_confidence_gate() -> None:
    assert fusion.confidence([], distinct_conversations=0) == "none"
    assert fusion.confidence([0.9], distinct_conversations=1) == "high"
    assert fusion.confidence([0.9, 0.89], distinct_conversations=2) == "low"  # flat
    assert fusion.confidence([0.2], distinct_conversations=1) == "none"
    assert fusion.confidence([0.4], distinct_conversations=1) == "low"


def test_sort_is_stable_on_equal_scores() -> None:
    class Card:
        def __init__(self, score, sent_at, uid):
            self.score, self.sent_at, self.part_uid = score, sent_at, uid

    cards = [Card(0.5, 10, "b#a"), Card(0.5, 10, "a#a"), Card(0.5, 20, "c#a")]
    ordered = fusion.sort_cards(cards)
    assert [c.part_uid for c in ordered] == ["c#a", "a#a", "b#a"]
