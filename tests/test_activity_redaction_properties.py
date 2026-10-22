"""Properties of the free-text secret redactor (``contracts.redact_text_secrets``) over generated text.

Three review rounds each found a way one rule hid another or a shared stretch was rescanned per keyword. These
tests check the two guarantees directly instead of example by example:

- it only adds redactions: every value the base revision ``efe9bb27d`` replaced is still replaced, and every
  value a phrase loses on its own it still loses next to, or nested in, other phrases;
- it stays near-linear: for each adversarial shape, 40 KB costs well under 16 times 10 KB.
"""

from __future__ import annotations

import itertools
import random
import re
import time
from collections.abc import Callable, Iterable

import pytest

from mordred_hermes.activity import contracts
from tests._activity_redaction_baseline import BASE_SPANS, base_spans

#: One phrase per form, positive and negative, English and Japanese.
PHRASES = [
    "type demo-user as the username and Hunter2-fake-pw as the password",
    "use Hunter2-fake-pw for the password",
    "enter 4821 for the PIN",
    "type Hunter2-fake-pw into the password field",
    "use swordfish as the password",
    "fill in 'correct horse battery' as the passphrase",
    "set the password to Hunter2-x",
    "change my password to 'abc def'",
    "update the PIN to 4821",
    "set the password for the bank to Hunter2-x",
    "change the password for bank is Hunter2-x to OtherPw-3",
    "the password for the bank is Hunter2-x",
    "my password on example.com is: abc123!",
    "password for admin = s3cr3t!",
    "password for account PIN=4821 is Hunter2-x",
    "password: hunter2",
    "PIN=4821",
    "my password is Hunter2-fake-pw",
    "the passcode was 99-red-balloons",
    "api key: abc123def",
    "otp 123456 expires soon",
    "Hunter2をパスワードに入力",
    "パスワードにHunter2を入力",
    "Hunter2というパスワード",
    "パスワードはabc123です",
    "the password field is empty",
    "pin the tab",
    "set the password to expire",
]
#: Separators that end a phrase: what one phrase loses it must still lose next to another.
CLAUSE_SEPARATORS = [". ", "; ", ", ", "\n"]
#: Every separator, words merged too: the base revision's values must still be replaced.
ALL_SEPARATORS = [*CLAUSE_SEPARATORS, " ", ""]
#: Frames that nest a phrase in a qualifier, before or after "to" / "is", or after "as".
FRAMES = [
    "password for account {} is Hunter2-x",
    "set the password for {} to Hunter2-x",
    "{} as the password",
    "the password is {}",
    "set the password to {}. done",
    "use {} for the PIN",
]


def _now(text: str) -> list[tuple[int, int]]:
    return contracts._secret_spans(contracts.redact_secret_tokens(text))


def _covered(spans: Iterable[tuple[int, int]], now: list[tuple[int, int]]) -> list[tuple[int, int]]:
    """The spans of ``spans`` that no span of ``now`` contains."""
    return [(start, end) for start, end in spans if not any(lo <= start and end <= hi for lo, hi in now)]


def _alone(phrase: str, offset: int) -> list[tuple[int, int]]:
    return [(start + offset, end + offset) for start, end in _now(phrase)]


def _joined(parts: tuple[str, ...], separator: str) -> tuple[str, list[tuple[int, int]]]:
    """``parts`` joined by ``separator`` and the spans each part loses on its own, placed in the join."""
    expected: list[tuple[int, int]] = []
    offset = 0
    for part in parts:
        expected += _alone(part, offset)
        offset += len(part) + len(separator)
    return separator.join(parts), expected


#: Each form of the redactor on its own: ``(form, whether it is read for an ASCII keyword only)``.
FORMS: list[tuple[Callable[[contracts._TextIndex, re.Match[str]], tuple[int, int] | None], bool]] = [
    (contracts._english_value_before, True),
    (contracts._japanese_value_before, False),
    (contracts._secret_value, False),
    (contracts._japanese_value_after, False),
    (contracts._value_after_to, False),
    (contracts._qualified_value, False),
]


def _each_form(text: str) -> list[tuple[int, int]]:
    """Every span any single form finds for any keyword outside a URL, each form read alone."""
    clean = contracts.redact_secret_tokens(text)
    index = contracts._TextIndex(clean)
    urls = [match.span() for match in contracts._URL_IN_TEXT_RE.finditer(clean)]
    spans = []
    for keyword in contracts._SECRET_KEYWORD_RE.finditer(clean):
        if any(lo <= keyword.start() < hi for lo, hi in urls):
            continue
        for form, ascii_only in FORMS:
            span = None if ascii_only and not keyword.group(0).isascii() else form(index, keyword)
            if span is not None and not any(lo < span[0] < hi or lo < span[1] < hi for lo, hi in urls):
                spans.append(span)
    return spans


def test_the_frozen_base_redactor_matches_what_the_base_revision_replaced() -> None:
    assert {text: base_spans(text) for text in BASE_SPANS} == BASE_SPANS


def _pairs() -> list[tuple[str, ...]]:
    return list(itertools.product(PHRASES, repeat=2))


def _triples(count: int = 600) -> list[tuple[str, ...]]:
    chooser = random.Random(20261022)  # fixed: the same sample on every run
    return [tuple(chooser.choice(PHRASES) for _ in range(3)) for _ in range(count)]


@pytest.mark.parametrize("separator", ALL_SEPARATORS, ids=repr)
def test_the_base_revisions_values_stay_replaced_in_every_combination(separator: str) -> None:
    failures = []
    for parts in [*_pairs(), *_triples(200)]:
        text = separator.join(parts)
        missed = _covered(base_spans(text), _now(text))
        if missed:
            failures.append((text, missed))
    assert not failures, failures[:5]


@pytest.mark.parametrize("separator", CLAUSE_SEPARATORS, ids=repr)
def test_a_phrase_loses_its_values_next_to_any_other_phrase(separator: str) -> None:
    failures = []
    for parts in [*_pairs(), *_triples()]:
        text, expected = _joined(parts, separator)
        missed = _covered(expected, _now(text))
        if missed:
            failures.append((text, [text[start:end] for start, end in missed]))
    assert not failures, failures[:5]


@pytest.mark.parametrize("separator", ALL_SEPARATORS, ids=repr)
def test_no_form_hides_another(separator: str) -> None:
    """Whatever one form finds for one keyword, read alone, the redactor replaces (Codex review: a matched
    "to" form once stopped the qualifier form, a qualified value once stopped the keywords inside it)."""
    failures = []
    for text in [*PHRASES, *(separator.join(parts) for parts in [*_pairs(), *_triples(200)])]:
        missed = _covered(_each_form(text), _now(text))
        if missed:
            failures.append((text, missed))
    assert not failures, failures[:5]


@pytest.mark.parametrize("frame", FRAMES)
def test_a_phrase_loses_its_values_nested_in_another_form(frame: str) -> None:
    before = frame.index("{}")
    failures = []
    for phrase in PHRASES:
        text = frame.format(phrase)
        missed = _covered([*_alone(phrase, before), *base_spans(text), *_each_form(text)], _now(text))
        if missed:
            failures.append((text, [text[start:end] for start, end in missed]))
    assert not failures, failures[:5]


# --- near-linear time on adversarial shapes ------------------------------------------------------------------

#: Each shape builds a text of about ``size`` characters.
SHAPES: dict[str, Callable[[int], str]] = {
    "pin-colon": lambda size: "pin:" * (size // 4),
    "pin-equals": lambda size: "pin=" * (size // 4),
    "keyword-is": lambda size: "password is " * (size // 12),
    "keyword-label": lambda size: "password: " * (size // 10),
    "set-to": lambda size: "set the password to " * (size // 20),
    "value-as": lambda size: "x as the password " * (size // 18),
    "qualifier-is": lambda size: "the password for a b c is " * (size // 26),
    "keyword-qualifier-alternating": lambda size: "password for pin is " * (size // 20),
    "qualified-to-alternating": lambda size: "set password for pin to x " * (size // 26),
    "dots-after-pins": lambda size: "pin:" * (size // 8) + "." * (size // 2),
    "brackets-after-pins": lambda size: "pin:" * (size // 8) + ")" * (size // 2),
    "curly-quotes-after-pins": lambda size: "pin:" * (size // 8) + "”" * (size // 2),
    "long-value-then-pins": lambda size: "password: " + "x" * (size // 2) + "-pin:" * (size // 10),
    "open-double-quotes": lambda size: 'password "' * (size // 10),
    "open-single-quote-words": lambda size: "type '" + "a " * (size // 2) + "' as the password",
    "open-brackets": lambda size: "password: " + "(" * size,
    "opening-marks-then-as": lambda size: "(" * size + "x as the password",
    "labels-run": lambda size: "password" + ":" * size + "x",
    "ja-topic": lambda size: "パスワードは" * (size // 6),
    "ja-object-target": lambda size: "aをパスワードに" * (size // 8),
    "ja-target-ascii-run": lambda size: "パスワードに" + "a" * size + "を",
    "ja-called-quotes": lambda size: "」というパスワード" * (size // 9),
    "ja-particles": lambda size: "を" * size + "パスワード" + "に" * size,
    "ascii-run-then-ja": lambda size: "a" * size + "をパスワードに",
    "heads": lambda size: "Hunter2 as the password settings " * (size // 33),
    "url-params": lambda size: "http://a/?" + "password=x&" * (size // 11),
    "long-token-before-as": lambda size: "a" * size + " as the password",
    "words-then-is": lambda size: "the password for " + "a " * (size // 2) + "is x1",
}


def _best_seconds(text: str, runs: int = 2) -> float:
    best = float("inf")
    for _ in range(runs):
        started = time.perf_counter()
        contracts.redact_text_secrets(text)
        best = min(best, time.perf_counter() - started)
    return best


@pytest.mark.parametrize("shape", SHAPES)
def test_each_adversarial_shape_stays_near_linear(shape: str) -> None:
    small = _best_seconds(SHAPES[shape](10_000))
    large = _best_seconds(SHAPES[shape](40_000))
    assert large < 2.0, (shape, small, large)
    # Linear work is 4x; quadratic would be 16x. Tiny times are mostly timer noise, so a floor applies.
    assert large < 6 * max(small, 0.002), (shape, small, large)
