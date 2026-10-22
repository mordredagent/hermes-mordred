"""Properties of the free-text secret redactor (``contracts.redact_text_secrets``) over generated text.

Three review rounds each found a way one rule hid another or a shared stretch was rescanned per keyword. These
tests check the two guarantees directly instead of example by example:

- it only adds redactions: every value the base revision ``efe9bb27d`` replaced is still replaced, and every
  value a phrase loses on its own it still loses next to, or nested in, other phrases;
- it stays near-linear: for each adversarial shape, 40 KB costs well under 16 times 10 KB.

The values a text names (``contracts.secret_values``) stay bounded and near-linear too, and given values are found
(``contracts.redact_values``) exactly as the combined pattern they replaced found them.
"""

from __future__ import annotations

import itertools
import random
import re
import sys
import time
import tracemalloc
import weakref
from collections.abc import Callable, Iterable

import pytest

from mordred_hermes.activity import contracts
from tests import _activity_redaction_baseline as base
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
    # control characters, other spaces, zero-width characters and other scripts (security review 2026-10-22)
    "Hun\x01ter2-x をパスワードに入力",
    "Hun\x7fter2-xをパスワードに",
    "パスワードにHun\x1bter2を入力",
    "use Hun\x00ter2-x for the password",
    "the password for the bank is Hun\x08ter2-x",
    "set the password to Hun\x0eter2-x",
    "my password is\xa0Hunter2-fake-pw",
    "my\u3000password\u3000is\u3000Hunter2-x",
    "パスワードは\u3000abc123",
    "password\u200b: Hunter2-x",
    "Hunter2-x\u200b as the password",
    "пароль Hunter2-x as the password \U0001f642",
    "the password is \u0397unter2-x",
    "\u30d1\u30b9\u30ef\u30fc\u30c9\u306bHun\x01ter2-x\u3092\u5165\u529b",
    "api  key: abc123def",
    "api\xa0key: abc123def",
    "access\ttoken = abcdef",
    "pin\u3000code 0000",
    "pin  code=1234",
]
#: Separators that end a phrase: what one phrase loses it must still lose next to another.
CLAUSE_SEPARATORS = [". ", "; ", ", ", "\n"]
#: Every separator, words merged too: the base revision's values must still be replaced.
ALL_SEPARATORS = [*CLAUSE_SEPARATORS, " ", "", "\xa0", "\u3000", "\u200b", "\x01", "\x7f"]
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
    for match in contracts._SECRET_KEYWORD_RE.finditer(clean):
        if any(lo <= match.start() < hi for lo, hi in urls):
            continue
        for keyword in contracts._readings(clean, match):
            for form, ascii_only in FORMS:
                span = None if ascii_only and not keyword.group(0).isascii() else form(index, keyword)
                if span is not None and not any(lo < span[0] < hi or lo < span[1] < hi for lo, hi in urls):
                    spans.append(span)
    return spans


class _ReferenceIndex:
    """The scans the near-linear index (:class:`.contracts._TextIndex`) replaced, one character at a time, with
    the character classes of the code they replaced."""

    def __init__(self, text: str) -> None:
        self.text = text

    def run_end(self, pos: int) -> int:
        tail = base._VALUE_TAIL_RE.match(self.text, pos)
        return tail.end() if tail else pos

    def trimmed(self, start: int, end: int) -> int:
        return int(base._without_closing_marks(self.text, start, end))

    def opened(self, start: int, end: int) -> int:
        while start < end and self.text[start] in base._VALUE_QUOTES:
            start += 1
        return start

    def token_start(self, end: int) -> int:
        while end > 0 and not self.text[end - 1].isspace():
            end -= 1
        return end

    def ascii_start(self, end: int) -> int:
        while end > 0 and self.text[end - 1].isascii() and not self.text[end - 1].isspace():
            end -= 1
        return end

    def ascii_end(self, pos: int) -> int:
        while pos < len(self.text) and self.text[pos].isascii() and not self.text[pos].isspace():
            pos += 1
        return pos

    def breaker(self, pos: int) -> int:
        marks = {*base._VALUE_QUOTES, *contracts._JA_AFTER_KEYWORD}
        return next((at for at in range(pos, len(self.text)) if self.text[at] in marks), len(self.text))


#: Pieces of generated text: every kind of character the scans tell apart, and runs longer than the index's
#: local look (:data:`.contracts._LOCAL_SCAN_CHARS`), so its tables are used too.
PIECES = [
    *(" ", "\xa0", "\u3000", "\u200b", "\ufeff", "\x00", "\x01", "\x7f", "\x1c", "\t", "\n", "\r"),
    *(".", ")", "\u201d", ":", "=", "\uff1a", "(", "\u300c", "'", '"', "a", "Z", "9", "-", "_", "/"),
    *("\u3092", "\u306b", "\u3068", "\u6b04", "\u30d1\u30b9\u30ef\u30fc\u30c9", "password", "pin", "PIN"),
    *(" is ", " for ", " to ", " as the password", "set ", "Hunter2-x", "\u043f", "\u0397", "\U0001f642"),
    *("a" * 70, "." * 70, " " * 40, "(" * 70, "\x01" * 70, "\u3000" * 40, "pin:" * 20, "\u201d" * 70),
]


def _generated(count: int, seed: int) -> list[str]:
    chooser = random.Random(seed)
    return ["".join(chooser.choice(PIECES) for _ in range(chooser.randint(1, 60))) for _ in range(count)]


def test_the_index_reads_the_same_characters_as_the_scans_it_replaced() -> None:
    """Each table of the index stops at exactly the characters the replaced scan stopped at (every BMP code
    point and a sample beyond); the ASCII run may only be wider than the printable run it replaced forward."""
    for code in [*range(0x10000), *range(0x10000, 0x110000, 997), 0x1F642]:
        char = chr(code)
        assert bool(contracts._WHITESPACE_RE.match(char)) == char.isspace(), hex(code)
        assert bool(contracts._NOT_VALUE_RE.match(char)) != bool(base._VALUE_TAIL_RE.fullmatch(char)), hex(code)
        assert bool(contracts._NOT_CLOSING_RE.match(char)) == (char not in base._TRAILING_MARKS), hex(code)
        assert bool(contracts._NOT_OPENING_RE.match(char)) == (char not in base._VALUE_QUOTES), hex(code)
        ascii_run = char.isascii() and not char.isspace()
        assert (not contracts._NOT_ASCII_RUN_RE.match(char)) == ascii_run == contracts._ascii_not_space(char)
        assert contracts._not_space(char) == (not char.isspace())
        breaker = char in base._VALUE_QUOTES or char in contracts._JA_AFTER_KEYWORD
        assert bool(contracts._REGION_BREAKERS_RE.match(char)) == breaker, hex(code)
        if "!" <= char <= "~":
            assert ascii_run  # never narrower than the printable run it replaced


def test_the_index_answers_like_the_scans_it_replaced() -> None:
    for text in _generated(150, seed=1):
        fast, slow = contracts._TextIndex(text), _ReferenceIndex(text)
        for pos in range(len(text) + 1):
            assert fast.run_end(pos) == slow.run_end(pos), (text, pos)
            assert fast.token_start(pos) == slow.token_start(pos), (text, pos)
            assert fast.ascii_start(pos) == slow.ascii_start(pos), (text, pos)
            assert fast.ascii_end(pos) == slow.ascii_end(pos), (text, pos)
            assert fast.breaker(pos) == slow.breaker(pos), (text, pos)
            for start in {0, max(0, pos - 3), pos}:
                assert fast.trimmed(start, pos) == slow.trimmed(start, pos), (text, start, pos)
                assert fast.opened(start, len(text)) == slow.opened(start, len(text)), (text, start)


def test_the_index_redacts_exactly_like_the_scans_it_replaced(monkeypatch: pytest.MonkeyPatch) -> None:
    texts = [*_generated(400, seed=2), *PHRASES, *(" ".join(parts) for parts in _triples(100))]
    fast = [contracts._secret_spans(text) for text in texts]
    monkeypatch.setattr(contracts, "_TextIndex", _ReferenceIndex)
    slow = [contracts._secret_spans(text) for text in texts]
    assert [(text, a) for text, a, b in zip(texts, fast, slow, strict=True) if a != b] == []


def test_a_control_character_inside_a_value_never_splits_it() -> None:
    for text in ("Hun\x01ter2-x をパスワードに入力", "Hun\x7fter2-xをパスワードに", "パスワードにHun\x1bter2を入力"):
        clean, replaced = contracts.redact_text_secrets(text)
        assert replaced and "ter2" not in clean and "Hun" not in clean, repr(clean)


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


@pytest.mark.parametrize("separator", [". ", " "], ids=repr)
def test_every_value_a_form_finds_is_a_named_secret(separator: str) -> None:
    """``secret_values`` lists each value any single form finds for any keyword, not only the merged spans
    (Codex review of 6da5ccad2: "PIN code=1234" once listed only "code=1234", not "1234")."""
    failures = []
    for text in [*PHRASES, *(separator.join(parts) for parts in [*_pairs(), *_triples(200)])]:
        clean = contracts.redact_secret_tokens(text)
        found = contracts.secret_values(text)
        named = set(found.values)
        missing = [clean[start:end] for start, end in _each_form(text) if clean[start:end] not in named]
        if missing or not found.complete:  # the bound never bites on ordinary text
            failures.append((text, missing, found.complete))
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


# --- the values a text names stay bounded (Codex review of 7a1084bee) -------------------------------------------


def _suffixes(size: int) -> str:
    """Codex's input: each ``pin:`` names the rest of the run, so listing every value once materialised every
    suffix (about 200 MB for 40 KB) and compiled them all into one pattern."""
    return "pin:" * (size // 4) + "1234"


def _runs(size: int) -> str:
    """Runs whose values are all short enough to list, but each run's keywords name 63 overlapping ones."""
    return ("pin=" * 63 + "1 ") * (size // 254)


#: Each adversarial shape of the redactor, and two whose values overlap, for :func:`contracts.secret_values`.
NAMED_SHAPES: dict[str, Callable[[int], str]] = {**SHAPES, "suffixes": _suffixes, "runs": _runs}


@pytest.mark.parametrize("size", [4_000, 40_000])
def test_overlapping_values_stay_bounded_and_mark_the_list_incomplete(size: int) -> None:
    text = _suffixes(size)
    tracemalloc.start()
    try:
        found = contracts.secret_values(text)
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
    assert not found.complete  # the caller withholds everything instead (fail closed)
    assert len(found.values) <= contracts.MAX_SECRET_VALUES
    assert all(len(value) <= contracts.MAX_SECRET_VALUE_CHARS for value in found.values)
    assert peak < 64 * len(text) + 1_000_000, peak  # linear; the listed values once took about 200 MB at 40 KB


def test_the_bound_counts_distinct_values_and_their_length() -> None:
    def pins(count: int) -> str:
        return "; ".join(f"PIN={1000 + number}" for number in range(count))

    bound = contracts.MAX_SECRET_VALUES
    assert contracts.secret_values(pins(bound)) == contracts.SecretValues(
        tuple(str(1000 + number) for number in range(bound)), complete=True
    )
    assert contracts.secret_values(pins(bound) + "; " + pins(bound)).complete  # a repeated value counts once
    over = contracts.secret_values(pins(bound + 1))
    assert not over.complete and len(over.values) == bound
    longest = ("x1" * contracts.MAX_SECRET_VALUE_CHARS)[: contracts.MAX_SECRET_VALUE_CHARS]
    assert contracts.secret_values(f"password: {longest}") == contracts.SecretValues((longest,), complete=True)
    too_long = contracts.secret_values(f"PIN=4821, password: {longest}9")
    assert not too_long.complete and f"{longest}9" not in too_long.values


def _named_seconds(text: str, runs: int = 2) -> float:
    best = float("inf")
    for _ in range(runs):
        started = time.perf_counter()
        contracts.secret_values(text)
        best = min(best, time.perf_counter() - started)
    return best


@pytest.mark.parametrize("shape", NAMED_SHAPES)
def test_each_adversarial_shape_names_its_values_in_near_linear_time(shape: str) -> None:
    small = _named_seconds(NAMED_SHAPES[shape](10_000))
    large = _named_seconds(NAMED_SHAPES[shape](40_000))
    assert large < 2.0, (shape, small, large)
    assert large < 6 * max(small, 0.002), (shape, small, large)


def test_codex_input_is_named_fast() -> None:
    assert _named_seconds(_suffixes(40_000)) < 0.05


# --- given values are found as the combined pattern found them, without one ------------------------------------


def _alternation(text: str, values: Iterable[str]) -> tuple[str, bool]:
    """``contracts.redact_values`` of 7a1084bee: one pattern of every value, the longest first."""
    ordered = sorted({value for value in values if value}, key=len, reverse=True)
    if not ordered:
        return text, False
    pattern = re.compile(
        r"(?<![A-Za-z0-9])(?:" + "|".join(map(re.escape, ordered)) + r")(?![A-Za-z0-9])", re.IGNORECASE
    )
    return pattern.subn(contracts.REDACTED, text)[0], bool(pattern.search(text))


#: Pieces of generated values and texts: word joiners and boundaries, and characters whose case ``re`` pairs.
VALUE_PIECES = [
    *("a", "A", "b", "B", "1", "9", "-", "+", ".", "@", " ", "\n", "\xa0", "\u3000", "ab", "a-b", "1a", "x" * 70),
    *("\u00e9", "\u00c9", "\u03c3", "\u03a3", "\u03c2", "\u212a", "k", "K", "\u017f", "s", "S", "\u0131", "i"),
    *("I", "\u0130", "\u00df", "\u1e9e", "\u0390", "\u1fd3", "\ufb05", "\ufb06", "\u01c5", "\u01c4", "\u01c6"),
    *("\u30d1", "\U0001f642", "\U00010400", "\U00010428"),
]


def _pieces(chooser: random.Random, most: int) -> str:
    return "".join(chooser.choice(VALUE_PIECES) for _ in range(chooser.randint(1, most)))


def test_given_values_are_found_exactly_as_the_combined_pattern_found_them() -> None:
    chooser = random.Random(20261023)  # fixed: the same sample on every run
    failures = []
    for _ in range(3000):
        values = [_pieces(chooser, 3) for _ in range(chooser.randint(1, 6))]
        text = " ".join([_pieces(chooser, 12), *(chooser.choice(values) for _ in range(3)), _pieces(chooser, 12)])
        text = "".join(chooser.sample(text, len(text))) if chooser.random() < 0.2 else text
        expected = _alternation(text, values)
        if contracts.redact_values(text, values) != expected or contracts.contains_values(text, values) != expected[1]:
            failures.append((text, values))
    assert not failures, failures[:5]


@pytest.mark.parametrize("case", ["codex-overlaps", "swallowed", "shared-beginnings", "letters", "joined-letters"])
def test_hard_value_sets_are_found_exactly_as_the_combined_pattern_found_them(case: str) -> None:
    values, text = MATCH_CASES[case]
    for size in (0, 1, 2, 3, 7, 50, 301, 1000):
        for typed in (text(size), "x" + text(size), text(size) + "x", "-" + text(size) + "Z"):
            expected = _alternation(typed, values)
            assert contracts.redact_values(typed, values) == expected, (case, typed)
            assert contracts.contains_values(typed, values) == expected[1], (case, typed)


def _codes() -> list[int]:
    """Every BMP code point, every one beyond with a case mapping, and a sample of the rest."""
    beyond = range(0x10000, sys.maxunicode + 1)
    cased = [code for code in beyond if chr(code).lower() != chr(code) or chr(code).upper() != chr(code)]
    return sorted({*range(0x10000), *cased, *beyond[::997]})


def test_each_character_is_compared_without_case_as_re_ignorecase_compares_it() -> None:
    """One key per character (``contracts._case_key``), of one character, so positions agree; two characters share a
    key exactly when ``re.IGNORECASE`` matches one against the other, and a key is an ASCII letter or digit exactly
    when ``(?i)[A-Za-z0-9]`` matches the character (the whole-word boundary)."""
    boundary = re.compile(r"(?i)[A-Za-z0-9]")
    keys: dict[str, list[str]] = {}
    for code in _codes():
        char = chr(code)
        key = contracts._case_key(char)
        assert len(key) == 1, hex(code)
        assert bool(boundary.match(char)) == (key.isascii() and key.isalnum()), hex(code)
        keys.setdefault(key, []).append(char)
        for other in {char.lower(), char.upper(), char.title(), char.casefold(), char.swapcase()}:
            if len(other) == 1 and re.fullmatch(re.escape(char), other, re.IGNORECASE):
                assert contracts._case_key(other) == key, (hex(code), hex(ord(other)))
    for key, chars in keys.items():
        for char in chars:  # every character of a key is the key's own under re.IGNORECASE, both ways
            assert re.fullmatch(re.escape(char), key, re.IGNORECASE), (hex(ord(char)), hex(ord(key)))
            assert re.fullmatch(re.escape(key), char, re.IGNORECASE), (hex(ord(char)), hex(ord(key)))


#: Sets of named values (the bound's worth) and typed texts of ``size`` characters, each hard for one way of matching
#: (Codex review of f435dfc10: listing every overlapping place of ``"-a-" * i`` in ``"-a-" * 13333`` took 1.4 s).
MATCH_CASES: dict[str, tuple[list[str], Callable[[int], str]]] = {
    # every value a whole word at every third character
    "codex-overlaps": (["-a-" * count for count in range(1, 65)], lambda size: "-a-" * (size // 3)),
    # the values of every second place swallowed by a short one just before it
    "swallowed": (["+a", *("a" + "-+a" * count for count in range(63))], lambda size: "-+a" * (size // 3)),
    # long shared beginnings that fail at their last character
    "shared-beginnings": (
        [("a-+" * 85)[: 3 * count] + "Z" for count in range(1, 65)],
        lambda size: "a-+" * (size // 3),
    ),
    "letters": (["a" * count for count in range(1, 65)], lambda size: "a" * size),
    "joined-letters": ([("a-" * 128)[:count] for count in range(1, 65)], lambda size: "a-" * (size // 2)),
    "joiners": (["-" * count for count in range(4, 68)], lambda size: "-" * size),
    "words": (
        [f"{word}-{number}" for word in ("ordinary", "typed", "text", "hunter") for number in range(16)],
        lambda size: "ordinary typed text " * (size // 20),
    ),
    "non-ascii": (
        ["\u00e9" * count for count in range(1, 33)] + ["\u212a\u017f" * count for count in range(1, 33)],
        lambda size: "\u00e9\u212a\u017f " * (size // 4),
    ),
}


def _match_seconds(match: Callable[[], object], runs: int = 3) -> float:
    best = float("inf")
    for _ in range(runs):
        started = time.perf_counter()
        match()
        best = min(best, time.perf_counter() - started)
    return best


@pytest.mark.parametrize("case", MATCH_CASES)
def test_given_values_are_found_in_linear_time(case: str) -> None:
    """Whether typed text holds a named value (``contains_values``) and replacing them (``redact_values``) each
    take under 50 ms for 40 KB, and 40 KB under 6 times 10 KB."""
    values, text = MATCH_CASES[case]
    assert len(values) <= contracts.MAX_SECRET_VALUES
    for match in (contracts.contains_values, contracts.redact_values):
        small = _match_seconds(lambda match=match: match(text(10_000), values))
        large = _match_seconds(lambda match=match: match(text(40_000), values))
        assert large < 0.05, (match.__name__, small, large)
        assert large < 6 * max(small, 0.002), (match.__name__, small, large)


# --- compiled value patterns stay bounded (Codex review of 29c6be5c0) -------------------------------------------


def _module_cache_keys() -> set[object]:
    """What the :mod:`re` module's own caches hold (``_cache``; also ``_cache2`` from Python 3.12)."""
    return {key for name in ("_cache", "_cache2") for key in getattr(re, name, {})}


def test_value_patterns_are_compiled_outside_the_module_cache() -> None:
    """``re.compile`` keeps every pattern in the module's cache after this module's own cache dropped it (about 1 MiB
    for 32 withheld values of 4,000 characters); ``re._compiler.compile`` does not. It is private API: this test
    fails loudly if Python drops it (``contracts._compile_uncached`` then purges the module cache instead)."""
    assert contracts._COMPILE_UNCACHED is re._compiler.compile  # type: ignore[attr-defined]
    marker = f"marker-{random.Random().getrandbits(64):x}"
    before = _module_cache_keys()
    assert contracts.contains_values(f"a {marker} b", [marker, f"{marker}-2"])
    assert contracts.redact_values(f"a {marker} b", [marker]) == ("a redacted b", True)
    after = _module_cache_keys()
    assert after <= before and not any(marker in str(key) for key in after)


def test_without_the_private_compiler_the_module_cache_is_purged(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(contracts, "_COMPILE_UNCACHED", None)
    contracts._VALUE_PATTERNS.clear()
    marker = f"marker-{random.Random().getrandbits(64):x}"
    assert contracts.redact_values(f"a {marker} b", [marker]) == ("a redacted b", True)
    assert not any(marker in str(key) for key in _module_cache_keys())
    contracts._VALUE_PATTERNS.clear()


def test_the_value_pattern_cache_frees_what_it_evicts(monkeypatch: pytest.MonkeyPatch) -> None:
    compiled: list[weakref.ref[re.Pattern[str]]] = []
    compile_uncached = contracts._compile_uncached

    def recorded(source: str) -> re.Pattern[str]:
        pattern = compile_uncached(source)
        compiled.append(weakref.ref(pattern))
        return pattern

    monkeypatch.setattr(contracts, "_compile_uncached", recorded)
    contracts._VALUE_PATTERNS.clear()
    for number in range(40):
        assert contracts.contains_values(f"x value-{number} y", [f"value-{number}", "other"])
    assert len(compiled) == 40
    alive = [pattern for ref in compiled if (pattern := ref()) is not None]
    assert len(alive) == contracts._MAX_VALUE_PATTERNS
    # a set larger than the character budget is compiled for the call, never kept
    huge = ["x" * 3_996 + f"{number:04d}" for number in range(70)]
    assert contracts.contains_values("x " + huge[3] + " y", huge)
    assert compiled[-1]() is None
    assert contracts._VALUE_PATTERNS.chars <= contracts._MAX_VALUE_PATTERN_CHARS
    contracts._VALUE_PATTERNS.clear()
