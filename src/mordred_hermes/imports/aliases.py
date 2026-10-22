"""Identity-keyed aliases and safe display strings for imported history.

Security contract:

- Aliases (``⟦P1⟧`` people, ``⟦C1⟧`` chats, ``⟦E1⟧`` e-mail addresses,
  ``⟦T1⟧`` phone numbers) are assigned by *stable identity* when the source
  provides one, else by display name. Two people who share a display name get
  distinct tokens; :meth:`IdentityAliases.dealias` renders the second as
  ``<name> (2)``. Unknown identities are never merged on a guessed name.
- The alias table holds real names and never leaves this process. Its
  ``repr`` shows counts only, so a traceback or log line cannot leak it.
- :func:`neutralize` turns literal ``⟦``/``⟧`` in third-party text into
  ``[[``/``]]`` so imported text cannot forge an alias.
- :func:`safe_display` makes a display name safe for a one-line head: control
  and format characters are removed, the length is bounded, and a name that
  collides with a reserved role label (``account owner``, ``me``, ``assistant``,
  ...) is rendered as ``<name> (contact)``. Only code ever emits the owner label.
  The collision check ignores zero-width characters and combining marks and
  reads Cyrillic, Greek and Armenian look-alike letters as Latin, so a
  homoglyph spelling of a label is caught too (:func:`_skeleton`).

Behaviour of :meth:`IdentityAliases.scrub_text` and
:meth:`IdentityAliases.dealias_stream` mirrors ``extension/telegram/ask.py``
(copied, not imported, so this library does not depend on the telegram extra).
"""

from __future__ import annotations

import re
import unicodedata
from collections.abc import AsyncGenerator, AsyncIterator
from dataclasses import dataclass, field
from typing import Final, Literal

from ._labels import RESERVED_LABELS, labels_for

AliasKind = Literal["P", "C", "E", "T"]

ALIAS_OPEN: Final = "⟦"
ALIAS_CLOSE: Final = "⟧"
_ALIAS_KINDS: Final = frozenset({"P", "C", "E", "T"})
_MAX_DISPLAY_CHARS: Final = 64
_MAX_HELD_BACK: Final = 16
_MIN_QUESTION_NAME_CHARS: Final = 2

_EMAIL_RE: Final = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_PHONE_CANDIDATE_RE: Final = re.compile(r"(?<![\w+])\+?\d[\d\s().-]{7,}\d(?![\w])")
_DATE_PREFIX_RE: Final = re.compile(r"\d{4}[-./]\d{1,2}[-./]\d{1,2}")
_TOKEN_RE: Final = re.compile(re.escape(ALIAS_OPEN) + r"[PCET]\d+" + re.escape(ALIAS_CLOSE))
_ASCII_WORD: Final = re.compile(r"[A-Za-z0-9]")
# Head-line grammar characters. A display name or title must not be able to
# fake a field (``speaker:``), a qualifier ``(...)``, the ``/ <date>`` tail or
# an arrow, so these become their full-width (written as escapes) or ASCII look-alikes.
_GRAMMAR: Final = str.maketrans({"→": "->", "⇄": "<->", "(": "\uff08", ")": "\uff09", "/": "\uff0f", ":": "\uff1a"})


def neutralize(text: str) -> str:
    """Stop third-party text from forging an alias (e.g. a literal ⟦P1⟧)."""
    return text.replace(ALIAS_OPEN, "[[").replace(ALIAS_CLOSE, "]]")


def _looks_like_phone(value: str) -> bool:
    """10-15 digits, written with a leading + or with separators, not a date."""
    digits = sum(c.isdigit() for c in value)
    if not 10 <= digits <= 15 or _DATE_PREFIX_RE.match(value):
        return False
    return value.startswith("+") or any(c in value for c in " -()")


def clean_display(name: str | None, *, max_chars: int = _MAX_DISPLAY_CHARS) -> str:
    """One bounded line: drop control/format characters, defuse grammar characters."""
    if not name:
        return ""
    kept: list[str] = []
    for char in name:
        category = unicodedata.category(char)
        if category == "Cf":
            continue
        kept.append(" " if category in {"Cc", "Zl", "Zp"} else char)
    collapsed = " ".join("".join(kept).translate(_GRAMMAR).split())
    if len(collapsed) > max_chars:
        collapsed = collapsed[: max_chars - 1].rstrip() + "…"
    return collapsed


def _fold(text: str) -> str:
    return " ".join(unicodedata.normalize("NFKC", text).casefold().split())


# Reserved-label comparison only (display text is never changed): letters of
# other scripts that look like Latin ones, written as escapes because the
# letters themselves are confusable. Upper case maps straight to lower case.
_CONFUSABLES: Final = str.maketrans(
    {
        # Cyrillic a e o p c x y i j s h d q w l
        "\u0430": "a", "\u0435": "e", "\u043e": "o", "\u0440": "p", "\u0441": "c", "\u0445": "x",
        "\u0443": "y", "\u0456": "i", "\u0458": "j", "\u0455": "s", "\u04bb": "h", "\u0501": "d",
        "\u051b": "q", "\u051d": "w", "\u04cf": "l",
        # Cyrillic A B E K M H O P C T X Y I J S H D Q W l
        "\u0410": "a", "\u0412": "b", "\u0415": "e", "\u041a": "k", "\u041c": "m", "\u041d": "h",
        "\u041e": "o", "\u0420": "p", "\u0421": "c", "\u0422": "t", "\u0425": "x", "\u0423": "y",
        "\u0406": "i", "\u0408": "j", "\u0405": "s", "\u04ba": "h", "\u0500": "d", "\u051a": "q",
        "\u051c": "w", "\u04c0": "l",
        # Greek a o p v i k t u
        "\u03b1": "a", "\u03bf": "o", "\u03c1": "p", "\u03bd": "v", "\u03b9": "i", "\u03ba": "k",
        "\u03c4": "t", "\u03c5": "u",
        # Greek A B E Z H I K M N O P T Y X
        "\u0391": "a", "\u0392": "b", "\u0395": "e", "\u0396": "z", "\u0397": "h", "\u0399": "i",
        "\u039a": "k", "\u039c": "m", "\u039d": "n", "\u039f": "o", "\u03a1": "p", "\u03a4": "t",
        "\u03a5": "y", "\u03a7": "x",
        # Armenian n u o h; Latin script g, dotless i, alpha
        "\u0578": "n", "\u057d": "u", "\u0585": "o", "\u0570": "h", "\u0261": "g", "\u0131": "i",
        "\u0251": "a",
    }
)  # fmt: skip
# Letters that render as blank space (Hangul fillers, braille blank).
_BLANKS: Final = frozenset("\u115f\u1160\u3164\uffa0\u2800")
# Dropped from the comparison form: format (zero-width) characters, combining
# marks, private-use characters and lone surrogates.
_SKELETON_DROPPED: Final = frozenset({"Cf", "Mn", "Me", "Co", "Cs"})
_SKELETON_SPACE: Final = frozenset({"Cc", "Zs", "Zl", "Zp"})
_LOOKALIKE_SCRIPTS: Final = frozenset({"CYRILLIC", "GREEK", "ARMENIAN"})
# Stands for an unmapped look-alike letter. Private use, so a name can never
# carry one into the comparison form (``Co`` is dropped first).
_WILDCARD: Final = "\ue000"


def _script(char: str) -> str:
    """First word of a letter's Unicode name (``LATIN``, ``CYRILLIC``, ...); ``""`` otherwise."""
    return unicodedata.name(char, "").partition(" ")[0] if char.isalpha() else ""


def _word_skeleton(word: str) -> str:
    """Map look-alike letters to Latin.

    In a word that mixes Latin with Cyrillic, Greek or Armenian letters, every
    such letter left unmapped becomes :data:`_WILDCARD`, so a look-alike this
    table does not know (``a<Greek lunate sigma>count``) still collides. A
    word in a single script keeps its letters, so a Cyrillic name never holds
    a wildcard.
    """
    scripts = {_script(char) for char in word}
    mapped = word.translate(_CONFUSABLES)
    if "LATIN" not in scripts or not scripts & _LOOKALIKE_SCRIPTS:
        return mapped
    return "".join(_WILDCARD if _script(char) in _LOOKALIKE_SCRIPTS else char for char in mapped)


def _skeleton(text: str) -> str:
    """The form compared against reserved labels.

    Compatibility decomposition, then format characters (zero-width ones
    included), combining marks and private-use characters are dropped and
    blank-looking letters become spaces; look-alike letters are mapped per
    word (:func:`_word_skeleton`); finally NFKC, case folding and whitespace
    collapsing.
    """
    kept: list[str] = []
    for char in unicodedata.normalize("NFKD", text):
        category = unicodedata.category(char)
        if category in _SKELETON_DROPPED:
            continue
        kept.append(" " if category in _SKELETON_SPACE or char in _BLANKS else char)
    words = " ".join(_word_skeleton(word) for word in "".join(kept).split())
    return " ".join(unicodedata.normalize("NFKC", words).casefold().translate(_CONFUSABLES).split())


_RESERVED_SKELETONS: Final = tuple(sorted({_skeleton(label) for label in RESERVED_LABELS}))


def _collides(skeleton: str, label: str) -> bool:
    """``skeleton`` is ``label`` or starts with it as a word; a wildcard matches any letter."""
    if len(skeleton) < len(label):
        return False
    if any(
        char != want and not (char == _WILDCARD and want.isalpha()) for char, want in zip(skeleton, label, strict=False)
    ):
        return False
    rest = skeleton[len(label) :]
    return not rest or not label.isascii() or not _ASCII_WORD.match(rest[0])


def _is_reserved(name: str) -> bool:
    skeleton = _skeleton(name)
    return any(_collides(skeleton, label) for label in _RESERVED_SKELETONS)


def safe_display(name: str | None, *, lang: str = "en") -> str:
    """A display name that can never read as a role label.

    Empty names become the ``unknown sender`` label; names colliding with a
    reserved label (exactly, or as a prefix such as ``account owner <a@b>``)
    become ``<name> (contact)``.
    """
    labels = labels_for(lang)
    display = neutralize(clean_display(name))
    if not display:
        return labels["unknown_sender"]
    if _is_reserved(display):
        return f"{display} ({labels['contact']})"
    return display


def _name_pattern(name: str) -> str:
    parts = [re.escape(word) for word in name.split()]
    body = r"\s+".join(parts)
    head = r"(?<![A-Za-z0-9])" if _ASCII_WORD.match(name[0]) else ""
    tail = r"(?![A-Za-z0-9])" if _ASCII_WORD.match(name[-1]) else ""
    return f"{head}{body}{tail}"


@dataclass
class IdentityAliases:
    """Two-way alias table for one request, keyed by stable identity."""

    enabled: bool = True
    _forward: dict[tuple[str, str], str] = field(default_factory=dict, init=False, repr=False)
    _reverse: dict[str, str] = field(default_factory=dict, init=False, repr=False)
    _counters: dict[str, int] = field(default_factory=dict, init=False, repr=False)
    _display_counts: dict[tuple[str, str], int] = field(default_factory=dict, init=False, repr=False)
    # Folded person display name -> aliases assigned to people with that name.
    _person_names: dict[str, list[str]] = field(default_factory=dict, init=False, repr=False)
    _person_displays: set[str] = field(default_factory=set, init=False, repr=False)

    def __repr__(self) -> str:
        return f"IdentityAliases(enabled={self.enabled}, size={len(self._forward)})"

    def alias(self, kind: AliasKind, key: str, display: str) -> str:
        """Alias for the identity ``(kind, key)``; ``key`` falls back to ``display``.

        When disabled, returns the display itself, still disambiguated with
        ``(2)``, ``(3)``... for a second identity with the same display.
        """
        if kind not in _ALIAS_KINDS:
            raise ValueError("unknown_alias_kind")
        if not display:
            return display
        ident = (kind, key or display)
        existing = self._forward.get(ident)
        if existing is not None:
            return existing
        count = self._display_counts.get((kind, display), 0) + 1
        self._display_counts[(kind, display)] = count
        rendered = display if count == 1 else f"{display} ({count})"
        if self.enabled:
            self._counters[kind] = self._counters.get(kind, 0) + 1
            value = f"{ALIAS_OPEN}{kind}{self._counters[kind]}{ALIAS_CLOSE}"
            self._reverse[value] = rendered
        else:
            value = rendered
        self._forward[ident] = value
        if kind == "P" and not _is_reserved(display):
            # Role-like labels ("unknown sender", "<name> (contact)") are never
            # substituted into a question.
            self._person_names.setdefault(_fold(display), []).append(value)
            self._person_displays.add(display)
        return value

    def scrub_text(self, text: str) -> str:
        """Replace e-mail addresses and phone numbers with ``⟦E⟧``/``⟦T⟧`` aliases."""
        if not self.enabled:
            return text
        text = _EMAIL_RE.sub(lambda m: self.alias("E", m.group(0), m.group(0)), text)
        return _PHONE_CANDIDATE_RE.sub(self._phone, text)

    def _phone(self, match: re.Match[str]) -> str:
        value = match.group(0)
        return self.alias("T", value, value) if _looks_like_phone(value) else value

    def alias_question(self, question: str) -> str:
        """Apply already-known person aliases to a question (longest name first).

        A name shared by several identities becomes ``⟦P1⟧/⟦P2⟧``. Latin names
        match case-insensitively on word boundaries; any whitespace run
        (including U+3000) matches the name's spaces.
        """
        if not self.enabled:
            return question
        question = neutralize(question)
        names = [name for name in self._person_displays if len("".join(name.split())) >= _MIN_QUESTION_NAME_CHARS]
        if not names:
            return question
        names.sort(key=len, reverse=True)
        pattern = re.compile("|".join(_name_pattern(name) for name in names), re.IGNORECASE)

        def replace(match: re.Match[str]) -> str:
            tokens = self._person_names.get(_fold(match.group(0)))
            return "/".join(tokens) if tokens else match.group(0)

        return pattern.sub(replace, question)

    def dealias(self, text: str) -> str:
        """Map alias tokens back to (disambiguated) real values."""
        if not self.enabled or not self._reverse:
            return text
        return _TOKEN_RE.sub(lambda m: self._reverse.get(m.group(0), m.group(0)), text)

    async def dealias_stream(self, chunks: AsyncIterator[str]) -> AsyncGenerator[str, None]:
        """Dealias streamed text; a token split across chunks is held back until complete."""
        if not self.enabled or not self._reverse:
            async for chunk in chunks:
                yield chunk
            return
        pending = ""
        async for chunk in chunks:
            pending += chunk
            cut = pending.rfind(ALIAS_OPEN)
            if cut != -1 and ALIAS_CLOSE not in pending[cut:] and len(pending) - cut <= _MAX_HELD_BACK:
                ready, pending = pending[:cut], pending[cut:]
            else:
                ready, pending = pending, ""
            if ready:
                yield self.dealias(ready)
        if pending:
            yield self.dealias(pending)
