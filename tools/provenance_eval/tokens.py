"""Fact tokens such as ``KM-4821`` and their normalised matching.

Every generated fact carries one unique token, so scoring is deterministic
substring matching: answers are NFKC-normalised and hyphen look-alikes become
``-`` before tokens are searched. A token-shaped string that no generated fact
carries is a fabrication.
"""

from __future__ import annotations

import re
import unicodedata
from typing import Final

__all__ = ["TOKEN_PREFIXES", "TOKEN_RE", "find_tokens", "normalize", "split_sentences", "visible_tokens"]

TOKEN_PREFIXES: Final = ("KM", "QX", "RB", "TZ", "LV", "PN", "WD", "HC", "JF", "SG")
#: Hyphen look-alikes NFKC leaves alone (written as escapes; they look identical).
_HYPHENS: Final = str.maketrans(dict.fromkeys("\u2010\u2011\u2012\u2013\u2014\u2015\u2212\u2043\ufe58\ufe63", "-"))
TOKEN_RE: Final = re.compile(r"(?<![A-Za-z0-9])([A-Z]{2})[ \t]?-[ \t]?(\d{4})(?![0-9])")
_SENTENCE_SPLIT_RE: Final = re.compile(r"(?<=[。\uff0e\uff01\uff1f!?])|(?<=\.)(?=\s)|\n")


def normalize(text: str) -> str:
    """NFKC, then hyphen look-alikes to ``-``."""
    return unicodedata.normalize("NFKC", text).translate(_HYPHENS)


def find_tokens(text: str) -> tuple[str, ...]:
    """Distinct tokens in ``text`` (normalised first), in order of appearance."""
    found = (f"{match.group(1)}-{match.group(2)}" for match in TOKEN_RE.finditer(normalize(text)))
    return tuple(dict.fromkeys(found))


def split_sentences(line: str) -> list[str]:
    """Split one line on sentence terminators; empty pieces are dropped."""
    return [piece.strip() for piece in _SENTENCE_SPLIT_RE.split(line) if piece and piece.strip()]


def visible_tokens(text: str, cap: int) -> tuple[str, ...]:
    """Tokens whose end lies within ``cap`` characters of the rendered (indented) body."""
    body = "\n".join("  " + line for line in text.split("\n"))
    visible: list[str] = []
    for match in TOKEN_RE.finditer(body):
        if match.end() <= cap:
            visible.append(f"{match.group(1)}-{match.group(2)}")
    return tuple(dict.fromkeys(visible))
