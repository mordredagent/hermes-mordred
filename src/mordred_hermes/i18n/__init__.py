"""The words Mordred shows on the Mac itself, in the Mac's language.

The browser extension has its own catalog; this one covers what macOS shows for
Mordred: the Touch ID reasons and the one-step installer's dialogs (which read
the same files with ``plutil``). ``strings/<language>.json`` holds the
translations, nested by group (``{"touchId": {"setup": ...}}``); English lives
in the code that asks for a text, so a missing file or key still says something.

The language is the first of macOS's preferred languages that Mordred has words
for (``defaults read -g AppleLanguages``), else ``LANG``, else English.
"""

from __future__ import annotations

import functools
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Final

__all__ = ["LANGUAGES", "text", "ui_language"]

#: The languages Mordred has words for: the extension's 25 locales.
LANGUAGES: Final = (
    "en", "ja", "zhCN", "zhTW", "ko", "vi", "th", "id", "ms", "es", "pt", "fr", "de",
    "it", "nl", "sv", "pl", "ru", "uk", "tr", "ar", "he", "fa", "hi", "bn",
)  # fmt: skip
_STRINGS: Final = Path(__file__).resolve().parent / "strings"


def language_of(tag: str) -> str:
    """A BCP 47 tag or POSIX locale (``ja-JP``, ``zh-Hant-TW``, ``pt_BR.UTF-8``) → one of :data:`LANGUAGES`."""
    tag = tag.strip().replace("_", "-").split(".")[0]
    lower = tag.lower()
    if lower.startswith(("zh-hans", "zh-cn", "zh-sg")) or lower == "zh":
        return "zhCN"
    if lower.startswith(("zh-hant", "zh-tw", "zh-hk", "zh-mo")):
        return "zhTW"
    base = lower.split("-")[0]
    return base if base in LANGUAGES and base not in {"zhCN", "zhTW"} else "en"


def _mac_languages() -> list[str]:
    try:
        out = subprocess.run(
            ["/usr/bin/defaults", "read", "-g", "AppleLanguages"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return []
    return re.findall(r'^\s*"?([A-Za-z0-9-]+)"?,?\s*$', out, flags=re.MULTILINE)


@functools.cache
def ui_language() -> str:
    """The language for what this Mac shows the user (cached for the process)."""
    tags = _mac_languages() if sys.platform == "darwin" else []
    tags.append(os.environ.get("LANG", ""))
    for tag in tags:
        if tag and (language := language_of(tag)) != "en":
            return language
        if tag.lower().startswith("en"):
            return "en"
    return "en"


@functools.cache
def _catalog(language: str) -> dict[str, dict[str, str]]:
    try:
        data = json.loads((_STRINGS / f"{language}.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def text(key: str, english: str, *, language: str | None = None, **params: object) -> str:
    """``key`` (``group.name``) in the Mac's language, else ``english``; then ``{name}`` filled in."""
    group, _, name = key.partition(".")
    chosen = language or ui_language()
    translated = _catalog(chosen).get(group, {}).get(name) if chosen != "en" else None
    result = translated if isinstance(translated, str) and translated else english
    for param, value in params.items():
        result = result.replace("{" + param + "}", str(value))
    return result
