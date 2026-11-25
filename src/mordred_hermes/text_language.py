"""Which language a short text is written in, without a model.

Lightweight and table-driven so it works for any language in the tables and says
"not sure" (``None``) for the rest:

* a writing system used by one language decides it (kana → Japanese, Hangul →
  Korean, Thai, Greek, Hebrew, ...);
* Han without kana is Chinese;
* Latin and Cyrillic texts are told apart by their most common short words and a
  few letters only one language uses (``ñ ¿`` Spanish, ``ß`` German, ``ã õ``
  Portuguese, ...).

Callers treat ``None`` as "don't steer and don't judge": a wrong guess would push
a reply into the wrong language, which is worse than no guess.
"""

# ruff: noqa: RUF001 - word tables in many scripts (a Cyrillic letter there is Ukrainian, not Latin)

from __future__ import annotations

import re
from typing import Final

#: English names, used in instructions to the model ("Reply in Spanish.").
NAMES: Final[dict[str, str]] = {
    "ja": "Japanese",
    "ko": "Korean",
    "zh": "Chinese",
    "en": "English",
    "es": "Spanish",
    "fr": "French",
    "de": "German",
    "pt": "Portuguese",
    "it": "Italian",
    "nl": "Dutch",
    "ru": "Russian",
    "uk": "Ukrainian",
    "el": "Greek",
    "he": "Hebrew",
    "ar": "Arabic",
    "fa": "Persian",
    "th": "Thai",
    "hi": "Hindi",
}

_KANA = re.compile(r"[\u3040-\u30ff\u31f0-\u31ff\uff66-\uff9f]")
_HANGUL = re.compile(r"[\uac00-\ud7af\u1100-\u11ff\u3130-\u318f]")
_HAN = re.compile(r"[\u4e00-\u9fff\u3400-\u4dbf]")
_LATIN_WORD = re.compile(r"[A-Za-z\u00c0-\u00d6\u00d8-\u00f6\u00f8-\u024f]{2,}")
_CYRILLIC = re.compile(r"[\u0400-\u04ff]")
#: Scripts one language owns (for the purpose of choosing the reply language).
_OWN_SCRIPT: Final[tuple[tuple[str, re.Pattern[str]], ...]] = (
    ("th", re.compile(r"[\u0e00-\u0e7f]")),
    ("el", re.compile(r"[\u0370-\u03ff]")),
    ("he", re.compile(r"[\u0590-\u05ff]")),
    ("hi", re.compile(r"[\u0900-\u097f]")),
)
_ARABIC = re.compile(r"[\u0600-\u06ff]")
_PERSIAN_ONLY = re.compile(r"[پچژگ]")

#: Common short words (articles, pronouns, question words, negation).
_WORDS: Final[dict[str, frozenset[str]]] = {
    lang: frozenset(words.split())
    for lang, words in {
        "en": "the a an and is are was were you i my me your it this that of to in on for with not no can "
        "cannot do does did what how who when where which why have has there please could would will",
        "es": "el la los las un una y es son de del que en por para con no se su mi tu me te lo le "
        "qué cuál cuánto cuántos cuántas cómo dónde cuándo quién puedo puedes tengo hay pero muy",
        "fr": "le la les un une des et est sont de du que qui en pour avec pas ne je tu il vous nous "
        "mon ma mes quel quelle quels combien comment où quand peux ai suis sur au aux",
        "de": "der die das ein eine und ist sind von zu mit nicht kein keine ich du sie wir mein dein "
        "was wie wer wann wo welche welches welcher habe hat kann bitte für auf den dem des ist in einem einen im",
        "pt": "o a os as um uma e é são de do da dos das que em para com não se eu você meu minha "
        "qual quais quanto quantos quantas como onde quando quem posso tenho há mas ao no na",
        "it": "il lo la gli le un una e è sono di del della che in per con non mi ti io tu "
        "qual quale quanto quanti come dove quando chi posso ho ci",
        "nl": "de het een en is zijn van te met niet geen ik jij je mijn wat hoe wie wanneer waar "
        "welke kan heb er op voor",
        "ru": "и в не на что как это я ты мы вы он она мой где когда кто какой сколько можно есть",
        "uk": "і в не на що як це я ти ми ви він вона мій де коли хто який скільки можна є",
    }.items()
}
#: Letters only one of the word-table languages uses.
_LETTERS: Final[dict[str, re.Pattern[str]]] = {
    "es": re.compile(r"[ñ¿¡]"),
    "de": re.compile(r"[ßäöü]"),
    "pt": re.compile(r"[ãõ]"),
    "fr": re.compile(r"[èêëœ]"),
    "uk": re.compile(r"[іїєґ]"),
}
_TOKEN = re.compile(r"[^\W\d_]+", re.UNICODE)


def detect(text: str) -> str | None:
    """ISO code of the language ``text`` is written in, or ``None`` when unsure."""
    if not text or not text.strip():
        return None
    kana, hangul, han = len(_KANA.findall(text)), len(_HANGUL.findall(text)), len(_HAN.findall(text))
    cyrillic, arabic = len(_CYRILLIC.findall(text)), len(_ARABIC.findall(text))
    owned = [(len(p.findall(text)), lang) for lang, p in _OWN_SCRIPT]
    # A CJK character carries about a word, so CJK characters are weighed against Latin
    # words, not letters: a Japanese or Chinese sentence naming "Homebrew" stays CJK, an
    # English one quoting a place name in kanji stays English.
    words = len(_LATIN_WORD.findall(text))
    counts = sorted(
        [
            (kana + han if kana else 0, "ja"),
            (hangul / 2, "ko"),
            (han if not kana else 0, "zh"),
            (words * 1.5, "latin"),
            (cyrillic / 5, "cyrillic"),
            (arabic / 5, "arabic"),
            *((n / 5, lang) for n, lang in owned),
        ],
        reverse=True,
    )
    top, script = counts[0]
    if top == 0:
        return None
    if script == "ja":
        # Japanese runs on kana; a Chinese text quoting a Japanese word has only a few.
        return "ja" if kana >= 0.15 * (kana + han) else "zh"
    if script in ("ko", "zh") or script in dict((lang, 1) for _n, lang in owned):
        return script
    if script == "arabic":
        return "fa" if _PERSIAN_ONLY.search(text) else "ar"
    return _by_words(text, ("ru", "uk") if script == "cyrillic" else ("en", "es", "fr", "de", "pt", "it", "nl"))


def _by_words(text: str, langs: tuple[str, ...]) -> str | None:
    lower = text.lower()
    tokens = _TOKEN.findall(lower)
    score = {lang: float(sum(t in _WORDS[lang] for t in tokens)) for lang in langs}
    for lang, pattern in _LETTERS.items():
        if lang in score and pattern.search(lower):
            score[lang] += 2
    ranked = sorted(score.items(), key=lambda kv: kv[1], reverse=True)
    (best, top), (_second, runner_up) = ranked[0], ranked[1]
    # Short questions carry one or two cue words; ask for a clear lead, not a large count.
    if (top >= 2 and top >= runner_up + 1) or (top >= 1 and runner_up == 0):
        return best
    return None


def name(code: str | None) -> str | None:
    """English name of ``code`` (for an instruction to the model), or ``None``."""
    return NAMES.get(code or "")


_CJK_RUN = re.compile(r"[\u3040-\u30ff\u3400-\u9fff\uac00-\ud7af]+")
_COMMON: Final[frozenset[str]] = frozenset().union(*_WORDS.values())
_HIRAGANA_PAIR = re.compile(r"[\u3040-\u309f]{2}")


def content_units(text: str) -> set[str]:
    """What ``text`` is about, as comparable units, in any language.

    Runs of CJK characters give character pairs (there are no spaces to split
    words on), except pairs of hiragana, which are grammar; other words count
    when they are at least three letters long and not one of the common short
    words of the tables above. Two texts about the
    same thing share units, whatever language each is in, as long as they share
    the names and terms.
    """
    units: set[str] = set()
    for token in re.findall(r"[^\W_]+", text.lower()):
        rest = token
        for run in _CJK_RUN.findall(token):
            pairs = (run[i : i + 2] for i in range(len(run) - 1))
            # Two hiragana are grammar ("して", "です"), not what the text is about.
            units.update(pair for pair in pairs if not _HIRAGANA_PAIR.fullmatch(pair))
            rest = rest.replace(run, " ")
        units.update(w for w in rest.split() if len(w) >= 3 and w not in _COMMON and not w.isdigit())
    return units
