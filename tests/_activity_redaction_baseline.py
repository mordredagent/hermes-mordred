"""The free-text redactor of the base revision ``efe9bb27d``, frozen, as the oracle of the "only adds
redactions" tests, and the value spans it replaced in the contracts corpus.

The definitions between the markers are copied from ``efe9bb27d``'s
``src/mordred_hermes/activity/contracts.py`` (the keyword-value part of ``redact_text_secrets`` and
``redact_secret_tokens``), unchanged but for formatting; :func:`base_spans` is that revision's
``_redact_keyword_values`` loop returning
spans instead of text. ``BASE_SPANS`` was produced by running that revision's own module, so a test can check
that this copy still matches it. Positions index the text after :func:`redact_secret_tokens`.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Final, NamedTuple

# --- copied from efe9bb27d ------------------------------------------------------------------------------

#: Replacement for a credential value inside a URL.
REDACTED: Final = "redacted"

#: A URL in free text. The scheme is bounded so that scanning stays linear on hostile input.
_URL_IN_TEXT_RE: Final = re.compile(r"(?i)\b[a-z][a-z0-9+.-]{0,31}://\S+")

#: ``eyJ`` (base64url of ``{"``) followed by three dot-separated base64url segments (the last may be
#: empty), starting a base64url run (the lookbehind keeps scanning linear).
_JWT_RE: Final = re.compile(r"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*")

#: Well-known credential prefixes starting a token, followed by at least 8 key characters: OpenAI-style
#: ``sk-``, Stripe ``sk_live_`` / ``sk_test_`` / ``rk_live_`` / ``rk_test_``, GitHub ``ghp_`` / ``gho_`` /
#: ``ghs_`` / ``ghu_`` / ``github_pat_``, GitLab ``glpat-``, AWS ``AKIA`` / ``ASIA``, Google ``AIza`` /
#: ``ya29.``, Slack ``xoxb-`` / ``xoxp-`` / ``xoxa-`` / ``xoxe-`` / ``xoxr-`` / ``xoxs-`` / ``xapp-``, npm
#: ``npm_`` and Hugging Face ``hf_``.
KEY_PREFIXES: Final = (
    "sk-",
    "sk_live_",
    "sk_test_",
    "rk_live_",
    "rk_test_",
    "ghp_",
    "gho_",
    "ghs_",
    "ghu_",
    "github_pat_",
    "glpat-",
    "AKIA",
    "ASIA",
    "AIza",
    "ya29.",
    "xoxb-",
    "xoxp-",
    "xoxa-",
    "xoxe-",
    "xoxr-",
    "xoxs-",
    "xapp-",
    "npm_",
    "hf_",
)

_KEY_PREFIX_RE: Final = re.compile(
    r"(?<![A-Za-z0-9_-])(?:" + "|".join(re.escape(prefix) for prefix in KEY_PREFIXES) + r")[A-Za-z0-9_-]{8,}"
)

#: The armour line of a PEM private key or certificate request (``-----BEGIN RSA PRIVATE KEY-----``).
_PEM_RE: Final = re.compile(r"-----BEGIN [A-Z0-9 ]{0,40}(?:PRIVATE KEY|KEY BLOCK)-----")

#: Keywords naming a secret in free text (case-insensitive). An ASCII keyword must not touch an ASCII letter
#: or digit on either side (``pinned``, ``tokens`` and ``password2`` are no keywords); ``pin code`` is tried
#: before ``pin``.
_ASCII_SECRET_KEYWORDS: Final = (
    r"pin[ -]?code|one[- ]?time[- ]?code|api[ _-]?(?:key|token)|access[ _-]?token"
    r"|pass(?:word|wd|phrase|code)|pwd|otp|pin|secret|token"
)

#: The Japanese words for one-time password, password, PIN, passcode and verification code; written without
#: spaces, so they need no word boundary.
JAPANESE_SECRET_KEYWORDS: Final = (
    "ワンタイムパスワード",
    "パスワード",
    "暗証番号",
    "パスコード",
    "認証コード",
)

_SECRET_KEYWORD_RE: Final = re.compile(
    r"(?i)(?<![A-Za-z0-9])(?:" + _ASCII_SECRET_KEYWORDS + r")(?![A-Za-z0-9])|" + "|".join(JAPANESE_SECRET_KEYWORDS)
)

#: Keywords that are ordinary English words too ("pin the tab", "the secret is out", "token count"): unless
#: labelled (``:`` / ``=``) or quoted, their value must be credential-shaped (:func:`_credential_shaped`).
AMBIGUOUS_SECRET_KEYWORDS: Final = frozenset({"pin", "secret", "token"})

#: Values after a keyword that are interface or function words, not secrets ("the password field",
#: "reset password page", "the password is incorrect"); compared without case.
SECRET_VALUE_STOP_WORDS: Final = frozenset(
    {
        # interface words
        *("field", "fields", "box", "boxes", "input", "inputs", "form", "forms", "reset", "manager", "managers"),
        *("page", "pages", "button", "buttons", "prompt", "prompts", "dialog", "dialogs", "hint", "hints"),
        *("policy", "policies", "strength", "requirement", "requirements", "rule", "rules", "length", "screen"),
        *("settings", "setting", "link", "menu", "entry", "label", "change", "changes", "changed", "recovery"),
        *("generator", "protected", "protection", "expired", "expires", "expiry", "incorrect", "invalid", "wrong"),
        *("mismatch", "error", "sent", "verification", "confirmation", "confirm", "required", "optional", "login"),
        *("sign", "show", "hide", "forgot", "remember", "cancel", "submit", "continue", "next", "back", "ok"),
        *("enter", "type", "create", "new", "current", "old", "repeat", "edit", "update", "updated", "save"),
        *("saved", "set", "use", "used", "here", "below", "above", "none", "empty", "weak", "strong", "valid"),
        # function words
        *("a", "an", "the", "and", "or", "but", "nor", "to", "for", "of", "in", "on", "at", "by", "with", "from"),
        *("into", "is", "was", "are", "were", "be", "been", "it", "its", "this", "that", "these", "those", "my"),
        *("your", "our", "their", "his", "her", "not", "no", "if", "as", "so", "too", "there", "then", "when"),
        *("will", "would", "can", "could", "should", "must", "may", "has", "have", "had", "do", "does", "did"),
        "please",
        # the Japanese words for field, input field, field (katakana), reset, change, screen, input, setting,
        # resetting and confirmation
        *("欄", "入力欄", "フィールド", "リセット"),
        *("変更", "画面", "入力", "設定", "再設定", "確認"),
    }
)

#: Connectors between a keyword and its value: labels (``:``, ``=``, full-width too), the Japanese particles
#: of topic, object and subject, and the words ``is``, ``was`` and ``of`` after whitespace.
_LABEL_MARKS: Final = frozenset(":=\uff1a\uff1d")  # full-width colon and equals sign

_PARTICLES: Final = frozenset("はをが")

_WORD_CONNECTOR_RE: Final = re.compile(r"(?i)(?:is|was|of)(?=[\s:=\uff1a\uff1d\"'\u201c\u2018「『])")

_SPACE_RE: Final = re.compile(r"\s{1,32}")

_MAX_CONNECTORS: Final = 4

#: Quotes and brackets around a value (kept in the text) and the mark that closes each: straight, curly and
#: corner quotes, ASCII and full-width brackets. Inside quotes (not brackets) a value may hold spaces.
_VALUE_QUOTES: Final[Mapping[str, str]] = dict(
    zip("\"'\u201c\u2018「『([<\uff08【", "\"'\u201d\u2019」』)]>\uff09】", strict=True)
)

_SPACED_QUOTES: Final = frozenset("\"'\u201c\u2018「『")

#: Quotes that may follow a keyword directly (``password"x"``, the Japanese corner brackets).
_DIRECT_QUOTES: Final = frozenset('"\u201c「『')

#: Longest secret value inspected; a longer unquoted run is redacted to its end when it is accepted.
MAX_SECRET_VALUE_CHARS: Final = 256

#: An unquoted value: no whitespace, hiragana (a particle or verb ending), CJK punctuation or full-width
#: punctuation.
_VALUE_CHARS: Final = r"[^\s\u3040-\u309f\u3000-\u303f\uff01-\uff0f\uff1a-\uff20\uff3b-\uff40\uff5b-\uff65]"

_BARE_VALUE_RE: Final = re.compile(_VALUE_CHARS + f"{{1,{MAX_SECRET_VALUE_CHARS}}}")

_VALUE_TAIL_RE: Final = re.compile(_VALUE_CHARS + "*")

#: Punctuation that ends a sentence or closes a bracket after an unquoted value; kept outside the replacement.
_TRAILING_MARKS: Final = frozenset(".,;:!?)]}>\"'\u201d\u2019")


def redact_secret_tokens(text: str) -> str:
    """``text`` with JWTs, key-prefixed tokens and PEM armour lines replaced by :data:`REDACTED`."""
    return _PEM_RE.sub(REDACTED, _KEY_PREFIX_RE.sub(REDACTED, _JWT_RE.sub(REDACTED, text)))


class _Connection(NamedTuple):
    """What joins a keyword to its value: where the value starts and which connectors were seen."""

    start: int
    joined: bool  # any connector, whitespace included
    labelled: bool  # ``:`` or ``=``
    linked: bool  # ``is`` / ``was`` / ``of`` or a Japanese particle


def _connection(text: str, pos: int) -> _Connection:
    """Up to :data:`_MAX_CONNECTORS` connectors after a keyword: whitespace, labels, particles and words."""
    joined = labelled = linked = False
    for _ in range(_MAX_CONNECTORS):
        space = _SPACE_RE.match(text, pos)
        if space:
            pos, joined = space.end(), True
        char = text[pos : pos + 1]
        word = _WORD_CONNECTOR_RE.match(text, pos) if space else None
        if char and char in _LABEL_MARKS:
            pos, joined, labelled = pos + 1, True, True
        elif char and char in _PARTICLES:
            pos, joined, linked = pos + 1, True, True
        elif word:
            pos, linked = word.end(), True
        else:
            break
    return _Connection(pos, joined, labelled, linked)


def _quoted_value(text: str, pos: int) -> tuple[int, int] | None:
    """``(start, end)`` of a value inside the quote or bracket at ``pos``, without the marks."""
    closer = _VALUE_QUOTES.get(text[pos : pos + 1])
    if closer is None:
        return None
    close = text.find(closer, pos + 1, pos + 2 + MAX_SECRET_VALUE_CHARS)
    inner = text[pos + 1 : close] if close > pos + 1 else ""
    if not inner or inner != inner.strip() or "\n" in inner:
        return None  # a quote that closes the keyword's own quotation (``"password" or "pin"``)
    if text[pos] not in _SPACED_QUOTES and any(char.isspace() for char in inner):
        return None
    return pos + 1, close


def _without_closing_marks(text: str, start: int, end: int) -> int:
    while end > start and text[end - 1] in _TRAILING_MARKS:
        end -= 1
    return end


def _bare_value(text: str, pos: int) -> tuple[tuple[int, int] | None, bool]:
    """``((start, end) or None, capped)`` of an unquoted value: one token, closing punctuation left out;
    ``capped`` when the token runs past :data:`MAX_SECRET_VALUE_CHARS` (only that much was inspected)."""
    run = _BARE_VALUE_RE.match(text, pos)
    if run is None:
        return None, False
    end = _without_closing_marks(text, pos, run.end())
    capped = run.end() - pos == MAX_SECRET_VALUE_CHARS
    return ((pos, end) if end > pos else None), capped


def _credential_shaped(value: str) -> bool:
    """A digit, a non-alphanumeric character or an upper-case letter after the first one."""
    return any(char.isdigit() or not char.isalnum() for char in value) or any(char.isupper() for char in value[1:])


def _plausible_value(value: str, keyword: str, connection: _Connection, quoted: bool) -> bool:
    """A value that may be a secret, not an interface word, a URL or a masked placeholder."""
    if value == REDACTED or "://" in value or not any(char.isascii() and char.isalnum() for char in value):
        return False
    if value.lower() in SECRET_VALUE_STOP_WORDS or _SECRET_KEYWORD_RE.fullmatch(value):
        return False
    if connection.labelled or quoted:
        return True
    if connection.linked and keyword.lower() not in AMBIGUOUS_SECRET_KEYWORDS:
        return True
    return _credential_shaped(value)


def _secret_value(text: str, keyword: re.Match[str]) -> tuple[int, int] | None:
    """``(start, end)`` of the secret value following ``keyword``, or ``None``."""
    connection = _connection(text, keyword.end())
    pos = connection.start
    direct = text[pos : pos + 1] in _DIRECT_QUOTES
    if not (connection.joined or direct or not keyword.group(0).isascii()):
        return None  # ``password_reset``, ``password?``
    span = _quoted_value(text, pos)
    quoted, capped = span is not None, False
    if span is None:
        span, capped = _bare_value(text, pos + 1 if text[pos : pos + 1] in _VALUE_QUOTES else pos)
    if span is None or not _plausible_value(text[span[0] : span[1]], keyword.group(0), connection, quoted):
        return None
    if capped:  # a long run is redacted to its end, never left half visible
        tail = _VALUE_TAIL_RE.match(text, span[0])
        return span[0], _without_closing_marks(text, span[0], tail.end() if tail else span[1])
    return span


# --- end of the copy ------------------------------------------------------------------------------


def base_spans(text: str) -> tuple[tuple[int, int], ...]:
    """The value spans ``efe9bb27d``'s ``redact_text_secrets`` replaced in ``redact_secret_tokens(text)``."""
    clean = redact_secret_tokens(text)
    urls = [match.span() for match in _URL_IN_TEXT_RE.finditer(clean)]
    spans: list[tuple[int, int]] = []
    pos = index = 0
    while (keyword := _SECRET_KEYWORD_RE.search(clean, pos)) is not None:
        while index < len(urls) and urls[index][1] <= keyword.start():
            index += 1
        if index < len(urls) and urls[index][0] <= keyword.start():
            pos = urls[index][1]
            continue
        span = _secret_value(clean, keyword)
        if span is None:
            pos = keyword.end()
            continue
        spans.append(span)
        pos = span[1]
    return tuple(spans)


BASE_SPANS: dict[str, tuple[tuple[int, int], ...]] = {
    "Log in with the username demo-user and the password Hunter2-fake-pw": ((52, 67),),
    "password: hunter2": ((10, 17),),
    "PIN=4821": ((4, 8),),
    "my password is Hunter2-fake-pw.": ((15, 30),),
    "the passcode was 99-red-balloons, okay": ((17, 32),),
    "my PIN is 4821": ((10, 14),),
    "passphrase 'correct horse battery staple' please": ((12, 40),),
    'use password="s3cr3t!" here': ((14, 21),),
    "API key: abc123def": ((9, 18),),
    "DB_PASSWORD=xyz": ((12, 15),),
    "Your one-time code is 482913": ((22, 28),),
    "otp 123456 expires soon": ((4, 10),),
    "pin code 0000": ((9, 13),),
    "access token: abcdef": ((14, 20),),
    "the secret: swordfish": ((12, 21),),
    "(password Hunter2)": ((10, 17),),
    "パスワードはHunter2です": ((6, 13),),
    "パスワード「abc123」で": ((6, 12),),
    "パスワードは abc123": ((7, 13),),
    "認証コード\uff1a123456": ((6, 12),),
    "暗証番号は1234です。": ((5, 9),),
    "ワンタイムパスワード 482913 を入力": ((11, 17),),
    "パスコードを『x9y8』に変更": ((7, 11),),
    "パスワードをHunter2-xに変更して": ((6, 15),),
    "パスワードを 「abc def」 に設定": ((8, 15),),
    "PINを1234に変更": ((4, 8),),
    "password for account PIN=4821 is Hunter2-x": ((25, 29),),
    "set the password for PIN=4821 to Hunter2-x": ((25, 29),),
    "type Hunter2-x as the password for token=abcd1234efgh": ((41, 53),),
    "password: pin=4821 token=x9y8z7w6": ((10, 18), (25, 33)),
    "use Hunter2-x as the password, not the password Hunter3-y": ((48, 57),),
    "password Hunter2-x as the password": ((9, 18),),
    "submit with password: hunter2": ((22, 29),),
    "done; the new PIN is 4821": ((21, 25),),
    "Welcome, your password is Hunter2-fake-pw": ((26, 41),),
    "Your one-time code is 482913. Do not share it.": ((22, 28),),
    "wrong account; the password is Winter-2026 for the finance login": ((31, 42),),
    "my password is something": ((15, 24),),
    "the password is case-sensitive": ((16, 30),),
    "the passcode is value": ((16, 21),),
    "the password is text": ((16, 20),),
    "my password is anything you like": ((15, 23),),
    "password for account token: abcdef is Hunter2-x": ((28, 34),),
    "password for account api key: abc123def is Hunter2-x": ((30, 39),),
    "password for account pwd=xyz is Hunter2-x": ((25, 28),),
    "password for account secret=Swordfish-1 is Hunter2-x": ((28, 39),),
    "password for account otp 123456 is Hunter2-x": ((25, 31),),
    "password for account password is Hunter2-z is Hunter2-x": ((33, 42),),
    "password for account the passcode was 99-red-balloons is Hunter2-x": ((38, 53),),
    "set the password for token: abcdef to Hunter2-x": ((28, 34),),
    "set the password for api key: abc123def to Hunter2-x": ((30, 39),),
    "set the password for pwd=xyz to Hunter2-x": ((25, 28),),
    "set the password for secret=Swordfish-1 to Hunter2-x": ((28, 39),),
    "set the password for otp 123456 to Hunter2-x": ((25, 31),),
    "set the password for password is Hunter2-z to Hunter2-x": ((33, 42),),
    "set the password for the passcode was 99-red-balloons to Hunter2-x": ((38, 53),),
    "type Hunter2-x as the password for PIN=4821": ((39, 43),),
    "type Hunter2-x as the password for token: abcdef": ((42, 48),),
    "type Hunter2-x as the password for api key: abc123def": ((44, 53),),
    "type Hunter2-x as the password for pwd=xyz": ((39, 42),),
    "type Hunter2-x as the password for secret=Swordfish-1": ((42, 53),),
    "type Hunter2-x as the password for otp 123456": ((39, 45),),
    "type Hunter2-x as the password for password is Hunter2-z": ((47, 56),),
    "type Hunter2-x as the password for the passcode was 99-red-balloons": ((52, 67),),
    "the password for PIN=4821 = s3cr3t!": ((21, 25),),
    "the password for token: abcdef = s3cr3t!": ((24, 30),),
    "the password for api key: abc123def = s3cr3t!": ((26, 35),),
    "the password for pwd=xyz = s3cr3t!": ((21, 24),),
    "the password for secret=Swordfish-1 = s3cr3t!": ((24, 35),),
    "the password for otp 123456 = s3cr3t!": ((21, 27),),
    "the password for password is Hunter2-z = s3cr3t!": ((29, 38),),
    "the password for the passcode was 99-red-balloons = s3cr3t!": ((34, 49),),
    "PIN=4821 as the password": ((4, 8),),
    "token: abcdef as the password": ((7, 13),),
    "api key: abc123def as the password": ((9, 18),),
    "pwd=xyz as the password": ((4, 7),),
    "secret=Swordfish-1 as the password": ((7, 18),),
    "otp 123456 as the password": ((4, 10),),
    "password is Hunter2-z as the password": ((12, 21),),
    "the passcode was 99-red-balloons as the password": ((17, 32),),
    "password: PIN=4821 now": ((10, 18),),
    "password: token: abcdef now": ((17, 23),),
    "password: api key: abc123def now": ((10, 13),),
    "password: pwd=xyz now": ((10, 17),),
    "password: secret=Swordfish-1 now": ((10, 28),),
    "password: otp 123456 now": ((14, 20),),
    "password: password is Hunter2-z now": ((22, 31),),
    "password: the passcode was 99-red-balloons now": ((27, 42),),
    "use PIN=4821 for the PIN": ((8, 12),),
    "use token: abcdef for the PIN": ((11, 17),),
    "use api key: abc123def for the PIN": ((13, 22),),
    "use pwd=xyz for the PIN": ((8, 11),),
    "use secret=Swordfish-1 for the PIN": ((11, 22),),
    "use otp 123456 for the PIN": ((8, 14),),
    "use password is Hunter2-z for the PIN": ((16, 25),),
    "use the passcode was 99-red-balloons for the PIN": ((21, 36),),
    "Log in with the username demo-user and the password Hunter2-fake-pw password: hunter2": ((52, 67), (78, 85)),
    "password: hunter2 PIN=4821": ((10, 17), (22, 26)),
    "PIN=4821 my password is Hunter2-fake-pw.": ((4, 8), (24, 39)),
    "my password is Hunter2-fake-pw. the passcode was 99-red-balloons, okay": ((15, 30), (49, 64)),
    "the passcode was 99-red-balloons, okay my PIN is 4821": ((17, 32), (49, 53)),
    "my PIN is 4821 passphrase 'correct horse battery staple' please": ((10, 14), (27, 55)),
    "passphrase 'correct horse battery staple' please use password=\"s3cr3t!\" here": ((12, 40), (63, 70)),
    'use password="s3cr3t!" here API key: abc123def': ((14, 21), (37, 46)),
    "API key: abc123def DB_PASSWORD=xyz": ((9, 18), (31, 34)),
    "DB_PASSWORD=xyz Your one-time code is 482913": ((12, 15), (38, 44)),
    "Your one-time code is 482913 otp 123456 expires soon": ((22, 28), (33, 39)),
    "otp 123456 expires soon pin code 0000": ((4, 10), (33, 37)),
    "pin code 0000 access token: abcdef": ((9, 13), (28, 34)),
    "access token: abcdef the secret: swordfish": ((14, 20), (33, 42)),
    "the secret: swordfish (password Hunter2)": ((12, 21), (32, 39)),
    "(password Hunter2) パスワードはHunter2です": ((10, 17), (25, 32)),
    "パスワードはHunter2です パスワード「abc123」で": ((6, 13), (22, 28)),
    "パスワード「abc123」で パスワードは abc123": ((6, 12), (22, 28)),
    "パスワードは abc123 認証コード\uff1a123456": ((7, 13), (20, 26)),
    "認証コード\uff1a123456 暗証番号は1234です。": ((6, 12), (18, 22)),
    "暗証番号は1234です。 ワンタイムパスワード 482913 を入力": ((5, 9), (24, 30)),
    "ワンタイムパスワード 482913 を入力 パスコードを『x9y8』に変更": ((11, 17), (29, 33)),
    "パスコードを『x9y8』に変更 use eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJl to call": ((7, 11),),
}
