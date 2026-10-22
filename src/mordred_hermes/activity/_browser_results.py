"""Reading hermes-agent browser tool results: page URLs, snapshot lines, field kinds and page text.

Pure helpers for :mod:`.capture_hermes` (no state, no configuration, no store):

- :func:`http_url` / :func:`page_location` / :func:`reported_url`: the page a
  result reports. Only an ``http(s)`` URL whose host fits the receiver's host
  rule is a known page; an ``about:`` page is known to have no URL; anything
  else is unknown, so it can never stand for an excluded host's page.
- :func:`ref_line` / :func:`element_label` / :func:`field_kind`: an element's
  line in an accessibility snapshot, its label (role and accessible name,
  never the value) and whether a field is ``sensitive``, ``text`` or
  ``other``.
- :func:`page_text`: a navigation snapshot as stored page text, without the
  values of secret fields.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from typing import Any, Final
from urllib.parse import urlsplit

from .contracts import MAX_TARGET_CHARS, SENSITIVE_FIELD_KIND, redact_text_secrets

__all__ = [
    "MAX_RESULT_CHARS",
    "PAGE_TEXT_CHARS",
    "element_label",
    "field_kind",
    "http_url",
    "json_object",
    "page_location",
    "page_text",
    "ref_line",
    "reported_url",
    "text_field",
]

#: Characters of a navigation's snapshot stored as its page text (:data:`.contracts.MAX_PAGE_TEXT_CHARS`).
PAGE_TEXT_CHARS: Final = 8000
MAX_REF_LINE_CHARS: Final = 400
MAX_URL_CHARS: Final = 4096
#: Results larger than this are not parsed (:data:`.hooks_history.MAX_RESULT_CHARS`).
MAX_RESULT_CHARS: Final = 1_000_000
#: A ref line naming a secret field: password (also German ``Passwort``), passcode, passphrase, passkey, PIN,
#: one-time code, OTP, 2FA/MFA, secret, token, card, card security code, verification or authentication code,
#: and the Japanese words for these.
_SENSITIVE_FIELD_RE: Final = re.compile(
    r"(?i)pass(?:w|code|phrase|key)|(?<![a-z])(?:pwd|otp|pin|cvc|cvv|csc|2fa|mfa)(?![a-z])"
    r"|(?<![a-z])(?:secret|token|card)|one[\s_-]?time|security[\s_-]?code|verification[\s_-]?code"
    r"|auth(?:entication|orization)?[\s_-]?code"
    r"|パスワード|暗証番号|パスコード|ワンタイム|認証コード|確認コード|セキュリティコード|カード|秘密|トークン"
)
#: A tool's ``ref`` argument (``@e5`` or ``e5``).
_REF_TOKEN_RE: Final = re.compile(r"@?([A-Za-z][A-Za-z0-9_-]{0,31})")
#: An accessibility line's role and quoted accessible name (``- textbox "Email" [ref=e3]: value``).
_NAMED_LINE_RE: Final = re.compile(r'^[\s*-]*(?P<role>[A-Za-z][\w-]{0,40})\s+"(?P<name>(?:[^"\\\n]|\\.){1,300})"')
_ANNOTATION_RE: Final = re.compile(r"\[[^\]\n]{0,200}\]")
#: The receiver's host rule (``contracts._HOST_RE``).
_HOST_RE: Final = re.compile(r"[a-z0-9.:-]{1,253}")


def http_url(value: Any) -> str | None:
    """An ``http(s)`` URL with an ASCII host, else ``None`` (``about:blank``, ``file:``, ``chrome:`` pages)."""
    if not isinstance(value, str) or not value.strip() or len(value) > MAX_URL_CHARS:
        return None
    text = value.strip()
    try:
        parts = urlsplit(text)
        host = parts.hostname
    except ValueError:
        return None
    if parts.scheme.lower() not in ("http", "https") or not host or not _HOST_RE.fullmatch(host):
        return None
    return text


def page_location(value: Any) -> tuple[bool, str | None]:
    """``(known, url)`` of a reported page URL: an ``http(s)`` URL (:func:`http_url`) is known, an ``about:`` page is
    known to have none; anything else (missing, empty, another scheme, a host outside the receiver's rules) is
    unknown, so it can never stand for an excluded host's page."""
    url = http_url(value)
    if url is not None:
        return True, url
    return isinstance(value, str) and value.strip().lower().startswith("about:"), None


def _line_at(snapshot: str, start: int, end: int) -> str:
    first = snapshot.rfind("\n", 0, start) + 1
    last = snapshot.find("\n", end)
    return snapshot[first : len(snapshot) if last == -1 else last].strip()[:MAX_REF_LINE_CHARS]


def _ref_position(snapshot: str, token: str) -> tuple[int, int] | None:
    """Where ``ref=<token>`` (agent-browser) or ``[<token>]`` stands, not as a prefix of a longer ref."""
    for needle in (f"ref={token}", f"[{token}]"):
        start = 0
        while (pos := snapshot.find(needle, start)) != -1:
            end = pos + len(needle)
            if needle.startswith("[") or not (_continues(snapshot, end) or _continues(snapshot, pos - 1)):
                return pos, end
            start = end
    return None


def _continues(text: str, index: int) -> bool:
    """``text[index]`` would make a ``ref=…`` match part of a longer word (``xref=e4``, ``ref=e40``)."""
    return 0 <= index < len(text) and (text[index].isalnum() or text[index] in "_-")


def ref_line(snapshot: str | None, ref: Any) -> str | None:
    """The snapshot line of element ``ref`` (``@e5`` / ``e5``), stripped and bounded; ``None`` when absent."""
    if not snapshot or not isinstance(ref, str):
        return None
    match = _REF_TOKEN_RE.fullmatch(ref.strip())
    if match is None:
        return None
    found = _ref_position(snapshot, match.group(1))
    return None if found is None else _line_at(snapshot, *found) or None


def _label_parts(line: str) -> tuple[str, bool]:
    """``(label, names something)``: role and quoted name, else the line before its value without annotations."""
    named = _NAMED_LINE_RE.match(line)
    if named is not None:
        return f'{named.group("role")} "{named.group("name")}"', True
    head = " ".join(_ANNOTATION_RE.sub(" ", line).split(":", 1)[0].split()).strip(" *-")
    words = [word for word in head.split() if any(char.isalnum() for char in word)]
    return head, len(words) > 1


def element_label(line: str | None) -> str | None:
    """How an event names an element: its role and accessible name (``textbox "Email"``), never its value."""
    if not line:
        return None
    label = _label_parts(line)[0]
    return label[:MAX_TARGET_CHARS] or None


def field_kind(line: str | None) -> str:
    """``sensitive`` when the ref line names a secret field, ``other`` when it is missing or names nothing,
    else ``text``."""
    if not line:
        return "other"
    if _SENSITIVE_FIELD_RE.search(line):
        return SENSITIVE_FIELD_KIND
    return "text" if _label_parts(line)[1] else "other"


def _without_value(line: str) -> str:
    """A snapshot line up to the end of its role and accessible name (or its head before ``:``)."""
    named = _NAMED_LINE_RE.match(line)
    return line[: named.end()] if named is not None else line.split(":", 1)[0].rstrip()


def page_text(snapshot: str) -> str:
    """A navigation snapshot as stored page text: at most :data:`PAGE_TEXT_CHARS` characters, every line that
    :func:`field_kind` calls ``sensitive`` cut after its role and name (a filled-in PIN or card number is part
    of the line), then :func:`.contracts.redact_text_secrets`."""
    lines = snapshot[:PAGE_TEXT_CHARS].split("\n")
    kept = [_without_value(line) if field_kind(line) == SENSITIVE_FIELD_KIND else line for line in lines]
    return redact_text_secrets("\n".join(kept))[0]


def json_object(result: Any) -> dict[str, Any] | None:
    """A tool result's JSON object; ``None`` for anything else or above :data:`MAX_RESULT_CHARS`."""
    if not isinstance(result, str) or len(result) > MAX_RESULT_CHARS:
        return None
    try:
        payload = json.loads(result)
    except ValueError:
        return None
    return payload if isinstance(payload, dict) else None


def text_field(payload: Mapping[str, Any] | None, key: str) -> str | None:
    """``payload[key]`` when it is a non-empty string."""
    value = payload.get(key) if payload is not None else None
    return value if isinstance(value, str) and value else None


def reported_url(payload: Mapping[str, Any] | None) -> str | None:
    """The page URL a result reports: its ``url``, else the browser supervisor's top frame (``frame_tree``);
    ``None`` when it reports none (an empty ``url``, as a Camofox click may return, is none)."""
    if payload is None:
        return None
    url = text_field(payload, "url")
    if url is not None and url.strip():
        return url
    frames = payload.get("frame_tree")
    top = frames.get("top") if isinstance(frames, dict) else None
    frame_url = top.get("url") if isinstance(top, dict) else None
    return frame_url if isinstance(frame_url, str) and frame_url.strip() else None
