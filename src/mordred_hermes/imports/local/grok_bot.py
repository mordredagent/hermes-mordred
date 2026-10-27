"""Grok Bot (desktop app): ``~/Library/Application Support/Grok Bot/sand-client-persistence``.

The app keeps one JSON blob per key; a file's name is the key in lowercase
unpadded base32. ``….transcript.replicas.<bot id>`` holds a bot's whole
transcript (``value.entries``) and ``….roster.last-roster`` the bots' names.
Entries of kind ``message`` are the user's turns (``content``); entries of
kind ``send-message`` with a text ``message`` are the bot's replies. Voice
calls, widgets, attachments and events are skipped. An entry's key is its id.
"""

from __future__ import annotations

import base64
import binascii
import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any, Final, Literal

from ._model import Entry, Transcript, clean_text, ms_seconds, safe_key, title_of

_REPLICA: Final = ".transcript.replicas."
_ROSTER: Final = ".roster.last-roster"


def blob_key(path: Path) -> str | None:
    """The storage key a blob file stands for, or ``None`` when its name is not base32."""
    if path.suffix != ".blob":
        return None
    name = path.stem.upper()
    try:
        return base64.b32decode(name + "=" * (-len(name) % 8)).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError, ValueError):
        return None


def _load(path: Path) -> Any:
    try:
        return json.loads(path.read_bytes())
    except (OSError, ValueError):
        return None


def files(root: Path) -> Iterator[Path]:
    for path in sorted(root.glob("*.blob")):
        key = blob_key(path)
        if key is not None and _REPLICA in key:
            yield path


def bot_names(root: Path) -> dict[str, str]:
    names: dict[str, str] = {}
    for path in sorted(root.glob("*.blob")):
        key = blob_key(path)
        if key is None or not key.endswith(_ROSTER):
            continue
        data = _load(path)
        value = data.get("value") if isinstance(data, dict) else None
        rows = value.get("rows") if isinstance(value, dict) else None
        for row in rows if isinstance(rows, list) else []:
            if isinstance(row, dict) and isinstance(row.get("id"), str):
                name = row.get("name") or row.get("title")
                if isinstance(name, str) and name.strip():
                    names[row["id"]] = name.strip()[:80]
    return names


def _entry(raw: dict[str, Any]) -> Entry | None:
    kind, key = raw.get("kind"), raw.get("id")
    if not isinstance(key, str) or not key:
        return None
    role: Literal["owner", "agent"]
    if kind == "message":
        text, role = raw.get("content"), "owner"
    elif kind == "send-message":
        message = raw.get("message")
        if not isinstance(message, dict) or message.get("type") != "text":
            return None
        text, role = message.get("content"), "agent"
    else:
        return None
    if not isinstance(text, str) or not (cleaned := clean_text(text)):
        return None
    return Entry(key=safe_key(key, "entry"), role=role, sent_at=ms_seconds(raw.get("timestampMs")), text=cleaned)


def read(path: Path, names: dict[str, str] | None = None) -> list[Transcript]:
    key = blob_key(path)
    if key is None or _REPLICA not in key:
        return []
    bot = key.rsplit(_REPLICA, 1)[1]
    data = _load(path)
    value = data.get("value") if isinstance(data, dict) else None
    raw_entries = value.get("entries") if isinstance(value, dict) else None
    if not isinstance(raw_entries, list):
        return []
    entries: list[Entry] = []
    seen: set[str] = set()
    for raw in raw_entries:
        entry = _entry(raw) if isinstance(raw, dict) else None
        if entry is not None and entry.key not in seen:
            seen.add(entry.key)
            entries.append(entry)
    if not entries:
        return []
    kept = tuple(entries)
    name = (names or {}).get(bot, "")
    return [Transcript(key=safe_key(bot, "bot"), title=name or title_of(kept), entries=kept, agent_name=name)]
