"""Antigravity (Google's agent IDE): ``~/.gemini/antigravity``.

Each conversation is a SQLite file ``conversations/<id>.db`` whose steps are
protobuf blobs. The app also keeps, in ``conversation_summaries.db``, a full-text
copy of every conversation (``conversations_fts``): per chunk, the user's words
(``user_body``) and the agent's replies (``agent_body``) as plain text, with
``user_step_byte_offsets`` / ``agent_step_byte_offsets`` (JSON ``[[step, byte],
...]``) marking where each step's text starts. That copy is read here, so the
protobuf of the steps is never decoded for text; only each step's creation time
is taken from the step's ``metadata`` blob (field 1, a Timestamp, its seconds).
Tool calls and other steps have no text there and are not kept.

Both databases are opened read-only and never written. A conversation is keyed
by its id, an entry by its step index, so a reimport finds every message as a
duplicate.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterator
from pathlib import Path
from typing import Any, Final, Literal
from urllib.parse import unquote, urlsplit

from ._model import Entry, Transcript, clean_text, safe_key, title_of

SUMMARIES: Final = "conversation_summaries.db"
_CONVERSATIONS: Final = "conversations"
#: Plausible step times (2020-01-01 .. 2036-01-01), to tell a Timestamp from other numbers.
_MIN_TIME: Final = 1_577_836_800
_MAX_TIME: Final = 2_082_758_400


def files(root: Path) -> Iterator[Path]:
    """Each conversation's database (its name is the conversation id)."""
    folder = root / _CONVERSATIONS
    if folder.is_dir():
        yield from sorted(p for p in folder.glob("*.db") if p.is_file())


def signature_extra(root: Path) -> str:
    """The summaries database's size and time: a conversation's text changes there, not in its own file."""
    try:
        stat = (root / SUMMARIES).stat()
    except OSError:
        return ""
    return f"{stat.st_size}.{stat.st_mtime_ns}"


def _connect(path: Path) -> sqlite3.Connection:
    """Read-only, never creating or writing a file; a database the app holds open is read as it is on disk."""
    uri = f"file:{path}?mode=ro"
    try:
        con = sqlite3.connect(uri, uri=True)
        con.execute("select 1 from sqlite_master limit 1")
        return con
    except sqlite3.Error:
        return sqlite3.connect(f"{uri}&immutable=1", uri=True)


def _varint(data: bytes, i: int) -> tuple[int, int]:
    value = shift = 0
    while True:
        if i >= len(data) or shift > 63:
            raise ValueError("varint")
        byte = data[i]
        i += 1
        value |= (byte & 0x7F) << shift
        shift += 7
        if not byte & 0x80:
            return value, i


def _fields(data: bytes) -> Iterator[tuple[int, int, Any]]:
    """``(field, wire type, value)`` of a protobuf message; length-delimited values as bytes."""
    i = 0
    while i < len(data):
        key, i = _varint(data, i)
        field, wire = key >> 3, key & 7
        value: int | bytes
        if wire == 0:
            value, i = _varint(data, i)
        elif wire == 1:
            value, i = data[i : i + 8], i + 8
        elif wire == 2:
            size, i = _varint(data, i)
            value, i = data[i : i + size], i + size
        elif wire == 5:
            value, i = data[i : i + 4], i + 4
        else:
            raise ValueError("wire type")
        yield field, wire, value


def step_time(metadata: bytes | None) -> int | None:
    """Unix seconds a step was created: ``metadata`` field 1 (a Timestamp), its field 1."""
    if not metadata:
        return None
    try:
        for field, wire, value in _fields(metadata):
            if field == 1 and wire == 2:
                for inner, inner_wire, seconds in _fields(value):
                    if inner == 1 and inner_wire == 0 and _MIN_TIME <= seconds <= _MAX_TIME:
                        return int(seconds)
                return None
    except (ValueError, IndexError):
        return None
    return None


def _step_times(path: Path) -> dict[int, int]:
    try:
        con = _connect(path)
        try:
            rows = con.execute("select idx, metadata from steps").fetchall()
        finally:
            con.close()
    except sqlite3.Error:
        return {}
    times: dict[int, int] = {}
    for idx, metadata in rows:
        when = step_time(bytes(metadata) if metadata else None)
        if isinstance(idx, int) and when is not None:
            times[idx] = when
    return times


def _offsets(raw: object) -> list[tuple[int, int]]:
    if isinstance(raw, bytes | bytearray | memoryview):
        raw = bytes(raw).decode("utf-8", "replace")
    try:
        data = json.loads(raw) if isinstance(raw, str) and raw else []
    except ValueError:
        return []
    out = []
    for item in data if isinstance(data, list) else []:
        if isinstance(item, list) and len(item) == 2 and all(isinstance(v, int) and v >= 0 for v in item):
            out.append((item[0], item[1]))
    return sorted(out, key=lambda pair: pair[1])


def _steps(body: object, offsets: list[tuple[int, int]]) -> Iterator[tuple[int, str]]:
    """``(step, text)`` cut from a chunk's body at its byte offsets."""
    data = body.encode("utf-8") if isinstance(body, str) else b""
    for n, (step, start) in enumerate(offsets):
        end = offsets[n + 1][1] if n + 1 < len(offsets) else len(data)
        if 0 <= start <= end <= len(data):
            yield step, data[start:end].decode("utf-8", "replace")


def _place(workspace_uris: object) -> str:
    """The first working folder: a ``file://`` URI or a path, alone, comma-separated or a JSON list."""
    if not isinstance(workspace_uris, str) or not workspace_uris.strip():
        return ""
    text = workspace_uris.strip()
    try:
        items = json.loads(text) if text.startswith("[") else text.replace("\n", ",").split(",")
    except ValueError:
        items = [text]
    first = next((str(i).strip() for i in items if str(i).strip()), "")
    if first.startswith("file://"):
        return unquote(urlsplit(first).path)
    return first


def read(path: Path, root: Path | None = None) -> list[Transcript]:
    """The conversation stored in ``path`` (``conversations/<id>.db``), from the summaries database's text."""
    base = root if root is not None else path.parent.parent
    conversation_id = path.stem
    summaries = base / SUMMARIES
    if not summaries.is_file():
        return []
    con = _connect(summaries)
    try:
        info = con.execute(
            "select title, workspace_uris from conversation_summaries where conversation_id = ?", (conversation_id,)
        ).fetchone()
        chunks = con.execute(
            "select user_body, user_step_byte_offsets, agent_body, agent_step_byte_offsets"
            " from conversations_fts where conversation_id = ? and chunk_index >= 0 order by chunk_index",
            (conversation_id,),
        ).fetchall()
    finally:
        con.close()
    texts: dict[tuple[int, str], str] = {}
    for user_body, user_offsets, agent_body, agent_offsets in chunks:
        role: Literal["owner", "agent"]
        for role, body, offsets in (("owner", user_body, user_offsets), ("agent", agent_body, agent_offsets)):
            for step, text in _steps(body, _offsets(offsets)):
                texts[(step, role)] = texts.get((step, role), "") + text
    if not texts:
        return []
    times = _step_times(path)
    entries = tuple(
        Entry(key=f"s{step}", role=role, sent_at=times.get(step), text=cleaned)  # type: ignore[arg-type]
        for (step, role), text in sorted(texts.items())
        if (cleaned := clean_text(text))
    )
    if not entries:
        return []
    title = clean_text(str(info[0])) if info and info[0] else ""
    return [
        Transcript(
            key=safe_key(conversation_id, "conversation"),
            title=title[:80] or title_of(entries),
            entries=entries,
            agent_name="antigravity",
            place=_place(info[1]) if info else "",
        )
    ]
