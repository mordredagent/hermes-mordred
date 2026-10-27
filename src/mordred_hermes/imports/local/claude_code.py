"""Claude Code sessions: ``~/.claude/projects/<encoded path>/*.jsonl``.

One row per event; ``user`` and ``assistant`` rows carry ``message.content`` as
a string or a list of blocks. Only ``text`` blocks are kept (tool use, tool
results and thinking are skipped), and so are meta rows (``isMeta``) and
sub-agent rows (``isSidechain``). An entry's key is the row's ``uuid``.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from typing import Any

from ._jsonl import injected, rows
from ._model import Entry, Transcript, clean_text, iso_seconds, safe_key, title_of

GLOB = "*.jsonl"


def _text(message: Any) -> str:
    content = message.get("content") if isinstance(message, dict) else message
    if isinstance(content, str):
        chunks = [content]
    elif isinstance(content, list):
        chunks = [
            block["text"]
            for block in content
            if isinstance(block, dict) and block.get("type") == "text" and isinstance(block.get("text"), str)
        ]
    else:
        return ""
    return clean_text("\n".join(chunk for chunk in chunks if not injected(chunk)))


def files(root: Path) -> Iterator[Path]:
    yield from sorted(root.rglob(GLOB))


def read(path: Path) -> list[Transcript]:
    session: str | None = None
    title = ""
    entries: list[Entry] = []
    seen: set[str] = set()
    for row in rows(path):
        if session is None and isinstance(row.get("sessionId"), str):
            session = row["sessionId"]
        if row.get("type") == "custom-title" and isinstance(row.get("customTitle"), str):
            title = row["customTitle"].strip()[:80]
        role = row.get("type")
        if role not in ("user", "assistant") or row.get("isMeta") or row.get("isSidechain"):
            continue
        text = _text(row.get("message"))
        if not text:
            continue
        key = safe_key(row.get("uuid"), f"n{len(entries) + 1:06d}")
        if key in seen:
            continue
        seen.add(key)
        entries.append(
            Entry(
                key=key,
                role="owner" if role == "user" else "agent",
                sent_at=iso_seconds(row.get("timestamp")),
                text=text,
            )
        )
    if not entries:
        return []
    kept = tuple(entries)
    return [Transcript(key=safe_key(session or path.stem, path.stem), title=title or title_of(kept), entries=kept)]
