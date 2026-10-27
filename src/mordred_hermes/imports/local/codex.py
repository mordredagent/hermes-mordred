"""Codex rollouts: ``~/.codex/sessions/YYYY/MM/DD/rollout-*.jsonl``.

``session_meta`` names the session; ``response_item`` rows whose payload is a
``message`` from ``user`` or ``assistant`` carry the turns. Reasoning, tool
calls, tool output and token counts are skipped: they dominate the bytes and
are not something the user said or was told. An entry's key is its ordinal
among the kept turns, so an appended rollout keeps the keys it had.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from typing import Any

from ._jsonl import injected, rows
from ._model import Entry, Transcript, clean_text, iso_seconds, safe_key, title_of

GLOB = "rollout-*.jsonl"


def _text(payload: dict[str, Any]) -> str:
    chunks: list[str] = []
    for item in payload.get("content") or []:
        text = item.get("text") if isinstance(item, dict) else item
        if isinstance(text, str) and not injected(text):
            chunks.append(text)
    return clean_text("\n".join(chunks))


def files(root: Path) -> Iterator[Path]:
    yield from sorted(root.rglob(GLOB))


def read(path: Path) -> list[Transcript]:
    session: str | None = None
    entries: list[Entry] = []
    for row in rows(path):
        payload = row.get("payload")
        if not isinstance(payload, dict):
            continue
        if row.get("type") == "session_meta" and session is None:
            session = str(payload.get("id") or payload.get("session_id") or "") or None
            continue
        if row.get("type") != "response_item" or payload.get("type") != "message":
            continue
        role = payload.get("role")
        if role not in ("user", "assistant"):
            continue
        text = _text(payload)
        if not text:
            continue
        entries.append(
            Entry(
                key=f"{len(entries) + 1:06d}",
                role="owner" if role == "user" else "agent",
                sent_at=iso_seconds(row.get("timestamp")),
                text=text,
            )
        )
    if not entries:
        return []
    kept = tuple(entries)
    return [Transcript(key=safe_key(session or path.stem, path.stem), title=title_of(kept), entries=kept)]
