"""Encrypted conversation history for the Mordred extension (SPEC §4 / §1 chat).

History is recorded **encrypted at rest** with the pairing's shared AES key
(the same `🔒ENC:v1:` envelope used for Slack), so it survives gateway restarts
and is readable from any paired surface — extension, Slack, or the localhost
page — without re-running the conversation. It is NOT wiped when viewed.

Storage: ``~/.hermes/extension/history.enc`` — a single `🔒ENC:v1:` blob whose
plaintext is the JSON agent-message list. We rewrite the whole blob per turn
(chat-scale data); a paired client decrypts it (or Hermes decrypts server-side
for the keyless localhost page).
"""

from __future__ import annotations

import contextlib
import json
import logging
from pathlib import Path
from typing import Any

from ..keyvault._storage import atomic_write
from .crypto import decrypt_message, encrypt_message
from .pairing import load_pairing

logger = logging.getLogger(__name__)


def _history_path() -> Path:
    from .._home import hermes_home

    d = hermes_home() / "extension"
    d.mkdir(parents=True, exist_ok=True)
    return d / "history.enc"


def _key() -> bytes | None:
    p = load_pairing()
    return p.aes_key if p else None


def save_messages(messages: list[dict[str, Any]]) -> None:
    """Encrypt and persist the full agent message list (best-effort)."""
    key = _key()
    if key is None:
        return
    try:
        blob = encrypt_message(key, json.dumps(messages, ensure_ascii=False))
        # Canonical 0600 atomic write (keyvault._storage): unpredictable tmp
        # name, O_EXCL | O_NOFOLLOW, fsync of the tmp fd and the parent dir, and
        # tmp cleanup on failure — the hand-rolled version used a fixed ".tmp"
        # name and leaked it when the write blew up. The parent dir is mkdir'd
        # by _history_path().
        atomic_write(_history_path(), blob.encode("utf-8"))
    except Exception:
        logger.debug("extension history save failed", exc_info=True)


def load_messages() -> list[dict[str, Any]]:
    """Decrypt and return the stored agent message list ([] if none)."""
    key = _key()
    if key is None:
        return []
    path = _history_path()
    if not path.exists():
        return []
    try:
        blob = path.read_text("utf-8").strip()
        data = json.loads(decrypt_message(key, blob))
        return data if isinstance(data, list) else []
    except Exception:
        logger.debug("extension history load failed", exc_info=True)
        return []


def clear() -> None:
    with contextlib.suppress(OSError):
        _history_path().unlink()


def projected_turns() -> list[dict[str, str]]:
    """A viewer-friendly [{role, content}] projection (user + assistant text)."""
    out: list[dict[str, str]] = []
    for msg in load_messages():
        role = msg.get("role")
        if role not in ("user", "assistant"):
            continue
        text = _content_text(msg.get("content"))
        if text:
            out.append({"role": role, "content": text})
    return out


def _content_text(content: Any) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for p in content:
            if isinstance(p, dict):
                if p.get("type") in ("text", "input_text", "output_text") and p.get("text"):
                    parts.append(str(p["text"]))
                elif "text" in p and isinstance(p["text"], str):
                    parts.append(p["text"])
        return "\n".join(parts)
    return ""
