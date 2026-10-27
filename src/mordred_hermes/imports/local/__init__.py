"""Local agent transcripts (Codex, Claude Code, Grok Bot) imported into ``mordred.db``.

These sources are files on this machine, written by the agent apps themselves:

- Codex: ``~/.codex/sessions/**/rollout-*.jsonl`` (:mod:`.codex`).
- Claude Code: ``~/.claude/projects/**/*.jsonl`` (:mod:`.claude_code`).
- Grok Bot: the desktop app's ``sand-client-persistence/*.blob`` transcript
  replicas, one per bot (:mod:`.grok_bot`).

Each reader turns a file into :class:`~._model.Transcript` objects; only the
user's own turns and the agent's replies are kept (tool calls, reasoning and
attachments are skipped). :func:`.runner.run_local_import` writes them through
the ordinary :class:`~mordred_hermes.imports.store.ImportStore` run protocol.
UIDs come from session and entry ids, never from text, so importing the same
files again finds every message as a duplicate and writes nothing new, and a
per-file cursor in ``import_meta`` skips files that did not change.
"""

from __future__ import annotations

from ._model import LOCAL_SOURCES, Entry, Transcript
from .runner import LocalImportError, default_root, local_status, run_local_import

__all__ = [
    "LOCAL_SOURCES",
    "Entry",
    "LocalImportError",
    "Transcript",
    "default_root",
    "local_status",
    "run_local_import",
]
