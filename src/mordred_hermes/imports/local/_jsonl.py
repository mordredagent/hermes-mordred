"""JSON Lines reading shared by the Codex and Claude Code readers."""

from __future__ import annotations

import json
import re
from collections.abc import Iterator
from pathlib import Path
from typing import Any, Final

# Agent apps inject context into the user's turn as one tagged block
# (``<environment_context>…</environment_context>``, ``<system-reminder>…``).
# Those are not the user's words; a turn that is only such a block is skipped.
_INJECTED: Final = re.compile(r"\A<([A-Za-z][A-Za-z0-9_-]*)[^>]*>.*</\1>\Z", re.DOTALL)


def rows(path: Path) -> Iterator[dict[str, Any]]:
    """Each JSON object line of ``path``; blank, broken and non-object lines are skipped."""
    with path.open(encoding="utf-8", errors="replace") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                value = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(value, dict):
                yield value


def injected(text: str) -> bool:
    return bool(_INJECTED.match(text.strip()))
