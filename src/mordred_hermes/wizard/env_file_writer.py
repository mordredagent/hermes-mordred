"""``~/.hermes/.env`` upsert writer (Phase 3 PR3a Task #6b).

The Mordred wizard writes a single secret (the Mullvad account number) to
``~/.hermes/.env`` so the Mullvad CLI can pick it up via env-var indirection
without ever being persisted into ``policy.json`` / ``config.yaml``. The
secret never crosses any other Mordred-owned filesystem path -- that file's
0600 mode plus the parent dir's 0700 mode is the only at-rest protection
v1 provides (Phase 4 keyvault encrypts it later).

Contract (mirrors PATHS.md §193 "credentials directory"):
- Upserts ``KEY=value`` lines without disturbing unrelated lines.
- Empty value → remove the line if present (so a user clearing the
  prompt removes the stale secret instead of leaving ``KEY=`` empty).
- Refuses non-POSIX env-var names + values containing newlines (defence
  in depth against shell-injection from a maliciously edited config).
- Atomic write via :func:`mordred_hermes._config_text_io._atomic_write_text`
  so a crash mid-write leaves the previous file intact.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, runtime_checkable

from .._config_io import DOTENV_LIMIT
from .._config_text_io import _atomic_write_text as _atomic_write_text
from .._config_text_io import _bounded_utf8, _windows
from .._dotenv_io import _dotenv_lock as _dotenv_lock
from .._dotenv_io import update_dotenv_file as update_dotenv_file
from .._dotenv_text import contains_newline, is_wizard_key, merge_assignments, replace_or_strip_key


@runtime_checkable
class EnvFileWriter(Protocol):
    """Persists one secret value (or its absence) to a ``.env``-style file."""

    def upsert(self, path: Path, *, key: str, value: str) -> None: ...


@dataclass(frozen=True, slots=True)
class DotEnvFileWriter:
    """Production :class:`EnvFileWriter` for ``~/.hermes/.env``.

    Upserts ``KEY=value`` lines atomically. Empty values remove the line.
    Refuses values / keys that could break the file format.
    """

    def upsert(self, path: Path, *, key: str, value: str) -> None:
        if not is_wizard_key(key):
            raise ValueError(
                f"refusing to write env var key {key!r}: must be uppercase, start with letter/underscore, "
                "and contain only alnum/underscore"
            )
        if contains_newline(value):
            raise ValueError(f"refusing to write env var value with newline in key {key!r}")

        if _windows():
            _bounded_utf8(value, DOTENV_LIMIT)

        def transform(existing: str) -> str:
            return merge_assignments(existing, {key: value}, mode="wizard")

        update_dotenv_file(path, transform)


def _replace_or_strip_key(lines: list[str], key: str, value: str) -> tuple[list[str], bool]:
    """Return (lines, found) where lines either has the new value or has the
    key removed (when ``value`` is empty).

    Used by :meth:`DotEnvFileWriter.upsert`. Match is exact: ``key=...`` only
    matches lines starting with ``<key>=``. Comments and lines that happen to
    contain ``key=`` as a substring elsewhere are preserved.

    Deduplication (review M2): if the on-disk file already had multiple
    matching lines (from a hand-edit or a half-finished write), only the
    first match keeps the new value -- subsequent matches are stripped --
    so the result is a single line. Empty-value removal strips all
    matches.
    """
    return replace_or_strip_key(lines, key, value)
