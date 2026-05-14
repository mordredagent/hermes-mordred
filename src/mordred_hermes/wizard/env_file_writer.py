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
- Atomic write via :func:`mordred_hermes.wizard.policy_writer._atomic_write_text`
  so a crash mid-write leaves the previous file intact.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, runtime_checkable

from .policy_writer import _atomic_write_text

# POSIX env-var name: start with letter/underscore, followed by alnum/underscore.
# We also require at least one uppercase letter -- Mordred owns the
# ``MORDRED_*`` namespace, and the prompts only ever emit fully-uppercase
# names. Restricting at this layer makes the file shell-injection-safe.
_VALID_ENV_KEY = re.compile(r"^[A-Z_][A-Z0-9_]*$")


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
        if not _VALID_ENV_KEY.match(key):
            raise ValueError(
                f"refusing to write env var key {key!r}: must be uppercase, start with letter/underscore, "
                "and contain only alnum/underscore"
            )
        if "\n" in value or "\r" in value:
            raise ValueError(f"refusing to write env var value with newline in key {key!r}")

        existing_lines: list[str] = []
        if path.exists():
            try:
                existing_lines = path.read_text(encoding="utf-8").splitlines()
            except OSError:
                # Treat unreadable file as empty -- the atomic write below
                # will recreate it with the new line.
                existing_lines = []

        new_lines, found = _replace_or_strip_key(existing_lines, key, value)
        if not found and value:
            new_lines.append(f"{key}={value}")
        new_text = "\n".join(new_lines) + ("\n" if new_lines else "")
        _atomic_write_text(path, new_text, mode=0o600)


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
    out: list[str] = []
    found = False
    prefix = f"{key}="
    for line in lines:
        if line.startswith(prefix):
            if value and not found:
                out.append(f"{key}={value}")
            # subsequent matches dropped (or all matches dropped when value is empty)
            found = True
            continue
        out.append(line)
    return out, found
