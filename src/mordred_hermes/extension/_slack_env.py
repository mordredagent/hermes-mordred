"""Dotenv writers backing the extension's Slack credential setup.

Split out of :mod:`mordred_hermes.extension.api`, which imports
:func:`_update_slack_env` for its ``slack_setup`` handler. The
``wizard.env_file_writer`` import stays inside each function so importing this
module never pulls the wizard package in.
"""

from __future__ import annotations

from pathlib import Path


def _dotenv_assignment(raw_line: str) -> tuple[str, bool, str] | None:
    """Return ``(name, exported, value)`` for one simple dotenv assignment."""
    line = raw_line.strip()
    if not line or line.startswith("#") or "=" not in line:
        return None
    name, value = line.split("=", 1)
    name = name.strip()
    exported = name.startswith("export ")
    if exported:
        name = name.removeprefix("export ").strip()
    return name, exported, value


def _dotenv_has_nonempty_key(existing: str, keys: set[str]) -> bool:
    """Whether dotenv text contains one of *keys* with a non-empty value."""
    for raw_line in existing.splitlines():
        assignment = _dotenv_assignment(raw_line)
        if assignment is None:
            continue
        name, _exported, value = assignment
        if name in keys and value.strip():
            return True
    return False


def _updated_env_text(existing: str, updates: dict[str, str]) -> str:
    """Return dotenv text with ``updates`` merged, preserving other lines."""
    seen: set[str] = set()
    out: list[str] = []
    for ln in existing.splitlines():
        assignment = _dotenv_assignment(ln)
        key, exported, _old_value = assignment if assignment is not None else ("", False, "")
        if key in updates:
            out.append(f"{'export ' if exported else ''}{key}={updates[key]}")
            seen.add(key)
        else:
            out.append(ln)
    out.extend(f"{key}={val}" for key, val in updates.items() if key not in seen)
    return "\n".join(out) + "\n"


def _validate_env_updates(updates: dict[str, str]) -> None:
    for key, val in updates.items():
        if any(c in key or c in val for c in ("\n", "\r")):
            raise ValueError("refusing to write a dotenv entry containing a newline")


def _upsert_env_vars(env_path: Path, updates: dict[str, str]) -> None:
    """Lock and atomically upsert dotenv entries while preserving other lines.

    Raises ``ValueError`` on a key/value carrying CR or LF: entries are emitted
    as raw ``KEY=value`` lines joined by "\\n", so such a value would inject
    arbitrary extra dotenv entries. Callers validate their own inputs (see
    ``_SLACK_BOT_TOKEN_RE``); this is the last line of defence for future ones.

    The shared sibling lock is also used by ``DotEnvFileWriter`` so concurrent
    Slack and wizard updates cannot both read the same old file and lose one
    another's unrelated entries.
    """
    from ..wizard.env_file_writer import update_dotenv_file

    _validate_env_updates(updates)
    update_dotenv_file(env_path, lambda existing: _updated_env_text(existing, updates))


class _SlackAlreadyConfigured(Exception):
    """Internal transaction-abort signal; never includes credential text."""


def _update_slack_env(env_path: Path, updates: dict[str, str], overwrite: bool) -> bool:
    """Check-and-upsert Slack credentials in one locked dotenv transaction."""
    from ..wizard.env_file_writer import update_dotenv_file

    _validate_env_updates(updates)

    def transform(existing: str) -> str:
        if not overwrite and _dotenv_has_nonempty_key(
            existing,
            {"SLACK_BOT_TOKEN", "SLACK_APP_TOKEN"},
        ):
            raise _SlackAlreadyConfigured
        return _updated_env_text(existing, updates)

    try:
        update_dotenv_file(env_path, transform)
    except _SlackAlreadyConfigured:
        return False
    return True
