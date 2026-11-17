"""Pure dotenv text operations for the preserved wizard and extension dialects.

These are simple line operations, without shell quoting or expansion. Callers
validate before opening a transaction and own their existing exception messages.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Literal

_VALID_ENV_KEY = re.compile(r"^[A-Z_][A-Z0-9_]*$")


def is_wizard_key(key: str) -> bool:
    return _VALID_ENV_KEY.fullmatch(key) is not None


def contains_newline(value: str) -> bool:
    return "\n" in value or "\r" in value


def parse_assignment(raw_line: str) -> tuple[str, bool, str] | None:
    """Recognize the extension's trimmed simple assignment syntax."""
    line = raw_line.strip()
    if not line or line.startswith("#") or "=" not in line:
        return None
    name, value = line.split("=", 1)
    name = name.strip()
    exported = name.startswith("export ")
    if exported:
        name = name.removeprefix("export ").strip()
    return name, exported, value


def has_nonempty_key(existing: str, keys: set[str]) -> bool:
    for raw_line in existing.splitlines():
        assignment = parse_assignment(raw_line)
        if assignment is None:
            continue
        name, _exported, value = assignment
        if name in keys and value.strip():
            return True
    return False


def replace_or_strip_key(lines: list[str], key: str, value: str) -> tuple[list[str], bool]:
    """Wizard matching is unindented and exact, retaining only the first match."""
    out: list[str] = []
    found = False
    prefix = f"{key}="
    for line in lines:
        export = "export " if line.startswith("export " + prefix) else ""
        if line.startswith(prefix) or export:
            if value and not found:
                out.append(f"{export}{key}={value}")
            found = True
            continue
        out.append(line)
    return out, found


def merge_assignments(text: str, updates: Mapping[str, str], *, mode: Literal["wizard", "extension"]) -> str:
    """Merge validated assignments with the selected existing text contract."""
    if mode == "wizard":
        lines = text.splitlines()
        for key, value in updates.items():
            lines, found = replace_or_strip_key(lines, key, value)
            if not found and value:
                lines.append(f"{key}={value}")
        return "\n".join(lines) + ("\n" if lines else "")

    seen: set[str] = set()
    out: list[str] = []
    for line in text.splitlines():
        assignment = parse_assignment(line)
        key, exported, _old_value = assignment if assignment is not None else ("", False, "")
        if key in updates:
            out.append(f"{'export ' if exported else ''}{key}={updates[key]}")
            seen.add(key)
        else:
            out.append(line)
    out.extend(f"{key}={value}" for key, value in updates.items() if key not in seen)
    return "\n".join(out) + "\n"
