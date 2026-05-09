"""Parse SKILL.md YAML frontmatter, extract ``metadata.mordred.*``.

The agentskills.io spec defines ``metadata`` as a flat ``string -> string``
map; Mordred deviates by using a nested ``metadata.mordred`` block with
typed values (string enum, bool, list[str]). The deviation is documented
in POLICY.md. ``skills-ref validate`` may reject Mordred-flavoured skills
— this is acceptable because Mordred users go through ``hermes mordred install``.

This module reads files but does not write. ``ruamel.yaml`` ``safe`` mode
is used for parsing because it is already a declared dependency
(``pyproject.toml`` ``dependencies``); it is also strictly safer than
``yaml.unsafe_load`` from PyYAML.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final, cast

from ruamel.yaml import YAML

from .policy import VALID_NETWORK_REQUIREMENTS, NetworkRequirement

_FRONTMATTER_DELIMITER: Final = "---"


def _yaml_safe() -> YAML:
    """Per-call ``YAML`` instance.

    ``ruamel.yaml`` ``YAML`` objects hold mutable parser state and are not
    thread-safe; concurrent ``parse()`` calls across threads must each get
    their own instance.
    """
    return YAML(typ="safe", pure=True)


class SkillMetadataError(ValueError):
    """Raised when frontmatter is structurally invalid (malformed YAML, wrong type).

    Missing optional fields are NOT errors — they map to ``None`` / defaults.
    """


@dataclass(frozen=True, slots=True)
class SkillMetadata:
    """Mordred-relevant subset of SKILL.md frontmatter.

    ``name`` is the skill name from the top-level frontmatter field (per
    agentskills.io spec); we keep it for audit log ``skill_id`` correlation.
    Mordred-specific fields all live under ``metadata.mordred.*`` and are
    optional — missing fields map to ``None`` / ``False`` / ``()``.
    """

    name: str | None
    network_requirements: NetworkRequirement | None
    requires_keyvault: bool
    outbound_endpoints: tuple[str, ...]


def _split_frontmatter(text: str) -> str | None:
    """Return the YAML body between the leading ``---`` fences, or None.

    Tolerates LF and CRLF line endings. Returns ``None`` if the file does
    not start with ``---`` on its first line, or if no closing fence is
    found — both treated as "no frontmatter, no Mordred metadata".
    """
    lines = text.splitlines()
    if not lines or lines[0].strip() != _FRONTMATTER_DELIMITER:
        return None
    for i, line in enumerate(lines[1:], start=1):
        if line.strip() == _FRONTMATTER_DELIMITER:
            return "\n".join(lines[1:i])
    return None


def _coerce_endpoints(raw: Any) -> tuple[str, ...]:
    """Coerce ``outbound_endpoints`` to a tuple of strings.

    Returns ``()`` for missing/null. Raises :class:`SkillMetadataError` if
    present but not a list-of-strings — silently dropping a malformed list
    would be a security smell (caller declared an allowlist; we should not
    pretend it is empty).
    """
    if raw is None:
        return ()
    if not isinstance(raw, list) or not all(isinstance(x, str) for x in raw):
        raise SkillMetadataError(f"metadata.mordred.outbound_endpoints must be list[str], got {type(raw).__name__}")
    return tuple(raw)


def _coerce_network_requirements(raw: Any) -> NetworkRequirement | None:
    """Validate ``network_requirements`` against the closed enum."""
    if raw is None:
        return None
    if not isinstance(raw, str) or raw not in VALID_NETWORK_REQUIREMENTS:
        raise SkillMetadataError(
            f"metadata.mordred.network_requirements must be one of {sorted(VALID_NETWORK_REQUIREMENTS)}, got {raw!r}"
        )
    return cast(NetworkRequirement, raw)


def parse(skill_md_path: Path) -> SkillMetadata:
    """Parse a SKILL.md file and return its Mordred metadata view.

    Missing frontmatter, missing ``metadata`` block, and missing
    ``metadata.mordred`` block all return a ``SkillMetadata`` with all
    Mordred fields set to their "absent" sentinels (None / False / ()).
    The install wrapper distinguishes "missing metadata.mordred entirely"
    from "present but empty" by checking ``network_requirements is None``.

    Raises :class:`SkillMetadataError` on structurally invalid frontmatter
    (malformed YAML, wrong types). Raises ``OSError`` on file read failure.
    """
    text = skill_md_path.read_text(encoding="utf-8")
    body = _split_frontmatter(text)
    if body is None:
        return SkillMetadata(None, None, False, ())

    try:
        raw = _yaml_safe().load(body)
    except Exception as e:
        raise SkillMetadataError(f"malformed YAML frontmatter in {skill_md_path}: {e}") from e

    if raw is None:
        return SkillMetadata(None, None, False, ())
    if not isinstance(raw, dict):
        raise SkillMetadataError(f"frontmatter must be a YAML mapping, got {type(raw).__name__}")

    name_raw = raw.get("name")
    name: str | None = name_raw if isinstance(name_raw, str) else None

    metadata = raw.get("metadata") or {}
    if not isinstance(metadata, dict):
        raise SkillMetadataError(f"metadata must be a mapping, got {type(metadata).__name__}")

    mordred_block = metadata.get("mordred") or {}
    if not isinstance(mordred_block, dict):
        raise SkillMetadataError(f"metadata.mordred must be a mapping, got {type(mordred_block).__name__}")

    return SkillMetadata(
        name=name,
        network_requirements=_coerce_network_requirements(mordred_block.get("network_requirements")),
        requires_keyvault=bool(mordred_block.get("requires_keyvault", False)),
        outbound_endpoints=_coerce_endpoints(mordred_block.get("outbound_endpoints")),
    )
