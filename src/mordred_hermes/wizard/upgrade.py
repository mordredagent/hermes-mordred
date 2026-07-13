"""``hermes mordred upgrade`` -- Story 1 (idempotent migration) + Story 1.5 dispatch.

Story 1 covers the simple case: a Hermes-only install whose ``config.yaml``
either has no ``mordred_privacy_check`` section yet, or has one that
already matches the target snapshot. The flow:

1. Compute target snapshot (caller passes one, or defaults are used).
2. Compare against the on-disk section.
3. Decide: ``noop`` / ``applied`` / ``kept-existing`` / ``overwritten``
   based on diff + ``--policy-conflict`` + ``--reset``.

Story 1.5 (OpenClaw migration) is dispatched to
:mod:`mordred_hermes.wizard.openclaw_migration` when the legacy base
directory exists. Phase E lands the dispatch + report wiring; the actual
migrator implementation lives in that sibling module.

The :class:`UpgradeOptions` flag rules per PATHS.md §OpenClaw migration
L286 H5 table:

- ``--reset`` overrides every other policy and forces overwrite.
- ``--non-interactive`` requires ``--policy-conflict`` to be pre-specified
  whenever a conflict exists; otherwise we ``SystemExit`` rather than
  silently dropping the user's intent.
- ``--policy-conflict={keep-existing,overwrite,abort}`` selects the
  conflict resolution.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from .._yaml_io import load_plugin_section
from . import openclaw_migration
from ._runtime import DEFAULT_OPENCLAW_BASE
from .policy_writer import PolicySnapshot, PolicyWriter, _section_matches_dict

_LOG = logging.getLogger("mordred.wizard.upgrade")

PolicyConflict = Literal["keep-existing", "overwrite", "abort"]
AuditMerge = Literal["skip", "append-all", "abort"]

Story1Action = Literal["noop", "applied", "kept-existing", "overwritten"]
Story1_5Action = Literal["noop", "migrated", "skipped-marker"]


@dataclass(frozen=True, slots=True)
class UpgradeOptions:
    """CLI flag carrier for ``hermes mordred upgrade``.

    Defaults match the interactive form: prompt on conflict, do not
    reset, do not skip the audit log.
    """

    reset: bool = False
    non_interactive: bool = False
    audit_merge: AuditMerge | None = None
    policy_conflict: PolicyConflict | None = None


@dataclass(frozen=True, slots=True)
class UpgradeReport:
    """Outcome of an upgrade run -- structured for tests + audit log."""

    story1_action: Story1Action
    story1_5_action: Story1_5Action


#: Human phrases for the Story 1 (config.yaml) outcome shown by render_report.
_STORY1_PHRASES: dict[Story1Action, str] = {
    "noop": "already up to date",
    "applied": "Mordred defaults applied",
    "kept-existing": "kept existing settings",
    "overwritten": "overwritten with Mordred defaults",
}

#: Human phrases for the Story 1.5 (OpenClaw) outcome shown by render_report.
_STORY1_5_PHRASES: dict[Story1_5Action, str] = {
    "noop": "not needed (nothing to migrate)",
    "migrated": "migrated from ~/.openclaw",
    "skipped-marker": "already migrated (marker present)",
}


def render_report(report: UpgradeReport) -> str:
    """User-facing summary printed after ``hermes-mordred upgrade``.

    The CLI handler used to discard the report entirely, leaving the
    command silent even after migrating ~/.openclaw (UX review
    2026-06-11). Mirrors the configure/network-init summary style.
    """
    # .get with the raw action as fallback: a Story action added to the
    # Literal but missed here must degrade to the raw token, not KeyError
    # (review 2026-06-12).
    return "\n".join(
        [
            "Upgrade summary:",
            f"  config.yaml        : {_STORY1_PHRASES.get(report.story1_action, report.story1_action)}",
            f"  OpenClaw migration : {_STORY1_5_PHRASES.get(report.story1_5_action, report.story1_5_action)}",
        ]
    )


def _read_existing_section(config_path: Path) -> dict[str, Any] | None:
    """Read ``plugins.mordred_privacy_check`` from ``config.yaml``, or None.

    Returns ``None`` if the file or section is absent. Returns the body
    dict (matching ``PolicySnapshot.to_config_yaml_section()``) otherwise.
    ``round_trip=True`` is load-bearing: the safe loader raises on custom
    YAML tags, which the broad catch would collapse to "no section" and the
    caller would then overwrite a hand-edited section without the conflict
    prompt — the rt loader reads tags as values that compare unequal and
    route to conflict resolution. ``catch=(Exception,)`` keeps the
    historical broad net — an unreadable / unparseable config degrades to
    "no section" here rather than crashing the upgrade.
    """
    section = load_plugin_section(config_path, "mordred_privacy_check", catch=(Exception,), log=_LOG, round_trip=True)
    return None if section is None else dict(section)


def _section_matches(existing: dict[str, Any] | None, target: PolicySnapshot) -> bool:
    """True iff the on-disk section equals what the wizard would write."""
    return existing is not None and _section_matches_dict(existing, target.to_config_yaml_section())


def _resolve_story1(
    options: UpgradeOptions,
    policy_writer: PolicyWriter,
    target_snapshot: PolicySnapshot,
) -> Story1Action:
    """Run Story 1 (Hermes-only path). Returns the action taken.

    Mental model: ``upgrade`` migrates *existing* state; fresh installs
    go through ``configure``. So:

    - config.yaml absent entirely -> ``noop`` (no Hermes install to upgrade).
    - config.yaml exists, mordred section absent -> ``applied`` (back-fill).
    - section matches target -> ``noop`` (idempotency).
    - section differs -> resolve via ``--policy-conflict`` / ``--reset``.
    """
    if not policy_writer.config_path.exists():
        return "noop"

    existing = _read_existing_section(policy_writer.config_path)

    if existing is None:
        policy_writer.write(target_snapshot)
        return "applied"

    if _section_matches(existing, target_snapshot):
        return "noop"

    # Conflict: existing != target. Resolve per options.
    if options.reset:
        policy_writer.write(target_snapshot)
        return "overwritten"

    if options.policy_conflict is None:
        if options.non_interactive:
            raise SystemExit(
                "hermes-mordred upgrade: --non-interactive set but --policy-conflict "
                "not specified; refusing to overwrite existing mordred section"
            )
        raise SystemExit(
            "hermes-mordred upgrade: existing config.yaml plugins.mordred_privacy_check "
            "differs from the target snapshot. Re-run with one of "
            "--policy-conflict=keep-existing|overwrite|abort or --reset."
        )

    if options.policy_conflict == "keep-existing":
        return "kept-existing"
    if options.policy_conflict == "overwrite":
        policy_writer.write(target_snapshot)
        return "overwritten"
    raise SystemExit(
        "hermes-mordred upgrade: --policy-conflict=abort set; existing mordred section differs from target -- aborting."
    )


def _resolve_story1_5(
    options: UpgradeOptions,
    policy_writer: PolicyWriter,
    openclaw_base: Path,
) -> Story1_5Action:
    """Dispatch to OpenClaw migrator if legacy base exists."""
    if not openclaw_base.exists():
        return "noop"
    return openclaw_migration.migrate(
        openclaw_base=openclaw_base,
        policy_writer=policy_writer,
        options=options,
    )


def run(
    *,
    options: UpgradeOptions,
    policy_writer: PolicyWriter,
    target_snapshot: PolicySnapshot | None = None,
    openclaw_base: Path = DEFAULT_OPENCLAW_BASE,
) -> UpgradeReport:
    """Top-level upgrade entry.

    Args:
        options: CLI flag carrier.
        policy_writer: Sole writer for ``config.yaml`` + ``policy.json``.
        target_snapshot: What the wizard would write today. Defaults to
            ``PolicySnapshot(policy="lenient")`` -- the default established
            by ``configure``.
        openclaw_base: Override for tests; production = ``~/.openclaw/mordred``.
    """
    if target_snapshot is None:
        target_snapshot = PolicySnapshot(policy="lenient")

    story1 = _resolve_story1(options, policy_writer, target_snapshot)
    story1_5 = _resolve_story1_5(options, policy_writer, openclaw_base)
    return UpgradeReport(story1_action=story1, story1_5_action=story1_5)
