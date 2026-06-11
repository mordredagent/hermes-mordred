"""``hermes-mordred policy {show,explain,dry-run,reload}``.

Read-only inspection helpers over Mordred policy state -- no file
mutation other than the in-memory state reset performed by ``reload``.

Composition over the existing :mod:`mordred_hermes.privacy_check`
building blocks (``skill_frontmatter.parse`` + ``policy.evaluate_install``)
so that ``policy explain`` and ``policy dry-run`` cannot drift from the
real install-time decision.
"""

from __future__ import annotations

import argparse
import json
import logging
import re
import sys
from collections.abc import Iterable
from pathlib import Path
from typing import Any, Final

from .._home import HERMES_BASE
from ..privacy_check._keyvault_probe import KeyvaultProbeError, keyvault_initialized
from ..privacy_check._runtime import (
    DEFAULT_HERMES_CONFIG_PATH,
    get_active_policy_mode,
    is_poisoned,
    reload_state,
)
from ..privacy_check.policy import PolicyMode, evaluate_install
from ..privacy_check.skill_frontmatter import SkillMetadataError, parse
from ._runtime import DEFAULT_POLICY_JSON_PATH

_LOG = logging.getLogger("mordred.wizard.policy_explainer")

DEFAULT_SKILLS_DIRS: tuple[Path, ...] = (
    HERMES_BASE / "skills",
    Path.cwd() / ".hermes" / "skills",
)

# Skill IDs are restricted to ASCII alphanumerics + dot/underscore/hyphen.
# Layer 0 of the path-traversal defence -- rejects unicode look-alikes
# (U+FF0F FULLWIDTH SOLIDUS, U+2215 DIVISION SLASH, etc.) that would
# pass the ``"/" in skill_id`` substring check on POSIX but could be
# normalised on Windows or future runtimes. Layer 1 (substring guard)
# and Layer 2 (resolve + is_relative_to) remain as defence in depth.
_SKILL_ID_RE: Final = re.compile(r"[A-Za-z0-9._-]+")


# -----------------------------------------------------------------------------
# show -- print policy.json
# -----------------------------------------------------------------------------


def show(
    *,
    policy_json_path: Path = DEFAULT_POLICY_JSON_PATH,
    out: Any = sys.stdout,
) -> int:
    """Print the resolved Mordred policy. Exit code 0 on success, 1 if absent."""
    if not policy_json_path.exists():
        print(
            f"No Mordred policy configured at {policy_json_path}.\nRun `hermes-mordred configure` to create one.",
            file=sys.stderr,
        )
        return 1
    try:
        body = json.loads(policy_json_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        print(f"Failed to read {policy_json_path}: {e}", file=sys.stderr)
        return 1
    print(json.dumps(body, indent=2, sort_keys=False), file=out)
    return 0


# -----------------------------------------------------------------------------
# explain / dry-run -- evaluate a skill's install decision under current policy
# -----------------------------------------------------------------------------


def _resolve_policy_mode(config_path: Path = DEFAULT_HERMES_CONFIG_PATH) -> PolicyMode:
    """Resolve the active policy mode using the same source as the install hook.

    Reads ``~/.hermes/config.yaml plugins.mordred_privacy_check.policy``
    via :func:`privacy_check._runtime.get_active_policy_mode` so that
    ``policy explain`` / ``dry-run`` cannot drift from the actual
    install-time decision when users edit ``config.yaml`` directly.
    Defaults to ``"lenient"`` when the section is missing -- matching
    the privacy_check hook's defaulting behaviour.
    """
    return get_active_policy_mode(config_path=config_path)


def _find_skill_md(skill_id: str, search_paths: Iterable[Path]) -> Path | None:
    """Return the first ``<dir>/<skill_id>/SKILL.md`` that exists, or None.

    ``skill_id`` is treated as a single path segment -- traversal sequences
    (``/``, ``\\``, ``.``, ``..``) are rejected outright. Resolved candidates
    must remain under their search dir; symlinks pointing elsewhere are
    treated as misses.
    """
    if not _SKILL_ID_RE.fullmatch(skill_id) or skill_id in (".", ".."):
        return None
    for d in search_paths:
        candidate = d / skill_id / "SKILL.md"
        if not candidate.is_file():
            continue
        try:
            resolved = candidate.resolve(strict=True)
            base = d.resolve(strict=False)
        except (OSError, RuntimeError):
            continue
        if resolved.is_relative_to(base):
            return candidate
    return None


def explain(
    skill_id: str,
    *,
    config_path: Path = DEFAULT_HERMES_CONFIG_PATH,
    skills_dirs: Iterable[Path] = DEFAULT_SKILLS_DIRS,
    out: Any = sys.stdout,
) -> int:
    """Explain the install decision for an installed skill id.

    Searches ``~/.hermes/skills/<skill_id>/SKILL.md`` first, then a
    project-local ``.hermes/skills/<skill_id>/SKILL.md`` fallback.

    Policy mode is read from ``~/.hermes/config.yaml`` (the same source
    the install hook uses) -- not from the ``policy.json`` mirror -- so
    explainer output cannot drift when users edit config.yaml directly.
    """
    policy_mode = _resolve_policy_mode(config_path)
    skill_md = _find_skill_md(skill_id, skills_dirs)
    if skill_md is None:
        searched = ", ".join(str(p) for p in skills_dirs)
        print(
            f"Skill {skill_id!r} not found in any of: {searched}",
            file=sys.stderr,
        )
        return 1
    return _print_decision(skill_md, policy_mode, out=out)


def dry_run(
    skill_path: Path,
    *,
    config_path: Path = DEFAULT_HERMES_CONFIG_PATH,
    out: Any = sys.stdout,
) -> int:
    """Evaluate the install decision for a SKILL.md (or skill dir) path.

    No install side effect is taken. Useful before committing a new skill
    to verify Mordred will not block it under the active policy. Same
    drift-free policy resolution as :func:`explain`.
    """
    skill_md = skill_path if skill_path.is_file() else skill_path / "SKILL.md"
    if not skill_md.exists():
        print(f"SKILL.md not found at {skill_md}", file=sys.stderr)
        return 1
    policy_mode = _resolve_policy_mode(config_path)
    return _print_decision(skill_md, policy_mode, out=out, dry_run_label=True)


def _print_decision(
    skill_md_path: Path,
    policy_mode: PolicyMode,
    *,
    out: Any,
    dry_run_label: bool = False,
) -> int:
    try:
        meta = parse(skill_md_path)
    except SkillMetadataError as e:
        print(f"Malformed SKILL.md: {e}", file=sys.stderr)
        return 1
    # The keyvault-initialized probe is consulted only when the skill opts
    # in via ``requires_keyvault: true`` (TODO.md §4.1); otherwise the
    # explainer never touches the keyvault plugin or filesystem. A corrupt
    # keyvault must not crash this diagnostic command — it is reported on
    # stderr and treated as uninitialized (fail-closed: strict then shows
    # the ``block`` decision).
    vault_ready = True
    if meta.requires_keyvault:
        try:
            vault_ready = keyvault_initialized()
        except KeyvaultProbeError as e:
            print(f"warning: {e}; treating keyvault as uninitialized", file=sys.stderr)
            vault_ready = False
    outcome = evaluate_install(
        policy_mode=policy_mode,
        network_requirements=meta.network_requirements,
        requires_keyvault=meta.requires_keyvault,
        keyvault_initialized=vault_ready,
    )
    label = "dry-run:" if dry_run_label else "decision:"
    print(f"{label} {outcome.decision}", file=out)
    if outcome.reason is not None:
        print(f"reason: {outcome.reason}", file=out)
    print(f"skill_id: {meta.name or '<unnamed>'}", file=out)
    print(f"network_requirements: {meta.network_requirements or '<unset>'}", file=out)
    print(f"requires_keyvault: {meta.requires_keyvault}", file=out)
    print(f"policy_mode: {policy_mode}", file=out)
    return 0 if outcome.decision != "block" else 2


# -----------------------------------------------------------------------------
# reload -- clear in-process privacy_check state cache
# -----------------------------------------------------------------------------


def reload(*, out: Any = sys.stdout) -> int:
    """Reset the cached privacy_check PluginState in this process.

    Note: live sessions in OTHER processes are unaffected; users must
    restart those. This is documented in the wizard README.

    The poison flag is intentionally NOT cleared by reload (it is a
    process-lifetime invariant). If the calling process is poisoned the
    user is warned that reload alone will not unblock them.
    """
    poisoned = is_poisoned()
    reload_state()
    print("Mordred privacy_check policy state reloaded.", file=out)
    if poisoned:
        print(
            "Warning: this process is poisoned (sibling-disable detected at startup); "
            "reload does not clear the poison flag. Restart your Hermes session.",
            file=sys.stderr,
        )
    return 0


# -----------------------------------------------------------------------------
# CLI handler adapters (called by cli.py).
# -----------------------------------------------------------------------------


def cli_show(args: argparse.Namespace) -> int:
    # Read module-level constants at call time so tests can monkeypatch them.
    return show(policy_json_path=DEFAULT_POLICY_JSON_PATH)


def cli_explain(args: argparse.Namespace) -> int:
    return explain(
        args.skill_id,
        config_path=DEFAULT_HERMES_CONFIG_PATH,
        skills_dirs=DEFAULT_SKILLS_DIRS,
    )


def cli_dry_run(args: argparse.Namespace) -> int:
    return dry_run(Path(args.skill_path), config_path=DEFAULT_HERMES_CONFIG_PATH)


def cli_reload(args: argparse.Namespace) -> int:
    return reload()
