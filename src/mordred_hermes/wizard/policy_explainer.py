"""``hermes mordred policy {show,explain,dry-run,reload}``.

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
import sys
from collections.abc import Iterable
from pathlib import Path
from typing import Any, cast

from .._home import HERMES_BASE
from ..privacy_check._runtime import is_poisoned, reload_state
from ..privacy_check.policy import PolicyMode, evaluate_install
from ..privacy_check.skill_frontmatter import SkillMetadataError, parse
from ._runtime import DEFAULT_POLICY_JSON_PATH

_LOG = logging.getLogger("mordred.wizard.policy_explainer")

DEFAULT_SKILLS_DIRS: tuple[Path, ...] = (
    HERMES_BASE / "skills",
    Path.cwd() / ".hermes" / "skills",
)


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
            f"No Mordred policy configured at {policy_json_path}.\nRun `hermes mordred configure` to create one.",
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


def _resolve_policy_mode(policy_json_path: Path) -> PolicyMode:
    """Read policy.json -> ``policy`` field. Default 'lenient' if absent."""
    if not policy_json_path.exists():
        return "lenient"
    try:
        body = json.loads(policy_json_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return "lenient"
    raw = body.get("policy") if isinstance(body, dict) else None
    if raw in ("strict", "lenient", "off"):
        return cast(PolicyMode, raw)
    return "lenient"


def _find_skill_md(skill_id: str, search_paths: Iterable[Path]) -> Path | None:
    """Return the first ``<dir>/<skill_id>/SKILL.md`` that exists, or None.

    ``skill_id`` is treated as a single path segment -- traversal sequences
    (``/``, ``\\``, ``.``, ``..``) are rejected outright. Resolved candidates
    must remain under their search dir; symlinks pointing elsewhere are
    treated as misses.
    """
    if not skill_id or "/" in skill_id or "\\" in skill_id or skill_id in (".", ".."):
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
    policy_json_path: Path = DEFAULT_POLICY_JSON_PATH,
    skills_dirs: Iterable[Path] = DEFAULT_SKILLS_DIRS,
    out: Any = sys.stdout,
) -> int:
    """Explain the install decision for an installed skill id.

    Searches ``~/.hermes/skills/<skill_id>/SKILL.md`` first, then a
    project-local ``.hermes/skills/<skill_id>/SKILL.md`` fallback.
    """
    policy_mode = _resolve_policy_mode(policy_json_path)
    skill_md = _find_skill_md(skill_id, skills_dirs)
    if skill_md is None:
        print(
            f"Skill {skill_id!r} not found in any of: {[str(p) for p in skills_dirs]}",
            file=sys.stderr,
        )
        return 1
    return _print_decision(skill_md, policy_mode, out=out)


def dry_run(
    skill_path: Path,
    *,
    policy_json_path: Path = DEFAULT_POLICY_JSON_PATH,
    out: Any = sys.stdout,
) -> int:
    """Evaluate the install decision for a SKILL.md (or skill dir) path.

    No install side effect is taken. Useful before committing a new skill
    to verify Mordred will not block it under the active policy.
    """
    skill_md = skill_path if skill_path.is_file() else skill_path / "SKILL.md"
    if not skill_md.exists():
        print(f"SKILL.md not found at {skill_md}", file=sys.stderr)
        return 1
    policy_mode = _resolve_policy_mode(policy_json_path)
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
    outcome = evaluate_install(
        policy_mode=policy_mode,
        network_requirements=meta.network_requirements,
    )
    label = "dry-run:" if dry_run_label else "decision:"
    print(f"{label} {outcome.decision}", file=out)
    if outcome.reason is not None:
        print(f"reason: {outcome.reason}", file=out)
    print(f"skill_id: {meta.name or '<unnamed>'}", file=out)
    print(f"network_requirements: {meta.network_requirements or '<unset>'}", file=out)
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
        policy_json_path=DEFAULT_POLICY_JSON_PATH,
        skills_dirs=DEFAULT_SKILLS_DIRS,
    )


def cli_dry_run(args: argparse.Namespace) -> int:
    return dry_run(Path(args.skill_path), policy_json_path=DEFAULT_POLICY_JSON_PATH)


def cli_reload(args: argparse.Namespace) -> int:
    return reload()
