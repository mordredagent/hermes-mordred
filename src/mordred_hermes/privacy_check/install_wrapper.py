"""``hermes mordred install <skill>`` policy wrapper.

Reads SKILL.md frontmatter, evaluates policy, writes one ``pre_install``
audit entry, then either raises :class:`InstallBlocked` or delegates to
the real Hermes installer (``hermes skills install <skill>``).

Audit always lands BEFORE the side effect — block events are recorded
even when the call would fail; allow/warn events are recorded before
the subprocess is invoked so they cannot be lost to a crashed installer.

The ``runner`` parameter is injectable for tests; the default invokes
``hermes skills install`` via :mod:`subprocess`.
"""

from __future__ import annotations

import os
import subprocess
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import TypeAlias

from ._keyvault_probe import keyvault_initialized
from .audit import Writer
from .policy import PolicyMode, PolicyOutcome, evaluate_install
from .skill_frontmatter import parse

_platform = os.name

SubprocessRunner: TypeAlias = Callable[[list[str]], "subprocess.CompletedProcess[bytes]"]

# Probe injected for ``requires_keyvault`` enforcement (TODO.md §4.1). The
# default resolves the production keyvault; tests pass a fake. It is only
# invoked when the skill actually declares ``requires_keyvault: true``, so
# skills that do not opt in never touch the keyvault plugin.
KeyvaultProbe: TypeAlias = Callable[[], bool]


class InstallBlocked(RuntimeError):
    """Strict-mode policy refused this install."""

    def __init__(self, reason: str, skill_id: str | None) -> None:
        super().__init__(f"strict policy refused install of {skill_id!r}: {reason}")
        self.reason = reason
        self.skill_id = skill_id


@dataclass(frozen=True, slots=True)
class InstallResult:
    """Outcome of :func:`run`. Only populated on non-block decisions."""

    outcome: PolicyOutcome
    skill_id: str | None
    install_returncode: int


def _default_runner(cmd: list[str]) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(cmd, check=False)


def _resolve_skill_md(skill_path: Path, skill_md_name: str) -> Path:
    """Accept either a skill directory or an explicit SKILL.md path."""
    if skill_path.is_dir():
        return skill_path / skill_md_name
    return skill_path


def run(
    *,
    skill_path: Path,
    policy_mode: PolicyMode,
    audit: Writer,
    skill_md_name: str = "SKILL.md",
    runner: SubprocessRunner = _default_runner,
    keyvault_probe: KeyvaultProbe = keyvault_initialized,
    config_path: Path | None = None,
) -> InstallResult:
    """Run the install wrapper for one skill.

    Raises :class:`InstallBlocked` on strict-mode block (audit entry is
    written first). On allow / warn, invokes ``runner(["hermes", "skills",
    "install", <skill_path>])`` and returns its returncode.

    On Windows a fresh canonical read precedes every execution; ``config_path``
    selects an explicit canonical config leaf. A supplied mode can strengthen
    but cannot weaken that checked policy. An unreadable generation refuses
    before the keyvault probe or installer runs.

    ``keyvault_probe`` reports whether the Mordred keyvault is initialized;
    it is consulted *only* when the skill declares
    ``metadata.mordred.requires_keyvault: true`` (TODO.md §4.1), so skills
    that do not opt in incur no keyvault import or filesystem read.
    """
    if _platform == "nt":
        from . import _runtime
        from ._checked_policy import read_checked_policy

        try:
            checked = read_checked_policy(config_path or _runtime.DEFAULT_HERMES_CONFIG_PATH)
        except Exception:
            raise InstallBlocked("canonical privacy policy unavailable", None) from None
        # A caller may request a stricter policy, but cannot override the
        # current checked generation with a stale permissive mode.
        rank = {"off": 0, "lenient": 1, "strict": 2}
        if rank[checked.mode] > rank[policy_mode]:
            policy_mode = checked.mode
    md = _resolve_skill_md(skill_path, skill_md_name)
    metadata = parse(md)
    vault_ready = keyvault_probe() if metadata.requires_keyvault else True
    outcome = evaluate_install(
        policy_mode=policy_mode,
        network_requirements=metadata.network_requirements,
        requires_keyvault=metadata.requires_keyvault,
        keyvault_initialized=vault_ready,
    )

    audit.append(
        {
            "event": "pre_install",
            "decision": outcome.decision,
            "reason": outcome.reason,
            "skill_id": metadata.name,
        }
    )

    if outcome.decision == "block":
        raise InstallBlocked(outcome.reason or "unknown", metadata.name)

    completed = runner(["hermes", "skills", "install", str(skill_path)])
    return InstallResult(
        outcome=outcome,
        skill_id=metadata.name,
        install_returncode=completed.returncode,
    )
