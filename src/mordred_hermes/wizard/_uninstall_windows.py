"""Windows branch of ``hermes-mordred uninstall``.

- **Restore** covers agent memory only, through ``memory_cli.disable`` on
  ``win32`` (capabilities -> stopped-gateway gate -> installed-runtime proof
  -> checked disable; the CNG key is kept). A refusal stops the uninstall
  before anything is removed. The env/config seals are excluded on Windows:
  retained artifacts are reported and preserved, never restored or deleted.
- ``--purge-data`` purges the memory custody key through ``memory_cli.purge``
  on ``win32`` after the verified restore (no seal or staging entry may
  remain, then ``reset_role("memory")``). Audit and Telegram custody, a
  retained secret store or file vault, and the ``<home>\\mordred`` and
  ``<home>\\extension`` trees are kept and reported: Windows has no checked
  recursive removal yet, so nothing is force-removed.
- ``--erase-encrypted`` refuses: sealed memory is never deleted unread.

Heavy imports stay function-local so this module imports on any platform.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from . import _term
from ._windows_gates import WINDOWS, classify_exception

if TYPE_CHECKING:
    from .uninstall_cli import Restore, UninstallContext, UninstallPlan

__all__ = [
    "PLAN_NOTE",
    "PURGE_WARNING",
    "custody_roles",
    "device_keys",
    "erase_refusal",
    "kept_after_purge",
    "kept_lines",
    "purge",
    "purge_lines",
    "restore",
    "restores",
]

PLAN_NOTE = (
    "Windows: the memory restore refuses while any Hermes gateway or Hermes Desktop session runs, or while the "
    "process inventory is unknown; stop them first. Retained file-vault/seal/secret-store state is excluded or "
    "not ported on Windows and is preserved unchanged."
)
PURGE_WARNING = (
    "\nWARNING: --purge-data on Windows permanently deletes the Windows CNG memory custody key after the\n"
    "memory restore (step 5, first line). Copies sealed under it elsewhere can no longer be decrypted.\n"
    "Everything else listed in step 5 is kept."
)
_ROLE_LABELS = {"memory": "memory", "audit": "audit", "telegram": "Telegram"}


def erase_refusal() -> int:
    _term.emit_error(
        "uninstall --erase-encrypted is not supported on Windows: sealed memory is never deleted without being "
        "decrypted, and Windows has no checked recursive removal yet. Run `hermes-mordred uninstall` (it decrypts "
        "memory back first), optionally with --purge-data. Nothing was changed."
    )
    return 1


def restores(home: Path) -> list[Restore]:
    """The memory restore the plan promises, from a load-only observation."""
    from ._windows_memory import observe
    from .uninstall_cli import Restore

    observation = observe(home, blocking=True)
    report = observation.report
    if observation.reason is not None or report is None:
        return [
            Restore(
                "memory",
                f"memory custody cannot be verified ({observation.reason}: {observation.detail}); the restore "
                "refuses and uninstall stops before removing anything",
                False,
            )
        ]
    if not (report.armed or report.sealed or report.broken or report.pending):
        return []
    return [
        Restore(
            "memory",
            "Windows: refuse unless every Hermes gateway is stopped, prove the installed Hermes runtime, then "
            f"decrypt {len(report.sealed)} sealed memory file(s) back with verified checked replacement; the CNG "
            "memory key is kept",
            False,
        )
    ]


def custody_roles(home: Path) -> tuple[list[str], str | None]:
    """Roles with owned CNG generations, read without waiting for a lock or touching the TPM."""
    from .._config_io import CanonicalPaths, canonical_session
    from ..keyvault._windows_custody import windows_custody_session
    from ..keyvault._windows_profile import ROLES

    try:
        with (
            canonical_session(CanonicalPaths(home), scope="policy", blocking=False) as canonical,
            windows_custody_session(home, canonical=canonical) as custody,
        ):
            owned: list[str] = []
            for role in ROLES:
                status = custody.role_status(role)
                if status.current is not None or status.retained or status.pending:
                    owned.append(role)
    except Exception as exc:  # a plan line must never break the plan
        return [], f"{classify_exception(exc)} — {type(exc).__name__}: {exc}"
    return owned, None


def device_keys(home: Path, vault_root: Path) -> list[str]:
    roles, error = custody_roles(home)
    keys = [f"Windows CNG {_ROLE_LABELS[role]} custody key (TPM-bound, this account and profile)" for role in roles]
    if error is not None:
        keys.append(f"Windows custody not checked ({error})")
    if vault_root.exists():
        keys.append(f"retained file vault {vault_root} (excluded on Windows; preserved unchanged)")
    if (home / "mordred" / "keyvault").exists():
        keys.append("retained secret store (not ported to Windows; preserved unchanged)")
    return keys


def purge_lines(home: Path) -> list[str]:
    """What ``--purge-data`` does on Windows, exactly."""
    roles, _ = custody_roles(home)
    lines = []
    if "memory" in roles:
        lines.append(
            "delete the Windows CNG memory custody key after the verified restore (only when no sealed memory or "
            "staging entry remains)"
        )
    if "audit" in roles:
        lines.append("keep audit custody and audit history (their destructive purge is a separate ceremony)")
    if "telegram" in roles:
        lines.append("keep Telegram custody and credentials (Telegram logout/forget is a separate ceremony)")
    for name in ("mordred", "extension"):
        if (home / name).is_dir():
            lines.append(
                f"keep {home / name}: reported, not removed (Windows has no checked recursive removal yet; remove "
                "it by hand after checking)"
            )
    return lines


_MEMORY_KEY = "Windows CNG memory custody key"
_MEMORY_FILES = ("memory-key.wrapped", "memory-vault.optout")


def kept_after_purge(purge: list[str], data: list[str]) -> list[str]:
    """``data`` lines that survive ``--purge-data``: the purged memory key and its files are not kept."""
    if not any(_MEMORY_KEY in line for line in purge):
        return data
    return [
        line
        for line in data
        if not line.startswith(_MEMORY_KEY) and not any(f"{name}  -- " in line for name in _MEMORY_FILES)
    ]


def restore(ctx: UninstallContext, planned: list[Restore]) -> int:
    """Step a on Windows: the proof-bound memory disable, or stop before removing anything."""
    from . import memory_cli

    for item in planned:
        print(f"Restoring {item.target} ...")
        if memory_cli.disable(home=ctx.home, root=ctx.vault_root, platform=WINDOWS) != 0:
            _term.emit_error(
                "uninstall stopped: memory could not be restored to plaintext (see above). Nothing was removed and "
                "Mordred stays installed, so Hermes keeps working. Fix the cause, then re-run "
                "`hermes-mordred uninstall` (or `encryption disable memory`)."
            )
            return 1
    return 0


def purge(ctx: UninstallContext) -> int:
    """``--purge-data`` on Windows: memory custody only; everything else is kept and reported."""
    from . import memory_cli

    roles, error = custody_roles(ctx.home)
    if error is not None:
        _term.emit_error(f"Windows custody could not be read ({error}); Mordred data was retained.")
        return 1
    if "memory" in roles and memory_cli.purge(home=ctx.home, root=ctx.vault_root, platform=WINDOWS) != 0:
        _term.emit_error("Windows memory custody could not be purged (see above); Mordred data was retained.")
        return 1
    for line in purge_lines(ctx.home):
        if line.startswith("keep "):
            print(line[0].upper() + line[1:] + ".")
    return 0


def kept_lines(plan: UninstallPlan) -> str:
    lines = [f"  {path}  -- {description}" for path, description in plan.data]
    lines += [f"  {key}" for key in plan.device_keys]
    if not lines:
        return "No Mordred data is left."
    return "\n".join(
        [
            "Kept on Windows -- Mordred data that remains on this machine (no checked recursive removal yet):",
            *lines,
            "Remove these paths by hand once you no longer need them.",
        ]
    )
