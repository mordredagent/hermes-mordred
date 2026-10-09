"""Windows branch of ``hermes-mordred uninstall``.

- **Restore** covers agent memory only, through ``memory_cli.disable`` on
  ``win32`` (capabilities -> stopped-gateway gate -> installed-runtime proof
  -> checked disable; the CNG key is kept). A refusal stops the uninstall
  before anything is removed. With ``--purge-data`` the restore is also
  planned for enrolled-but-inert custody that was never explicitly disabled,
  because the purge requires that disable. The env/config seals are excluded
  on Windows: retained artifacts are reported and preserved, never restored
  or deleted.
- ``--purge-data`` purges the memory custody key through ``memory_cli.purge``
  on ``win32`` right after the verified restore and before step b (no seal or
  staging entry may remain, then ``reset_role("memory")``), so every refusal
  -- gate, proof, verification or reset -- leaves Hermes's files, launchers
  and the package installed. Audit and Telegram custody, a retained secret
  store or file vault, and the ``<home>\\mordred`` and ``<home>\\extension``
  trees are kept and reported: Windows has no checked recursive removal yet,
  so nothing is force-removed.
- ``--erase-encrypted`` refuses: sealed memory is never deleted unread.

Heavy imports stay function-local so this module imports on any platform.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING

from . import _term
from ._windows_gates import WINDOWS, classify_exception

if TYPE_CHECKING:
    from .uninstall_cli import Restore, UninstallContext, UninstallPlan

__all__ = [
    "PLAN_NOTE",
    "custody_roles",
    "device_keys",
    "erase_refusal",
    "kept_after_purge",
    "kept_lines",
    "purge",
    "purge_lines",
    "purge_warning",
    "restore",
    "restore_step",
    "restores",
]

PLAN_NOTE = (
    "Windows: the memory restore refuses while any Hermes gateway or Hermes Desktop session runs, or while the "
    "process inventory is unknown; stop them first. Retained file-vault/seal/secret-store state is excluded or "
    "not ported on Windows and is preserved unchanged."
)
_ROLE_LABELS = {"memory": "memory", "audit": "audit", "telegram": "Telegram"}
_DELETE_MEMORY = "delete the Windows CNG memory custody key"
_UNREADABLE = "Windows custody could not be read"
_STOPPED = (
    "Nothing was removed and Mordred stays installed, so Hermes keeps working. Fix the cause, then re-run "
    "`hermes-mordred uninstall --purge-data` (or uninstall without --purge-data to keep the key)."
)
_GATED = "refuse unless every Hermes gateway is stopped, prove the installed Hermes runtime, then "


def erase_refusal() -> int:
    _term.emit_error(
        "uninstall --erase-encrypted is not supported on Windows: sealed memory is never deleted without being "
        "decrypted, and Windows has no checked recursive removal yet. Run `hermes-mordred uninstall` (it decrypts "
        "memory back first), optionally with --purge-data. Nothing was changed."
    )
    return 1


def restores(home: Path, *, purge_data: bool = False) -> list[Restore]:
    """The memory restore the plan promises, from a load-only observation.

    With ``purge_data`` an enrolled profile that was never explicitly disabled
    (inert custody from ``keyvault native init`` or an enable that refused at
    the proof) is restored too: the purge requires the opt-out the checked
    disable writes, so it is recorded before anything else happens.
    """
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
        if not (purge_data and report.managed and not report.opted_out):
            return []
        detail = (
            "Windows: nothing is sealed, but the enrolled memory custody was never explicitly disabled and "
            f"--purge-data requires that: {_GATED}record the disable (opt-out marker) through the checked disable; "
            "the CNG memory key is kept until the purge"
        )
        return [Restore("memory", detail, False)]
    broken = (
        f"; {len(report.broken)} broken seal(s) cannot be decrypted, so the restore refuses until they are restored "
        "from a backup or moved out of the memories directory by hand"
        if report.broken
        else ""
    )
    return [
        Restore(
            "memory",
            f"Windows: {_GATED}decrypt {len(report.sealed)} sealed memory file(s) back with verified checked "
            f"replacement; the CNG memory key is kept{broken}",
            False,
        )
    ]


def custody_roles(home: Path, *, blocking: bool = False) -> tuple[list[str], str | None]:
    """Roles with owned CNG generations, read without touching the TPM.

    The plan reads without waiting for a lock (``blocking=False``); the purge
    itself waits, like every other lifecycle command.
    """
    from .._config_io import CanonicalPaths, canonical_session
    from ..keyvault._windows_custody import windows_custody_session
    from ..keyvault._windows_profile import ROLES

    try:
        with (
            canonical_session(CanonicalPaths(home), scope="policy", blocking=blocking) as canonical,
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
    roles, error = custody_roles(home)
    lines = []
    if error is not None:
        lines.append(
            f"{_UNREADABLE} ({error}); the purge reads it again right after the restore and refuses -- stopping "
            "before anything is removed -- if it is still unreadable"
        )
    if "memory" in roles:
        lines.append(
            f"{_DELETE_MEMORY} right after the verified restore, before anything else is removed (it refuses, and "
            "the uninstall stops, while a gateway runs or sealed memory, a broken seal or staging remains)"
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


def purge_warning(purge: list[str] | None) -> str:
    """The typed-confirmation warning for ``--purge-data`` on Windows, from the plan's step 5."""
    lines = purge or []
    if any(line.startswith(_DELETE_MEMORY) for line in lines):
        return (
            "\nWARNING: --purge-data on Windows permanently deletes the Windows CNG memory custody key right after\n"
            "the memory restore (step 5, first line). Copies sealed under it elsewhere can no longer be decrypted.\n"
            "Everything else listed in step 5 is kept."
        )
    if any(line.startswith(_UNREADABLE) for line in lines):
        return (
            "\nWARNING: Windows custody could not be read (step 5). --purge-data on Windows deletes at most the\n"
            "Windows CNG memory custody key, right after the memory restore, and refuses before anything is\n"
            "removed while custody stays unreadable. Everything else listed in step 5 is kept."
        )
    return (
        "\nNote: no Windows CNG memory custody key is enrolled on this profile, so --purge-data on Windows\n"
        "deletes no key here. Everything listed in step 5 is kept."
    )


def restore_step(*, purge_data: bool) -> Callable[[UninstallContext, list[Restore]], int]:
    """Step a on Windows; with ``purge_data`` the memory custody purge follows at once, before step b."""

    def step(ctx: UninstallContext, planned: list[Restore]) -> int:
        if restore(ctx, planned) != 0:
            return 1
        return purge(ctx) if purge_data else 0

    return step


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
    """``--purge-data`` on Windows, right after the restore: memory custody only; the rest is kept and reported."""
    from . import memory_cli

    roles, error = custody_roles(ctx.home, blocking=True)
    if error is not None:
        _term.emit_error(f"uninstall stopped: {_UNREADABLE} ({error}). {_STOPPED}")
        return 1
    if "memory" in roles and memory_cli.purge(home=ctx.home, root=ctx.vault_root, platform=WINDOWS) != 0:
        _term.emit_error(f"uninstall stopped: Windows memory custody could not be purged (see above). {_STOPPED}")
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
