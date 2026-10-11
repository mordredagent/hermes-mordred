"""``hermes-mordred keyvault native init`` — explicit Windows native custody initialization.

The one ceremony that creates Windows CNG custody keys. It reads
``windows_capabilities(home)`` first, refuses unsafe, broken, uncertain or
helper-less custody with the classified remedy, and only then enrolls the
requested roles through C5a ``enroll_memory()`` / ``enroll_role("audit")`` /
``enroll_role("telegram")``.

- Enrollment is inert: no memory marker is written and no memory file changes.
  ``encryption enable memory`` may run this ceremony for the memory role; an
  audit writer or any other callback never enrolls a key.
- An already enrolled role is reported, never re-created. Retained evidence
  without ownership (a marker, wrapper, journal or sealed memory) refuses
  inside C5a before any native key is generated.
- Output is metadata only: role, generation and public-key fingerprint, plus
  :data:`CUSTODY_NOTICE` (no per-use presence, no portable recovery), which
  ``encryption enable memory`` also prints whenever it creates the key.

``--role telegram`` (C6-telegram) creates the independent Telegram custody
key that the C10b credential store seals to; ``telegram setup`` offers to run
exactly this ceremony and ``telegram login`` refuses until it has. An enrolled
telegram role is never rotated here (rotation would strand the sealed
credentials). Heavy imports stay function-local so this module imports
everywhere.
"""

from __future__ import annotations

import argparse
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Literal

from . import _term
from ._windows_gates import CUSTODY_FAILURES, HELPER_FAILURES, classify_exception, describe_capability, remedy

if TYPE_CHECKING:
    from ..keyvault._windows_capability import CapabilityName, WindowsCapability
    from ..keyvault._windows_custody import GenerationLease

__all__ = ["CUSTODY_NOTICE", "NATIVE_ROLES", "RoleOutcome", "cli_native_init", "enroll_roles", "native_init"]

NativeRole = Literal["memory", "audit", "telegram"]
NATIVE_ROLES: tuple[NativeRole, ...] = ("memory", "audit", "telegram")
_CAPABILITY_FOR: dict[NativeRole, CapabilityName] = {
    "memory": "memory_custody",
    "audit": "native_audit",
    "telegram": "telegram_hardware",
}
_OPERATION = "keyvault native init"
#: SPEC-frozen notice, printed whenever a Windows CNG custody key is created.
CUSTODY_NOTICE = (
    "There is no per-use presence and no portable recovery: losing the TPM, this Windows account or this "
    "profile directory loses data encrypted under these keys. Disable memory encryption while the TPM is "
    "usable to restore plaintext first."
)


@dataclass(frozen=True)
class RoleOutcome:
    """Metadata of one role after the ceremony; never key material."""

    role: str
    generation: str
    public_sha256: str
    created: bool


def _render(outcome: RoleOutcome) -> str:
    verb = "enrolled now" if outcome.created else "already enrolled (unchanged)"
    return (
        f"  {outcome.role.ljust(6)} : {verb} — generation {outcome.generation}, "
        f"public key SHA-256 {outcome.public_sha256}"
    )


def _refuse(operation: str, role: str, reason: str, detail: str, *, enrollment_attempted: bool = False) -> None:
    hint = remedy(reason)
    retained = (
        " Enrollment may have created a key; retained keys and journals are preserved for explicit reconciliation. "
        "No existing key is adopted or regenerated."
        if enrollment_attempted
        else " No key was generated for it; existing custody state is preserved."
    )
    _term.emit_error(
        f"{operation}: {role} custody refused ({reason}): {detail}" + (f" — {hint}." if hint else ".") + retained
    )


def _enroll_one(home: Path, role: NativeRole) -> tuple[GenerationLease, bool]:
    """Enroll ``role`` when absent, in its own custody scope; report an existing one."""
    from ..keyvault._windows_custody import windows_custody_session

    with windows_custody_session(home, create=True) as custody:
        # Memory ownership is read through memory_state(), which also fails
        # closed on retained memory evidence without committed ownership.
        current = custody.memory_state().lease if role == "memory" else custody.role_status(role).current
        if current is not None:
            custody.validate_lease(current)
            return current, False
        if role == "memory":
            # The returned key bytes are discarded at once: enrollment is inert.
            custody.enroll_memory()
            return custody.lease("memory"), True
        return custody.enroll_role(role), True


def enroll_roles(home: Path, roles: Sequence[NativeRole], *, operation: str = _OPERATION) -> list[RoleOutcome] | None:
    """Enroll each absent role in order; ``None`` after printing the first refusal.

    Each role uses its own custody scope, so an earlier committed enrollment
    is reported even when a later role refuses. The caller checks the
    capabilities first; C5a still refuses retained evidence without ownership
    before any native generation.
    """
    from ..keyvault._exceptions import WrapError

    if not home.is_dir():
        _term.emit_error(f"{operation}: the Hermes home {home} does not exist — run Hermes once first.")
        return None
    outcomes: list[RoleOutcome] = []
    for role in roles:
        try:
            lease, created = _enroll_one(home, role)
        except (OSError, RuntimeError, ValueError, WrapError) as exc:
            for outcome in outcomes:
                print(_render(outcome))
            # Native creation may succeed before verification or publication fails.
            # Do not infer absence or expose arbitrary native/OS exception content.
            _refuse(operation, role, classify_exception(exc), type(exc).__name__, enrollment_attempted=True)
            return None
        outcomes.append(RoleOutcome(role, lease.generation, lease.public_sha256, created))
    return outcomes


def _capabilities(home: Path) -> tuple[WindowsCapability, ...] | None:
    from .._private_fs import PrivateFSError
    from ..keyvault._windows_capability import windows_capabilities

    try:
        return windows_capabilities(home)
    except PrivateFSError as exc:
        reason, detail = classify_exception(exc), type(exc).__name__
        if reason == "unsupported":
            _term.emit_error(f"{_OPERATION}: Windows native custody exists only on native Windows.")
            return None
    except (OSError, RuntimeError, ValueError) as exc:
        reason, detail = classify_exception(exc), type(exc).__name__
    _refuse(_OPERATION, "Windows", reason, detail)
    return None


def native_init(*, home: Path, roles: Sequence[NativeRole] = ("memory",)) -> int:
    """Capabilities first, then explicit inert enrollment of ``roles``. Returns an exit code."""
    requested = tuple(dict.fromkeys(roles))
    capabilities = _capabilities(home)
    if capabilities is None:
        return 1
    by_name = {capability.name: capability for capability in capabilities}
    for role in requested:
        capability = by_name[_CAPABILITY_FOR[role]]
        if capability.reason in CUSTODY_FAILURES | HELPER_FAILURES:
            _refuse(_OPERATION, role, capability.reason, describe_capability(capability))
            return 1
    outcomes = enroll_roles(home, requested)
    if outcomes is None:
        return 1
    print("Windows native custody (machine-bound CNG key, this Windows account, this physical profile):")
    for outcome in outcomes:
        print(_render(outcome))
    if "memory" in requested:
        print(
            "Memory custody is inert until `hermes-mordred encryption enable memory` proves the installed Hermes "
            "runtime and seals the memories."
        )
    if "telegram" in requested:
        print(
            "Telegram custody seals the Telegram credentials and the archive key; `hermes-mordred telegram setup` "
            "and `hermes-mordred telegram login` use it after the machine-bound acknowledgement."
        )
    print(CUSTODY_NOTICE)
    for capability in capabilities:
        if not capability.supported:
            print(f"  {describe_capability(capability)}")
    return 0


def cli_native_init(args: argparse.Namespace) -> int:
    """argparse handler for ``keyvault native init [--role memory|audit|telegram ...]``."""
    from .._home import hermes_home

    roles: list[NativeRole] = list(getattr(args, "roles", None) or ["memory"])
    return native_init(home=hermes_home(), roles=roles)
