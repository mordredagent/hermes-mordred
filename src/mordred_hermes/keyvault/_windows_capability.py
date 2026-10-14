"""Truthful Windows keyvault capability predicates and excluded-path refusal (C5e).

Pure observation: no TPM/CNG operation, no unwrap, no subprocess and no
enrollment. ``supported`` is the Windows product contract; ``available`` is
derived only from C4 helper presence, C4 structural runtime admission and
checked, load-only custody reads. Predicates never wait for a lock: contention
is reported, not awaited. There is deliberately no aggregate "Windows ready"
flag, and installed-runtime proof (C5c) is not reported here.

Excluded capabilities (file vault, env/config/workspace seals, recovery,
per-use presence) refuse through :func:`refuse_excluded_on_windows`, and the
not-yet-ported generic secret store through :func:`refuse_unported_on_windows`,
before any ``_storage``, anchor/backend resolution, lock, mkdir or plaintext
operation. Retained artifacts are only reported, never adopted or erased.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Literal

from .._private_fs import PrivateFSError
from ._vault_errors import VaultError
from ._windows_profile import ROLES, CustodyError, Role

if TYPE_CHECKING:
    from ._windows_custody import WindowsCustodySession

__all__ = [
    "CAPABILITY_NAMES",
    "EXCLUDED_CAPABILITIES",
    "EXCLUDED_REASON",
    "NOT_PORTED_REASON",
    "SUPPORTED_CAPABILITIES",
    "UNPORTED_CAPABILITIES",
    "ExcludedArtifactReport",
    "KeyvaultUnsupportedOnWindows",
    "WindowsCapability",
    "excluded_artifacts",
    "refuse_excluded_on_windows",
    "refuse_unported_on_windows",
    "windows_capabilities",
    "windows_capability",
]

CapabilityName = Literal[
    "memory_custody",
    "native_audit",
    "telegram_hardware",
    "file_vault",
    "env_config_workspace_seals",
    "recovery",
    "presence",
    "secret_store",
]
ExcludedCapability = Literal["file_vault", "env_config_workspace_seals", "recovery", "presence"]
UnportedCapability = Literal["secret_store"]
UnavailableCapability = Literal["file_vault", "env_config_workspace_seals", "recovery", "presence", "secret_store"]
ExcludedArtifactKind = Literal["file_vault", "env_seal_optout", "config_seal_marker"]

SUPPORTED_CAPABILITIES: tuple[CapabilityName, ...] = ("memory_custody", "native_audit", "telegram_hardware")
EXCLUDED_CAPABILITIES: tuple[ExcludedCapability, ...] = (
    "file_vault",
    "env_config_workspace_seals",
    "recovery",
    "presence",
)
UNPORTED_CAPABILITIES: tuple[UnportedCapability, ...] = ("secret_store",)
CAPABILITY_NAMES: tuple[CapabilityName, ...] = SUPPORTED_CAPABILITIES + EXCLUDED_CAPABILITIES + UNPORTED_CAPABILITIES
EXCLUDED_REASON = "excluded-on-windows"
NOT_PORTED_REASON = "not-ported-on-windows"

_ROLE_FOR: dict[CapabilityName, Role] = {
    "memory_custody": "memory",
    "native_audit": "audit",
    "telegram_hardware": "telegram",
}
#: Retained ``<home>/mordred`` entries owned by excluded Windows capabilities.
_ARTIFACTS: dict[str, ExcludedArtifactKind] = {
    "vault": "file_vault",
    "env-vault.optout": "env_seal_optout",
    "config-vault.marker": "config_seal_marker",
}
_ARTIFACT_SCAN_LIMIT = 4096
_OWNERSHIP = frozenset({"enrolled", "not-enrolled"})


def _platform() -> str:
    return sys.platform


def _require_windows(operation: str) -> None:
    if _platform() != "win32":
        raise PrivateFSError("unsupported", operation)


@dataclass(frozen=True)
class WindowsCapability:
    name: CapabilityName
    supported: bool
    available: bool
    reason: str


@dataclass(frozen=True)
class ExcludedArtifactReport:
    """A retained artifact of an excluded capability, preserved and unsupported."""

    kind: ExcludedArtifactKind
    path: Path
    present: bool = True


class KeyvaultUnsupportedOnWindows(VaultError):
    """An excluded or not-yet-ported Windows keyvault capability refused before any state change."""

    def __init__(self, capability: UnavailableCapability, operation: str) -> None:
        self.capability = capability
        self.operation = operation
        if capability in UNPORTED_CAPABILITIES:
            self.reason = NOT_PORTED_REASON
            detail = "is not yet ported to Windows"
        else:
            self.reason = EXCLUDED_REASON
            detail = "is excluded on Windows"
        super().__init__(f"{capability} {detail} ({operation}); retained state is preserved unchanged")


def refuse_excluded_on_windows(capability: ExcludedCapability, operation: str) -> None:
    """Refuse an excluded capability on Windows; a no-op on every other platform."""
    if _platform() == "win32":
        raise KeyvaultUnsupportedOnWindows(capability, operation)


def refuse_unported_on_windows(capability: UnportedCapability, operation: str) -> None:
    """Refuse a capability that has no checked Windows port yet; a no-op elsewhere."""
    if _platform() == "win32":
        raise KeyvaultUnsupportedOnWindows(capability, operation)


def _unavailable(name: CapabilityName) -> WindowsCapability:
    reason = NOT_PORTED_REASON if name in UNPORTED_CAPABILITIES else EXCLUDED_REASON
    return WindowsCapability(name, False, False, reason)


def _classify(exc: BaseException) -> str:
    if isinstance(exc, PrivateFSError):
        if exc.commit_state != "uncertain" and exc.reason in ("unsafe", "access_denied", "unsupported"):
            return "custody-unsafe"
        return "custody-uncertain"  # including a held lock ("busy")
    if isinstance(exc, CustodyError):
        # Retained evidence that does not validate for this physical profile and
        # token: copied/foreign or malformed manifest, lost wrapper, orphan state.
        return "custody-broken"
    return "custody-uncertain"  # pending canonical policy publication


def _helper_reason() -> str | None:
    """C4 helper presence exactly as custody would select it; never a probe."""
    from . import _seckey_helper

    try:
        found = _seckey_helper.find_winkey_helper()
    except (OSError, RuntimeError, ValueError):
        return "helper-uncertain"
    return None if found is not None else "helper-missing"


def _runtime_reason() -> str | None:
    """C4 structural admission of this interpreter; no subprocess or proof."""
    from . import _memory_storage

    try:
        admitted = _memory_storage.windows_memory_runtime_admitted()
    except OSError:
        return "runtime-uncertain"
    return None if admitted else "runtime-not-admitted"


def _role_reason(session: WindowsCustodySession, role: Role) -> str:
    from .._config_io import PolicyPendingError

    try:
        status = session.role_status(role)
        if status.pending:
            return "custody-uncertain"
        if role == "memory":
            return "not-enrolled" if session.memory_state().lease is None else "enrolled"
        if status.current is None:
            return "not-enrolled"
        session.validate_lease(status.current)
        return "enrolled"
    except (PrivateFSError, PolicyPendingError, CustodyError) as exc:
        return _classify(exc)


def _custody_reasons(home: Path) -> dict[Role, str]:
    from .._config_io import CanonicalPaths, PolicyPendingError, canonical_session
    from ._windows_custody import windows_custody_session

    try:
        # A held process, home or Mordred lock is reported as busy, never awaited.
        with (
            canonical_session(CanonicalPaths(home), scope="policy", blocking=False) as canonical,
            windows_custody_session(home, canonical=canonical) as session,
        ):
            return {role: _role_reason(session, role) for role in ROLES}
    except (PrivateFSError, PolicyPendingError, CustodyError) as exc:
        # Entry or exit failure (including late uncertainty) invalidates every role.
        return dict.fromkeys(ROLES, _classify(exc))


def _supported(home: Path) -> tuple[WindowsCapability, ...]:
    helper = _helper_reason()
    runtime = _runtime_reason()  # structural checks run before custody locks
    custody = _custody_reasons(home)
    result = []
    for name in SUPPORTED_CAPABILITIES:
        role = _ROLE_FOR[name]
        reason = custody[role]
        if reason in _OWNERSHIP:
            if helper is not None:
                reason = helper
            elif role == "memory" and runtime is not None:
                reason = runtime
        result.append(WindowsCapability(name, True, reason == "enrolled", reason))
    return tuple(result)


def windows_capabilities(home: Path) -> tuple[WindowsCapability, ...]:
    """Report every frozen capability name in fixed order; never waits for a lock."""
    _require_windows("windows_capabilities")
    unavailable = EXCLUDED_CAPABILITIES + UNPORTED_CAPABILITIES
    return _supported(home) + tuple(_unavailable(name) for name in unavailable)


def windows_capability(home: Path, name: CapabilityName) -> WindowsCapability:
    """Report one capability; unavailable names are answered without custody reads."""
    _require_windows("windows_capability")
    if name not in CAPABILITY_NAMES:
        raise ValueError(f"unknown Windows capability {name!r}")
    if name not in SUPPORTED_CAPABILITIES:
        return _unavailable(name)
    return next(item for item in _supported(home) if item.name == name)


def excluded_artifacts(home: Path) -> tuple[ExcludedArtifactReport, ...]:
    """List retained excluded artifacts through the checked Mordred directory.

    Read-only and non-blocking: a checked absent home or Mordred directory
    reports nothing; a held lock raises ``PrivateFSError`` ``busy``, and every
    other inspection failure propagates and is never treated as empty.
    """
    _require_windows("excluded_artifacts")
    from .._config_io import CanonicalPaths, canonical_session

    with canonical_session(CanonicalPaths(home), scope="policy", blocking=False) as canonical:
        if canonical.home_directory_identity() is None:
            return ()
        try:
            with canonical.borrow_mordred_transaction() as tx:
                names = tx.list_names(max_entries=_ARTIFACT_SCAN_LIMIT)
        except PrivateFSError as exc:
            if exc.reason == "missing" and exc.operation == "mordred_transaction":
                return ()
            raise
    found = []
    for name in names:
        kind = _ARTIFACTS.get(name.casefold())
        if kind is not None:
            found.append(ExcludedArtifactReport(kind, home / "mordred" / name))
    return tuple(sorted(found, key=lambda report: (report.kind, report.path.name)))
