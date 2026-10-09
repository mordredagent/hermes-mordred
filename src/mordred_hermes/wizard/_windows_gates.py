"""Shared Windows routing for the wizard: capability reasons, remedies and refusals.

The keyvault owns the executable predicates (``keyvault._windows_capability``);
this module owns only how the wizard words them. Every Windows keyvault or
memory line is answered from those predicates and from load-only custody
reads, never from a TPM operation, an unwrap or a subprocess. There is no
aggregate "Windows ready" answer: each capability is shown with its own
``supported`` / ``available`` / ``reason``.

Heavy imports stay function-local so this module imports on any platform.
"""

from __future__ import annotations

import sys
from typing import TYPE_CHECKING

from . import _term

if TYPE_CHECKING:
    from ..keyvault._windows_capability import ExcludedCapability, UnportedCapability, WindowsCapability

__all__ = [
    "CUSTODY_FAILURES",
    "HELPER_FAILURES",
    "RUNTIME_REASONS",
    "WINDOWS",
    "classify_exception",
    "describe_capability",
    "excluded_refusal",
    "host_platform",
    "proof_remedy",
    "remedy",
    "unported_refusal",
]

WINDOWS = "win32"

#: Custody states that refuse every enrollment and lifecycle transition.
CUSTODY_FAILURES = frozenset({"custody-unsafe", "custody-uncertain", "custody-broken"})
#: The CNG helper is required for any native operation.
HELPER_FAILURES = frozenset({"helper-missing", "helper-uncertain"})
#: This interpreter's structural admission; the installed runtime is proven separately.
RUNTIME_REASONS = frozenset({"runtime-not-admitted", "runtime-uncertain"})

_REMEDIES: dict[str, str] = {
    "enrolled": "",
    "not-enrolled": "enroll it with `hermes-mordred keyvault native init`",
    "custody-unsafe": (
        "a custody file or directory of this profile is not private to this Windows account (broad ACL, "
        "foreign owner, hard link, junction or reparse point); Mordred never repairs ACLs or adopts unsafe "
        "state — fix the ownership/ACL by hand, then retry"
    ),
    "custody-uncertain": (
        "custody is busy, has an unresolved role journal, an uncertain earlier outcome or a pending policy "
        "publication — let other Hermes/Mordred processes finish and retry; an unresolved journal is kept for "
        "explicit reconciliation and a key is never regenerated in its place"
    ),
    "custody-broken": (
        "retained custody evidence does not validate for this physical profile and Windows account (a copied "
        "or restored home, a lost key wrapper, or an orphan marker/journal); it is preserved, never adopted "
        "or regenerated — use the original profile directory and account (decrypt there first to move it)"
    ),
    "helper-missing": "install the Windows CNG helper with `hermes-mordred keyvault enable-winkey`",
    "helper-uncertain": (
        "the Windows CNG helper location could not be checked — check MORDRED_WINKEY_HELPER and "
        "<HERMES_HOME>\\bin, then retry"
    ),
    "runtime-not-admitted": (
        "this interpreter is not a supported installed Python environment, so it cannot open managed memory "
        "itself; the installed Hermes runtime is proven separately when memory encryption is enabled"
    ),
    "runtime-uncertain": (
        "this interpreter's environment could not be checked; the installed Hermes runtime is proven "
        "separately when memory encryption is enabled"
    ),
    "unsupported": "Windows custody exists only on native Windows",
    "excluded-on-windows": "excluded on Windows; retained state is preserved unchanged",
    "not-ported-on-windows": "not yet ported to Windows; retained state is preserved unchanged",
}

_PROOF_REMEDIES: dict[str, str] = {
    "custody-not-enrolled": "enroll memory custody first with `hermes-mordred keyvault native init`",
    "custody-pending": ("an unresolved custody journal must be reconciled first; nothing is generated in its place"),
    "interpreter-invalid": (
        "no validated installed Hermes interpreter: set MORDRED_HERMES_PYTHON to the Hermes venv's "
        "python.exe (that override is authoritative and never falls back) or reinstall Hermes with the "
        "native installer"
    ),
    "module-outside-environment": (
        "that runtime imports mordred_hermes from outside its own environment (an editable source checkout "
        "cannot prove) — install the hermes-mordred wheel into the Hermes environment"
    ),
    "helper-mismatch": "the runtime used a different CNG helper than MORDRED_WINKEY_HELPER selects; make them agree",
    "proof-stale": "custody changed while the operation ran; re-run the command",
    "proof-expired": "the installed-runtime proof expired; re-run the command",
    "proof-not-issued": "re-run the command",
    "locks-held": "re-run the command outside any other Mordred operation",
}

_RUNTIME_REMEDY = (
    "the installed Hermes runtime could not prove it opens sealed memory with this profile's CNG key — "
    "install this hermes-mordred build into that runtime (`hermes-mordred upgrade` or the native installer), "
    "check `hermes-mordred keyvault enable-winkey`, then retry"
)

_CAPABILITY_LABELS: dict[str, str] = {
    "memory_custody": "memory custody",
    "native_audit": "audit custody",
    "telegram_hardware": "Telegram custody",
    "file_vault": "file vault",
    "env_config_workspace_seals": "env/config/workspace seals",
    "recovery": "recovery",
    "presence": "per-use presence",
    "secret_store": "secret store",
}


_ROLE_REMEDIES: dict[tuple[str, str], str] = {
    ("native_audit", "not-enrolled"): "enroll it with `hermes-mordred keyvault native init --role audit`",
    ("telegram_hardware", "not-enrolled"): "enrolled by the Windows Telegram setup ceremony",
}


def host_platform() -> str:
    """The platform the wizard routes on (a seam; never patch ``sys.platform``)."""
    return sys.platform


def remedy(reason: str) -> str:
    """Operator remedy for a capability ``reason`` (empty when nothing is needed)."""
    return _REMEDIES.get(reason, "re-run the command; report the reason if it persists")


def proof_remedy(reason: str) -> str:
    """Operator remedy for a ``WindowsRuntimeProofError.reason``."""
    return _PROOF_REMEDIES.get(reason, _RUNTIME_REMEDY)


def describe_capability(capability: WindowsCapability) -> str:
    """One line: label, supported/available and the classified reason (plus remedy)."""
    label = _CAPABILITY_LABELS.get(capability.name, capability.name)
    if not capability.supported:
        where = "excluded on Windows" if capability.reason == "excluded-on-windows" else "not ported to Windows"
        return f"{label}: {where} ({capability.reason})"
    state = "available" if capability.available else "unavailable"
    hint = _ROLE_REMEDIES.get((capability.name, capability.reason)) or remedy(capability.reason)
    return f"{label}: supported, {state} ({capability.reason})" + (f" — {hint}" if hint else "")


def classify_exception(exc: BaseException) -> str:
    """Map a custody/storage failure to the capability reason vocabulary."""
    from .._private_fs import PrivateFSError
    from ..keyvault._windows_profile import CustodyError

    if isinstance(exc, PrivateFSError):
        if exc.reason == "unsupported" and exc.commit_state != "uncertain":
            return "unsupported"
        if exc.commit_state != "uncertain" and exc.reason in ("unsafe", "access_denied"):
            return "custody-unsafe"
        return "custody-uncertain"
    if isinstance(exc, CustodyError):
        return "custody-broken"
    return "custody-uncertain"


def _emit_unavailable(operation: str, exc: Exception) -> int:
    reason = getattr(exc, "reason", "excluded-on-windows")
    _term.emit_error(
        f"{operation}: {exc} ({reason}). Nothing was generated, opened or written. "
        "Windows memory encryption uses `hermes-mordred keyvault native init` and "
        "`hermes-mordred encryption enable memory`."
    )
    return 1


def excluded_refusal(capability: ExcludedCapability, operation: str) -> int | None:
    """Refuse an excluded capability on Windows before any backend/store/prompt.

    Consults the C5e guard (``refuse_excluded_on_windows``), so the platform
    decision is the keyvault's. Returns ``1`` after printing the reason on
    Windows and ``None`` everywhere else.
    """
    from ..keyvault._windows_capability import KeyvaultUnsupportedOnWindows, refuse_excluded_on_windows

    try:
        refuse_excluded_on_windows(capability, operation)
    except KeyvaultUnsupportedOnWindows as exc:
        return _emit_unavailable(operation, exc)
    return None


def unported_refusal(capability: UnportedCapability, operation: str) -> int | None:
    """Refuse the not-yet-ported secret store on Windows before any prompt or ``_storage`` call."""
    from ..keyvault._windows_capability import KeyvaultUnsupportedOnWindows, refuse_unported_on_windows

    try:
        refuse_unported_on_windows(capability, operation)
    except KeyvaultUnsupportedOnWindows as exc:
        return _emit_unavailable(operation, exc)
    return None
