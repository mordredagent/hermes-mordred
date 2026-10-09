"""Windows agent-memory lifecycle for ``encryption {enable,disable,purge} memory``.

Every transition is ordered capabilities -> gate -> (ceremony) -> proof ->
lifecycle, and each step names itself when it refuses:

- **capabilities** — ``windows_capability(home, "memory_custody")`` plus, for
  disable/purge, the load-only ``verify_memory_purge_candidates`` scan.
  Unsafe, broken or uncertain custody and a missing helper refuse here.
- **gate** — :func:`._runtime_gate.runtime_gate` on ``win32``: refuses
  ``--force-runtime-unverified`` (Windows has no bypass) and then calls
  ``require_stopped_windows_gateways``; unknown or running gateways refuse.
- **ceremony** — enable only: inert memory enrollment when the role is absent
  (:mod:`.keyvault_windows_cli`), printing the same no-presence /
  no-portable-recovery notice as ``keyvault native init`` whenever the key is
  created. Audit is never enrolled here.
- **proof** — ``prove_windows_memory_runtime`` outside every lock, against the
  installed Hermes interpreter (``MORDRED_HERMES_PYTHON``, else the Hermes
  launcher's validated interpreter, else the C4 home venv).
- **lifecycle** — ``enable_memory_encryption`` / ``disable_memory_encryption``
  (key kept), or for purge ``reset_role("memory")``. The keyvault lifecycle
  never removes plaintext before its verified seal and is the only marker
  writer; this module never touches memory files or markers itself.

Heavy imports stay function-local so this module imports on any platform.
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from . import _term
from ._windows_gates import (
    CUSTODY_FAILURES,
    HELPER_FAILURES,
    RUNTIME_REASONS,
    WINDOWS,
    classify_exception,
    proof_remedy,
    remedy,
)

if TYPE_CHECKING:
    from ..keyvault._memory_storage import PurgeReport
    from ..keyvault._windows_capability import WindowsCapability
    from ..keyvault._windows_proof import WindowsRuntimeProof

__all__ = ["MemoryObservation", "disable", "enable", "observe", "proof_python", "purge", "routed"]

_UNCHANGED = "Memory files and markers are unchanged."
_KEPT = " The inert memory custody key is kept for a retry."


@dataclass(frozen=True)
class MemoryObservation:
    """Load-only Windows memory state; ``reason`` is set when it could not be read."""

    capability: WindowsCapability | None
    report: PurgeReport | None
    reason: str | None = None
    detail: str = ""


def routed(platform: str | None) -> bool:
    """Whether a ``memory_cli`` verb takes this Windows flow (``None`` means this host)."""
    return (sys.platform if platform is None else platform) == WINDOWS


def _refused(verb: str, step: str, reason: str, detail: str, hint: str, *, state: str = _UNCHANGED) -> int:
    _term.emit_error(
        f"encryption {verb} memory: refused at the {step} step ({reason}): {detail}"
        + (f" — {hint}." if hint else ".")
        + f" {state}"
    )
    return 1


def _errors() -> tuple[type[BaseException], ...]:
    from ..keyvault._exceptions import WrapError
    from ..keyvault.memory_crypto import MemoryCryptoError

    return (OSError, RuntimeError, ValueError, WrapError, MemoryCryptoError)


def _describe(exc: BaseException) -> str:
    return f"{type(exc).__name__}: {exc}"


# -----------------------------------------------------------------------------
# Load-only observation (status, setup, uninstall, disable/purge preflight)
# -----------------------------------------------------------------------------
def observe(home: Path, *, blocking: bool = False) -> MemoryObservation:
    """Capability plus a complete load-only scan; never unwraps, generates or launches.

    With ``blocking=False`` the scan joins a non-blocking canonical session, so a
    lock held by another process is reported as ``custody-uncertain``.
    """
    from .._config_io import CanonicalPaths, canonical_session
    from ..keyvault._memory_storage import verify_memory_purge_candidates
    from ..keyvault._windows_capability import windows_capability

    try:
        capability = windows_capability(home, "memory_custody")
    except _errors() as exc:
        return MemoryObservation(None, None, classify_exception(exc), _describe(exc))
    if capability.reason in CUSTODY_FAILURES:
        return MemoryObservation(capability, None, capability.reason)
    try:
        with canonical_session(CanonicalPaths(home), scope="policy", blocking=blocking):
            report = verify_memory_purge_candidates(home)
    except _errors() as exc:
        return MemoryObservation(capability, None, classify_exception(exc), _describe(exc))
    return MemoryObservation(capability, report)


def _preflight(verb: str, observation: MemoryObservation) -> int | None:
    """Refuse an unreadable or unsafe profile; ``None`` when it may continue."""
    if observation.reason is not None:
        detail = observation.detail or "Windows memory custody"
        return _refused(verb, "capabilities", observation.reason, detail, remedy(observation.reason))
    return None


def _helper_refusal(verb: str, observation: MemoryObservation) -> int | None:
    capability = observation.capability
    if capability is not None and capability.reason in HELPER_FAILURES:
        return _refused(verb, "capabilities", capability.reason, "the Windows CNG helper", remedy(capability.reason))
    return None


def _capability_refusal(verb: str, home: Path) -> int | None:
    """The capabilities step: unsafe/broken/uncertain custody or a missing helper refuse."""
    from ..keyvault._windows_capability import windows_capability

    try:
        capability = windows_capability(home, "memory_custody")
    except _errors() as exc:
        reason = classify_exception(exc)
        return _refused(verb, "capabilities", reason, _describe(exc), remedy(reason))
    if capability.reason in CUSTODY_FAILURES | HELPER_FAILURES:
        return _refused(verb, "capabilities", capability.reason, "Windows memory custody", remedy(capability.reason))
    if capability.reason in RUNTIME_REASONS:
        _term.emit_warn(f"memory custody: {capability.reason} — {remedy(capability.reason)}.")
    return None


def _gate(home: Path, *, force_runtime_unverified: bool) -> int:
    from . import memory_cli

    return memory_cli._runtime_gate(home=home, platform=WINDOWS, force_runtime_unverified=force_runtime_unverified)


# -----------------------------------------------------------------------------
# Installed-runtime proof
# -----------------------------------------------------------------------------
def proof_python(home: Path) -> Path | None:
    """The interpreter to prove: ``None`` defers to the proof's own selection.

    ``MORDRED_HERMES_PYTHON`` stays authoritative inside the proof. Otherwise
    a Hermes launcher on ``PATH`` (or Hermes's managed one) is authoritative
    too: its validated interpreter is passed, and a launcher without one
    refuses rather than falling back to an unrelated home venv. Without a
    launcher the proof uses the C4 home-venv candidates.
    """
    from .._windows_runtime import resolve_windows_python
    from ..keyvault._windows_proof import PYTHON_OVERRIDE_ENV, WindowsRuntimeProofError
    from ._uninstall_hermes_env import find_hermes_launcher

    if PYTHON_OVERRIDE_ENV in os.environ:
        return None
    launcher = find_hermes_launcher(home)
    if launcher is None:
        return None
    selected = resolve_windows_python(home, launcher)
    if selected is None:
        raise WindowsRuntimeProofError(
            "interpreter-invalid", f"the Hermes launcher {launcher} has no validated interpreter"
        )
    return selected


def _prove(verb: str, home: Path, *, state: str) -> WindowsRuntimeProof | None:
    from ..keyvault._runtime_probe import GatewayDiscoveryUnavailable
    from ..keyvault._windows_proof import WindowsRuntimeProofError, prove_windows_memory_runtime

    try:
        return prove_windows_memory_runtime(home, python=proof_python(home))
    except WindowsRuntimeProofError as exc:
        _refused(verb, "proof", exc.reason, str(exc), proof_remedy(exc.reason), state=state)
    except GatewayDiscoveryUnavailable as exc:
        _refused(verb, "gate", "gateways", str(exc), "stop every Hermes gateway for this profile", state=state)
    except _errors() as exc:
        reason = classify_exception(exc)
        _refused(verb, "proof", reason, _describe(exc), remedy(reason), state=state)
    return None


def _lifecycle_failure(verb: str, exc: BaseException, *, state: str) -> int:
    from ..keyvault._memory_storage import MemoryLifecycleError
    from ..keyvault._runtime_probe import GatewayDiscoveryUnavailable
    from ..keyvault._windows_proof import WindowsRuntimeProofError

    if isinstance(exc, MemoryLifecycleError):
        armed = (
            "the profile is NOT armed"
            if verb == "enable"
            else "custody, the remaining seals and the armed marker are kept"
        )
        outcome = "the last outcome is uncertain; " if exc.uncertain else ""
        _term.emit_error(
            f"encryption {verb} memory: stopped during the lifecycle step after {exc.completed} file(s), "
            f"{exc.remaining} remaining: {exc.__cause__ or exc}. Every memory file is its plaintext or an "
            f"authenticated seal and {armed}; {outcome}resolve the cause, then re-run "
            f"`hermes-mordred encryption {verb} memory` (a fresh installed-runtime proof finishes the transition)."
        )
        return 1
    if isinstance(exc, WindowsRuntimeProofError):
        return _refused(verb, "proof", exc.reason, str(exc), proof_remedy(exc.reason), state=state)
    if isinstance(exc, GatewayDiscoveryUnavailable):
        return _refused(verb, "gate", "gateways", str(exc), "stop every Hermes gateway for this profile", state=state)
    reason = classify_exception(exc)
    return _refused(verb, "lifecycle", reason, _describe(exc), remedy(reason), state=state)


# -----------------------------------------------------------------------------
# enable / disable / purge
# -----------------------------------------------------------------------------
def enable(*, home: Path, force_runtime_unverified: bool = False) -> int:
    """capabilities -> gate -> inert enrollment if absent -> proof -> enable_memory_encryption."""
    from ..keyvault._memory_storage import enable_memory_encryption
    from .keyvault_windows_cli import CUSTODY_NOTICE, enroll_roles

    if _capability_refusal("enable", home) is not None:
        return 1
    if _gate(home, force_runtime_unverified=force_runtime_unverified) != 0:
        return 1

    enrolled = enroll_roles(home, ("memory",), operation="encryption enable memory (ceremony step)")
    if enrolled is None:
        return 1
    state = _UNCHANGED + (_KEPT if enrolled[0].created else "")
    if enrolled[0].created:
        print(f"Enrolled inert Windows memory custody (generation {enrolled[0].generation}).")
        print(CUSTODY_NOTICE)

    proof = _prove("enable", home, state=state)
    if proof is None:
        return 1
    try:
        report = enable_memory_encryption(home, proof)
    except _errors() as exc:
        return _lifecycle_failure("enable", exc, state=state)
    print(
        f"Agent-memory encryption enabled on Windows: {report.sealed} file(s) sealed, {report.already_sealed} already "
        f"sealed and verified, {report.reconciled} interrupted staging entr(ies) reconciled; hook armed. Proven "
        f"runtime: {proof.python} (memory seam {proof.seam}). Restart Hermes gateways so they load the armed hook."
    )
    _warn_pending_approvals(home)
    return 0


def _warn_pending_approvals(home: Path) -> None:
    from . import memory_cli

    memory_cli._warn_pending_approvals(home)


def disable(*, home: Path) -> int:
    """capabilities (+ load-only scan) -> gate -> proof -> disable_memory_encryption (key kept)."""
    from ..keyvault._memory_storage import disable_memory_encryption

    observation = observe(home, blocking=True)
    refusal = _preflight("disable", observation)
    if refusal is not None:
        return refusal
    report = observation.report
    assert report is not None
    if not report.managed:
        if report.sealed or report.broken:
            return _refused(
                "disable",
                "capabilities",
                "custody-broken",
                f"{len(report.sealed) + len(report.broken)} sealed memory file(s) exist without memory custody on "
                "this profile",
                remedy("custody-broken"),
            )
        print("Agent-memory encryption is not enabled on this profile; nothing to disable.")
        return 0
    if _helper_refusal("disable", observation) is not None:
        return 1
    if report.opted_out and not (report.armed or report.sealed or report.broken or report.pending):
        print("Agent-memory encryption is already disabled (memories are plaintext; key kept for re-enable).")
        return 0

    if _gate(home, force_runtime_unverified=False) != 0:
        return 1
    proof = _prove("disable", home, state=_UNCHANGED)
    if proof is None:
        return 1
    try:
        result = disable_memory_encryption(home, proof, keep_key=True)
    except _errors() as exc:
        return _lifecycle_failure("disable", exc, state=_UNCHANGED)
    print(
        f"Agent-memory encryption disabled on Windows: {result.decrypted} file(s) decrypted back to plaintext, "
        f"{result.already_plaintext} already plaintext, {result.reconciled} staging entr(ies) reconciled; the "
        "CNG memory key is kept for re-enable (purge removes it)."
    )
    return 0


_PURGE_HINTS: dict[str, str] = {
    "memory opt-in marker is present": "run `hermes-mordred encryption disable memory` first",
    "memory has not been explicitly disabled": "run `hermes-mordred encryption disable memory` first",
    "sealed memory remains": "run `hermes-mordred encryption disable memory` to decrypt it first",
    "broken memory seals remain": (
        "broken seals cannot be decrypted — restore those files from a backup or move them out of the "
        "memories directory by hand; Mordred never deletes memory files"
    ),
    "interrupted lifecycle staging remains": "re-run `hermes-mordred encryption disable memory` to finish it",
}


def purge(*, home: Path) -> int:
    """capabilities -> gate -> verify_memory_purge_candidates -> reset_role("memory")."""
    from ..keyvault._windows_custody import windows_custody_session

    if _capability_refusal("purge", home) is not None:
        return 1
    if _gate(home, force_runtime_unverified=False) != 0:
        return 1
    # The complete scan follows the gate, so it cannot predate a gateway's last write.
    observation = observe(home, blocking=True)
    refusal = _preflight("purge", observation)
    if refusal is not None:
        return refusal
    report = observation.report
    assert report is not None
    if not report.managed and not (report.sealed or report.broken or report.pending):
        print("Windows memory custody is not enrolled on this profile; nothing to purge.")
        return 0
    if not report.may_purge:
        hints = "; ".join(dict.fromkeys(_PURGE_HINTS.get(reason, reason) for reason in report.reasons))
        return _refused("purge", "verification", "not-purgeable", "; ".join(report.reasons), hints)
    try:
        with windows_custody_session(home) as custody:
            # Memory reset ignores erasure authorization: seals always refuse.
            reset = custody.reset_role("memory", erase_authorized=False)
    except _errors() as exc:
        notes = " ".join(getattr(exc, "__notes__", ()))
        reason = classify_exception(exc)
        return _refused(
            "purge",
            "reset",
            reason,
            _describe(exc) + (f" ({notes})" if notes else ""),
            "a deletion journal, if one was written, is preserved and blocks the next purge until it is "
            "reconciled; " + remedy(reason),
            state="Memory files are unchanged.",
        )
    print(
        f"Windows memory custody purged: {len(reset.deleted)} generation(s) deleted from the TPM. Memories stay "
        "plaintext; audit and Telegram custody are unchanged. Copies sealed under the old key can no longer be "
        "decrypted."
    )
    return 0
