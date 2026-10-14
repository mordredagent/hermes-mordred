"""Windows lines for ``status``, ``encryption status`` and ``setup`` summaries.

Every Windows keyvault/memory line comes from ``windows_capabilities`` and the
load-only custody/memory scan (:func:`._windows_memory.observe`): no unwrap,
no native key operation, no subprocess, and no lock is waited for. Each
capability is shown with its own supported/available/reason; there is no
aggregate "Windows ready" line. A retained secret store, file vault or seal
artifact, a copied profile or a held lock prints its classified reason instead
of a traceback. Heavy imports stay function-local.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Literal

from ._encryption_status import TargetStatus
from ._windows_gates import HELPER_FAILURES, RUNTIME_REASONS, classify_exception, describe_capability, remedy

if TYPE_CHECKING:
    from ..keyvault._windows_capability import WindowsCapability
    from ._windows_memory import MemoryObservation

__all__ = [
    "capability_lines",
    "capability_rows",
    "collect_target_statuses",
    "keyvault_state",
    "memory_target_status",
    "setup_memory_state",
]

_EXCLUDED = "excluded on Windows (excluded-on-windows)"
_ARTIFACT_NOTES: dict[str, tuple[str, str]] = {
    "file_vault": ("env", "retained file vault preserved unchanged"),
    "env_seal_optout": ("env", "retained .env seal opt-out marker preserved unchanged"),
    "config_seal_marker": ("config", "retained config seal marker preserved unchanged"),
}


def capability_rows(home: Path) -> tuple[tuple[WindowsCapability, ...], str | None]:
    """``(capabilities, None)``, or ``((), classified reason)`` when they cannot be read."""
    from ..keyvault._windows_capability import windows_capabilities

    try:
        return windows_capabilities(home), None
    except Exception as exc:  # status never raises; the reason is printed instead
        return (), f"{classify_exception(exc)} — {type(exc).__name__}: {exc}"


def capability_lines(rows: tuple[WindowsCapability, ...], error: str | None) -> list[str]:
    """Indented per-capability lines; never an aggregate readiness verdict."""
    if error is not None:
        return [f"    capabilities unavailable: {error}"]
    return [f"    {describe_capability(row)}" for row in rows]


def keyvault_state(home: Path) -> tuple[bool, int, str]:
    """The secret-store line: not ported to Windows; a retained store is reported, not read."""
    from ..keyvault import _storage
    from ..keyvault._windows_capability import KeyvaultUnsupportedOnWindows

    base = "secret store not ported to Windows (not-ported-on-windows); Windows custody is listed below"
    try:
        with _storage.keyvault_read_lock(_storage.resolve_keyvault_dir(home)) as present:
            retained = present
    except KeyvaultUnsupportedOnWindows:
        retained = True
    except (OSError, RuntimeError, ValueError) as exc:
        return False, 0, f"{base}; retained state not checked ({type(exc).__name__}: {exc})"
    return False, 0, base + ("; a retained secret store is preserved unchanged" if retained else "")


def _excluded_notes(home: Path) -> tuple[dict[str, list[str]], str | None]:
    from ..keyvault._windows_capability import excluded_artifacts

    notes: dict[str, list[str]] = {"env": [], "config": []}
    try:
        artifacts = excluded_artifacts(home)
    except Exception as exc:  # status never raises
        return notes, f"retained artifacts not checked ({classify_exception(exc)})"
    for artifact in artifacts:
        target, note = _ARTIFACT_NOTES[artifact.kind]
        notes[target].append(note)
    return notes, None


def _excluded_status(target: str, notes: list[str], unchecked: str | None) -> TargetStatus:
    extra = notes + ([unchecked] if unchecked else [])
    return TargetStatus(target, bool(notes), False, "; ".join([_EXCLUDED, *extra]))


def _armed_detail(observation: MemoryObservation) -> tuple[bool, bool, str]:
    """``(active, drift, detail)`` for an armed profile."""
    report, capability = observation.report, observation.capability
    assert report is not None and capability is not None
    problems = []
    if report.plaintext:
        problems.append(f"{len(report.plaintext)} plaintext memory file(s) on disk — reseal: encryption enable memory")
    if report.broken:
        problems.append(f"broken seal(s): {', '.join(report.broken)}")
    if report.pending:
        problems.append("an interrupted transition left staging entries — re-run: encryption enable memory")
    if capability.reason in HELPER_FAILURES:
        problems.append(f"{capability.reason} — {remedy(capability.reason)}")
    if problems:
        return False, bool(report.plaintext), "enabled, but " + "; ".join(problems)
    note = f"; this interpreter: {capability.reason}" if capability.reason in RUNTIME_REASONS else ""
    return (
        True,
        False,
        f"sealed memory ({len(report.sealed)} file(s)); CNG key enrolled; hook armed "
        f"(installed-runtime proof is checked by enable, not by status){note}",
    )


def memory_target_status(observation: MemoryObservation) -> TargetStatus:
    """The ``memory`` target from a load-only observation; never unwraps."""
    report = observation.report
    if observation.reason == "unsupported":
        return TargetStatus("memory", False, False, "Windows memory custody exists only on native Windows")
    if observation.reason is not None or report is None:
        reason = observation.reason or "custody-uncertain"
        return TargetStatus("memory", False, False, f"UNAVAILABLE ({reason}) — {observation.detail or remedy(reason)}")
    if not report.managed:
        if report.sealed or report.broken:
            count = len(report.sealed) + len(report.broken)
            return TargetStatus(
                "memory",
                False,
                False,
                f"{count} sealed memory file(s) without memory custody on this profile (custody-broken) — "
                + remedy("custody-broken"),
            )
        return TargetStatus("memory", False, False, "not enabled — run: encryption enable memory")
    if report.armed:
        active, drift, detail = _armed_detail(observation)
        return TargetStatus("memory", True, active, detail, drift=drift)
    if report.opted_out:
        if report.sealed or report.broken or report.pending:
            return TargetStatus(
                "memory", True, False, "disabled, but seals or staging remain — re-run: encryption disable memory"
            )
        return TargetStatus(
            "memory",
            True,
            False,
            "disabled — memories are plaintext; CNG key kept; re-enable: encryption enable memory",
        )
    return TargetStatus(
        "memory", False, False, "memory custody enrolled (inert); not enabled — run: encryption enable memory"
    )


def collect_target_statuses(home: Path) -> list[TargetStatus]:
    """The four targets on Windows: excluded seals plus the proof-bound memory target."""
    from ._windows_memory import observe

    notes, unchecked = _excluded_notes(home)
    return [
        _excluded_status("env", notes["env"], unchecked),
        _excluded_status("config", notes["config"], unchecked),
        memory_target_status(observe(home, blocking=False)),
        TargetStatus("workspace", False, False, f"{_EXCLUDED}; the encrypted workspace is macOS-only"),
    ]


SetupAction = Literal["blocked", "done", "manual"]


def setup_memory_state(observation: MemoryObservation) -> tuple[SetupAction | None, str]:
    """``(action, detail)`` for setup's memory step; ``action`` is ``None`` when enable should run."""
    capability, report = observation.capability, observation.report
    if observation.reason is not None or report is None or capability is None:
        status = memory_target_status(observation)
        return "blocked", status.detail
    if report.opted_out and not (report.armed or report.sealed or report.broken or report.pending):
        return (
            "done",
            "paused by operator (`encryption disable memory`); "
            "re-enable with `hermes-mordred encryption enable memory`",
        )
    if capability.reason in HELPER_FAILURES:
        return "manual", f"{capability.reason} — {remedy(capability.reason)}"
    status = memory_target_status(observation)
    if status.active:
        return "done", status.detail
    return None, status.detail
