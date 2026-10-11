"""Windows half of the Hermes Desktop setup API (C11).

:mod:`.api` routes here on ``win32`` only; macOS and Linux never reach this
module. Every answer comes from public keyvault, wizard and Telegram APIs:

- **status** — one row per ``windows_capabilities`` entry (name, supported,
  available, reason) and no aggregate readiness answer; the helper presence
  read from those same non-blocking predicates; the load-only memory scan
  (``wizard._windows_memory.observe`` + ``memory_target_status``); Telegram
  ``flags()``. Nothing is unwrapped, generated, hashed, launched or waited for
  beyond the predicates' own bounded in-process wait. The explicit
  ``/hardware/build`` check additionally verifies the C4 installer receipt.
- **memory enable/disable** — the C6 order capabilities -> gate -> ceremony ->
  proof -> lifecycle, run in a worker thread, reporting the refusing step and
  reason. The gate is the C5c typed gateway inventory (unknown or running
  refuses; there is no force flag). The proof routes to the interpreter serving
  this Desktop API unless ``MORDRED_HERMES_PYTHON`` is set (Desktop launcher
  routing, deferred from C6).
- **Telegram** — the C10b store selected by ``default_secret_store()``. Login
  and the question model refuse until the ``telegram`` custody role is enrolled
  and the client acknowledged that Windows has no per-use presence; only then is
  the role verified with ``ensure_key(require_presence=False)``. Their memory
  guard reports a busy custody lock as ``custody_busy`` (retry), never as
  ``memory_encryption_required``. Forget runs ``wipe_archive(forget=True)``.

The wizard exposes no structured (step, reason) result for its Windows memory
verbs, so this module composes the same steps from their public parts
(recorded as a gap for the C6-telegram slice). Heavy imports stay local.
"""

from __future__ import annotations

import io
import os
import sys
import threading
from collections.abc import Callable, Mapping
from dataclasses import replace
from pathlib import Path
from typing import Any

from ._capture import captured_output

WINDOWS = "win32"
HARDWARE_KIND = "cng"
HELPER_COMMAND = "hermes-mordred keyvault enable-winkey"
ACK_NO_RECOVERY = "acknowledge_cng_no_recovery"
ACK_NO_PRESENCE = "acknowledge_no_presence"
MEMORY_ACKNOWLEDGEMENTS = (ACK_NO_RECOVERY, ACK_NO_PRESENCE)
TELEGRAM_ACKNOWLEDGEMENTS = (ACK_NO_PRESENCE,)
#: The C6 Telegram ceremony enrolls the role explicitly, outside the Desktop API.
TELEGRAM_CEREMONY_COMMAND = "hermes-mordred keyvault native init --role telegram"
PRESENCE_REASON = "excluded-on-windows"

_DETAIL_LIMIT = 2000
_MEMORY_LOCK = threading.Lock()
_GATE_REMEDY = (
    "stop every Hermes gateway for this profile (including one started by Hermes Desktop), then retry; an unknown "
    "process inventory is never treated as empty and there is no force option"
)
_CEREMONY_REMEDY = "the classified reason is in the detail; existing custody state is preserved and nothing was sealed"
_LIFECYCLE_REMEDY = (
    "every memory file is its plaintext or an authenticated seal; resolve the cause, then retry (a fresh "
    "installed-runtime proof finishes the transition)"
)
_BUSY_REMEDY = (
    "another Hermes or Mordred process is using memory custody right now (for example a gateway writing memory); "
    "retry in a moment"
)
_APPROVAL_WARNING = "memory-write-approval-plaintext"
_TELEGRAM_CODES = {
    "not-enrolled": "telegram_not_enrolled",
    "custody-unsafe": "custody_unsafe",
    "custody-uncertain": "custody_uncertain",
    "custody-broken": "custody_broken",
    "helper-missing": "tee_unavailable",
    "helper-uncertain": "tee_unavailable",
}


# -----------------------------------------------------------------------------
# Acknowledgements
# -----------------------------------------------------------------------------
def acknowledged(body: object, names: tuple[str, ...]) -> bool:
    """Every named acknowledgement is literally ``true`` in the request body."""
    return isinstance(body, Mapping) and all(body.get(name) is True for name in names)


# -----------------------------------------------------------------------------
# Status pieces (load-only)
# -----------------------------------------------------------------------------
def _classify(exc: BaseException) -> str:
    from ..wizard._windows_gates import classify_exception

    return classify_exception(exc)


def capability_rows(home: Path) -> tuple[list[dict[str, Any]], str | None]:
    """``windows_capabilities`` as plain rows, or ``([], classified reason)``; never raises."""
    from ..keyvault import _windows_capability

    try:
        rows = _windows_capability.windows_capabilities(home)
    except Exception as exc:  # status answers with the classified reason instead of a traceback
        return [], _classify(exc)
    return [
        {"name": row.name, "supported": row.supported, "available": row.available, "reason": row.reason} for row in rows
    ], None


_HELPER_ROLES = ("memory_custody", "native_audit", "telegram_hardware")


def _same_path(left: Path, right: Path) -> bool:
    return os.path.normcase(os.path.normpath(left)) == os.path.normcase(os.path.normpath(right))


def helper_report(home: Path) -> dict[str, Any]:
    """The C4 helper state: ``validated`` / ``installed`` / ``missing`` / ``uncertain``; never a probe or build.

    The selection is the one the custody predicates use (``find_winkey_helper``).
    ``validated`` means the default ``<home>\\bin`` executable carries a verified
    installer ownership receipt; ``installed`` means a helper is selected
    (override, PATH or an unowned file) without that receipt.
    """
    from ..keyvault import _seckey_helper
    from ..wizard import _windows_install

    report: dict[str, Any] = {"state": "uncertain", "path": None, "install_command": HELPER_COMMAND}
    try:
        found = _seckey_helper.find_winkey_helper()
        if found is None:
            report["state"] = "missing"
            return report
        path = Path(found)
        owned = _same_path(path.parent, home / "bin") and _windows_install.is_owned(path)
    except Exception:  # an explicit check answers "uncertain", never a 500
        return report
    report.update(state="validated" if owned else "installed", path=str(path))
    return report


def helper_from_predicates(rows: list[dict[str, Any]], error: str | None) -> dict[str, Any]:
    """Status helper state from the non-blocking capability rows only (no lock, no hash, no probe).

    The predicates evaluate custody failures before the helper, so a role row
    whose reason is a custody failure says nothing about the helper; the first
    supported role row with another reason decides. ``present`` means the C4
    selection found an executable; ownership is checked by ``/hardware/build``.
    """
    from ..wizard._windows_gates import CUSTODY_FAILURES

    report: dict[str, Any] = {"state": "uncertain", "reason": error, "install_command": HELPER_COMMAND}
    if error is not None:
        return report
    roles = [row for row in rows if row["supported"] and row["name"] in _HELPER_ROLES]
    decisive = [row for row in roles if row["reason"] not in CUSTODY_FAILURES]
    if not decisive:
        report.update(state="unchecked", reason=roles[0]["reason"] if roles else None)
        return report
    reason = str(decisive[0]["reason"])
    state = {"helper-missing": "missing", "helper-uncertain": "uncertain"}.get(reason, "present")
    report.update(state=state, reason=reason)
    return report


def memory_summary(home: Path) -> dict[str, Any]:
    """Load-only memory state from the C6 observation; ``active`` means armed, clean and readable."""
    from ..wizard import _windows_memory, _windows_status

    try:
        observation = _windows_memory.observe(home, blocking=False)
    except Exception as exc:  # status never raises
        failure = _classify(exc)
        return {"state": "unavailable", "active": False, "drift": False, "configured": False, "reason": failure}
    status = _windows_status.memory_target_status(observation)
    report, capability = observation.report, observation.capability
    reason: str | None = observation.reason
    if reason is not None or report is None:
        state, reason = "unavailable", reason or "custody-uncertain"
    elif not report.managed:
        state, reason = ("unavailable", "custody-broken") if (report.sealed or report.broken) else ("off", None)
    elif report.armed:
        state = "on" if status.active else ("exposed" if status.drift else "degraded")
    elif report.opted_out:
        # C6 wording: "disabled, but seals or staging remain — re-run: encryption disable memory".
        state = "disabled-incomplete" if (report.sealed or report.broken or report.pending) else "paused"
    else:
        state = "enrolled"
    if reason is None and capability is not None and capability.reason not in ("enrolled", "not-enrolled"):
        reason = capability.reason
    return {
        "state": state,
        "active": bool(status.active and not status.drift),
        "drift": bool(status.drift),
        "configured": bool(status.configured),
        "reason": reason,
        "detail": status.detail,
    }


def memory_active(home: Path) -> bool:
    return bool(memory_summary(home).get("active"))


def memory_refusal(home: Path) -> dict[str, Any] | None:
    """``None`` when Telegram may proceed; else the refusal for its memory guard.

    The load-only scan runs inside one non-blocking canonical session taken
    here first, so a lock held by another process (a gateway's memory hook
    takes the home lock first) is reported as ``custody_busy`` with a retry
    remedy instead of looking like unencrypted memory. Other custody failures
    keep their classified code; anything else is ``memory_encryption_required``.
    """
    from .._config_io import CanonicalPaths, canonical_session
    from .._private_fs import PrivateFSError

    try:
        with canonical_session(CanonicalPaths(home), scope="policy", blocking=False):
            active = memory_active(home)
    except PrivateFSError as exc:
        if exc.reason == "busy":
            return {"ok": False, "error": "custody_busy", "remedy": _BUSY_REMEDY}
        code = _TELEGRAM_CODES.get(_classify(exc), "memory_encryption_required")
        return {"ok": False, "error": code}
    return None if active else {"ok": False, "error": "memory_encryption_required"}


def memory_guard(home_fn: Callable[[], Path]) -> Callable[[], None]:
    """``TelegramService`` memory guard from the load-only Windows memory state (busy stays distinct)."""

    def guard() -> None:
        from ..extension.telegram.memory_guard import MemoryEncryptionRequired

        refusal = memory_refusal(home_fn())
        if refusal is not None:
            raise MemoryEncryptionRequired(str(refusal["error"]))

    return guard


def gateway_inventory(home: Path) -> dict[str, Any]:
    """The C5c typed inventory; ``unknown`` is reported as unknown (``running: None``), never as none."""
    from ..keyvault import _windows_processes

    try:
        inventory = _windows_processes.inspect_windows_gateway_runtimes(home)
    except Exception as exc:  # a failed inventory is unknown, never empty
        return {
            "state": "unknown",
            "running": None,
            "found": None,
            "pids": [],
            "reasons": [f"scan:{type(exc).__name__}"],
        }
    known = inventory.state == "known"
    return {
        "state": inventory.state,
        "running": len(inventory.runtimes) if known else None,
        # An unknown inventory is not a count: report nothing a client could read as zero.
        "found": len(inventory.runtimes) if known else None,
        "pids": [runtime.pid for runtime in inventory.runtimes if runtime.pid is not None],
        "reasons": list(inventory.reasons),
    }


def telegram_custody(home: Path, row: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """The ``telegram_hardware`` capability; enrollment belongs to the explicit wizard ceremony.

    ``row`` reuses an already-read capability row (status) instead of a second predicate read.
    """
    from ..keyvault import _windows_capability

    if row is not None:
        enrolled, reason = bool(row["available"] and row["reason"] == "enrolled"), str(row["reason"])
    else:
        try:
            capability = _windows_capability.windows_capability(home, "telegram_hardware")
            enrolled, reason = bool(capability.available and capability.reason == "enrolled"), capability.reason
        except Exception as exc:  # classified, never raised to the page
            enrolled, reason = False, _classify(exc)
    return {
        "enrolled": enrolled,
        "reason": reason,
        "ceremony_available": TELEGRAM_CEREMONY_COMMAND is not None,
        "ceremony_command": TELEGRAM_CEREMONY_COMMAND,
    }


def custody_store_selected(store: object) -> bool:
    """Whether ``default_secret_store()`` selected the C10b custody store."""
    from ..extension.telegram.windows_secrets import WindowsCustodySecretStore

    return isinstance(store, WindowsCustodySecretStore)


def _check(ok: bool, detail: str) -> dict[str, Any]:
    return {"ok": ok, "detail": detail}


def _telegram_checks(store: Any) -> tuple[dict[str, dict[str, Any]], dict[str, Any] | None]:
    """Load-only flags without waiting; ``store_busy`` stays distinct from unconfigured state."""
    try:
        flags = store.flags()
    except Exception as exc:  # classified code only
        code = getattr(exc, "code", None) or "telegram_store_unavailable"
        return {"login": _check(False, str(code)), "privacy_llm": _check(False, str(code))}, None
    if not isinstance(flags, dict):
        return {"login": _check(False, "not configured"), "privacy_llm": _check(False, "not configured")}, None
    logged_in = flags.get("logged_in") is True
    backend = flags.get("llm_backend")
    return {
        "login": _check(logged_in, "logged in" if logged_in else "logged out"),
        "privacy_llm": _check(backend in ("venice", "local"), str(backend) if backend else "not configured"),
    }, flags


def status_payload(home: Path, store: object) -> dict[str, Any]:
    """Everything ``/status?client_version>=3`` reports on Windows except the model check and jobs."""
    from ..wizard.keyvault_windows_cli import CUSTODY_NOTICE

    rows, error = capability_rows(home)
    by_name = {row["name"]: row for row in rows}
    presence = by_name.get("presence")
    telegram_row = by_name.get("telegram_hardware")
    platform_supported = bool(custody_store_selected(store) and telegram_row and telegram_row["supported"])
    helper = helper_from_predicates(rows, error)
    memory = memory_summary(home)
    if telegram_row is not None:
        telegram = telegram_custody(home, telegram_row)
    else:  # capabilities unreadable: report their classified reason without a second read
        telegram = {
            "enrolled": False,
            "reason": error or "custody-uncertain",
            "ceremony_available": TELEGRAM_CEREMONY_COMMAND is not None,
            "ceremony_command": TELEGRAM_CEREMONY_COMMAND,
        }
    helper_ok = helper["state"] == "present"
    checks: dict[str, dict[str, Any]] = {
        "hardware": _check(helper_ok, f"CNG helper {helper['state']}"),
        "memory_encryption": _check(bool(memory["active"]), str(memory["state"])),
        "telegram_custody": _check(bool(telegram["enrolled"]), str(telegram["reason"])),
    }
    flags: dict[str, Any] | None = None
    if platform_supported:
        telegram_checks, flags = _telegram_checks(store)
        checks.update(telegram_checks)
    return {
        "platform": WINDOWS,
        "telegram_supported": platform_supported,
        "telegram_platform_supported": platform_supported,
        "hardware_kind": HARDWARE_KIND,
        "user_presence_supported": False,
        "presence_reason": presence["reason"] if presence else PRESENCE_REASON,
        "capabilities": rows,
        "capabilities_error": error,
        "helper": helper,
        "memory": memory,
        "telegram_custody": telegram,
        "acknowledgements": {
            "memory_enable": list(MEMORY_ACKNOWLEDGEMENTS),
            "telegram": list(TELEGRAM_ACKNOWLEDGEMENTS),
        },
        "custody_notice": CUSTODY_NOTICE,
        "restart_required_after_memory_change": True,
        "uninstall": {"erase_supported": False, "purge_scope": "memory_custody_key"},
        "checks": checks,
        "telegram_api": bool((flags or {}).get("api_configured")),
    }


# -----------------------------------------------------------------------------
# Memory enable / disable: capabilities -> gate -> ceremony -> proof -> lifecycle
# -----------------------------------------------------------------------------
class _Refusal(Exception):
    """One refused step; ``fields`` adds structured context (never key material)."""

    def __init__(self, step: str, reason: str, remedy: str, detail: str = "", **fields: Any) -> None:
        super().__init__(f"{step}: {reason}")
        self.step, self.reason, self.remedy, self.detail, self.fields = step, reason, remedy, detail, fields

    def payload(self, error: str) -> dict[str, Any]:
        result: dict[str, Any] = {
            "ok": False,
            "error": error,
            "step": self.step,
            "reason": self.reason,
            "remedy": self.remedy,
        }
        if self.detail:
            result["detail"] = self.detail.strip()[-_DETAIL_LIMIT:]
        result.update(self.fields)
        return result


def _errors() -> tuple[type[BaseException], ...]:
    from ..keyvault._exceptions import WrapError
    from ..keyvault.memory_crypto import MemoryCryptoError

    return (OSError, RuntimeError, ValueError, WrapError, MemoryCryptoError)


def _describe(exc: BaseException) -> str:
    return f"{type(exc).__name__}: {exc}"


def desktop_proof_python(executable: str | None = None) -> Path | None:
    """The interpreter the Desktop flow proves (Desktop launcher routing).

    ``MORDRED_HERMES_PYTHON`` stays authoritative inside the proof (``None``).
    Otherwise the interpreter serving this Desktop API — the Desktop-managed
    Hermes runtime — is passed as ``python=``; the proof validates it and never
    falls back to a PATH launcher or the home venv.
    """
    from ..keyvault._windows_proof import PYTHON_OVERRIDE_ENV, WindowsRuntimeProofError

    if PYTHON_OVERRIDE_ENV in os.environ:
        return None
    selected = sys.executable if executable is None else executable
    if not selected:
        raise WindowsRuntimeProofError("interpreter-invalid", "the Desktop process reports no interpreter path")
    return Path(selected)


def _capabilities_step(home: Path) -> list[str]:
    from ..keyvault import _windows_capability
    from ..wizard._windows_gates import CUSTODY_FAILURES, HELPER_FAILURES, RUNTIME_REASONS, remedy

    try:
        capability = _windows_capability.windows_capability(home, "memory_custody")
    except _errors() as exc:
        reason = _classify(exc)
        raise _Refusal("capabilities", reason, remedy(reason), _describe(exc)) from exc
    if capability.reason in CUSTODY_FAILURES | HELPER_FAILURES:
        raise _Refusal("capabilities", capability.reason, remedy(capability.reason))
    return [capability.reason] if capability.reason in RUNTIME_REASONS else []


def _gate_step(home: Path, **fields: Any) -> None:
    """Equivalent to ``require_stopped_windows_gateways``, reporting the typed inventory."""
    inventory = gateway_inventory(home)
    if inventory["state"] != "known":
        raise _Refusal("gate", "gateways-unknown", _GATE_REMEDY, gateways=inventory, **fields)
    if inventory["running"]:
        raise _Refusal("gate", "gateways-running", _GATE_REMEDY, gateways=inventory, **fields)


def _ceremony_step(home: Path, captured: io.StringIO) -> dict[str, Any]:
    from ..wizard.keyvault_windows_cli import CUSTODY_NOTICE, enroll_roles

    mark = captured.tell()
    outcomes = enroll_roles(home, ("memory",), operation="Desktop memory enable (ceremony step)")
    if outcomes is None:
        raise _Refusal("ceremony", "ceremony-refused", _CEREMONY_REMEDY, captured.getvalue()[mark:])
    outcome = outcomes[0]
    fields: dict[str, Any] = {"enrolled": {"generation": outcome.generation, "created": outcome.created}}
    if outcome.created:
        fields["custody_notice"] = CUSTODY_NOTICE
    return fields


def _proof_step(home: Path, executable: str | None, fields: dict[str, Any]) -> Any:
    from ..keyvault._runtime_probe import GatewayDiscoveryUnavailable
    from ..keyvault._windows_proof import WindowsRuntimeProofError, prove_windows_memory_runtime
    from ..wizard._windows_gates import proof_remedy, remedy

    try:
        return prove_windows_memory_runtime(home, python=desktop_proof_python(executable))
    except WindowsRuntimeProofError as exc:
        raise _Refusal("proof", exc.reason, proof_remedy(exc.reason), str(exc), **fields) from exc
    except GatewayDiscoveryUnavailable as exc:
        raise _Refusal("gate", "gateways", _GATE_REMEDY, str(exc), **fields) from exc
    except _errors() as exc:
        reason = _classify(exc)
        raise _Refusal("proof", reason, remedy(reason), _describe(exc), **fields) from exc


def _lifecycle_refusal(exc: BaseException, verb: str, fields: dict[str, Any]) -> _Refusal:
    from ..keyvault._memory_storage import MemoryLifecycleError
    from ..keyvault._runtime_probe import GatewayDiscoveryUnavailable
    from ..keyvault._windows_proof import WindowsRuntimeProofError
    from ..wizard._windows_gates import proof_remedy, remedy

    if isinstance(exc, MemoryLifecycleError):
        return _Refusal(
            "lifecycle",
            "lifecycle-partial",
            _LIFECYCLE_REMEDY,
            str(exc),
            completed=exc.completed,
            remaining=exc.remaining,
            uncertain=exc.uncertain,
            armed=verb != "enable",
            **fields,
        )
    if isinstance(exc, WindowsRuntimeProofError):
        return _Refusal("proof", exc.reason, proof_remedy(exc.reason), str(exc), **fields)
    if isinstance(exc, GatewayDiscoveryUnavailable):
        return _Refusal("gate", "gateways", _GATE_REMEDY, str(exc), **fields)
    reason = _classify(exc)
    return _Refusal("lifecycle", reason, remedy(reason), _describe(exc), **fields)


def _enable(home: Path, executable: str | None, captured: io.StringIO) -> dict[str, Any]:
    from ..keyvault._memory_storage import enable_memory_encryption

    if memory_active(home):
        return {"ok": True, "already": True}
    warnings = _capabilities_step(home)
    _gate_step(home)
    fields = _ceremony_step(home, captured)
    proof = _proof_step(home, executable, fields)
    try:
        report = enable_memory_encryption(home, proof)
    except _errors() as exc:
        raise _lifecycle_refusal(exc, "enable", fields) from exc
    # The lifecycle report is authoritative; the load-only state is shown, never re-decided here.
    result: dict[str, Any] = {
        "ok": True,
        "restart_required": True,
        "sealed": report.sealed,
        "already_sealed": report.already_sealed,
        "reconciled": report.reconciled,
        "runtime": {"python": str(proof.python), "seam": proof.seam},
        "warnings": warnings,
        "memory": memory_summary(home),
        **fields,
    }
    if _write_approval_on(home):
        # Same disclosure as the wizard's enable: the approval queue is not sealed.
        warnings.append(_APPROVAL_WARNING)
        result["pending_approvals"] = str(home / "pending" / "memory")
    return result


def _write_approval_on(home: Path) -> bool:
    """``memory.write_approval`` parks pending writes as plaintext JSON outside the hooked memory files."""
    from .._yaml_io import load_yaml_mapping

    memory = load_yaml_mapping(home / "config.yaml").get("memory")
    return isinstance(memory, dict) and memory.get("write_approval") is True


def _disable(home: Path, executable: str | None) -> dict[str, Any]:
    from ..keyvault._memory_storage import disable_memory_encryption
    from ..wizard import _windows_memory
    from ..wizard._windows_gates import HELPER_FAILURES, remedy

    observation = _windows_memory.observe(home, blocking=True)
    if observation.reason is not None or observation.report is None:
        reason = observation.reason or "custody-uncertain"
        raise _Refusal("capabilities", reason, remedy(reason), observation.detail)
    report = observation.report
    if not report.managed:
        if report.sealed or report.broken:
            raise _Refusal("capabilities", "custody-broken", remedy("custody-broken"))
        return {"ok": True, "already": True}
    capability = observation.capability
    if capability is not None and capability.reason in HELPER_FAILURES:
        raise _Refusal("capabilities", capability.reason, remedy(capability.reason))
    if report.opted_out and not (report.armed or report.sealed or report.broken or report.pending):
        return {"ok": True, "already": True}
    _gate_step(home)
    proof = _proof_step(home, executable, {})
    try:
        result = disable_memory_encryption(home, proof, keep_key=True)
    except _errors() as exc:
        raise _lifecycle_refusal(exc, "disable", {}) from exc
    return {
        "ok": True,
        "restart_required": True,
        "decrypted": result.decrypted,
        "already_plaintext": result.already_plaintext,
        "reconciled": result.reconciled,
        "key_kept": True,
    }


def _serialized(error: str, run: Callable[[io.StringIO], dict[str, Any]]) -> dict[str, Any]:
    """One memory transition at a time; wizard output is captured, never printed by the server."""
    if not _MEMORY_LOCK.acquire(blocking=False):
        return {"ok": False, "error": "memory_operation_in_progress"}
    try:
        with captured_output() as captured:
            try:
                return run(captured)
            except _Refusal as refusal:
                return refusal.payload(error)
    finally:
        _MEMORY_LOCK.release()


def enable_memory(home: Path, *, executable: str | None = None) -> dict[str, Any]:
    """Run the Windows memory enable sequence (blocking; call from a worker thread)."""
    return _serialized("memory_encryption_refused", lambda captured: _enable(home, executable, captured))


def disable_memory(home: Path, *, executable: str | None = None) -> dict[str, Any]:
    """Run the Windows memory disable sequence, keeping the CNG key (blocking)."""
    return _serialized("memory_disable_refused", lambda captured: _disable(home, executable))


# -----------------------------------------------------------------------------
# Telegram
# -----------------------------------------------------------------------------
class NoPresenceStore:
    """The C10b store whose role check runs without per-use presence.

    Built only for requests that carried ``acknowledge_no_presence: true``:
    ``ensure_key()`` takes no argument here, so a caller cannot ask for
    presence and silently get an unattended check.
    """

    def __init__(self, store: Any) -> None:
        self._store = store

    def ensure_key(self) -> None:
        self._store.ensure_key(require_presence=False)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._store, name)


def telegram_refusal(home: Path, body: object) -> dict[str, Any] | None:
    """Refuse until the ``telegram`` role is enrolled and no-presence was acknowledged; ``None`` to proceed."""
    custody = telegram_custody(home)
    if not custody["enrolled"]:
        reason = str(custody["reason"])
        code = _TELEGRAM_CODES.get(reason, "telegram_custody_unavailable")
        payload: dict[str, Any] = {"ok": False, "error": code}
        if code == "telegram_not_enrolled":
            payload.update(
                ceremony_available=custody["ceremony_available"], ceremony_command=custody["ceremony_command"]
            )
        return payload
    if not acknowledged(body, TELEGRAM_ACKNOWLEDGEMENTS):
        return {"ok": False, "error": "presence_acknowledgement_required"}
    return None


def _client_factory() -> Any:
    from ..extension.telegram.client import build_client

    return build_client


async def _revoke(current: Any) -> bool:
    """Best-effort revocation at Telegram, as ``telegram logout`` does; never raises."""
    from ..extension.telegram.readonly import RequestPolicy

    try:
        client = _client_factory()(current.api_id, current.api_hash, current.session, policy=RequestPolicy(logout=True))
        await client.connect()
        try:
            if await client.is_user_authorized():
                await client.log_out()
        finally:
            await client.disconnect()
    except Exception:
        return False
    return True


def _drop_session(old: Any) -> Any:
    return replace(old, session=None) if old is not None else None


async def telegram_logout(store: Any, *, forget: bool) -> dict[str, Any]:
    """Windows logout (session dropped, archive kept) or forget (``wipe_archive(forget=True)``)."""
    import asyncio

    from ..extension.telegram.secrets import TelegramSecretsError

    try:
        snapshot = await asyncio.to_thread(store.load_snapshot)
    except TelegramSecretsError as exc:
        result: dict[str, Any] = {"ok": False, "error": exc.code}
        if forget and exc.code in ("secrets_corrupt", "telegram_not_enrolled"):
            result["remedy"] = (
                "Desktop cannot forget unreadable credentials. Run `hermes-mordred telegram logout --forget` "
                "in a terminal for checked recovery; also end the session in Telegram → Settings → Devices."
            )
        return result
    current = snapshot[0]
    if forget:
        return await _forget_telegram(store, current)
    revoked: bool | None = None
    if current is not None and current.session is not None:
        revoked = await _revoke(current)
    try:
        if current is not None:
            await asyncio.to_thread(store.update_from_snapshot, snapshot, _drop_session)
    except TelegramSecretsError as exc:
        result = {"ok": False, "error": exc.code, "revoked": revoked}
    else:
        result = {"ok": True, "forgot": False, "revoked": revoked}
    _manual_revoke_remedy(result, needed=revoked is False)
    return result


def _manual_revoke_remedy(result: dict[str, Any], *, needed: bool) -> None:
    if needed:
        result.update(manual_revoke=True, remedy="Also end the session in Telegram → Settings → Devices.")


def _credential_presence(root: Path) -> bool | None:
    """Corroborate advisory flag absence against the checked seal; a failed read stays unknown."""
    from ..extension.telegram import _windows_archive as checked

    try:
        with checked.transaction(root) as tx:
            return tx is not None and checked.present(tx, "credentials.sealed")
    except (OSError, RuntimeError, ValueError):
        return None


async def _forget_telegram(store: Any, current: Any) -> dict[str, Any]:
    """Checked wipe -> re-checked credentials -> revoke; preserve partial failures without retrying."""
    import asyncio

    from ..extension.telegram import store as archive
    from ..extension.telegram.secrets import TelegramSecretsError
    from ..wizard import _windows_telegram

    root = archive.telegram_dir()
    before = await asyncio.to_thread(_windows_telegram.observe, store, root)
    if current is not None and before.credentials is not True:
        before = replace(before, credentials=True)  # the loaded snapshot proves credentials existed
    failure = None
    try:
        # The real C10b plan preflights before deleting archive, credentials and the telegram role.
        await asyncio.to_thread(lambda: archive.wipe_archive(root, forget=True))
    except (TelegramSecretsError, archive.StoreError) as exc:
        failure = exc.code
    after = await asyncio.to_thread(_windows_telegram.observe, store, root)
    if after.credentials is False:
        # flags() can return None for non-object metadata even with a retained seal.
        after = replace(after, credentials=await asyncio.to_thread(_credential_presence, root))
    revoked: bool | None = None
    has_session = current is not None and current.session is not None
    if has_session and after.credentials is False:
        revoked = await _revoke(current)
    result: dict[str, Any] = {
        "ok": failure is None,
        "revoked": revoked,
        "outcome": _windows_telegram.outcome_lines(before, after, forget=True),
    }
    if failure is None:
        result["forgot"] = True
    else:
        result["error"] = failure
    _manual_revoke_remedy(result, needed=has_session and (after.credentials is None or revoked is False))
    return result
