"""Hook handlers for ``mordred_privacy_check``.

Hermes invokes hooks via ``invoke_hook(name, **kwargs)``. Each handler
must accept arbitrary kwargs because Hermes adds new payload fields
without breaking the existing call-site contract — the handler should
ignore unknown kwargs.

Return shape contracts (HOOK_PAYLOADS.md §1, §4):

- ``on_session_start`` — return value ignored. ``SystemExit`` propagates
  past Hermes's ``except Exception`` wrapper (because ``SystemExit``
  inherits ``BaseException``), letting strict mode actually abort the
  session. Defense in depth: also poisons the process so any
  subsequent ``pre_tool_call`` blocks unconditionally.
- ``pre_tool_call`` — return ``None`` to allow, or
  ``{"action": "block", "message": str}`` to block.
"""

from __future__ import annotations

import logging
from typing import Any

from .._audit_support import safe_audit_append
from . import _runtime
from .policy import evaluate_pre_tool_call

_LOG = logging.getLogger("mordred.privacy_check")


def check_plugin_integrity(**_kwargs: Any) -> None:
    """Detect an explicitly disabled Mordred plugin from any live sibling.

    Strict + sibling-disable → audit + poison + ``SystemExit``.
    Lenient/off + sibling-disable → audit (warn) + log warning, continue.

    Every runtime plugin registers this same callback. That is deliberate:
    relying on ``mordred_privacy_check`` alone would make disabling that plugin
    disable the detector too. As long as at least one runtime sibling remains
    active, strict mode therefore fails closed.
    """
    state = _runtime.ensure_state()
    disabled = _runtime.find_disabled_siblings(config_path=state.config_path)

    if disabled:
        decision = "block" if state.policy_mode == "strict" else "warn"
        # safe_audit_append, not a bare append: Hermes wraps every hook callback
        # in ``except Exception`` and logs-and-continues. A plain Exception from
        # the audit write (disk full, permission flip, an over-long entry) would
        # therefore be swallowed BEFORE the SystemExit below ever fires, and the
        # session would proceed unprotected — a fail-open bypass of the very gate
        # this hook exists to enforce. The refusal must outrank the audit write,
        # so audit-side errors are logged and swallowed here instead.
        safe_audit_append(
            state.audit,
            {
                "event": "on_session_start",
                "decision": decision,
                "reason": "mordred.degraded.disable_unprotected",
                "disabled_siblings": sorted(disabled),
            },
            logger=_LOG,
        )
        if state.policy_mode == "strict":
            msg = (
                f"Mordred strict mode: sibling plugins disabled: {sorted(disabled)}. "
                "Re-enable them or switch to lenient/off mode."
            )
            _runtime.poison(msg)
            _LOG.error(msg)
            raise SystemExit(msg)
        _LOG.warning("Mordred siblings disabled in %s mode: %s", state.policy_mode, sorted(disabled))


def on_session_start(**kwargs: Any) -> None:
    """Run the shared integrity gate and emit one-shot degraded markers.

    Always emits ``mordred.degraded.no_origin_skill`` once per process
    (HOOK_PAYLOADS §4: ``origin_skill`` absent from ``pre_tool_call`` payload).
    """
    check_plugin_integrity(**kwargs)
    state = _runtime.ensure_state()
    if _runtime.claim_no_origin_skill_emit():
        safe_audit_append(
            state.audit,
            {
                "event": "on_session_start",
                "decision": "warn",
                "reason": "mordred.degraded.no_origin_skill",
            },
            logger=_LOG,
        )


def pre_tool_call(**kwargs: Any) -> dict[str, Any] | None:
    """Evaluate the generic strict-mode tool-name allowlist.

    Per-skill enforcement is not possible at runtime — ``origin_skill``
    is absent from the payload (HOOK_PAYLOADS §4). Strict-mode
    per-skill checks live in :mod:`install_wrapper`.
    """
    state = _runtime.ensure_state()
    tool_name = str(kwargs.get("tool_name") or "")

    if _runtime.is_poisoned():
        # Same fail-open reasoning as on_session_start: the block decision must
        # survive an audit-write failure, so the append can never raise past us.
        safe_audit_append(
            state.audit,
            {
                "event": "pre_tool_call",
                "decision": "block",
                "reason": "mordred.degraded.disable_unprotected",
                "tool_name": tool_name,
            },
            logger=_LOG,
        )
        return {
            "action": "block",
            "message": _runtime.get_poison_reason() or "Mordred strict mode: process poisoned",
        }

    outcome = evaluate_pre_tool_call(
        policy_mode=state.policy_mode,
        tool_name=tool_name,
        active_path=None,
    )
    if outcome.decision == "block":
        safe_audit_append(
            state.audit,
            {
                "event": "pre_tool_call",
                "decision": "block",
                "reason": outcome.reason,
                "tool_name": tool_name,
            },
            logger=_LOG,
        )
        return {
            "action": "block",
            "message": (
                f"Mordred strict policy blocks tool {tool_name!r} on the clearnet path. "
                "Switch the active network path or disable strict mode."
            ),
        }
    return None
