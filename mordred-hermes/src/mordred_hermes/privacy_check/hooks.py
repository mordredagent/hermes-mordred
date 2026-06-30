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

from . import _runtime
from .policy import evaluate_pre_tool_call

_LOG = logging.getLogger("mordred.privacy_check")


def on_session_start(**kwargs: Any) -> None:
    """Load policy, detect sibling-disable, emit one-shot degraded markers.

    Strict + sibling-disable → audit + poison + ``SystemExit``.
    Lenient/off + sibling-disable → audit (warn) + log warning, continue.
    Always emits ``mordred.degraded.no_origin_skill`` once per process
    (HOOK_PAYLOADS §4: ``origin_skill`` absent from ``pre_tool_call`` payload).
    """
    state = _runtime.ensure_state()
    disabled = _runtime.find_disabled_siblings(config_path=state.config_path)

    if disabled:
        decision = "block" if state.policy_mode == "strict" else "warn"
        state.audit.append(
            {
                "event": "on_session_start",
                "decision": decision,
                "reason": "mordred.degraded.disable_unprotected",
                "disabled_siblings": sorted(disabled),
            }
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

    if _runtime.claim_no_origin_skill_emit():
        state.audit.append(
            {
                "event": "on_session_start",
                "decision": "warn",
                "reason": "mordred.degraded.no_origin_skill",
            }
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
        state.audit.append(
            {
                "event": "pre_tool_call",
                "decision": "block",
                "reason": "mordred.degraded.disable_unprotected",
                "tool_name": tool_name,
            }
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
        state.audit.append(
            {
                "event": "pre_tool_call",
                "decision": "block",
                "reason": outcome.reason,
                "tool_name": tool_name,
            }
        )
        return {
            "action": "block",
            "message": (
                f"Mordred strict policy blocks tool {tool_name!r} on the clearnet path. "
                "Switch the active network path or disable strict mode."
            ),
        }
    return None
