"""Hermes hooks for database encryption: the monitor (phase 4) and the status line (phase 5).

- ``on_session_start`` and ``pre_llm_call`` (every turn) run
  :func:`._monitor.check`. A violation is audited
  (``mordred.db_encryption.violation``), shown in Hermes Desktop, and either
  stops the turn (strict policy) or is told to the model for this turn so it
  can warn the user (lenient).
- The ``mordred.databases`` system-prompt section states the checked status,
  so the model never claims encryption that is not in effect.
"""

from __future__ import annotations

import contextlib
import logging
import sys
from pathlib import Path
from typing import Any

from ..privacy_check._exceptions import MordredIntegrityRefused
from . import _monitor, armed

_LOG = logging.getLogger("mordred.dbcrypt")
_REASON = "mordred.db_encryption.violation"
_reported: set[tuple[str, str]] = set()
_observation: tuple[Path, object, tuple[_monitor.Finding, ...]] | None = None
_SECTION_MAX_CHARS = 600
#: Room for the findings in the prompt section, inside ``_SECTION_MAX_CHARS``.
_SECTION_DETAIL_CHARS = 420


class DatabaseEncryptionRefused(MordredIntegrityRefused):
    """Strict policy: Hermes's databases are not protected; the turn is stopped."""


def _home() -> Path:
    from . import _home as home

    return home()


def _key_available() -> bool:
    return _key() is not None


def _key() -> Any:
    from . import _PROVIDER

    if _PROVIDER is None:
        return None
    try:
        return _PROVIDER()
    except Exception:
        return None


def _findings() -> list[_monitor.Finding]:
    from . import _PROVIDER

    if _PROVIDER is not None and _PROVIDER.runtime_native:
        authority = _PROVIDER.current_authority
        if authority is None:
            return [_monitor.Finding("no_key", "native database authority has not been acquired")]
        return list(_monitor.monitor_runtime(authority))
    return _monitor.check(_home(), key_available=_key_available, key=_key)


def _policy_mode() -> str:
    with contextlib.suppress(Exception):
        from ..privacy_check import _runtime

        return str(_runtime.ensure_state().policy_mode)
    return "strict"  # fail closed if the policy cannot be read


def _audit(findings: list[_monitor.Finding], event: str, decision: str) -> None:
    with contextlib.suppress(Exception):
        from .._audit_support import safe_audit_append
        from ..privacy_check import _runtime

        safe_audit_append(
            _runtime.ensure_state().audit,
            {
                "event": event,
                "decision": decision,
                "reason": _REASON,
                "findings": [f.code for f in findings],
            },
            logger=_LOG,
        )


def _notify(findings: list[_monitor.Finding]) -> None:
    with contextlib.suppress(Exception):
        from hermes_cli.plugin_events import broadcast_plugin_event

        broadcast_plugin_event(
            "mordred", "db_encryption", {"state": "violation", "findings": [f.detail for f in findings]}
        )


def _describe(findings: list[_monitor.Finding]) -> str:
    return "; ".join(f.detail for f in findings)


def evaluate(event: str) -> str | None:
    """Run the monitor; return a warning for the model, or raise under strict policy."""
    from . import _PROVIDER

    global _observation
    _observation = None
    try:
        checked = tuple(_findings())
        token = _PROVIDER.current_authority if _PROVIDER is not None and _PROVIDER.runtime_native else _PROVIDER
        _observation = (_home(), token, checked)
        findings = [f for f in checked if f.violation]
    except Exception as exc:  # the monitor itself must never take a turn down
        _LOG.warning("database encryption check failed: %s", exc)
        return None
    if not findings:
        return None
    strict = _policy_mode() == "strict"
    key = (event, _describe(findings))
    if key not in _reported:  # once per process and kind, not every turn
        _reported.add(key)
        _audit(findings, event, "block" if strict else "warn")
        _notify(findings)
        sys.stderr.write(f"mordred: Hermes's databases are not protected — {_describe(findings)}\n")
    if strict:
        raise DatabaseEncryptionRefused(
            f"Mordred stopped this turn: Hermes's databases are not protected ({_describe(findings)}). "
            "Open “Mordred” in Hermes Desktop or run `hermes-mordred databases status`."
        )
    return (
        "[Mordred] WARNING: Hermes's conversation history is NOT protected right now — "
        f"{_describe(findings)}. Tell the user this at the start of your reply, and do not say the history is "
        "encrypted."
    )


def on_session_start(**_kwargs: Any) -> None:
    evaluate("on_session_start")


def pre_llm_call(**_kwargs: Any) -> dict[str, str] | None:
    warning = evaluate("pre_llm_call")
    return {"context": warning} if warning else None


def _pending_line(home: Path) -> str:
    from ._capability import database_status

    status = database_status(home)
    if status.capability == "unavailable":
        return (
            "## Hermes's databases (Mordred)\nPending database encryption is unavailable on this runtime: "
            f"{status.reason}. The conversation history is not protected."
        )
    return (
        "## Hermes's databases (Mordred)\nEncryption of Hermes's databases is scheduled but not active yet: "
        "the conversation history remains unencrypted. Pending conversion requires explicit supported maintenance."
    )


def status_line(_info: Any = None) -> str:
    """The ``mordred.databases`` prompt section (empty when encryption is neither on nor scheduled).

    Hermes calls a section callable with the session-info mapping.
    """
    try:
        from . import _PROVIDER

        home = _home()
        token: object | None = _PROVIDER
        if _PROVIDER is not None and _PROVIDER.runtime_native:
            authority = _PROVIDER.current_authority
            token = authority
            if authority is not None:
                authority.check()  # Public metadata only; never authenticate or run SQL.
        cached = _observation
        if cached is not None and cached[0] == home and cached[1] is token:
            findings = list(cached[2])
        else:
            findings = [_monitor.Finding("no_key", "database protection has not been authenticated in this process")]
        if token is None and not any(f.violation for f in findings):
            findings = [_monitor.Finding("no_key", "database protection has not been authenticated in this process")]
    except Exception:
        return (
            "## Hermes's databases (Mordred)\nWARNING: Hermes's conversation history is NOT protected: "
            "database authority metadata could not be verified. Never say it is encrypted."
        )
    if not armed(home):
        if any(f.code == "pending" for f in findings) or (home / "mordred/db-encryption.pending").is_file():
            return _pending_line(home)
        return ""
    violations = [f for f in findings if f.violation]
    if violations:
        detail = _describe(violations)
        if len(detail) > _SECTION_DETAIL_CHARS:  # Hermes drops a section over its max_chars entirely
            detail = detail[: _SECTION_DETAIL_CHARS - 1] + "…"
        return (
            "## Hermes's databases (Mordred)\nWARNING: Hermes's conversation history is NOT protected: "
            f"{detail}. Tell the user; never say it is encrypted."
        )
    return (
        "## Hermes's databases (Mordred)\nHermes's conversation history and its other databases are encrypted "
        "at rest with SQLCipher (checked when this session started)."
    )


def register(ctx: Any) -> None:
    ctx.register_hook("on_session_start", on_session_start)
    ctx.register_hook("pre_llm_call", pre_llm_call)
    register_section = getattr(ctx, "register_system_prompt_section", None)
    if register_section is not None:
        with contextlib.suppress(Exception):
            register_section("mordred.databases", status_line, max_chars=_SECTION_MAX_CHARS)
