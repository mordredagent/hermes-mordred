"""Hook handlers for ``mordred_network`` (Phase 3 PR2-B).

Hermes invokes hooks via ``invoke_hook(name, **kwargs)``. Each handler
accepts arbitrary kwargs because Hermes adds payload fields without
breaking the call-site contract - the handler ignores unknown kwargs.

Return-shape contracts (HOOK_PAYLOADS.md §1, §4):

- ``on_session_start`` - return ignored. Raising
  :class:`MordredPathBringupFailed` (``BaseException``) escapes the
  ``except Exception`` wrapper inside ``hermes_cli.plugins.invoke_hook``
  so a strict-mode bring-up failure actually aborts the session.
- ``on_session_end`` - return ignored. We tear down the active path
  via :func:`api.stop`.
- ``pre_tool_call`` - return ``None`` to allow. Strict + dropped path
  raises :class:`MordredPathDropped` (``BaseException``) for the same
  escape reason.

The hooks delegate to :mod:`mordred_hermes.network.api` rather than to
:class:`mordred_hermes.network.runtime.Runtime` directly so the test
suite can swap in a tiny fake runtime via :func:`api.set_runtime`.
"""

from __future__ import annotations

import json
import logging
import time
from collections.abc import Mapping
from pathlib import Path
from typing import Any, Final, Protocol

from . import api
from ._exceptions import (
    BringupFailed,
    MordredNetworkError,
    MordredPathBringupFailed,
    MordredPathDropped,
)

_LOG = logging.getLogger("mordred.network.hooks")

_DEFAULT_POLICY_MODE: Final[str] = "off"
_DEFAULT_NETWORK_PATH: Final[str] = "clearnet"
_VALID_PATHS: Final[frozenset[str]] = frozenset({"tor", "vpn", "clearnet"})
_VALID_MODES: Final[frozenset[str]] = frozenset({"strict", "lenient", "off"})


class _AuditWriter(Protocol):
    def append(self, entry: Mapping[str, Any]) -> None: ...


# --------------------------------------------------------------------------- #
# Disk readers                                                                #
# --------------------------------------------------------------------------- #


def _read_policy_mode(policy_json_path: Path) -> str:
    """Read the enforcement policy mode, failing CLOSED on a damaged file.

    M1 (security review 2026-06-11): an absent file is a fresh install and
    keeps the historical ``"off"`` default — but a file that EXISTS and
    cannot be read or parsed reads as ``"strict"``. Falling back to
    ``"off"`` meant corrupting policy.json silently disabled strict
    enforcement on both hook paths (session bring-up and the per-tool
    dropped-path gate).

    Open-first (review follow-up): an ``exists()`` pre-check would both
    race the open (TOCTOU) and read a stat failure (e.g. search permission
    stripped from the parent dir) as "absent" → off. Only a clean
    ``FileNotFoundError`` — including a dangling symlink, equivalent to
    deletion — keeps the fresh-install default; every other failure is
    strict.
    """
    try:
        f = policy_json_path.open(encoding="utf-8")
    except FileNotFoundError:
        return _DEFAULT_POLICY_MODE
    except OSError as e:
        _LOG.error(
            "policy file %s exists but is unreadable (%s); failing closed to strict",
            policy_json_path,
            e,
        )
        return "strict"
    try:
        with f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        _LOG.error(
            "policy file %s exists but is unreadable (%s); failing closed to strict",
            policy_json_path,
            e,
        )
        return "strict"
    if not isinstance(data, dict):
        _LOG.error(
            "policy file %s has a non-dict root; failing closed to strict",
            policy_json_path,
        )
        return "strict"
    mode = data.get("policy", _DEFAULT_POLICY_MODE)
    # Codex round 3 P2 (2026-05-14): isinstance check before frozenset
    # membership — ``in`` on a frozenset raises TypeError for unhashable
    # values like ``[]`` / ``{}``.
    if isinstance(mode, str) and mode in _VALID_MODES:
        return mode
    _LOG.error(
        "invalid policy %r in %s; failing closed to strict", mode, policy_json_path
    )
    return "strict"


def _read_default_network_path(config_path: Path) -> str:
    """Read ``plugins.mordred_network.default_path`` from ``config.yaml``.

    Missing file / missing key / invalid value all collapse to
    ``clearnet`` (safe default). Wizard PR2-C is the writer.
    """
    if not config_path.exists():
        return _DEFAULT_NETWORK_PATH
    from ruamel.yaml import YAML
    from ruamel.yaml.error import YAMLError

    yaml = YAML(typ="safe", pure=True)
    try:
        with config_path.open(encoding="utf-8") as f:
            data = yaml.load(f)
    except (OSError, YAMLError) as e:
        _LOG.warning("could not read %s: %s", config_path, e)
        return _DEFAULT_NETWORK_PATH
    if not isinstance(data, dict):
        return _DEFAULT_NETWORK_PATH
    plugins = data.get("plugins")
    if not isinstance(plugins, dict):
        return _DEFAULT_NETWORK_PATH
    network = plugins.get("mordred_network")
    if not isinstance(network, dict):
        return _DEFAULT_NETWORK_PATH
    value = network.get("default_path", _DEFAULT_NETWORK_PATH)
    if isinstance(value, str) and value in _VALID_PATHS:
        return value
    return _DEFAULT_NETWORK_PATH


# --------------------------------------------------------------------------- #
# Hook handlers                                                               #
# --------------------------------------------------------------------------- #


def on_session_start(
    *,
    policy_json_path: Path,
    config_path: Path,
    audit: _AuditWriter | None = None,
    **kwargs: Any,
) -> None:
    """Bring up the configured default path.

    Also establishes the session's per-session Tor circuit-isolation token
    from the Hermes ``session_id`` (v2-N1) before bring-up, clearing it when
    no id is supplied so a reused runtime cannot leak a prior session's
    circuit identity.

    - ``off`` + clearnet default: skip - the user may manually switch
      paths later via ``hermes-mordred network use``.
    - Otherwise: call :func:`api.use` for the configured default.
      Strict-mode bring-up failure raises :class:`MordredPathBringupFailed`
      (BaseException) after emitting ``network.bringup_failed`` audit.
      Lenient-mode failure is absorbed by the runtime (fallback to
      clearnet + ``network.bringup_failed`` audit there); the hook
      itself returns normally.
    """
    policy_mode = _read_policy_mode(policy_json_path)
    target = _read_default_network_path(config_path)

    # Codex round 9 P1-B (2026-05-14): refresh the runtime's policy
    # before bring-up. ``register()`` reads policy.json once at plugin
    # discovery; long-lived processes can outlive a configure flow that
    # bumps the policy. Without this push, the runtime's stale
    # ``policy_mode`` would silently downgrade a strict bring-up
    # failure to a lenient fallback.
    api.update_policy_mode(policy_mode)

    # v2-N1: establish the session's circuit-isolation identity before any
    # bring-up. The Hermes ``session_id`` is a non-secret identifier, so it
    # is safe to place in ``os.environ`` (HTTPS_PROXY) where Tor reads it as
    # the SOCKS credential (``IsolateSOCKSAuth``). Set even for the
    # clearnet/off early-return so a later manual ``network use tor`` rides
    # the same per-session circuit. Per-skill keying remains v2-H2-blocked.
    #
    # Always push (clearing to None when absent) so a reused Runtime never
    # leaks a prior session's token into a session that supplied no id —
    # inheriting it would correlate the two onto one circuit.
    session_id = kwargs.get("session_id")
    api.set_isolation_token(str(session_id) if session_id else None)

    if policy_mode == "off" and target == _DEFAULT_NETWORK_PATH:
        return

    try:
        api.use(target)  # type: ignore[arg-type]
    except BringupFailed as e:
        if policy_mode == "strict":
            if audit is not None:
                _safe_audit_append(
                    audit,
                    {
                        "event": "on_session_start",
                        "decision": "block",
                        "reason": "network.bringup_failed",
                        "attempted_path": target,
                        "policy_mode": policy_mode,
                        "error": str(e),
                    },
                )
            msg = f"Mordred strict mode: network path {target!r} failed to bring up ({e}); refusing the session."
            _LOG.error(msg)
            raise MordredPathBringupFailed(msg) from e
        # lenient / off: runtime fell back already; hook stays silent.
    except MordredNetworkError as e:
        if policy_mode == "strict":
            msg = f"Mordred strict mode: api.use({target!r}) raised {e}; refusing the session."
            _LOG.error(msg)
            raise MordredPathBringupFailed(msg) from e
        _LOG.warning(
            "on_session_start: api.use(%r) raised %s; continuing in %s mode",
            target,
            e,
            policy_mode,
        )


def on_session_end(**_kwargs: Any) -> None:
    """Tear down the active path. Always safe to call."""
    try:
        api.stop()
    except Exception as e:
        # Tear-down errors must never propagate; the session is ending
        # regardless. Log so operators can see if Tor / Mullvad cleanup
        # is misbehaving.
        _LOG.warning("on_session_end: api.stop raised %s", e)


def pre_tool_call(
    *,
    tool_name: str = "",
    policy_json_path: Path | None = None,
    audit: _AuditWriter | None = None,
    **_kwargs: Any,
) -> dict[str, Any] | None:
    """Refuse the tool call when strict + the active path was dropped.

    Lenient/off return ``None`` regardless of drop state - the M9
    liveness worker has already emitted ``network.path_dropped`` with
    ``decision=warn``, so the user has visibility without losing the
    session.
    """
    if policy_json_path is None or not api.is_dropped():
        return None
    policy_mode = _read_policy_mode(policy_json_path)
    if policy_mode != "strict":
        return None
    if audit is not None:
        _safe_audit_append(
            audit,
            {
                "event": "pre_tool_call",
                "decision": "block",
                "reason": "network.path_dropped",
                "tool_name": tool_name,
            },
        )
    msg = (
        f"Mordred strict mode: active network path was dropped; refusing tool {tool_name!r}. "
        "Re-bring-up via `hermes-mordred network use <path>` or restart the session."
    )
    _LOG.error(msg)
    raise MordredPathDropped(msg)


# --------------------------------------------------------------------------- #
# Bootstrap polling fallback                                                  #
# --------------------------------------------------------------------------- #


def wait_until_ready(*, timeout: float = 5.0, poll_interval: float = 0.05) -> bool:
    """Poll ``api.status().ready`` until True or timeout (TODO §3.1 L295).

    Hermes loads bundled / user / project plugins before entry-point
    plugins (HOOK_PAYLOADS.md §1). Sibling plugins whose
    ``on_session_start`` fires earlier may issue outbound calls before
    our path is ready. Those plugins should call this helper to wait
    deterministically.

    Returns ``True`` when the runtime reports ``ready`` within the
    deadline, ``False`` otherwise. Never raises - the caller decides
    what to do with a non-ready state.
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            if api.status().ready:
                return True
        except MordredNetworkError:
            # No runtime registered yet, or runtime in an error state.
            pass
        time.sleep(poll_interval)
    try:
        return api.status().ready
    except MordredNetworkError:
        return False


# --------------------------------------------------------------------------- #
# Internals                                                                   #
# --------------------------------------------------------------------------- #


def _safe_audit_append(audit: _AuditWriter, entry: Mapping[str, Any]) -> None:
    """Best-effort audit append.

    Mirrors :func:`mordred_hermes.llm_guard.enforce._safe_audit_append` -
    a strict-mode refusal must raise even if audit write fails (disk
    full, permission denied, etc.). The underlying error is logged so
    operators can investigate.
    """
    try:
        audit.append(entry)
    except Exception as e:
        _LOG.error("network audit append failed for entry %r: %s", entry, e)


__all__ = ["on_session_end", "on_session_start", "pre_tool_call", "wait_until_ready"]
