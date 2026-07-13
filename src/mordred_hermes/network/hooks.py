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

import logging
import time
from collections.abc import Mapping
from pathlib import Path
from typing import Any, Final, cast

from .._audit_support import AuditWriter as _AuditWriter
from .._audit_support import safe_audit_append
from .._policy_io import load_policy_mapping, read_policy_mode_fail_closed
from .._policy_types import VALID_ACTIVE_PATHS, ActivePath, PolicyMode
from .._yaml_io import load_plugin_section, load_yaml_mapping
from . import api
from ._exceptions import (
    BringupFailed,
    MordredNetworkError,
    MordredPathBringupFailed,
    MordredPathDropped,
)
from .provider_transport_flagger import evaluate

_LOG = logging.getLogger("mordred.network.hooks")

_DEFAULT_POLICY_MODE: Final[str] = "off"
_DEFAULT_NETWORK_PATH: Final[str] = "clearnet"
# Audit reason code for a provider-vs-transport compatibility flag (FIX 1,
# 2026-07-13). ``decision`` is ``block`` for an abort-severity flag (strict
# refusal) and ``warn`` for a warning-severity one (audited, session continues).
_REASON_TRANSPORT_FLAG: Final[str] = "network.transport_incompatible"


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
    dropped-path gate). The open-first mechanics live in the shared
    :func:`.._policy_io.read_policy_mode_fail_closed` so llm_guard's
    reader cannot drift from this one.
    """
    return read_policy_mode_fail_closed(policy_json_path, default=_DEFAULT_POLICY_MODE, log=_LOG)


def resolve_default_path(section: Mapping[str, Any] | None) -> str:
    """Validated ``default_path`` from a ``plugins.mordred_network`` section.

    Missing section / missing key / invalid value all collapse to
    ``clearnet`` (safe default). THE single definition of that validation —
    the hook-time read (:func:`_read_default_network_path`), the
    registration-time bootstrap (``network.__init__._load_runtime_config``)
    and the wizard's status reader all resolve through here, so the path the
    runtime bootstraps with and the path the other readers report cannot
    drift.
    """
    value = (section or {}).get("default_path", _DEFAULT_NETWORK_PATH)
    if isinstance(value, str) and value in VALID_ACTIVE_PATHS:
        return value
    return _DEFAULT_NETWORK_PATH


def _read_default_network_path(config_path: Path) -> str:
    """Read ``plugins.mordred_network.default_path`` from ``config.yaml``.

    Wizard PR2-C is the writer.
    """
    return resolve_default_path(load_plugin_section(config_path, "mordred_network", log=_LOG))


# --------------------------------------------------------------------------- #
# Hook handlers                                                               #
# --------------------------------------------------------------------------- #


def on_session_start(
    *,
    policy_json_path: Path,
    config_path: Path,
    auth_json_path: Path | None = None,
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

    # FIX 1 (2026-07-13): provider-vs-transport compatibility gate. Once the
    # path is up (or fell back to clearnet in lenient), verify the provider
    # Hermes will use can actually reach the upstream API over the active
    # transport. A strict Tor session talking to a SOCKS5h-ignoring provider
    # (e.g. bedrock) is refused HERE — the abort the flagger always promised
    # but that nothing in production ever invoked. Fail-safe: a bug in
    # resolution or flagging must never crash a normal session, so it is
    # wrapped in ``except Exception``; the strict refusal is raised as
    # :class:`MordredPathBringupFailed` (a ``BaseException``) which escapes
    # that handler by design (same escape the bring-up refusal relies on).
    try:
        _flag_transport_compat(
            active_path=cast(ActivePath, api.status().active_path),
            providers=_resolve_active_providers(config_path=config_path, auth_json_path=auth_json_path),
            policy_mode=policy_mode,
            disable_ipv6=_read_disable_ipv6(policy_json_path, policy_mode),
            audit=audit,
        )
    except Exception as flag_err:
        _LOG.warning("on_session_start: transport-compat flagging failed: %s", flag_err)


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
    """Best-effort audit append binding this module's logger.

    Thin wrapper over :func:`mordred_hermes._audit_support.safe_audit_append`
    -- a strict-mode refusal must still raise even if the audit write fails
    (disk full, permission denied, etc.).
    """
    safe_audit_append(audit, entry, logger=_LOG)


# --------------------------------------------------------------------------- #
# Provider-vs-transport compatibility gate (FIX 1)                            #
# --------------------------------------------------------------------------- #


def _read_config_model_provider(config_path: Path) -> str | None:
    """Read ``model.provider`` from ``config.yaml`` (Hermes' persistent
    provider-of-record).

    Returns ``None`` when the key is absent, non-string, empty, or the
    ``"auto"`` sentinel (Hermes' "defer to auth.json / env" marker). Mirrors
    ``llm_guard._read_config_model_provider`` — same shared ``load_yaml_mapping``
    reader — so the two plugins resolve the same provider from the same file.
    """
    data = load_yaml_mapping(config_path, log=_LOG)
    model = data.get("model")
    if not isinstance(model, dict):
        return None
    value = model.get("provider")
    if not isinstance(value, str):
        return None
    normalized = value.strip().lower()
    if not normalized or normalized == "auto":
        return None
    return normalized


def _read_auth_active_provider(auth_json_path: Path) -> str | None:
    """Read ``active_provider`` from ``auth.json`` (Hermes' auto-resolution
    fallback when ``model.provider`` is unset / ``auto``).

    Mirrors ``llm_guard._read_auth_active_provider`` — the shared
    ``load_policy_mapping`` reader collapses a missing / unreadable / malformed
    file to ``{}`` so this degrades to ``None`` (no provider) rather than
    raising out of the session-start hook.
    """
    value = load_policy_mapping(auth_json_path, log=_LOG).get("active_provider")
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized:
            return normalized
    return None


def _resolve_active_providers(*, config_path: Path, auth_json_path: Path | None) -> list[str]:
    """Resolve the provider(s) Hermes will run, for the transport gate.

    Same resolution order as ``llm_guard._resolve_active_provider``:
    ``config.yaml model.provider`` wins, else ``auth.json active_provider``. A
    single active provider is enough for the transport gate. Returns the RAW
    (lower-cased) id — :func:`provider_transport_flagger.evaluate` applies
    ``canonicalize_provider`` itself and preserves the raw id in the
    unknown-provider Flag message. Returns ``[]`` when neither source yields a
    provider, so ``evaluate`` simply emits no provider-specific flags
    (fail-safe: a provider-less session is never refused by this gate).
    """
    configured = _read_config_model_provider(config_path)
    if configured:
        return [configured]
    if auth_json_path is not None:
        resolved = _read_auth_active_provider(auth_json_path)
        if resolved:
            return [resolved]
    return []


def _read_disable_ipv6(policy_json_path: Path, policy_mode: str) -> bool:
    """Reproduce ``RuntimeConfig.disable_ipv6`` for the transport flagger.

    The flagger's IPv6-leak branch must run with the SAME ``disable_ipv6`` the
    runtime rendered into the torrc (``ClientUseIPv6 0``): otherwise a strict
    session could abort on an IPv6 dimension the runtime already neutralised
    (strict default ``True`` masks the unverified IPv6 seeds on the OpenAI-
    compatible providers), or fail to surface it when it didn't. Reuses the
    runtime's own resolver (``network.__init__._resolve_disable_ipv6``) against
    the same ``policy.json`` so the two derivations cannot drift. The import is
    function-local because ``network.__init__`` imports this module at package
    load time (a top-level import would be circular).
    """
    from . import _resolve_disable_ipv6

    data = load_policy_mapping(policy_json_path, log=_LOG)
    return _resolve_disable_ipv6(data, policy_mode)


def _flag_transport_compat(
    *,
    active_path: ActivePath,
    providers: list[str],
    policy_mode: str,
    disable_ipv6: bool,
    audit: _AuditWriter | None,
) -> None:
    """Run the provider-vs-transport flagger and enforce its severity.

    Strict + an ``abort``-severity flag refuses the session by raising
    :class:`MordredPathBringupFailed` (``BaseException``), the same escape the
    bring-up refusal uses so Hermes' ``except Exception`` wrapper cannot
    swallow it. A ``warning`` flag (an unknown provider, a lenient-downgraded
    abort, or a clearnet informational) is audited and the session continues.
    ``off`` mode never reaches the abort branch: ``evaluate`` returns ``[]``.

    An ``abort`` severity only survives ``evaluate`` under strict policy
    (lenient downgrades abort→warning, off returns ``[]``), so the explicit
    ``policy_mode == "strict"`` guard is belt-and-braces around that invariant.
    """
    flags = evaluate(
        active_path=active_path,
        providers=providers,
        policy_mode=cast(PolicyMode, policy_mode),
        disable_ipv6=disable_ipv6,
    )
    if not flags:
        return
    abort_reasons: list[str] = []
    for flag in flags:
        if audit is not None:
            _safe_audit_append(
                audit,
                {
                    "event": "on_session_start",
                    "decision": "block" if flag.severity == "abort" else "warn",
                    "reason": _REASON_TRANSPORT_FLAG,
                    "active_path": active_path,
                    "provider": flag.provider,
                    "severity": flag.severity,
                    "detail": flag.reason,
                    "policy_mode": policy_mode,
                },
            )
        if flag.severity == "abort":
            abort_reasons.append(f"{flag.provider}: {flag.reason}")
    if abort_reasons and policy_mode == "strict":
        msg = (
            f"Mordred strict mode: provider transport is incompatible with network path "
            f"{active_path!r}: {'; '.join(abort_reasons)}; refusing the session."
        )
        _LOG.error(msg)
        # Tear the path down BEFORE refusing. Unlike the bring-up-failure refusal
        # (runtime._switch restores env + resets active_path when it raises), this
        # gate runs AFTER a SUCCESSFUL switch — the Tor daemon is spawned, the
        # SOCKS proxy is written into os.environ, and the liveness thread is
        # running. Raising without teardown would orphan all three if the host
        # doesn't call on_session_end after on_session_start raises. Best-effort:
        # a stop() failure must not mask the refusal.
        try:
            api.stop()
        except Exception as stop_err:
            _LOG.warning("transport-compat abort: api.stop() during teardown raised %s", stop_err)
        raise MordredPathBringupFailed(msg)


__all__ = ["on_session_end", "on_session_start", "pre_tool_call", "wait_until_ready"]
