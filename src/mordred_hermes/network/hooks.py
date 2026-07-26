"""Hook handlers for ``mordred_network`` (Phase 3 PR2-B).

Hermes invokes hooks via ``invoke_hook(name, **kwargs)``. Each handler
accepts arbitrary kwargs because Hermes adds payload fields without
breaking the call-site contract - the handler ignores unknown kwargs.

Return-shape contracts (HOOK_PAYLOADS.md §1, §4):

- ``on_session_start`` - return ignored. Raising
  :class:`MordredPathBringupFailed` (``BaseException``) escapes the
  ``except Exception`` wrapper inside ``hermes_cli.plugins.invoke_hook``
  so a strict-mode bring-up failure actually aborts the session.
- ``on_session_end`` - return ignored. Hermes fires this after every turn, so
  the active path is deliberately retained for the next turn.
- ``pre_api_request`` - return ignored. Strict + Tor revalidates the
  request-resolved provider and raises :class:`MordredPathBringupFailed`
  before egress when its transport is not verified compatible.
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
from typing import Any, Final, Literal, cast

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
from .provider_transport_flagger import ProviderEntry, TransportClass, evaluate

_LOG = logging.getLogger("mordred.network.hooks")

_DEFAULT_POLICY_MODE: Final[str] = "off"
_DEFAULT_NETWORK_PATH: Final[str] = "clearnet"
# Audit reason code for a provider-vs-transport compatibility flag (FIX 1,
# 2026-07-13). ``decision`` is ``block`` for an abort-severity flag (strict
# refusal) and ``warn`` for a warning-severity one (audited, session continues).
_REASON_TRANSPORT_FLAG: Final[str] = "network.transport_incompatible"
_UNRESOLVED_PROVIDER: Final[str] = "<unresolved>"
_OVERRIDE_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "transport",
        "respects_proxy",
        "respects_socks5h",
        "localhost_only",
        "dns_quirk",
        "unverified_baseline",
        "transport_class",
        "respects_ipv6_proxy",
    }
)
_TRANSPORT_CLASSES: Final[frozenset[str]] = frozenset({"http", "tcp", "udp", "quic", "grpc", "websocket"})


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


def _read_default_network_path_strict(config_path: Path) -> str:
    """Read ``default_path`` without hiding damage to an existing config.

    A missing file, absent ``plugins`` key, absent ``mordred_network`` section,
    or absent ``default_path`` is a legitimate unconfigured state and resolves
    to clearnet. Existing malformed YAML, non-mapping container shapes, and an
    invalid explicit ``default_path`` raise so strict request-time enforcement
    can fail closed rather than misclassifying damaged Tor configuration as
    intentional clearnet.
    """
    from ruamel.yaml import YAML

    try:
        f = config_path.open(encoding="utf-8")
    except FileNotFoundError:
        return _DEFAULT_NETWORK_PATH
    with f:
        data = YAML(typ="safe", pure=True).load(f)
    if data is None:
        return _DEFAULT_NETWORK_PATH
    if not isinstance(data, dict):
        raise ValueError("config.yaml must contain a top-level mapping")
    if "plugins" not in data:
        return _DEFAULT_NETWORK_PATH
    plugins = data["plugins"]
    if not isinstance(plugins, dict):
        raise ValueError("config.yaml plugins must be a mapping")
    if "mordred_network" not in plugins:
        return _DEFAULT_NETWORK_PATH
    section = plugins["mordred_network"]
    if not isinstance(section, dict):
        raise ValueError("config.yaml plugins.mordred_network must be a mapping")
    if "default_path" not in section:
        return _DEFAULT_NETWORK_PATH
    value = section["default_path"]
    if not isinstance(value, str) or value not in VALID_ACTIVE_PATHS:
        raise ValueError(
            f"config.yaml plugins.mordred_network.default_path must be one of {sorted(VALID_ACTIVE_PATHS)!r}"
        )
    return value


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
    - After bring-up, resolve the active provider and run the transport gate.
      Strict + Tor fails closed for unsafe/unresolved providers, malformed
      overrides, or an internal gate error. Lenient downgrades provider flags;
      off skips them. Malformed overrides and internal errors warn and continue
      in lenient/off.
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
    # transport. A strict Tor session talking to an incompatible, unknown, or
    # unverified provider is refused HERE. Internal errors are also
    # policy-sensitive: strict + Tor tears down and refuses because continuing
    # would silently drop the anonymity gate; lenient/off warn and continue.
    gate_stage = "status"
    gate_active_path = cast(ActivePath, target)
    gate_providers = [_UNRESOLVED_PROVIDER]
    try:
        raw_active_path = api.status().active_path
        if raw_active_path not in VALID_ACTIVE_PATHS:
            raise ValueError(f"runtime reported invalid active path {raw_active_path!r}")
        gate_active_path = cast(ActivePath, raw_active_path)
        gate_stage = "provider_resolution"
        gate_providers = _resolve_active_providers(config_path=config_path, auth_json_path=auth_json_path)
        gate_stage = "provider_overrides"
        overrides = _read_provider_overrides(policy_json_path)
        gate_stage = "policy_config"
        disable_ipv6 = _read_disable_ipv6(policy_json_path, policy_mode)
        gate_stage = "evaluate"
        _flag_transport_compat(
            active_path=gate_active_path,
            providers=gate_providers,
            policy_mode=policy_mode,
            disable_ipv6=disable_ipv6,
            overrides=overrides,
            audit=audit,
        )
    except Exception as flag_err:
        _handle_transport_gate_error(
            error=flag_err,
            stage=gate_stage,
            target_path=cast(ActivePath, target),
            active_path=gate_active_path,
            providers=gate_providers,
            policy_mode=policy_mode,
            audit=audit,
        )


def on_session_end(**_kwargs: Any) -> None:
    """Keep the active path alive across Hermes conversation turns.

    Hermes 0.13--0.19 fires ``on_session_end`` after every
    ``run_conversation`` call, not only when the logical session is over.
    Stopping here resets the runtime to clearnet, while continuation turns do
    not fire ``on_session_start`` again. Consequently a strict Tor session
    would send its second turn over clearnet.

    The Runtime is process-global and can serve multiple gateway sessions, so
    session-finalize/reset hooks cannot own teardown either. ``register()``
    installs a single process-exit callback for final cleanup.
    """


def pre_api_request(
    *,
    policy_json_path: Path,
    config_path: Path,
    audit: _AuditWriter | None = None,
    provider: Any = None,
    **_kwargs: Any,
) -> None:
    """Authoritatively gate the resolved runtime provider on strict Tor.

    ``on_session_start`` can only inspect the provider persisted in
    ``config.yaml`` / ``auth.json``. Hermes can override that provider later
    through CLI flags, environment variables, one-shot calls, or gateway model
    switches. ``pre_api_request`` carries the provider that is actually about
    to receive the request, so strict Tor re-runs the transport evidence gate
    here immediately before egress.

    The configured path is checked again here because continuation turns do
    not fire ``on_session_start``. Under strict policy, a configured Tor path
    that is no longer active fails closed before provider evaluation.

    Missing provider evidence, malformed overrides, invalid runtime state, and
    internal evaluation errors all fail closed. A refusal keeps the current
    runtime state intact and raises :class:`MordredPathBringupFailed`, whose
    ``BaseException`` inheritance escapes Hermes's ``except Exception`` hook
    wrappers.
    """
    policy_mode = _read_policy_mode(policy_json_path)
    if policy_mode != "strict":
        return

    runtime_provider = (
        provider.strip().lower() if isinstance(provider, str) and provider.strip() else _UNRESOLVED_PROVIDER
    )
    # Default to Tor until config resolution succeeds. If the reader itself
    # fails under strict policy, the error path must assume the protected route
    # was Tor rather than silently allowing possible clearnet egress.
    configured_path: ActivePath = "tor"
    active_path: ActivePath = "tor"
    stage = "configured_path"
    try:
        configured_path = cast(ActivePath, _read_default_network_path_strict(config_path))
        stage = "status"
        raw_active_path = api.status().active_path
        if raw_active_path not in VALID_ACTIVE_PATHS:
            raise ValueError(f"runtime reported invalid active path {raw_active_path!r}")
        active_path = cast(ActivePath, raw_active_path)
        if configured_path == "tor" and active_path != "tor":
            stage = "required_path"
            raise RuntimeError(f"configured Tor path is not active (runtime active_path={active_path!r})")
        if active_path != "tor":
            return

        stage = "provider_overrides"
        overrides = _read_provider_overrides(policy_json_path)
        stage = "policy_config"
        disable_ipv6 = _read_disable_ipv6(policy_json_path, policy_mode)
        stage = "evaluate"
        _flag_transport_compat(
            active_path=active_path,
            providers=[runtime_provider],
            policy_mode=policy_mode,
            disable_ipv6=disable_ipv6,
            overrides=overrides,
            audit=audit,
            event="pre_api_request",
            refusal_context="outbound API request",
            teardown_on_refusal=False,
        )
    except Exception as gate_error:
        # Under strict policy an unreadable runtime status cannot establish
        # that the request is outside Tor. Treat it as a Tor-gate failure
        # rather than guessing clearnet and allowing egress.
        _handle_transport_gate_error(
            error=gate_error,
            stage=stage,
            target_path=configured_path,
            active_path=active_path,
            providers=[runtime_provider],
            policy_mode=policy_mode,
            audit=audit,
            event="pre_api_request",
            refusal_context="outbound API request",
            teardown_on_refusal=False,
        )


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
    file to ``{}`` so this reader degrades to ``None``. The caller then sends
    the explicit unresolved-provider sentinel through the normal transport
    severity matrix (strict + Tor refuses; lenient warns).
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
    unknown-provider Flag message. When neither source yields a provider, the
    explicit ``<unresolved>`` sentinel is returned. That sentinel follows the
    normal unknown-provider severity matrix: strict + Tor aborts, lenient +
    Tor warns, and clearnet remains informational.
    """
    configured = _read_config_model_provider(config_path)
    if configured:
        return [configured]
    if auth_json_path is not None:
        resolved = _read_auth_active_provider(auth_json_path)
        if resolved:
            return [resolved]
    return [_UNRESOLVED_PROVIDER]


def _read_provider_overrides(policy_json_path: Path) -> dict[str, ProviderEntry]:
    """Parse additive transport facts from ``policy.json``.

    Missing fields take conservative defaults so an incomplete entry cannot
    accidentally satisfy strict Tor: SOCKS5h/IPv6 support default false and
    ``unverified_baseline`` defaults true. Invalid types and unknown fields
    raise ``ValueError``; the caller turns that into a strict-Tor refusal or a
    lenient/off warning. Baseline replacement remains prohibited by
    :func:`provider_transport_flagger.evaluate`.
    """
    data = load_policy_mapping(policy_json_path, log=_LOG)
    if "provider_overrides" not in data:
        return {}
    raw_overrides = data["provider_overrides"]
    if not isinstance(raw_overrides, dict):
        raise ValueError("policy.json provider_overrides must be an object")

    overrides: dict[str, ProviderEntry] = {}
    for raw_name, raw_entry in raw_overrides.items():
        if not isinstance(raw_name, str) or not raw_name.strip():
            raise ValueError("provider_overrides keys must be non-empty strings")
        name = raw_name.strip().lower()
        if name in overrides:
            raise ValueError(f"provider_overrides contains duplicate normalized provider {name!r}")
        overrides[name] = _parse_provider_override(name, raw_entry)
    return overrides


def _parse_provider_override(name: str, raw_entry: Any) -> ProviderEntry:
    if not isinstance(raw_entry, dict):
        raise ValueError(f"provider override {name!r} must be an object")
    unknown_fields = [field for field in raw_entry if field not in _OVERRIDE_FIELDS]
    if unknown_fields:
        raise ValueError(f"provider override {name!r} has unsupported field {unknown_fields[0]!r}")

    raw_transport = raw_entry.get("transport", "unknown")
    if not isinstance(raw_transport, str) or not raw_transport.strip():
        raise ValueError(f"provider override {name!r} transport must be a non-empty string")

    raw_respects_proxy = raw_entry.get("respects_proxy", False)
    if not isinstance(raw_respects_proxy, bool) and raw_respects_proxy != "partial":
        raise ValueError(f"provider override {name!r} respects_proxy must be boolean or 'partial'")
    respects_proxy = cast(bool | Literal["partial"], raw_respects_proxy)

    raw_transport_class = raw_entry.get("transport_class", "http")
    if not isinstance(raw_transport_class, str) or raw_transport_class not in _TRANSPORT_CLASSES:
        raise ValueError(f"provider override {name!r} transport_class must be one of {sorted(_TRANSPORT_CLASSES)!r}")

    return ProviderEntry(
        name=name,
        transport=raw_transport.strip(),
        respects_proxy=respects_proxy,
        respects_socks5h=_read_override_bool(raw_entry, name=name, field="respects_socks5h", default=False),
        localhost_only=_read_override_bool(raw_entry, name=name, field="localhost_only", default=False),
        dns_quirk=_read_override_bool(raw_entry, name=name, field="dns_quirk", default=False),
        unverified_baseline=_read_override_bool(
            raw_entry,
            name=name,
            field="unverified_baseline",
            default=True,
        ),
        transport_class=cast(TransportClass, raw_transport_class),
        respects_ipv6_proxy=_read_override_bool(
            raw_entry,
            name=name,
            field="respects_ipv6_proxy",
            default=False,
        ),
    )


def _read_override_bool(entry: Mapping[str, Any], *, name: str, field: str, default: bool) -> bool:
    value = entry.get(field, default)
    if not isinstance(value, bool):
        raise ValueError(f"provider override {name!r} {field} must be boolean")
    return value


def _read_disable_ipv6(policy_json_path: Path, policy_mode: str) -> bool:
    """Reproduce ``RuntimeConfig.disable_ipv6`` for the transport flagger.

    The flagger receives the SAME ``disable_ipv6`` the runtime rendered into
    torrc (``ClientUseIPv6 0``), but that Tor option is advisory from the
    provider SDK's perspective: it neither disables host IPv6 nor filters AAAA
    answers. The flagger includes it in diagnostics but never treats it as
    host-level enforcement. Reuses the runtime's own resolver
    (``network.__init__._resolve_disable_ipv6``) against the same
    ``policy.json`` so diagnostics cannot drift. The import is function-local
    because ``network.__init__`` imports this module at package load time (a
    top-level import would be circular).
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
    overrides: Mapping[str, ProviderEntry] | None = None,
    audit: _AuditWriter | None,
    event: str = "on_session_start",
    refusal_context: str = "session",
    teardown_on_refusal: bool = True,
) -> None:
    """Run the provider-vs-transport flagger and enforce its severity.

    Strict + an ``abort``-severity flag refuses the guarded operation by raising
    :class:`MordredPathBringupFailed` (``BaseException``), the same escape the
    bring-up refusal uses so Hermes' ``except Exception`` wrapper cannot
    swallow it. A ``warning`` flag (a lenient-downgraded abort or a clearnet
    informational) is audited and the guarded operation continues. Unknown and
    unverified providers abort on strict Tor because they have no transport
    evidence for the anonymity contract. ``off`` mode never reaches the abort
    branch: ``evaluate`` returns ``[]``.

    An ``abort`` severity only survives ``evaluate`` under strict policy
    (lenient downgrades abort→warning, off returns ``[]``), so the explicit
    ``policy_mode == "strict"`` guard is belt-and-braces around that invariant.
    """
    flags = evaluate(
        active_path=active_path,
        providers=providers,
        policy_mode=cast(PolicyMode, policy_mode),
        overrides=overrides,
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
                    "event": event,
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
            f"{active_path!r}: {'; '.join(abort_reasons)}; refusing the {refusal_context}."
        )
        _LOG.error(msg)
        # Session-start failures tear down a path that otherwise has no owner.
        # Request-time refusals deliberately KEEP Tor active: Runtime.stop()
        # resets active_path to clearnet, which would let a long-lived gateway's
        # next request skip the strict-Tor transport gate. Keeping the path means
        # every subsequent request is re-evaluated until the operator explicitly
        # chooses a different path or provider.
        if teardown_on_refusal:
            _stop_after_transport_gate_failure("transport-compat abort")
        raise MordredPathBringupFailed(msg)


def _handle_transport_gate_error(
    *,
    error: Exception,
    stage: str,
    target_path: ActivePath,
    active_path: ActivePath,
    providers: list[str],
    policy_mode: str,
    audit: _AuditWriter | None,
    event: str = "on_session_start",
    refusal_context: str = "session",
    teardown_on_refusal: bool = True,
) -> None:
    """Apply fail-closed semantics to an internal transport-gate error."""
    strict_tor = policy_mode == "strict" and (target_path == "tor" or active_path == "tor")
    detail = f"transport gate {stage} failed ({type(error).__name__}: {error})"
    if audit is not None:
        _safe_audit_append(
            audit,
            {
                "event": event,
                "decision": "block" if strict_tor else "warn",
                "reason": _REASON_TRANSPORT_FLAG,
                "active_path": active_path,
                "provider": providers[0] if len(providers) == 1 else ",".join(providers),
                "severity": "abort" if strict_tor else "warning",
                "detail": detail,
                "policy_mode": policy_mode,
                "stage": stage,
            },
        )
    if not strict_tor:
        _LOG.warning("%s: %s; continuing in %s mode", event, detail, policy_mode)
        return

    if teardown_on_refusal:
        _stop_after_transport_gate_failure(f"transport gate {stage} failure")
    msg = f"Mordred strict mode: {detail}; refusing the {refusal_context}."
    _LOG.error(msg)
    raise MordredPathBringupFailed(msg) from error


def _stop_after_transport_gate_failure(context: str) -> None:
    """Best-effort teardown that never masks a strict policy refusal."""
    try:
        api.stop()
    except Exception as stop_err:
        _LOG.warning("%s: api.stop() during teardown raised %s", context, stop_err)


__all__ = [
    "on_session_end",
    "on_session_start",
    "pre_api_request",
    "pre_tool_call",
    "wait_until_ready",
]
