"""mordred_network - Tor / VPN / Clearnet path management.

Phase 3 PR2 wiring:

1. Construct the singleton :class:`Runtime` (PR2-A) reading config from
   ``~/.hermes/config.yaml plugins.mordred_network.*`` and
   ``~/.hermes/mordred/policy.json``.
2. Register it process-wide via :func:`api.set_runtime`.
3. Register :mod:`hooks` callbacks for ``on_session_start`` /
   ``on_session_end`` / ``pre_api_request`` / ``pre_tool_call``.
4. Register one process-exit callback that owns final runtime teardown.

Side-effect-free at module import: provider, hook, and runtime
registration all happen inside :func:`register`. Tests verify this via
the ``register(FakeCtx)`` assertions in
``tests/test_network_hooks_registration.py``.
"""

from __future__ import annotations

import atexit
import functools
import logging
import threading
from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING, Any, NoReturn, Protocol

from .._audit_support import build_audit_writer, safe_audit_append
from .._home import HERMES_BASE
from .._policy_io import load_policy_mapping
from .._policy_types import VALID_ACTIVE_PATHS
from .._yaml_io import load_plugin_section
from . import api, hooks
from . import settings as settings_mod
from ._exceptions import MordredPathBringupFailed
from .runtime import Runtime, RuntimeConfig, route_config_fingerprint
from .vpn_providers import known_providers

if TYPE_CHECKING:
    from ..privacy_check.audit import Writer

_LOG = logging.getLogger("mordred.network")

DEFAULT_POLICY_JSON_PATH: Path = HERMES_BASE / "mordred" / "policy.json"
DEFAULT_CONFIG_PATH: Path = HERMES_BASE / "config.yaml"
DEFAULT_AUDIT_PATH: Path = HERMES_BASE / "mordred" / "audit.log"
# FIX 1 (2026-07-13): the session-start transport gate resolves the active
# provider the same way llm_guard does — config.yaml model.provider first,
# then auth.json active_provider. Same file llm_guard reads.
DEFAULT_AUTH_JSON_PATH: Path = HERMES_BASE / "auth.json"
_PROCESS_SHUTDOWN_REGISTERED = False
_PROCESS_RUNTIME_LOCK = threading.RLock()


class _UnavailableAuditWriter:
    """No-op writer used only to preserve a fail-closed audit-init refusal."""

    def append(self, _entry: Any) -> None:
        return

    def close(self) -> None:
        return


_UNAVAILABLE_AUDIT_WRITER = _UnavailableAuditWriter()


class PluginContext(Protocol):
    """Subset of ``hermes_cli.plugins.PluginContext`` used by mordred_network."""

    def register_hook(self, hook_name: str, callback: Callable[..., Any]) -> None: ...


def register(ctx: PluginContext) -> None:
    """Hermes plugin entry point. Wires the runtime + enforcement hooks.

    Codex P1 fix (2026-05-14): build :class:`RuntimeConfig` from
    ``policy.json`` + ``config.yaml`` rather than the always-``off``
    defaults. The runtime's ``policy_mode`` drives the strict-vs-lenient
    branch in :meth:`Runtime._switch` (raise vs fall back to clearnet),
    the ``policy_mode`` argument passed to :func:`paths.vpn.bring_up`
    (Mullvad lockdown), and the audit ``decision`` field for
    ``network.path_dropped``. A stale ``"off"`` silently downgraded
    every one of those.
    """
    audit = _registration_audit()
    config = _registration_config(audit)
    new_runtime = _prepare_process_runtime(config=config, audit=audit)
    try:
        _wire_network_hooks(ctx=ctx, audit=audit)
    except Exception as e:
        if new_runtime is not None:
            _discard_failed_process_runtime(new_runtime, context="network hook registration failure")
        _raise_process_route_refusal(
            audit=audit,
            attempted_path=config.default_path,
            policy_mode=config.policy_mode,
            error=e,
            lifecycle_context="while registering mandatory network hooks",
        )


def _registration_audit() -> Writer:
    """Build the mandatory audit writer or refuse before runtime setup."""
    try:
        return _build_audit_writer(DEFAULT_AUDIT_PATH)
    except Exception as e:
        _raise_process_route_refusal(
            audit=_UNAVAILABLE_AUDIT_WRITER,
            attempted_path="<uninitialized>",
            policy_mode="strict",
            error=e,
            lifecycle_context="before audit initialization",
        )


def _registration_config(audit: Writer) -> RuntimeConfig:
    """Load activation config or convert an ordinary reader error to refusal."""
    try:
        return _load_runtime_config(
            policy_json_path=DEFAULT_POLICY_JSON_PATH,
            config_path=DEFAULT_CONFIG_PATH,
        )
    except Exception as e:
        _raise_process_route_refusal(
            audit=audit,
            attempted_path="<invalid-config>",
            policy_mode=_policy_mode_for_registration_refusal(),
            error=e,
        )


def _policy_mode_for_registration_refusal() -> str:
    """Best-effort policy label; the refusal itself always remains strict."""
    try:
        return settings_mod.read_policy_mode(DEFAULT_POLICY_JSON_PATH, log=_LOG)
    except Exception as error:
        _LOG.error("policy-mode read failed while preparing network refusal: %s", error)
        return "strict"


def _prepare_process_runtime(*, config: RuntimeConfig, audit: Writer) -> Runtime | None:
    """Create+publish one runtime, or validate the already-published runtime.

    Returns the newly created runtime so a later hook-wiring failure can clean
    it up. ``None`` means re-discovery reused a runtime that may already have
    provider clients and therefore must not be session-scoped teardown.
    """
    with _PROCESS_RUNTIME_LOCK:
        existing_runtime = api._RUNTIME
        if existing_runtime is not None:
            _register_shutdown_for_reused_runtime(config=config, audit=audit)
            _validate_reusable_process_route(runtime=existing_runtime, config=config, audit=audit)
            return None
        return _create_activate_publish_runtime(config=config, audit=audit)


def _create_activate_publish_runtime(*, config: RuntimeConfig, audit: Writer) -> Runtime:
    """Construct a private runtime, atomically activate it, then publish it."""
    try:
        runtime = Runtime(config=config, audit=audit)
    except Exception as e:
        _raise_process_route_refusal(
            audit=audit,
            attempted_path=config.default_path,
            policy_mode=config.policy_mode,
            error=e,
        )
    _register_shutdown_for_new_runtime(runtime=runtime, config=config, audit=audit)
    _activate_process_route(runtime=runtime, config=config, audit=audit)
    try:
        # Publication after freeze closes the api.use() interleaving window.
        api.set_runtime(runtime)
    except Exception as e:
        _discard_failed_process_runtime(runtime, context="runtime singleton publication failure")
        _raise_process_route_refusal(
            audit=audit,
            attempted_path=config.default_path,
            policy_mode=config.policy_mode,
            error=e,
            lifecycle_context="while publishing the process runtime",
        )
    return runtime


def _register_shutdown_for_new_runtime(*, runtime: Runtime, config: RuntimeConfig, audit: Writer) -> None:
    try:
        _register_process_shutdown()
    except Exception as e:
        _discard_failed_process_runtime(runtime, context="process-shutdown registration failure")
        _raise_process_route_refusal(
            audit=audit,
            attempted_path=config.default_path,
            policy_mode=config.policy_mode,
            error=e,
            lifecycle_context="while registering process-shutdown cleanup",
        )


def _register_shutdown_for_reused_runtime(*, config: RuntimeConfig, audit: Writer) -> None:
    try:
        _register_process_shutdown()
    except Exception as e:
        _raise_process_route_refusal(
            audit=audit,
            attempted_path=config.default_path,
            policy_mode=config.policy_mode,
            error=e,
            lifecycle_context="while registering process-shutdown cleanup",
        )


def _wire_network_hooks(*, ctx: PluginContext, audit: Writer) -> None:
    """Load and register every mandatory network/integrity hook."""
    check_plugin_integrity = _load_integrity_hook()

    def _on_session_start(**kwargs: Any) -> None:
        hooks.on_session_start(
            policy_json_path=DEFAULT_POLICY_JSON_PATH,
            config_path=DEFAULT_CONFIG_PATH,
            auth_json_path=DEFAULT_AUTH_JSON_PATH,
            audit=audit,
            **kwargs,
        )

    def _pre_tool_call(**kwargs: Any) -> dict[str, Any] | None:
        return hooks.pre_tool_call(
            policy_json_path=DEFAULT_POLICY_JSON_PATH,
            config_path=DEFAULT_CONFIG_PATH,
            audit=audit,
            **kwargs,
        )

    def _pre_api_request(**kwargs: Any) -> None:
        hooks.pre_api_request(
            policy_json_path=DEFAULT_POLICY_JSON_PATH,
            config_path=DEFAULT_CONFIG_PATH,
            audit=audit,
            **kwargs,
        )

    # The integrity hook is duplicated across siblings so disabling
    # privacy_check cannot disable its own sibling detector.
    ctx.register_hook("on_session_start", check_plugin_integrity)
    ctx.register_hook("on_session_start", _on_session_start)
    ctx.register_hook("on_session_end", hooks.on_session_end)
    ctx.register_hook("pre_api_request", _pre_api_request)
    ctx.register_hook("pre_tool_call", _pre_tool_call)


def _load_integrity_hook() -> Callable[..., Any]:
    """Load the mandatory sibling-integrity hook behind a testable boundary."""
    from ..privacy_check.hooks import check_plugin_integrity

    return check_plugin_integrity


def _activate_process_route(*, runtime: Runtime, config: RuntimeConfig, audit: Writer) -> None:
    """Activate and freeze the configured route before provider construction.

    Hermes creates OpenAI/Anthropic HTTP clients before ``on_session_start``;
    those clients snapshot proxy environment variables at construction. Plugin
    registration is the last available pre-client lifecycle point, so the
    process route must be ready before :func:`register` returns.
    """
    target = config.default_path
    try:
        runtime.activate_and_freeze(target)
    except Exception as e:
        # Standard lenient/off bring-up failures are absorbed by Runtime.use()
        # via clearnet fallback. Any propagated error means no deterministic
        # pre-client transport exists, so process startup cannot safely proceed.
        _discard_failed_process_runtime(runtime, context=f"route {target!r} activation failure")
        _raise_process_route_refusal(
            audit=audit,
            attempted_path=target,
            policy_mode=config.policy_mode,
            error=e,
        )


def _discard_failed_process_runtime(runtime: Runtime, *, context: str) -> None:
    """Best-effort cleanup for a registration-time route refusal."""
    try:
        runtime.stop()
    except Exception as cleanup_error:
        _LOG.warning("%s: runtime.stop() raised %s", context, cleanup_error)
    finally:
        api._clear_runtime_if_current(runtime)


def _validate_reusable_process_route(
    *,
    runtime: api.Runtime,
    config: RuntimeConfig,
    audit: Writer,
) -> None:
    """Fail closed unless a re-discovered plugin can reuse its first route."""
    target = config.default_path
    try:
        status = runtime.status()
        if status.active_path not in VALID_ACTIVE_PATHS:
            raise ValueError(f"existing runtime reported invalid active path {status.active_path!r}")
        if type(status.ready) is not bool or type(status.last_health) is not bool:
            raise ValueError("existing runtime reported non-boolean readiness/health state")
        if getattr(runtime, "process_route_frozen", False) is not True:
            raise RuntimeError("existing process route is not frozen")
        frozen_route_config = getattr(runtime, "frozen_route_config", None)
        if frozen_route_config != route_config_fingerprint(config):
            raise RuntimeError("existing process route was built from different activation configuration")
        frozen_requested_path = getattr(runtime, "frozen_requested_path", status.active_path)
        if frozen_requested_path != target:
            raise RuntimeError(
                f"existing process route was frozen for {frozen_requested_path!r}, "
                f"but configuration now requires {target!r}"
            )
        if not status.ready:
            raise RuntimeError(f"existing process route {target!r} is not ready")
        if not status.last_health:
            raise RuntimeError(f"existing process route {target!r} is unhealthy")
        if runtime.is_dropped():
            raise RuntimeError(f"existing process route {target!r} was dropped")
    except Exception as e:
        _raise_process_route_refusal(
            audit=audit,
            attempted_path=target,
            policy_mode=config.policy_mode,
            error=e,
            lifecycle_context="during plugin re-registration",
        )


def _raise_process_route_refusal(
    *,
    audit: Writer,
    attempted_path: str,
    policy_mode: str,
    error: Exception,
    lifecycle_context: str = "before provider client construction",
) -> NoReturn:
    """Audit and raise a fail-closed process-start refusal."""
    safe_audit_append(
        audit,
        {
            "event": "network.register",
            "decision": "block",
            "reason": "network.bringup_failed",
            "attempted_path": attempted_path,
            "policy_mode": policy_mode,
            "error": str(error),
        },
        logger=_LOG,
    )
    msg = (
        f"Mordred {policy_mode} mode: process network route {attempted_path!r} could not be activated "
        f"{lifecycle_context} ({error}); refusing process startup."
    )
    _LOG.error(msg)
    raise MordredPathBringupFailed(msg) from error


def _stop_runtime_at_process_exit() -> None:
    """Best-effort teardown for the process-global network runtime."""
    try:
        api.stop()
    except Exception as e:
        # Interpreter shutdown must continue even if Tor / VPN cleanup fails.
        _LOG.warning("process-exit network teardown raised %s", e)


def _register_process_shutdown() -> None:
    """Register exactly one finalizer for the process-global runtime.

    Hermes's session hooks have narrower ownership than this singleton:
    ``on_session_end`` fires per turn, while ``on_session_finalize`` can fire
    for one gateway session while other sessions remain active. The callback
    resolves :mod:`api`'s current singleton at interpreter exit instead.
    """
    global _PROCESS_SHUTDOWN_REGISTERED
    if _PROCESS_SHUTDOWN_REGISTERED:
        return
    atexit.register(_stop_runtime_at_process_exit)
    _PROCESS_SHUTDOWN_REGISTERED = True


def _load_runtime_config(*, policy_json_path: Path, config_path: Path) -> RuntimeConfig:
    """Build a :class:`RuntimeConfig` from disk state.

    Reads:
    - ``policy.json`` for ``policy_mode`` (strict / lenient / off)
    - ``policy.json`` for ``disable_ipv6`` (advisory IPv6-leak defence;
      strict-mode default ``True``, lenient/off default ``False``, Phase 3
      PR3a Task #2). User pin always wins.
    - ``config.yaml plugins.mordred_network`` for ``default_path``,
      ``tor_binary_path`` -> ``tor_binary``, ``tor_socks_port``, and
      ``mullvad_relay_country`` -> ``mullvad_region`` (codex P2,
      2026-05-14). Without those four the wizard's choices are
      persisted to disk but never reach the runtime.

    Also pins ``tor_data_dir`` to the active Hermes profile via
    :data:`HERMES_BASE` (Codex P2 round 2, 2026-05-14). Falling back to
    :class:`RuntimeConfig`'s built-in default would hard-code
    ``~/.hermes`` and leak Tor cookies across profiles when the user
    has ``HERMES_HOME`` set or an ``active_profile`` configured.

    Missing policy/config files use the unconfigured defaults (off /
    clearnet / built-in ``RuntimeConfig`` values). Damaged existing policy
    state always resolves to strict. Under strict policy, malformed config
    structure or an invalid explicit ``default_path`` raises so registration
    can refuse before provider construction; lenient/off retain tolerant
    field-level defaults. These semantics match the hook layer.

    ``mullvad_killswitch`` is intentionally NOT wired here yet
    (RuntimeConfig has no field for it; the VPN path derives lockdown
    from ``policy_mode``). Threading an explicit user override is a
    follow-up.
    """
    policy_data = _load_policy_json(policy_json_path)
    # Registration precedes provider construction, so it must use the same
    # fail-closed policy reader as the hook layer. A damaged existing policy
    # cannot silently disable pre-client route activation.
    policy_mode = settings_mod.read_policy_mode(policy_json_path, log=_LOG)
    disable_ipv6 = settings_mod.resolve_disable_ipv6(policy_data, policy_mode)
    network = _load_network_section(config_path)
    # Under strict policy, damage to an existing config must abort before a
    # direct provider client can be constructed. Missing/unconfigured files
    # still resolve to clearnet by the strict reader's contract.
    default_path = (
        settings_mod.read_default_path_strict(config_path)
        if policy_mode == "strict"
        else settings_mod.resolve_default_path(network)
    )
    return RuntimeConfig(
        policy_mode=policy_mode,
        default_path=default_path,
        tor_binary=_resolve_tor_binary(network),
        tor_socks_port=_resolve_tor_socks_port(network),
        tor_data_dir=HERMES_BASE / "mordred" / "tor-data",
        vpn_provider=_resolve_vpn_provider(network),
        wireguard_config_path=_resolve_wireguard_config_path(network),
        custom_up_cmd=_resolve_custom_cmd(network, "custom_up_cmd"),
        custom_down_cmd=_resolve_custom_cmd(network, "custom_down_cmd"),
        custom_health_cmd=_resolve_custom_health_cmd(network),
        mullvad_region=_resolve_mullvad_region(network),
        disable_ipv6=disable_ipv6,
    )


def _load_policy_json(policy_json_path: Path) -> dict[str, Any]:
    """Open ``policy.json`` once and return its dict (or ``{}`` on miss).

    Phase 3 PR3a Task #2: ``_load_runtime_config`` derives multiple
    fields from the same JSON so a single read amortises the IO. All
    failure modes (absent, unreadable, malformed, non-dict root) collapse
    to ``{}`` so downstream resolvers can apply their own defaults
    without crashing plugin registration.
    """
    return load_policy_mapping(policy_json_path, log=_LOG)


def _load_network_section(config_path: Path) -> dict[str, Any]:
    """Open ``config.yaml`` and return ``plugins.mordred_network`` as a dict.

    Codex P2 (2026-05-14): a single read amortises IO for the four
    network fields the runtime consumes (``default_path``,
    ``tor_binary_path``, ``tor_socks_port``, ``mullvad_relay_country``).
    All failure modes collapse to ``{}`` so downstream resolvers apply
    their own defaults without crashing plugin registration. The
    ``plugins.mordred_network`` extraction is shared with
    :func:`network.settings.read_default_path` via
    :func:`load_plugin_section` so the readers cannot drift.
    """
    return load_plugin_section(config_path, "mordred_network", log=_LOG) or {}


def _resolve_tor_binary(network: dict[str, Any]) -> str:
    """Derive ``RuntimeConfig.tor_binary`` from ``tor_binary_path``.

    The wizard's ``tor_binary_path`` key maps to ``tor_binary`` because
    ``RuntimeConfig.tor_binary`` accepts either an absolute path or a
    shell-resolvable name (e.g., bare ``"tor"``). Any non-string value
    falls back to the safe default ``"tor"`` so the runtime can still
    spawn via PATH lookup.
    """
    value = network.get("tor_binary_path")
    if isinstance(value, str) and value:
        return value
    return "tor"


def _resolve_tor_socks_port(network: dict[str, Any]) -> int:
    """Derive ``RuntimeConfig.tor_socks_port`` from on-disk config.

    Returns ``0`` (= "let the runtime pick from the candidate list") when
    the field is absent or malformed. Out-of-range or non-int values
    collapse to ``0`` so a typo doesn't surface as a port-binding
    failure.
    """
    value = network.get("tor_socks_port")
    if isinstance(value, bool):
        # bool is a subclass of int in Python; reject it explicitly so
        # ``mullvad_killswitch: true`` placed under the wrong key can't
        # silently become port 1.
        return 0
    if isinstance(value, int) and 0 < value <= 65535:
        return value
    return 0


def _resolve_mullvad_region(network: dict[str, Any]) -> str:
    """Derive ``RuntimeConfig.mullvad_region`` from ``mullvad_relay_country``.

    The wizard validates the input shape (``"auto"`` or 2-letter lowercase
    code) so this reader trusts a well-formed string and falls back to
    ``"auto"`` only when the field is absent or non-string.
    """
    value = network.get("mullvad_relay_country")
    if isinstance(value, str) and value:
        return value
    return "auto"


def _resolve_vpn_provider(network: dict[str, Any]) -> str:
    """Derive ``RuntimeConfig.vpn_provider`` from ``vpn_provider``.

    Validated against the registered provider names so an unknown value
    (typo, future provider on an old build) falls back to ``mullvad``
    instead of crashing plugin registration when ``Runtime`` resolves the
    provider via ``build_provider`` (which raises ``UnknownVpnProvider``).
    """
    value = network.get("vpn_provider", "mullvad")
    if isinstance(value, str) and value in known_providers():
        return value
    return "mullvad"


def _resolve_wireguard_config_path(network: dict[str, Any]) -> str | None:
    """Derive ``RuntimeConfig.wireguard_config_path`` (vpn_provider=wireguard)."""
    value = network.get("wireguard_config_path")
    if isinstance(value, str) and value:
        return value
    return None


def _resolve_custom_cmd(network: dict[str, Any], key: str) -> tuple[str, ...]:
    """Derive a custom-provider argv tuple from a YAML list of strings.

    Non-list values, or lists with non-string elements, collapse to an
    empty tuple so a malformed entry surfaces as a clear "no up command
    configured" bring-up error rather than a confusing exec failure.
    """
    value = network.get(key)
    if isinstance(value, list) and all(isinstance(x, str) for x in value):
        return tuple(value)
    return ()


def _resolve_custom_health_cmd(network: dict[str, Any]) -> tuple[str, ...] | None:
    """Derive ``RuntimeConfig.custom_health_cmd`` (None when unset/empty)."""
    cmd = _resolve_custom_cmd(network, "custom_health_cmd")
    return cmd or None


@functools.lru_cache(maxsize=1)
def _build_audit_writer(path: Path) -> Writer:
    """Module-local reference to the process-wide writer for ``path``.

    The module-local ``lru_cache`` preserves the cheap repeated-call and
    ``cache_clear()`` behavior tests rely on. The authoritative ownership is
    delegated to the shared
    :func:`mordred_hermes._audit_support.build_audit_writer`, which returns the
    same normalized-path singleton used by privacy_check, llm_guard and
    extension-sign. Clearing this local cache cannot close or replace a writer
    still used by another plugin.
    """
    return build_audit_writer(path)
