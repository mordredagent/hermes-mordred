"""mordred_network - Tor / VPN / Clearnet path management.

Phase 3 PR2 wiring:

1. Construct the singleton :class:`Runtime` (PR2-A) reading config from
   ``~/.hermes/config.yaml plugins.mordred_network.*`` and
   ``~/.hermes/mordred/policy.json``.
2. Register it process-wide via :func:`api.set_runtime`.
3. Register :mod:`hooks` callbacks for ``on_session_start`` /
   ``on_session_end`` / ``pre_tool_call``.

Side-effect-free at module import: provider, hook, and runtime
registration all happen inside :func:`register`. Tests verify this via
the ``register(FakeCtx)`` assertions in ``tests/test_network_hooks.py``.
"""

from __future__ import annotations

import functools
import json
import logging
from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final, Protocol, cast

from .._audit_support import build_audit_writer
from .._home import HERMES_BASE
from . import api, hooks
from .runtime import ActivePath, PolicyMode, Runtime, RuntimeConfig
from .vpn_providers import known_providers

if TYPE_CHECKING:
    from ..privacy_check.audit import NDJSONWriter

_LOG = logging.getLogger("mordred.network")

DEFAULT_POLICY_JSON_PATH: Path = HERMES_BASE / "mordred" / "policy.json"
DEFAULT_CONFIG_PATH: Path = HERMES_BASE / "config.yaml"
DEFAULT_AUDIT_PATH: Path = HERMES_BASE / "mordred" / "audit.log"


class PluginContext(Protocol):
    """Subset of ``hermes_cli.plugins.PluginContext`` used by mordred_network."""

    def register_hook(self, hook_name: str, callback: Callable[..., Any]) -> None: ...


_VALID_POLICY_MODES: Final[frozenset[str]] = frozenset({"strict", "lenient", "off"})
_VALID_PATHS: Final[frozenset[str]] = frozenset({"tor", "vpn", "clearnet"})


def register(ctx: PluginContext) -> None:
    """Hermes plugin entry point. Wires the runtime + 3 hooks.

    Codex P1 fix (2026-05-14): build :class:`RuntimeConfig` from
    ``policy.json`` + ``config.yaml`` rather than the always-``off``
    defaults. The runtime's ``policy_mode`` drives the strict-vs-lenient
    branch in :meth:`Runtime._switch` (raise vs fall back to clearnet),
    the ``policy_mode`` argument passed to :func:`paths.vpn.bring_up`
    (Mullvad lockdown), and the audit ``decision`` field for
    ``network.path_dropped``. A stale ``"off"`` silently downgraded
    every one of those.
    """
    audit = _build_audit_writer(DEFAULT_AUDIT_PATH)
    config = _load_runtime_config(
        policy_json_path=DEFAULT_POLICY_JSON_PATH,
        config_path=DEFAULT_CONFIG_PATH,
    )
    runtime = Runtime(config=config, audit=audit)
    api.set_runtime(runtime)

    def _on_session_start(**kwargs: Any) -> None:
        hooks.on_session_start(
            policy_json_path=DEFAULT_POLICY_JSON_PATH,
            config_path=DEFAULT_CONFIG_PATH,
            audit=audit,
            **kwargs,
        )

    def _pre_tool_call(**kwargs: Any) -> dict[str, Any] | None:
        return hooks.pre_tool_call(
            policy_json_path=DEFAULT_POLICY_JSON_PATH,
            audit=audit,
            **kwargs,
        )

    ctx.register_hook("on_session_start", _on_session_start)
    ctx.register_hook("on_session_end", hooks.on_session_end)
    ctx.register_hook("pre_tool_call", _pre_tool_call)


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

    Falls back to safe defaults (off / clearnet / built-in
    RuntimeConfig defaults) when the policy / config files are absent
    or malformed -- matches the hooks-layer fallback so the two readers
    stay in agreement.

    ``mullvad_killswitch`` is intentionally NOT wired here yet
    (RuntimeConfig has no field for it; the VPN path derives lockdown
    from ``policy_mode``). Threading an explicit user override is a
    follow-up.
    """
    policy_data = _load_policy_json(policy_json_path)
    policy_mode = _resolve_policy_mode(policy_data)
    disable_ipv6 = _resolve_disable_ipv6(policy_data, policy_mode)
    network = _load_network_section(config_path)
    default_path = _resolve_default_path(network)
    return RuntimeConfig(
        policy_mode=cast(PolicyMode, policy_mode),
        default_path=cast(ActivePath, default_path),
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
    if not policy_json_path.exists():
        return {}
    try:
        with policy_json_path.open(encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        _LOG.warning("could not read %s: %s; defaulting to empty", policy_json_path, e)
        return {}
    if not isinstance(data, dict):
        return {}
    return cast(dict[str, Any], data)


def _resolve_policy_mode(data: dict[str, Any]) -> str:
    """Derive ``policy_mode`` from a pre-loaded ``policy.json`` dict."""
    mode = data.get("policy", "off")
    # Codex round 3 P2 (2026-05-14): isinstance check first; ``in`` on a
    # frozenset raises TypeError for unhashable values like ``[]`` or
    # ``{}``. A corrupted ``policy.json`` must collapse to ``off``, not
    # crash plugin registration before the hooks are installed.
    if isinstance(mode, str) and mode in _VALID_POLICY_MODES:
        return mode
    return "off"


def _resolve_disable_ipv6(data: dict[str, Any], policy_mode: str) -> bool:
    """Derive ``disable_ipv6`` from a pre-loaded ``policy.json`` dict.

    Phase 3 PR3a Task #2. If the user pinned a bool, honour it. Otherwise
    default by policy mode: ``strict`` → ``True`` (safe-by-default IPv6
    leak defence), ``lenient`` / ``off`` → ``False`` (user-friendly).

    Non-bool values (``"yes"``, ``1``, ``[]``) collapse to the mode default
    -- the contract is documented in POLICY.md §disable_ipv6 schema.
    """
    raw = data.get("disable_ipv6")
    if isinstance(raw, bool):
        return raw
    return policy_mode == "strict"


def _load_network_section(config_path: Path) -> dict[str, Any]:
    """Open ``config.yaml`` and return ``plugins.mordred_network`` as a dict.

    Codex P2 (2026-05-14): a single read amortises IO for the four
    network fields the runtime consumes (``default_path``,
    ``tor_binary_path``, ``tor_socks_port``, ``mullvad_relay_country``).
    All failure modes collapse to ``{}`` so downstream resolvers apply
    their own defaults without crashing plugin registration.
    """
    if not config_path.exists():
        return {}
    from ruamel.yaml import YAML
    from ruamel.yaml.error import YAMLError

    yaml = YAML(typ="safe", pure=True)
    try:
        with config_path.open(encoding="utf-8") as f:
            data = yaml.load(f)
    except (OSError, YAMLError) as e:
        _LOG.warning("could not read %s: %s", config_path, e)
        return {}
    if not isinstance(data, dict):
        return {}
    plugins = data.get("plugins")
    if not isinstance(plugins, dict):
        return {}
    network = plugins.get("mordred_network")
    if not isinstance(network, dict):
        return {}
    return cast(dict[str, Any], network)


def _resolve_default_path(network: dict[str, Any]) -> str:
    value = network.get("default_path", "clearnet")
    if isinstance(value, str) and value in _VALID_PATHS:
        return value
    return "clearnet"


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
def _build_audit_writer(path: Path) -> NDJSONWriter:
    """Per-process cached NDJSON writer (one ``mkdir`` + ``chmod`` per path).

    The module-local ``lru_cache`` keeps this cache -- and the
    ``cache_clear()`` the tests drive -- separate from ``llm_guard``'s
    identically-pathed writer; construction is delegated to the shared
    :func:`mordred_hermes._audit_support.build_audit_writer`, which does the
    lazy ``privacy_check`` import to keep ``register`` cheap.
    """
    return build_audit_writer(path)
