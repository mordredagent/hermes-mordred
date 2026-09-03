"""Disk -> :class:`RuntimeConfig` loaders for ``mordred_network``.

Split out of :mod:`mordred_hermes.network` so the package module stays focused
on plugin registration and hook wiring. The package re-imports
:func:`_load_runtime_config` under its historical name, so
``network._load_runtime_config`` remains reachable as a package attribute for
the hooks' call-time lookup and for the tests; the ``_load_*`` / ``_resolve_*``
helpers below are private to this module.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from .._policy_io import load_policy_mapping
from .._yaml_io import load_plugin_section
from . import settings as settings_mod
from .runtime import RuntimeConfig
from .vpn_providers import known_providers

_LOG = logging.getLogger("mordred.network")


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
    # ``HERMES_BASE`` is read back through the package at call time rather than
    # bound at import: the active Hermes profile is the knob that decides where
    # Tor's data dir lands, and it is patched on the package attribute.
    from . import HERMES_BASE

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
    # Runtime derives ControlPort as SOCKSPort + 1.
    if isinstance(value, int) and 0 < value < 65535:
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
