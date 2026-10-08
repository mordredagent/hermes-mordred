"""One checked canonical generation for each native Windows network decision.

Mirrors ``llm_guard._windows_policy``. The C2 coordinator has closed every
handle and lock before parsing, auditing, route activation, Tor/VPN process
calls or provider network calls can run. POSIX callers keep their existing
readers. This module never caches filesystem admission: each decision point
re-reads, so a pending marker, ACL/identity change or new generation applies
at the next request.
"""

from __future__ import annotations

import hashlib
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final, cast

from .._config_io import CanonicalPaths, CanonicalSnapshot, read_canonical_snapshot
from .._policy_io import policy_mapping_from_snapshot
from .._policy_types import VALID_ACTIVE_PATHS, VALID_POLICY_MODES, ActivePath, PolicyMode
from .._yaml_io import yaml_mapping_from_snapshot
from ._exceptions import MordredPathBringupFailed
from .provider_transport_flagger import ProviderEntry
from .settings import DEFAULT_NETWORK_PATH, DEFAULT_POLICY_MODE, parse_provider_overrides
from .vpn_providers import known_providers

_SECTION: Final[str] = "mordred_network"
# Optional string fields consumed by ``network._resolve_*``. ``None`` is the
# unset value those resolvers already map to their defaults.
_OPTIONAL_STRINGS: Final[tuple[str, ...]] = ("tor_binary_path", "wireguard_config_path", "mullvad_relay_country")
_COMMANDS: Final[tuple[str, ...]] = ("custom_up_cmd", "custom_down_cmd", "custom_health_cmd")


@dataclass(frozen=True)
class NetworkDecision:
    """Everything one network decision consumes, from one checked generation."""

    mode: PolicyMode
    default_path: ActivePath
    section: dict[str, Any]
    disable_ipv6: bool
    provider_overrides: dict[str, ProviderEntry]
    config_provider: str | None
    generation: str


def read_network_decision(policy_path: Path, config_path: Path) -> NetworkDecision | None:
    """Return None only on POSIX; unsafe Windows state always refuses."""
    if sys.platform != "win32":
        return None
    try:
        home = policy_path.parent.parent
        if policy_path.parent.name.casefold() != "mordred":
            raise ValueError("policy must be a canonical home/mordred leaf")
        if str(config_path.parent) != str(home):
            raise ValueError("config and policy must share a canonical home")
        paths = CanonicalPaths(
            home,
            config_name=config_path.name,
            mordred_name=policy_path.parent.name,
            policy_name=policy_path.name,
        )
        snapshot = read_canonical_snapshot(paths)
        policy = policy_mapping_from_snapshot(snapshot)
        config = yaml_mapping_from_snapshot(snapshot)
        mode = policy.get("policy", DEFAULT_POLICY_MODE)
        if not isinstance(mode, str) or mode not in VALID_POLICY_MODES:
            raise ValueError("invalid policy mode")
        disable_ipv6 = policy.get("disable_ipv6", mode == "strict")
        if not isinstance(disable_ipv6, bool):
            raise ValueError("invalid IPv6 preference")
        section = _network_section(config)
        return NetworkDecision(
            mode=cast(PolicyMode, mode),
            default_path=_default_path(section),
            section=section,
            disable_ipv6=disable_ipv6,
            provider_overrides=parse_provider_overrides(policy),
            config_provider=_config_provider(config),
            generation=_generation(paths, snapshot),
        )
    except Exception as exc:
        # BaseException is deliberate: Hermes catches ordinary exceptions and
        # continues. Do not expose policy/config bytes or parser diagnostics.
        raise MordredPathBringupFailed(
            "Mordred refuses this network operation because canonical Windows policy/config "
            f"could not be safely read ({type(exc).__name__}). Inspect the profile and recover configuration."
        ) from None


def _network_section(config: dict[str, Any]) -> dict[str, Any]:
    plugins = config.get("plugins", {})
    if not isinstance(plugins, dict):
        raise ValueError("invalid plugins mapping")
    section = plugins.get(_SECTION, {})
    if not isinstance(section, dict):
        raise ValueError("invalid network mapping")
    for field in _OPTIONAL_STRINGS:
        value = section.get(field)
        if value is not None and not isinstance(value, str):
            raise ValueError("invalid network string field")
    port = section.get("tor_socks_port")
    # bool is an int subclass; 0 asks the runtime picker, port + 1 is control.
    if port is not None and (isinstance(port, bool) or not isinstance(port, int) or not 0 <= port < 65535):
        raise ValueError("invalid Tor SOCKS port")
    provider = section.get("vpn_provider")
    if provider is not None and (not isinstance(provider, str) or provider not in known_providers()):
        raise ValueError("invalid VPN provider")
    for field in _COMMANDS:
        command = section.get(field)
        if command is not None and (
            not isinstance(command, list) or any(not isinstance(argument, str) for argument in command)
        ):
            raise ValueError("invalid custom VPN command")
    return section


def _default_path(section: dict[str, Any]) -> ActivePath:
    value = section.get("default_path", DEFAULT_NETWORK_PATH)
    if not isinstance(value, str) or value not in VALID_ACTIVE_PATHS:
        raise ValueError("invalid default network path")
    return cast(ActivePath, value)


def _config_provider(config: dict[str, Any]) -> str | None:
    """``model.provider`` as ``_provider_resolution`` normalizes it."""
    model = config.get("model")
    if model is None or isinstance(model, str):
        return None
    if not isinstance(model, dict):
        raise ValueError("invalid model configuration")
    value = model.get("provider")
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError("invalid model provider")
    normalized = value.strip().lower()
    return normalized if normalized and normalized != "auto" else None


def _generation(paths: CanonicalPaths, snapshot: CanonicalSnapshot) -> str:
    """Digest built exactly like ``llm_guard._windows_policy``."""
    generation = hashlib.sha256()
    generation.update(str(paths).encode("utf-8"))
    for member in (snapshot.config, snapshot.policy):
        if member is None:
            generation.update(b"absent\0")
        else:
            generation.update(repr(member.metadata.identity).encode("utf-8"))
            generation.update(len(member.data).to_bytes(8, "big"))
            generation.update(member.data)
    return generation.hexdigest()
