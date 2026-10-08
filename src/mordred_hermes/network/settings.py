"""Canonical readers and validators for ``mordred_network`` settings.

This module is deliberately independent of the plugin registration and hook
layers. Registration, request-time hooks, and wizard status commands all need
to interpret the same files, but importing private helpers across those
layers previously created a circular ``network.__init__`` ↔ ``hooks``
dependency. The small pure readers below are the shared boundary instead.
"""

from __future__ import annotations

import logging
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any, Final, Literal, cast

from .._policy_io import read_policy_mode_fail_closed
from .._policy_types import VALID_ACTIVE_PATHS, ActivePath, PolicyMode
from .._yaml_io import load_plugin_section
from .provider_transport_flagger import ProviderEntry, TransportClass

DEFAULT_NETWORK_PATH: Final[ActivePath] = "clearnet"
DEFAULT_POLICY_MODE: Final[PolicyMode] = "off"
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


def read_policy_mode(
    policy_json_path: Path,
    *,
    log: logging.Logger,
) -> PolicyMode:
    """Read network policy mode, failing closed on damaged existing state."""
    value = read_policy_mode_fail_closed(
        policy_json_path,
        default=DEFAULT_POLICY_MODE,
        log=log,
    )
    return cast(PolicyMode, value)


def resolve_default_path(section: Mapping[str, Any] | None) -> ActivePath:
    """Return a validated ``default_path`` or the safe clearnet default."""
    value = (section or {}).get("default_path", DEFAULT_NETWORK_PATH)
    if isinstance(value, str) and value in VALID_ACTIVE_PATHS:
        return cast(ActivePath, value)
    return DEFAULT_NETWORK_PATH


def read_default_path(
    config_path: Path,
    *,
    log: logging.Logger | None = None,
) -> ActivePath:
    """Read ``plugins.mordred_network.default_path`` with tolerant fallback."""
    section = load_plugin_section(config_path, "mordred_network", log=log)
    return resolve_default_path(section)


def read_default_path_strict(config_path: Path) -> ActivePath:
    """Read ``default_path`` while surfacing damage to existing config.

    Missing files and absent keys are legitimate unconfigured state and map
    to clearnet. Malformed YAML/container shapes and invalid explicit values
    raise so strict request-time enforcement can fail closed.

    On Windows the value comes from one checked canonical generation of the
    ``config.yaml`` / ``mordred/policy.json`` pair. A refused generation keeps
    this function's ordinary-exception contract (callers such as the extension
    egress gate convert it to their own refusal) and carries no file bytes.
    """
    if sys.platform == "win32":
        return _checked_default_path(config_path)
    return _posix_default_path_strict(config_path)


def _posix_default_path_strict(config_path: Path) -> ActivePath:
    from ruamel.yaml import YAML

    try:
        f = config_path.open(encoding="utf-8")
    except FileNotFoundError:
        return DEFAULT_NETWORK_PATH
    with f:
        data = YAML(typ="safe", pure=True).load(f)
    if data is None:
        return DEFAULT_NETWORK_PATH
    if not isinstance(data, dict):
        raise ValueError("config.yaml must contain a top-level mapping")
    if "plugins" not in data:
        return DEFAULT_NETWORK_PATH
    plugins = data["plugins"]
    if not isinstance(plugins, dict):
        raise ValueError("config.yaml plugins must be a mapping")
    if "mordred_network" not in plugins:
        return DEFAULT_NETWORK_PATH
    section = plugins["mordred_network"]
    if not isinstance(section, dict):
        raise ValueError("config.yaml plugins.mordred_network must be a mapping")
    if "default_path" not in section:
        return DEFAULT_NETWORK_PATH
    value = section["default_path"]
    if not isinstance(value, str) or value not in VALID_ACTIVE_PATHS:
        raise ValueError(
            f"config.yaml plugins.mordred_network.default_path must be one of {sorted(VALID_ACTIVE_PATHS)!r}"
        )
    return cast(ActivePath, value)


def _checked_default_path(config_path: Path) -> ActivePath:
    """Windows ``default_path`` from one checked generation; ordinary refusal."""
    from ._exceptions import MordredPathBringupFailed
    from ._windows_policy import read_network_decision

    message = "checked Windows network decision unavailable"
    try:
        decision = read_network_decision(config_path.parent / "mordred" / "policy.json", config_path)
    except MordredPathBringupFailed as refusal:
        decision, message = None, str(refusal)
    if decision is None:
        # Raised outside the handler: the ordinary refusal carries no chain.
        raise ValueError(message) from None
    return decision.default_path


def resolve_disable_ipv6(data: Mapping[str, Any], policy_mode: str) -> bool:
    """Resolve the advisory IPv6 preference from policy data."""
    raw = data.get("disable_ipv6")
    if isinstance(raw, bool):
        return raw
    return policy_mode == "strict"


def parse_provider_overrides(data: Mapping[str, Any]) -> dict[str, ProviderEntry]:
    """Parse additive transport facts from a ``policy.json`` mapping.

    Missing fields take conservative defaults so an incomplete entry cannot
    accidentally satisfy strict Tor: SOCKS5h/IPv6 support default false and
    ``unverified_baseline`` defaults true. Invalid types and unknown fields
    raise ``ValueError``. Baseline replacement remains prohibited by
    :func:`provider_transport_flagger.evaluate`. POSIX hooks and the checked
    Windows reader share this parser so the two platforms cannot drift.
    """
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
