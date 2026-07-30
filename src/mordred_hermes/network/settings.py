"""Canonical readers and validators for ``mordred_network`` settings.

This module is deliberately independent of the plugin registration and hook
layers. Registration, request-time hooks, and wizard status commands all need
to interpret the same files, but importing private helpers across those
layers previously created a circular ``network.__init__`` ↔ ``hooks``
dependency. The small pure readers below are the shared boundary instead.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping
from pathlib import Path
from typing import Any, Final, cast

from .._policy_io import read_policy_mode_fail_closed
from .._policy_types import VALID_ACTIVE_PATHS, ActivePath, PolicyMode
from .._yaml_io import load_plugin_section

DEFAULT_NETWORK_PATH: Final[ActivePath] = "clearnet"
DEFAULT_POLICY_MODE: Final[PolicyMode] = "off"


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
    """
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


def resolve_disable_ipv6(data: Mapping[str, Any], policy_mode: str) -> bool:
    """Resolve the advisory IPv6 preference from policy data."""
    raw = data.get("disable_ipv6")
    if isinstance(raw, bool):
        return raw
    return policy_mode == "strict"
