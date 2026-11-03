"""Shared disk-state provider resolution for Mordred enforcement plugins.

Hermes chooses a provider from two persistent sources:

1. ``config.yaml`` → ``model.provider`` when it names a concrete provider.
2. ``auth.json`` → ``active_provider`` when the config value is missing,
   empty, or the ``"auto"`` sentinel.

Both ``mordred_llm_guard`` and ``mordred_network`` must reproduce that order.
Keeping the readers here prevents the strict LLM gate and the network
transport gate from silently making different decisions about the same
session. Runtime overrides remain the responsibility of the request-time
hooks, which receive the actually resolved provider from Hermes.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from pathlib import Path

from ._policy_io import load_policy_mapping
from ._yaml_io import load_yaml_mapping


def read_config_model_provider(
    config_path: Path,
    *,
    log: logging.Logger | None = None,
) -> str | None:
    """Return a concrete ``model.provider`` value, normalized to lowercase.

    Missing, malformed, empty, and ``"auto"`` values return ``None`` so the
    caller can fall back to ``auth.json`` exactly as Hermes does.
    """
    data = load_yaml_mapping(config_path, log=log)
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


def read_auth_active_provider(
    auth_json_path: Path,
    *,
    log: logging.Logger | None = None,
) -> str | None:
    """Return ``auth.json.active_provider``, normalized to lowercase."""
    value = load_policy_mapping(auth_json_path, log=log).get("active_provider")
    if not isinstance(value, str):
        return None
    normalized = value.strip().lower()
    return normalized or None


def resolve_disk_provider(
    *,
    config_path: Path,
    auth_json_path: Path | None,
    log: logging.Logger | None = None,
    config_reader: Callable[[Path], str | None] | None = None,
    auth_reader: Callable[[Path], str | None] | None = None,
) -> str | None:
    """Resolve the raw provider id using Hermes' persistent-state order.

    Reader injection keeps legacy plugin-level seams available to focused
    tests while single-sourcing the precedence rule itself.
    """
    configured = (
        config_reader(config_path) if config_reader is not None else read_config_model_provider(config_path, log=log)
    )
    if configured:
        return configured
    if auth_json_path is None:
        return None
    resolved = (
        auth_reader(auth_json_path) if auth_reader is not None else read_auth_active_provider(auth_json_path, log=log)
    )
    return resolved or None
