"""One checked canonical generation for each native Windows LLM decision.

The coordinator has closed all handles and locks before parsing, auditing,
provider construction, prompting or network callbacks can run. POSIX callers
keep their existing readers. This module never caches filesystem admission.
"""

from __future__ import annotations

import hashlib
import sys
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, TypeVar

from .._config_io import CanonicalPaths, read_canonical_snapshot
from .._policy_io import policy_mapping_from_snapshot
from .._policy_types import VALID_POLICY_MODES
from .._yaml_io import yaml_mapping_from_snapshot
from ._exceptions import MordredSessionRefused
from ._policy_settings import _PolicySettings, settings_from_mapping


@dataclass(frozen=True)
class Decision:
    mode: str
    settings: _PolicySettings
    config: dict[str, Any]
    generation: str


def read_decision(policy_path: Path, config_path: Path | None = None) -> Decision | None:
    """Return None only on POSIX; unsafe Windows state always aborts the hook."""
    if sys.platform != "win32":
        return None
    failure = "Exception"
    try:
        home = policy_path.parent.parent
        if policy_path.parent.name.casefold() != "mordred":
            raise ValueError("policy must be a canonical home/mordred leaf")
        if config_path is not None and str(config_path.parent) != str(home):
            raise ValueError("config and policy must share a canonical home")
        paths = CanonicalPaths(
            home,
            config_name=config_path.name if config_path else "config.yaml",
            mordred_name=policy_path.parent.name,
            policy_name=policy_path.name,
        )
        snapshot = read_canonical_snapshot(paths)
        policy = policy_mapping_from_snapshot(snapshot)
        config = yaml_mapping_from_snapshot(snapshot)
        mode = policy.get("policy", "lenient")
        if not isinstance(mode, str) or mode not in VALID_POLICY_MODES:
            raise ValueError("invalid policy mode")
        _validate_policy(policy)
        _validate_config(config)
        generation = hashlib.sha256()
        generation.update(str(paths).encode("utf-8"))
        for member in (snapshot.config, snapshot.policy):
            if member is None:
                generation.update(b"absent\0")
            else:
                generation.update(repr(member.metadata.identity).encode("utf-8"))
                generation.update(len(member.data).to_bytes(8, "big"))
                generation.update(member.data)
        return Decision(mode, settings_from_mapping(policy), config, generation.hexdigest())
    except Exception as exc:
        # Keep only the type name. Raising after the handler leaves no
        # ``__context__`` that could retain the parser exception or bytes.
        failure = type(exc).__name__
    # BaseException is deliberate: Hermes catches ordinary exceptions and
    # continues. Do not expose policy/config bytes or parser diagnostics.
    raise MordredSessionRefused(
        "Mordred refuses this LLM operation because canonical Windows policy/config "
        f"could not be safely read ({failure}). Inspect the profile and recover configuration."
    ) from None


def _validate_policy(policy: dict[str, Any]) -> None:
    if "allow_cloud_llm" in policy and not isinstance(policy["allow_cloud_llm"], bool):
        raise ValueError("invalid cloud flag")
    if "cloud_provider_allowlist" in policy:
        values = policy["cloud_provider_allowlist"]
        if not isinstance(values, list) or any(not isinstance(value, str) for value in values):
            raise ValueError("invalid cloud allowlist")
    if "local_llm_endpoint" in policy:
        value = policy["local_llm_endpoint"]
        if not isinstance(value, str) or not value.strip():
            raise ValueError("invalid local endpoint")
    if "cloud_attempt_action" in policy and policy["cloud_attempt_action"] not in ("always-block", "prompt-once"):
        raise ValueError("invalid cloud action")


def _validate_config(config: dict[str, Any]) -> None:
    plugins = config.get("plugins", {})
    if not isinstance(plugins, dict):
        raise ValueError("invalid plugins mapping")
    section = plugins.get("mordred_llm_guard", {})
    if not isinstance(section, dict):
        raise ValueError("invalid LLM guard mapping")
    if "harness_primary" in section and not isinstance(section["harness_primary"], str):
        raise ValueError("invalid harness primary")
    _validate_main_model(config)
    _validate_routes(config)


def _validate_main_model(config: dict[str, Any]) -> None:
    if "model" not in config:
        return
    model = config["model"]
    if isinstance(model, str):
        return
    if not isinstance(model, dict):
        raise ValueError("invalid model configuration")
    if "provider" in model and not isinstance(model["provider"], str):
        raise ValueError("invalid model provider")
    # Hermes consumes these as strings before resolving the main route. Its
    # null/empty defaults are valid; falsy non-strings must not become absence.
    for field in ("base_url", "default", "model"):
        value = model.get(field)
        if value is not None and not isinstance(value, str):
            raise ValueError("invalid main model field")


def _validate_routes(config: dict[str, Any]) -> None:
    for key in ("fallback_providers", "fallback_model"):
        _validate_route_chain(config.get(key), allow_single=True)
    auxiliary = config.get("auxiliary", {})
    if not isinstance(auxiliary, dict) or any(
        not isinstance(key, str) or not isinstance(value, dict) for key, value in auxiliary.items()
    ):
        raise ValueError("invalid auxiliary mapping")
    for route in auxiliary.values():
        _validate_route(route)
        _validate_route_chain(route.get("fallback_chain"))


def _validate_route_chain(value: Any, *, allow_single: bool = False) -> None:
    if value is None:
        return
    entries = [value] if allow_single and isinstance(value, dict) else value
    if not isinstance(entries, list) or any(not isinstance(entry, dict) for entry in entries):
        raise ValueError("invalid fallback chain")
    for entry in entries:
        _validate_route(entry)


def _validate_route(route: dict[str, Any]) -> None:
    for field in ("provider", "model", "base_url"):
        value = route.get(field)
        if value is not None and not isinstance(value, str):
            raise ValueError("invalid route field")
    enabled = route.get("enabled")
    if enabled is not None and not isinstance(enabled, bool):
        raise ValueError("invalid route enabled flag")


_Audit = TypeVar("_Audit")


def guarded_audit_factory(factory: Callable[[Path], _Audit], path: Path) -> _Audit:
    """An unavailable audit factory cannot become a swallowed enforcement error."""
    try:
        return factory(path)
    except Exception:
        if sys.platform != "win32":
            raise
    # Raised after the handler so no ``__context__`` retains the factory error.
    raise MordredSessionRefused("Mordred refuses this LLM operation because audit initialization failed.") from None
