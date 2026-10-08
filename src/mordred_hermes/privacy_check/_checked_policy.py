"""One checked canonical generation for a Windows privacy decision."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

from .._config_io import CanonicalPaths, read_canonical_snapshot
from .._policy_io import policy_mapping_from_snapshot
from .._policy_types import POLICY_MODES
from .._yaml_io import yaml_mapping_from_snapshot
from .egress import LEVELS, EgressPolicy, parse_policy
from .policy import PolicyMode


@dataclass(frozen=True)
class CheckedPolicy:
    mode: PolicyMode
    allow_cloud_llm: bool
    cloud_provider_allowlist: tuple[str, ...]
    audit_log_path: str | None
    egress: EgressPolicy
    enabled: frozenset[str] | None
    disabled: frozenset[str]


def _strings(value: object, field: str) -> tuple[str, ...]:
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise ValueError(f"invalid {field}")
    return tuple(value)


def _mirror(data: dict[str, Any]) -> tuple[PolicyMode, bool, tuple[str, ...], str | None]:
    mode = data.get("policy", "lenient")
    allow = data.get("allow_cloud_llm", False)
    audit = data.get("audit_log_path")
    if not isinstance(mode, str) or mode not in POLICY_MODES:
        raise ValueError("invalid privacy policy mode")
    if not isinstance(allow, bool) or (audit is not None and not isinstance(audit, str)):
        raise ValueError("invalid privacy permission or audit path")
    providers = _strings(data.get("cloud_provider_allowlist", []), "cloud_provider_allowlist")
    return cast(PolicyMode, mode), allow, providers, audit


def read_checked_policy(path: Path) -> CheckedPolicy:
    # Explicit canonical paths also protect custom config leaves. C2 releases
    # every filesystem capability before parsing or invoking any caller code.
    snapshot = read_canonical_snapshot(CanonicalPaths(path.parent, config_name=path.name))
    config = yaml_mapping_from_snapshot(snapshot)
    policy = policy_mapping_from_snapshot(snapshot)
    plugins = config.get("plugins", {})
    if not isinstance(plugins, dict):
        raise ValueError("plugins must be a mapping")
    section = plugins.get("mordred_privacy_check", {})
    if not isinstance(section, dict):
        raise ValueError("privacy section must be a mapping")
    config_values = _mirror(section)
    policy_values = _mirror(policy)
    if snapshot.config is not None and snapshot.policy is not None and config_values != policy_values:
        raise ValueError("privacy policy mirrors disagree")
    mode, allow, providers, audit = policy_values if snapshot.config is None else config_values
    raw_egress = section.get("tool_egress")
    if "tool_egress" in section:
        if not isinstance(raw_egress, dict):
            raise ValueError("tool_egress must be a mapping")
        level = raw_egress.get("level", "ask")
        if not isinstance(level, str) or level not in LEVELS:
            raise ValueError("invalid tool-egress level")
        for field in ("blocklist", "blocked_tools"):
            _strings(raw_egress.get(field, []), field)
        for field in ("taint", "lockdown_after_private_data"):
            if field in raw_egress and not isinstance(raw_egress[field], bool):
                raise ValueError(f"invalid {field}")
    enabled = frozenset(_strings(plugins["enabled"], "enabled")) if "enabled" in plugins else None
    disabled = frozenset(_strings(plugins.get("disabled", []), "disabled"))
    return CheckedPolicy(mode, allow, providers, audit, parse_policy(raw_egress), enabled, disabled)
