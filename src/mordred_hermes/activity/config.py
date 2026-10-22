"""``plugins.mordred_activity`` in the owning profile's ``config.yaml``.

Everything defaults to off: no existing profile is silently enrolled. A value
that is unknown or has the wrong type falls back to its default and is named
(key only, never the value) in :attr:`ActivityConfig.warnings`. Excluded
sites from configuration are added to :data:`contracts.DEFAULT_EXCLUDED_SITES`,
which is empty: no site is excluded by default, so every exclusion comes from
``excluded_sites`` here. ``retention_raw_days: 0`` keeps raw events and
episodes forever.
"""

from __future__ import annotations

import math
from collections.abc import Callable, Mapping
from dataclasses import dataclass, fields
from pathlib import Path
from typing import Any, Final

from .contracts import DEFAULT_EXCLUDED_SITES, MAX_BATCH_BYTES, MAX_BATCH_EVENTS, MAX_EVENT_BYTES

SECTION: Final = "mordred_activity"
REVIEW_MODES: Final = frozenset({"manual", "task_boundary"})


@dataclass(frozen=True)
class ActivityConfig:
    enabled: bool = False
    collection_enabled: bool = False
    review_mode: str = "manual"
    recall_enabled: bool = True
    max_batch_events: int = MAX_BATCH_EVENTS
    max_event_bytes: int = MAX_EVENT_BYTES
    max_batch_bytes: int = MAX_BATCH_BYTES
    #: ``0`` means raw events and episodes are never deleted.
    retention_raw_days: int = 365
    retention_candidate_days: int = 90
    #: The effective exclusions: ``DEFAULT_EXCLUDED_SITES | configured``.
    #: The default set is empty, so only configured hosts (and their subdomains) are excluded.
    excluded_sites: frozenset[str] = DEFAULT_EXCLUDED_SITES
    review_provider: str | None = None
    review_model: str | None = None
    review_max_input_tokens: int = 6000
    review_max_output_tokens: int = 1000
    review_timeout_s: int = 30
    review_attempts_per_day: int = 2
    review_min_spacing_s: int = 1800
    #: ``None`` means no paid automatic review calls at all.
    review_paid_budget_usd: float | None = None
    recall_max_items: int = 3
    recall_max_tokens: int = 1000
    recall_max_bytes: int = 4096
    recall_session_token_budget: int = 2000
    warnings: tuple[str, ...] = ()

    @property
    def collecting(self) -> bool:
        return self.enabled and self.collection_enabled

    @classmethod
    def from_mapping(cls, section: Mapping[str, Any]) -> ActivityConfig:
        values: dict[str, Any] = {}
        warnings: list[str] = []
        known = {f.name for f in fields(cls)} - {"warnings"}
        for key, raw in section.items():
            if key not in known:
                warnings.append(f"unknown key {key}" if isinstance(key, str) else "unknown key")
                continue
            parsed = _PARSERS[key](raw)
            if parsed is _INVALID:
                warnings.append(f"invalid value for {key}")
                continue
            values[key] = parsed
        configured = values.get("excluded_sites", frozenset())
        values["excluded_sites"] = DEFAULT_EXCLUDED_SITES | configured
        return cls(**values, warnings=tuple(warnings))

    @classmethod
    def load(cls, home: Path) -> ActivityConfig:
        """Read ``<home>/config.yaml``; an absent or unreadable file yields the (disabled) defaults."""
        from .._yaml_io import load_plugin_section

        return cls.from_mapping(load_plugin_section(home / "config.yaml", SECTION) or {})


_INVALID: Final = object()


def _bool(raw: Any) -> Any:
    return raw if isinstance(raw, bool) else _INVALID


def _positive_int(raw: Any) -> Any:
    return raw if isinstance(raw, int) and not isinstance(raw, bool) and raw > 0 else _INVALID


def _non_negative_int(raw: Any) -> Any:
    return raw if isinstance(raw, int) and not isinstance(raw, bool) and raw >= 0 else _INVALID


def _capped_int(cap: int) -> Callable[[Any], Any]:
    """Configuration may tighten a wire limit, never raise it above the contract's."""

    def parse(raw: Any) -> Any:
        value = _positive_int(raw)
        return value if value is _INVALID or value <= cap else _INVALID

    return parse


def _optional_name(raw: Any) -> Any:
    if raw is None:
        return None
    return raw.strip() if isinstance(raw, str) and raw.strip() and len(raw) <= 128 else _INVALID


def _optional_budget(raw: Any) -> Any:
    if raw is None:
        return None
    ok = isinstance(raw, int | float) and not isinstance(raw, bool) and math.isfinite(raw) and raw >= 0
    return float(raw) if ok else _INVALID


def _review_mode(raw: Any) -> Any:
    return raw if raw in REVIEW_MODES else _INVALID


def _sites(raw: Any) -> Any:
    if not isinstance(raw, list) or not all(isinstance(site, str) and site.strip() for site in raw):
        return _INVALID
    return frozenset(site.strip().lower() for site in raw)


_PARSERS: Final[Mapping[str, Callable[[Any], Any]]] = {
    "enabled": _bool,
    "collection_enabled": _bool,
    "recall_enabled": _bool,
    "review_mode": _review_mode,
    "excluded_sites": _sites,
    "retention_raw_days": _non_negative_int,
    "review_provider": _optional_name,
    "review_model": _optional_name,
    "review_paid_budget_usd": _optional_budget,
    "max_batch_events": _capped_int(MAX_BATCH_EVENTS),
    "max_event_bytes": _capped_int(MAX_EVENT_BYTES),
    "max_batch_bytes": _capped_int(MAX_BATCH_BYTES),
    **{
        name: _positive_int
        for name in (
            "retention_candidate_days",
            "review_max_input_tokens",
            "review_max_output_tokens",
            "review_timeout_s",
            "review_attempts_per_day",
            "review_min_spacing_s",
            "recall_max_items",
            "recall_max_tokens",
            "recall_max_bytes",
            "recall_session_token_budget",
        )
    },
}
