"""``plugins.mordred_activity`` in the owning profile's ``config.yaml``.

Everything defaults to off: no existing profile is silently enrolled. A value
that is unknown or has the wrong type falls back to its default and is named
(key only, never the value) in :attr:`ActivityConfig.warnings`. Excluded
sites from configuration are added to :data:`contracts.DEFAULT_EXCLUDED_SITES`,
which is empty: no site is excluded by default, so every exclusion comes from
``excluded_sites`` here. ``retention_raw_days: 0`` keeps raw events and
episodes forever. Keys of the removed lesson pipeline (``review_*``,
``recall_*``, ``retention_candidate_days``) are unknown keys like any other.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, fields
from pathlib import Path
from typing import Any, Final

from .contracts import DEFAULT_EXCLUDED_SITES, MAX_BATCH_BYTES, MAX_BATCH_EVENTS, MAX_EVENT_BYTES

SECTION: Final = "mordred_activity"


@dataclass(frozen=True)
class ActivityConfig:
    enabled: bool = False
    collection_enabled: bool = False
    max_batch_events: int = MAX_BATCH_EVENTS
    max_event_bytes: int = MAX_EVENT_BYTES
    max_batch_bytes: int = MAX_BATCH_BYTES
    #: ``0`` means raw events and episodes are never deleted.
    retention_raw_days: int = 365
    #: The effective exclusions: ``DEFAULT_EXCLUDED_SITES | configured``.
    #: The default set is empty, so only configured hosts (and their subdomains) are excluded.
    excluded_sites: frozenset[str] = DEFAULT_EXCLUDED_SITES
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


def _sites(raw: Any) -> Any:
    if not isinstance(raw, list) or not all(isinstance(site, str) and site.strip() for site in raw):
        return _INVALID
    return frozenset(site.strip().lower() for site in raw)


_PARSERS: Final[Mapping[str, Callable[[Any], Any]]] = {
    "enabled": _bool,
    "collection_enabled": _bool,
    "excluded_sites": _sites,
    "retention_raw_days": _non_negative_int,
    "max_batch_events": _capped_int(MAX_BATCH_EVENTS),
    "max_event_bytes": _capped_int(MAX_EVENT_BYTES),
    "max_batch_bytes": _capped_int(MAX_BATCH_BYTES),
}
