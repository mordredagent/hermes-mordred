"""``plugins.mordred_activity`` in the owning profile's ``config.yaml``.

The feature switch ``enabled`` defaults to off, so no existing profile is
silently enrolled; the ``history_*`` switches default to on but act only while
``enabled`` is on. A value that is unknown or has the wrong type falls back to
its default and is named (key only, never the value) in
:attr:`ActivityConfig.warnings`. Excluded sites from configuration are added
to :data:`contracts.DEFAULT_EXCLUDED_SITES`, which is empty: no site is
excluded by default, so every exclusion comes from ``excluded_sites`` here.
``retention_raw_days: 0`` keeps raw events and episodes forever. Keys of the
removed lesson pipeline (``review_*``, ``recall_*``,
``retention_candidate_days``) are unknown keys like any other.

The ``history_*`` keys govern Hermes's use of the stored history
(:mod:`.history`): ``history_enabled`` is the master switch over every surface;
``history_capture_hermes`` and ``history_chat_corrections`` are parsed but have
no effect yet (the next phase records Hermes's own browser calls).
"""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass, fields
from pathlib import Path
from typing import Any, Final
from urllib.parse import urlsplit

from .contracts import DEFAULT_EXCLUDED_SITES, MAX_BATCH_BYTES, MAX_BATCH_EVENTS, MAX_EVENT_BYTES

SECTION: Final = "mordred_activity"
_EXCLUDED_SITES: Final = "excluded_sites"
_HOST_LABELS_RE: Final = re.compile(r"^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$")

HISTORY_MAX_CHARS: Final = 1500
HISTORY_MAX_EPISODES: Final = 3
HISTORY_LOOKBACK_DAYS: Final = 90
HISTORY_SESSION_BUDGET_CHARS: Final = 8000
HISTORY_MAX_TOOL_BYTES: Final = 4096


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
    #: Master switch: Hermes uses the history in ordinary conversations and browser work (needs ``enabled``).
    history_enabled: bool = True
    #: Append a site's history to successful ``browser_navigate`` results.
    history_on_navigate: bool = True
    #: Add human-authored history to the turn when the user message names a host or shares task terms.
    history_turn_context: bool = True
    #: Record Hermes's own browser tool calls (parsed; no effect until that phase ships).
    history_capture_hermes: bool = True
    #: Record ``correct:`` messages typed in Hermes chat (parsed; no effect until that phase ships).
    history_chat_corrections: bool = True
    #: Characters per injected block.
    history_max_chars: int = HISTORY_MAX_CHARS
    #: Episodes per injected block.
    history_max_episodes: int = HISTORY_MAX_EPISODES
    #: Episodes older than this are never injected (the lookup tools may still return them).
    history_lookback_days: int = HISTORY_LOOKBACK_DAYS
    #: Characters injected per Hermes session; afterwards only the lookup tools answer.
    history_session_budget_chars: int = HISTORY_SESSION_BUDGET_CHARS
    #: UTF-8 bytes per lookup-tool result.
    history_max_tool_bytes: int = HISTORY_MAX_TOOL_BYTES
    warnings: tuple[str, ...] = ()

    @property
    def collecting(self) -> bool:
        return self.enabled and self.collection_enabled

    @property
    def excluded_sites_valid(self) -> bool:
        """``excluded_sites`` was absent or valid; an invalid value never silently means "exclude nothing"."""
        return f"invalid value for {_EXCLUDED_SITES}" not in self.warnings

    @property
    def history_active(self) -> bool:
        """Hermes may use the history: the feature and the master switch are on and the exclusions are valid."""
        return self.enabled and self.history_enabled and self.excluded_sites_valid

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


def _int_range(low: int, high: int) -> Callable[[Any], Any]:
    """An integer within ``[low, high]``; anything else is invalid."""

    def parse(raw: Any) -> Any:
        ok = isinstance(raw, int) and not isinstance(raw, bool) and low <= raw <= high
        return raw if ok else _INVALID

    return parse


def _site(entry: Any) -> str | None:
    """One exclusion as a bare lower-case host: ``https://Bank.example/x``, ``*.bank.example``,
    ``bank.example.`` and ``bank.example:443`` all become ``bank.example``; ``None`` when it names no host."""
    if not isinstance(entry, str) or not entry.strip():
        return None
    text = entry.strip().lower().removeprefix("*.")
    try:
        host = urlsplit(text if "://" in text else "//" + text).hostname
        host = (host or "").rstrip(".").encode("idna").decode("ascii")
    except (ValueError, UnicodeError):
        return None
    return host if _HOST_LABELS_RE.fullmatch(host) else None


def _sites(raw: Any) -> Any:
    """Every entry must name a host; one that does not makes the whole value invalid (never a partial list)."""
    if not isinstance(raw, list):
        return _INVALID
    hosts = [_site(entry) for entry in raw]
    if any(host is None for host in hosts):
        return _INVALID
    return frozenset(host for host in hosts if host is not None)


_PARSERS: Final[Mapping[str, Callable[[Any], Any]]] = {
    "enabled": _bool,
    "collection_enabled": _bool,
    "excluded_sites": _sites,
    "retention_raw_days": _non_negative_int,
    "max_batch_events": _capped_int(MAX_BATCH_EVENTS),
    "max_event_bytes": _capped_int(MAX_EVENT_BYTES),
    "max_batch_bytes": _capped_int(MAX_BATCH_BYTES),
    "history_enabled": _bool,
    "history_on_navigate": _bool,
    "history_turn_context": _bool,
    "history_capture_hermes": _bool,
    "history_chat_corrections": _bool,
    # Hermes spills a hook context above 10,000 characters to a file; a block stays below that.
    "history_max_chars": _int_range(200, 8000),
    "history_max_episodes": _int_range(1, 10),
    "history_lookback_days": _int_range(1, 3650),
    "history_session_budget_chars": _int_range(0, 1_000_000),
    "history_max_tool_bytes": _int_range(1024, 65536),
}
