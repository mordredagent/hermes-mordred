"""Dry-run report of a mail import: counts only.

The report never contains a subject, body, display name or recipient. The
only strings besides fixed keys are Gmail label names (so the owner can find a
localised Sent label) and the addresses of Sent-labelled mail whose ``From`` is
not in the own-address list (addresses only, never names). Do not forward the
report to an audit log or a model; audit events carry numeric counts only.
"""

from __future__ import annotations

import json
from collections import Counter
from collections.abc import Mapping
from dataclasses import asdict, dataclass, field
from typing import Final

__all__ = ["DryRunReport"]

_MAX_LABELS: Final = 100
_MAX_ADDRESSES: Final = 50


def _top(counter: Mapping[str, int], limit: int | None = None) -> dict[str, int]:
    items = sorted(((key, value) for key, value in counter.items() if value), key=lambda kv: (-kv[1], kv[0]))
    return dict(items[:limit] if limit is not None else items)


def _prefixed(stats: Mapping[str, int], prefix: str) -> dict[str, int]:
    return _top({key[len(prefix) :]: value for key, value in stats.items() if key.startswith(prefix)})


@dataclass(frozen=True, kw_only=True)
class DryRunReport:
    parsed: int = 0
    conversations: int = 0
    skipped: dict[str, int] = field(default_factory=dict)
    duplicates: int = 0
    conflicts: int = 0
    labels: dict[str, int] = field(default_factory=dict)
    owner_classes: dict[str, int] = field(default_factory=dict)  # "<owner_class>:<evidence code>"
    sent_from_not_own: tuple[str, ...] = ()
    sender_kinds: dict[str, int] = field(default_factory=dict)
    threads_by_method: dict[str, int] = field(default_factory=dict)
    partial_threads: int = 0
    parts_by_kind: dict[str, int] = field(default_factory=dict)
    part_authors: dict[str, int] = field(default_factory=dict)  # "<kind>:<author evidence>"
    quote_forward_parts: int = 0
    unknown_author_quote_forward_parts: int = 0
    marker_locales: dict[str, int] = field(default_factory=dict)
    unknown_dates: int = 0
    html_only: int = 0
    charset_fallbacks: int = 0
    truncations: int = 0
    attachment_kinds: dict[str, int] = field(default_factory=dict)
    defects: dict[str, int] = field(default_factory=dict)
    errors: dict[str, int] = field(default_factory=dict)

    @property
    def unknown_author_share(self) -> float:
        """Share of quoted/forwarded parts whose author is unknown (0.0 when there are none)."""
        if not self.quote_forward_parts:
            return 0.0
        return round(self.unknown_author_quote_forward_parts / self.quote_forward_parts, 4)

    @classmethod
    def from_counts(
        cls,
        *,
        stats: Mapping[str, int],
        tallies: Mapping[str, Counter[str]],
        labels: Counter[str],
        sent_from_not_own: set[str],
        scalars: Mapping[str, int],
    ) -> DryRunReport:
        """Assemble from the importer's counters (``stats`` uses ``prefix:key`` names)."""
        return cls(
            parsed=scalars.get("parsed", 0),
            conversations=scalars.get("conversations", 0),
            skipped=_top(tallies.get("skipped", Counter())),
            duplicates=scalars.get("duplicates", 0),
            conflicts=scalars.get("conflicts", 0),
            labels=_top(labels, _MAX_LABELS),
            owner_classes=_top(tallies.get("owner_classes", Counter())),
            sent_from_not_own=tuple(sorted(sent_from_not_own)[:_MAX_ADDRESSES]),
            sender_kinds=_top(tallies.get("sender_kinds", Counter())),
            threads_by_method=_top(tallies.get("threads_by_method", Counter())),
            partial_threads=scalars.get("partial_threads", 0),
            parts_by_kind=_top(tallies.get("parts_by_kind", Counter())),
            part_authors=_top(tallies.get("part_authors", Counter())),
            quote_forward_parts=scalars.get("quote_forward_parts", 0),
            unknown_author_quote_forward_parts=scalars.get("unknown_author_quote_forward_parts", 0),
            marker_locales=_prefixed(stats, "marker:"),
            unknown_dates=stats.get("unknown_date", 0),
            html_only=stats.get("html_only", 0),
            charset_fallbacks=stats.get("charset_fallback", 0),
            truncations=stats.get("truncated", 0),
            attachment_kinds=_prefixed(stats, "attachment:"),
            defects=_prefixed(stats, "defect:"),
            errors={**_prefixed(stats, "error:"), **_prefixed(stats, "invalid_record:")},
        )

    def as_dict(self) -> dict[str, object]:
        data = asdict(self)
        data["sent_from_not_own"] = list(self.sent_from_not_own)
        data["unknown_author_share"] = self.unknown_author_share
        return data

    def as_json(self) -> str:
        return json.dumps(self.as_dict(), ensure_ascii=False, sort_keys=True, indent=2)

    def as_text(self) -> str:
        lines: list[str] = []
        for key, value in self.as_dict().items():
            if isinstance(value, dict):
                lines.append(f"{key}:" + ("" if value else " none"))
                lines.extend(f"  {name}: {count}" for name, count in value.items())
            elif isinstance(value, list):
                lines.append(f"{key}:" + ("" if value else " none"))
                lines.extend(f"  {item}" for item in value)
            else:
                lines.append(f"{key}: {value}")
        return "\n".join(lines)
