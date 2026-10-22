"""File-based mail collector (library only; standard library, no plugin component).

Reads Gmail Takeout mbox files, single ``.eml`` files and directories of
``.eml`` read-only, and plans canonical import records:

- :mod:`.source` — streaming ``rb`` mbox splitter and ``.eml`` readers.
- :mod:`.headers` — RFC 2047, addresses, dates, Message-IDs, Gmail labels.
- :mod:`.owner` — :func:`classify` (owner class + evidence code per message).
- :mod:`.threading` — Gmail thread ids, reference union-find, guarded subjects.
- :mod:`.body` / :mod:`.segment` — body text, then authored/quoted/forwarded segments.
- :mod:`.link` — quote-authorship linking (owner only when linked).
- :mod:`.normalize` — one raw message → :class:`~..records.ImportMessage`.
- :mod:`.importer` — :func:`plan_import` (two passes) and :class:`ImportPlan`.

Nothing here writes to the store, logs content, or creates temporary files.
"""

from __future__ import annotations

from .importer import ImportPlan, PlannedThread, plan_import
from .link import IndexEntry, LinkedAuthor, Linker, MetadataIndex, QuoteClaim, chain_linkers, quote_contained
from .normalize import NormalizeContext, NormalizedMessage, Skipped, normalize
from .owner import Classification, OwnAddresses, classify
from .report import DryRunReport
from .source import EmlBytes, EmlSource, MailSource, MboxBytes, MboxSource, RawMessage, SourceError

__all__ = [
    "Classification",
    "DryRunReport",
    "EmlBytes",
    "EmlSource",
    "ImportPlan",
    "IndexEntry",
    "LinkedAuthor",
    "Linker",
    "MailSource",
    "MboxBytes",
    "MboxSource",
    "MetadataIndex",
    "NormalizeContext",
    "NormalizedMessage",
    "OwnAddresses",
    "PlannedThread",
    "QuoteClaim",
    "RawMessage",
    "Skipped",
    "SourceError",
    "chain_linkers",
    "classify",
    "normalize",
    "plan_import",
    "quote_contained",
]
