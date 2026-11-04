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
- :mod:`.store_link` — :class:`StoreLinker` (quote links to committed records) and the
  account's own addresses in ``import_accounts``; used by ``hermes-mordred mail import``.
- :mod:`.imap` / :mod:`.imap_sync` / :mod:`.secrets` — the read-only IMAP collector
  (``hermes-mordred mail setup|fetch`` and the Hermes tool ``mordred_mail_sync``);
  imported on use only (macOS, POSIX locking), never from this package's namespace.

Only :mod:`.store_link` touches the store (reads, and the own-address row). Nothing here
logs content or creates temporary files.
"""

from __future__ import annotations

from .importer import ImportPlan, PlannedThread, plan_import
from .link import IndexEntry, LinkedAuthor, Linker, MetadataIndex, QuoteClaim, chain_linkers, quote_contained
from .normalize import NormalizeContext, NormalizedMessage, Skipped, normalize
from .owner import Classification, OwnAddresses, classify
from .report import DryRunReport
from .source import (
    EmlBytes,
    EmlSource,
    MailSource,
    MboxBytes,
    MboxSource,
    RawMessage,
    SourceError,
    TrustedBytes,
    TrustedMeta,
)
from .store_link import StoreLinker, mail_store_status, remember_own_addresses, stored_own_addresses

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
    "StoreLinker",
    "TrustedBytes",
    "TrustedMeta",
    "chain_linkers",
    "classify",
    "mail_store_status",
    "normalize",
    "plan_import",
    "quote_contained",
    "remember_own_addresses",
    "stored_own_addresses",
]
