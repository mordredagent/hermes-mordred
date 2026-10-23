"""Quote-authorship linking: a quoted/forwarded part is the owner's only when linked.

A quote or forward *claims* an author (an attribution line or a forwarded
header). A claim naming an own address is not proof: anyone can type it. A
part becomes ``account_owner`` only when a :data:`Linker` resolves it to an
imported owner record that is a true Sent copy (owner evidence in
:data:`ANCHOR_EVIDENCE`; an ``own_address`` or ``list_rewrite`` record is
itself only a header claim and never anchors a link):

- ``linked_message_id`` — a Message-ID the container references (or the
  attached message's own id) belongs to an owner record AND the quote text is
  contained in that record's authored text;
- ``linked_address_date`` — the claimed own address and a claimed date within
  :data:`LINK_WINDOW_SECONDS` of an owner record AND containment;
- ``linked_text_hash`` — the quote text equals the authored text of exactly one
  record author.

Text comparison uses :func:`~._text.link_key` (NFKC, whitespace ignored), so
re-wrapped quotes still link but an altered quote does not. Containment needs
a quote key of at least :data:`MIN_QUOTE_KEY_CHARS` characters (a shorter
quote links only when it is the record's whole text). The store-backed
linker of the CLI (PR 10) implements the same :data:`Linker` callable against
``import_parts``; :class:`MetadataIndex` is the in-plan implementation built
by the importer's first pass.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Final

from ..records import OwnerClass, PartKind, SenderKind
from .owner import canonical_address

__all__ = [
    "ANCHOR_EVIDENCE",
    "LINK_WINDOW_SECONDS",
    "MIN_QUOTE_KEY_CHARS",
    "IndexEntry",
    "LinkedAuthor",
    "Linker",
    "MetadataIndex",
    "QuoteClaim",
    "chain_linkers",
    "quote_contained",
    "text_digest",
]

LINK_WINDOW_SECONDS: Final = 600
#: A quote key (``link_key``: NFKC, no whitespace) shorter than this is contained in
#: almost any long text (``ok``, ``Thanks!``), so it links by containment only when it
#: equals the record's whole authored text.
MIN_QUOTE_KEY_CHARS: Final = 24
#: Owner evidence of the records a quote may link to: Gmail filed the copy as sent.
#: ``own_address``/``list_rewrite`` owners rest on headers anyone can type.
ANCHOR_EVIDENCE: Final = frozenset({"gmail_label_sent"})


@dataclass(frozen=True, kw_only=True)
class QuoteClaim:
    """Everything a linker may use to resolve one quoted or forwarded part."""

    container_uid: str  # source uid of the message carrying the quote
    kind: PartKind  # QUOTED or FORWARDED
    claimed_address: str | None  # lowercased address from the attribution / forwarded header
    claimed_name: str  # display name (never decides identity)
    claimed_at: int | None  # claimed original date (unix seconds)
    claimed_message_id: str | None  # an attached message's own Message-ID
    reply_message_ids: tuple[str, ...]  # container In-Reply-To, then References nearest first
    text: str  # the part text as it will be stored
    text_key: str  # link_key(text)
    text_digest: str  # text_digest(text_key)


@dataclass(frozen=True, kw_only=True)
class LinkedAuthor:
    """A linker's answer: the imported record the quote belongs to."""

    owner_class: OwnerClass
    sender_kind: SenderKind
    author_id: str | None
    author_name: str
    evidence_code: str  # linked_message_id | linked_address_date | linked_text_hash
    original_sent_at: int | None
    original_ref: str | None  # source uid of the linked record


Linker = Callable[[QuoteClaim], LinkedAuthor | None]


def text_digest(key: str) -> str:
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


def quote_contained(quote_key: str, record_key: str) -> bool:
    """True when the (link-normalised) quote is a substring of the record's authored text.

    A key shorter than :data:`MIN_QUOTE_KEY_CHARS` must equal ``record_key``.
    """
    if not quote_key or not record_key:
        return False
    if len(quote_key) < MIN_QUOTE_KEY_CHARS:
        return quote_key == record_key
    return quote_key in record_key


@dataclass(frozen=True, kw_only=True)
class IndexEntry:
    """Pass-one metadata of one imported record (authored text only for owner records)."""

    source_uid: str
    message_id: str | None
    owner_class: OwnerClass
    sender_kind: SenderKind
    address: str | None
    name: str
    sent_at: int | None
    text_key: str


@dataclass
class MetadataIndex:
    """In-plan :data:`Linker` over the records of one import (owner records only).

    The caller adds anchor records only (:data:`ANCHOR_EVIDENCE`); ``add``
    itself rejects any record that is not ``account_owner``.
    """

    window_seconds: int = LINK_WINDOW_SECONDS
    _by_id: dict[str, IndexEntry] = field(default_factory=dict, repr=False)
    _by_address: dict[str, list[IndexEntry]] = field(default_factory=dict, repr=False)
    _by_digest: dict[str, list[IndexEntry]] = field(default_factory=dict, repr=False)

    def __repr__(self) -> str:
        return f"MetadataIndex(texts={len(self._by_digest)})"

    def add(self, entry: IndexEntry) -> None:
        if entry.owner_class is not OwnerClass.ACCOUNT_OWNER or not entry.text_key:
            return
        if entry.message_id:
            self._by_id.setdefault(entry.message_id, entry)
        if entry.address:
            self._by_address.setdefault(canonical_address(entry.address), []).append(entry)
        self._by_digest.setdefault(text_digest(entry.text_key), []).append(entry)

    def __call__(self, claim: QuoteClaim) -> LinkedAuthor | None:
        return self._by_message_id(claim) or self._by_address_date(claim) or self._by_text(claim)

    def _by_message_id(self, claim: QuoteClaim) -> LinkedAuthor | None:
        ids = (claim.claimed_message_id, *claim.reply_message_ids)
        for message_id in ids:
            entry = self._by_id.get(message_id) if message_id else None
            if (
                entry is not None
                and entry.source_uid != claim.container_uid
                and quote_contained(claim.text_key, entry.text_key)
            ):
                return _linked(entry, "linked_message_id")
        return None

    def _by_address_date(self, claim: QuoteClaim) -> LinkedAuthor | None:
        if not claim.claimed_address or claim.claimed_at is None:
            return None
        for entry in self._by_address.get(canonical_address(claim.claimed_address), []):
            if entry.sent_at is None or entry.source_uid == claim.container_uid:
                continue
            close = abs(entry.sent_at - claim.claimed_at) <= self.window_seconds
            if close and quote_contained(claim.text_key, entry.text_key):
                return _linked(entry, "linked_address_date")
        return None

    def _by_text(self, claim: QuoteClaim) -> LinkedAuthor | None:
        entries = [e for e in self._by_digest.get(claim.text_digest, []) if e.source_uid != claim.container_uid]
        authors = {(entry.owner_class, canonical_address(entry.address or "")) for entry in entries}
        if len(authors) != 1:
            return None  # none, or the same text from different people: ambiguous
        return _linked(min(entries, key=lambda entry: entry.source_uid), "linked_text_hash")


def _linked(entry: IndexEntry, code: str) -> LinkedAuthor:
    return LinkedAuthor(
        owner_class=entry.owner_class,
        sender_kind=entry.sender_kind,
        author_id=entry.address,
        author_name=entry.name,
        evidence_code=code,
        original_sent_at=entry.sent_at,
        original_ref=entry.source_uid,
    )


def chain_linkers(*linkers: Linker | None) -> Linker | None:
    """The first non-``None`` answer of ``linkers`` (``None`` entries are ignored)."""
    active = [linker for linker in linkers if linker is not None]
    if not active:
        return None

    def chained(claim: QuoteClaim) -> LinkedAuthor | None:
        for linker in active:
            found = linker(claim)
            if found is not None:
                return found
        return None

    return chained
