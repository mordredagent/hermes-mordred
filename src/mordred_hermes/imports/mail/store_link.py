"""Store-backed half of the mail collector: quote linking and own addresses in ``mordred.db``.

:class:`StoreLinker` is the :data:`~.link.Linker` the ``mail import`` CLI passes to
:func:`~.importer.plan_import`. It resolves a :class:`~.link.QuoteClaim` against the
*committed* mail records of ONE account, with exactly the in-plan rules of
:class:`~.link.MetadataIndex` (the importer consults the in-plan index first):

- ``linked_message_id`` — a referenced Message-ID belongs to an anchor record;
- ``linked_address_date`` — the claimed address is the anchor record's sender
  address and the claimed date is within :data:`~.link.LINK_WINDOW_SECONDS`;
- ``linked_text_hash`` — the quote text equals the authored text of exactly one
  record author.

Only anchor records (``account_owner`` with evidence in
:data:`~.link.ANCHOR_EVIDENCE`) can be linked to, and every answer is re-checked
with :func:`~.link.quote_contained` against the linked record's authored text, so
an altered quote never links. The anchor records are read once, on the first
claim, with a single :meth:`~..store.ImportStore.find_messages` call (one short
connection instead of one per quote). A store failure never raises into the
normaliser (which would count it as a parse error and drop the message): the
linker answers ``None`` from then on and records the content-free code in
:attr:`StoreLinker.error`, which the CLI turns into a failed run.

The own-address helpers keep an account's own addresses in
``import_accounts.own_addresses_json`` (the encrypted file; never
``config.yaml``). Nothing here logs; errors carry codes only.
"""

from __future__ import annotations

import json
import re
import sqlite3
from collections.abc import Iterable, Mapping
from typing import Any, Final

from ..records import OwnerClass, PartKind, Source, mail_conv_uid
from ..store import ImportRefused, ImportStore
from ._text import link_key
from .link import ANCHOR_EVIDENCE, IndexEntry, LinkedAuthor, MetadataIndex, QuoteClaim, quote_contained

__all__ = [
    "StoreLinker",
    "mail_store_status",
    "remember_own_addresses",
    "stored_own_addresses",
]

_SOURCE: Final = Source.MAIL.value
#: The importer's fallback id for a message without a usable Message-ID (never a reference target).
_FALLBACK_ID_RE: Final = re.compile(r"h:[0-9a-f]{32}")


def _error_code(exc: BaseException) -> str:
    code = getattr(exc, "code", None)
    return code if isinstance(code, str) and code else type(exc).__name__


class StoreLinker:
    """:data:`~.link.Linker` over one mail account's committed anchor records in an :class:`ImportStore`."""

    def __init__(self, store: ImportStore, account: str) -> None:
        mail_conv_uid(account, "probe")  # validates the account label (RecordError ``bad_account``)
        self._store = store
        self._account = account
        self._index: MetadataIndex | None = None
        self._keys: dict[str, str] = {}
        #: Content-free code of the store failure that disabled the linker, else ``None``.
        self.error: str | None = None

    def __repr__(self) -> str:
        state = "unloaded" if self._index is None else f"records={len(self._keys)}"
        return f"StoreLinker({state}, error={self.error})"

    @property
    def records(self) -> int:
        """Anchor records loaded so far (0 before the first claim)."""
        return len(self._keys)

    def __call__(self, claim: QuoteClaim) -> LinkedAuthor | None:
        index = self._load()
        if index is None:
            return None
        linked = index(claim)
        if linked is None or linked.original_ref is None:
            return None
        if not quote_contained(claim.text_key, self._keys.get(linked.original_ref, "")):
            return None
        return linked

    def _load(self) -> MetadataIndex | None:
        if self._index is not None or self.error is not None:
            return self._index
        try:
            stored = self._store.find_messages(_SOURCE, self._account, owner_class=OwnerClass.ACCOUNT_OWNER)
        except Exception as exc:  # store refusal or undecodable row: disable linking, report a code
            self.error = _error_code(exc)
            return None
        index = MetadataIndex()
        for item in stored:
            msg, part = item.message, item.part
            if part.part_kind is not PartKind.AUTHORED or msg.owner_evidence not in ANCHOR_EVIDENCE:
                continue
            if msg.source_uid in self._keys:
                continue  # one authored text per record (the first authored part)
            entry = IndexEntry(
                source_uid=msg.source_uid,
                message_id=None if _FALLBACK_ID_RE.fullmatch(msg.message_id) else msg.message_id,
                owner_class=msg.owner_class,
                sender_kind=msg.sender_kind,
                address=msg.sender_id,
                name=msg.sender_name,
                sent_at=msg.sent_at,
                text_key=link_key(part.text),
            )
            index.add(entry)
            self._keys[msg.source_uid] = entry.text_key
        self._index = index
        return index


# --- own addresses (``import_accounts``) ------------------------------------------------------


def _decode_addresses(raw: object) -> frozenset[str]:
    """The stored JSON list of addresses; anything else is a corrupt row (fail closed)."""
    try:
        value = json.loads(str(raw))
    except ValueError:
        raise ImportRefused("store_unavailable") from None
    if not isinstance(value, list) or not all(isinstance(item, str) and item for item in value):
        raise ImportRefused("store_unavailable")
    return frozenset(value)


def stored_own_addresses(store: ImportStore, account: str) -> frozenset[str]:
    """The own addresses recorded for mail ``account`` (empty when none are recorded)."""
    with store.connection() as conn:
        row = conn.execute(
            "SELECT own_addresses_json FROM import_accounts WHERE source = ? AND account = ?",
            (_SOURCE, account),
        ).fetchone()
    return frozenset() if row is None else _decode_addresses(row[0])


def remember_own_addresses(store: ImportStore, account: str, addresses: Iterable[str]) -> int:
    """Merge ``addresses`` into the recorded set of mail ``account`` (one transaction); returns its size."""
    mail_conv_uid(account, "probe")
    incoming = frozenset(address for address in addresses if address)
    with store.connection() as conn:
        conn.execute("BEGIN IMMEDIATE")
        try:
            row = conn.execute(
                "SELECT own_addresses_json FROM import_accounts WHERE source = ? AND account = ?",
                (_SOURCE, account),
            ).fetchone()
            merged = sorted(incoming | (frozenset() if row is None else _decode_addresses(row[0])))
            conn.execute(
                "INSERT OR REPLACE INTO import_accounts (source, account, own_addresses_json) VALUES (?, ?, ?)",
                (_SOURCE, account, json.dumps(merged, ensure_ascii=False, separators=(",", ":"))),
            )
            conn.execute("COMMIT")
        except BaseException:
            if conn.in_transaction:
                conn.rollback()
            raise
    return len(merged)


def _mail_runs(conn: sqlite3.Connection) -> tuple[dict[str, int], dict[str, Any] | None]:
    runs = {
        str(state): int(count)
        for state, count in conn.execute(
            "SELECT state, count(*) FROM import_runs WHERE source = ? GROUP BY state ORDER BY state", (_SOURCE,)
        )
    }
    last = conn.execute(
        "SELECT state, started_at, finished_at, counts_json FROM import_runs WHERE source = ? "
        "ORDER BY started_at DESC, rowid DESC LIMIT 1",
        (_SOURCE,),
    ).fetchone()
    if last is None:
        return runs, None
    try:
        counts = json.loads(str(last[3]))
    except ValueError:
        counts = {}
    return runs, {"state": str(last[0]), "started_at": last[1], "finished_at": last[2], "counts": counts}


def mail_store_status(store: ImportStore) -> dict[str, Any]:
    """Counts only: mail rows, mail runs, and the NUMBER of own addresses per account label."""
    summary = store.status()
    empty: Mapping[str, int] = {"conversations": 0, "messages": 0, "parts": 0, "uncommitted_messages": 0}
    with store.connection() as conn:
        runs, last_run = _mail_runs(conn)
        accounts = {
            str(account): len(_decode_addresses(raw))
            for account, raw in conn.execute(
                "SELECT account, own_addresses_json FROM import_accounts WHERE source = ? ORDER BY account",
                (_SOURCE,),
            )
        }
    return {
        "schema_version": summary["schema_version"],
        "mail": dict(summary["sources"].get(_SOURCE, empty)),
        "runs": runs,
        "last_run": last_run,
        "accounts": {account: {"own_addresses": count} for account, count in accounts.items()},
    }
