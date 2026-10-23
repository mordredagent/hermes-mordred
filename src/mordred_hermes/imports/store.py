"""``ImportStore``: imported conversations, messages and parts in ``mordred.db`` (``import_*`` v2).

Mirrors :class:`mordred_hermes.activity.store.ActivityStore`: :func:`open_import_store`
runs the activity protection gate and passes the gate's keyed opener; tests pass
a plain-SQLite opener (the only test seam). The tables share the activity
store's encrypted file but keep their own ``import_meta``; ``activity_*`` is never touched.
:func:`open_import_store_readonly` is the status path (the Desktop page's polling): it
creates, initialises, upgrades and unlocks nothing (see its docstring).

Every public method runs one short connection and one transaction (``BEGIN IMMEDIATE``
for writes, busy timeout 2 s). SQLite failures become :class:`ImportRefused` (``busy``,
``disk_full``, ``store_unavailable``); nothing is retried and no exception text carries
imported content. :data:`REFUSAL_CODES` is the closed set of codes a refusal from this
module (its gate included) carries; :func:`refusal_code` maps anything else to
``store_unavailable``. Records are validated before any write; a record that does not fit
the store (unknown conversation, wrong source for the run) raises
:class:`~.records.RecordError` inside the transaction, which rolls it back.

Runs are the durable staging journal: :meth:`ImportStore.write_thread` writes under an
``open`` run, and every reader only sees rows whose run is ``committed``. A ``dry_run``
run executes the same writes and rolls them back, so its :class:`WriteResult` is exactly
what a real run would report.

Idempotency on ``source_uid``, decided per message in this order:

1. not stored, or last written by another run that never committed: ``inserted``;
2. an incoming ``legacy`` record never replaces a non-legacy one: ``duplicates``;
3. a non-legacy record replaces a ``legacy`` one (provenance upgrade): ``revised``;
4. Sent evidence wins (:data:`SENT_EVIDENCE_RANK`): a copy with stronger sent-copy
   owner evidence replaces the stored record even when the bytes are identical
   (``revised``: an INBOX copy later seen in Sent, or with Gmail's ``\\Sent``),
   and a copy with weaker evidence never replaces a stored sent copy, whatever
   its revision (``duplicates``: a changed received copy keeps the Sent record);
5. same ``source_revision`` and ``content_digest``: ``duplicates``;
6. a different ``source_revision``: ``revised`` (the row and all its parts are replaced);
7. same ``source_revision``, different ``content_digest``: ``conflicts``, nothing overwritten.

Backup and restore: ``ActivityStore.backup`` / ``restore`` copy the whole
``mordred.db`` file, ``import_*`` tables included; there is no second copy path.

``import_meta`` also carries small content-free markers (:meth:`ImportStore.get_meta` /
:meth:`ImportStore.set_meta`); the store's own keys (:data:`RESERVED_META_KEYS`) are never
settable that way. :data:`TELEGRAM_RETIRED_ACCOUNT` names the Telegram account whose
history lives here, so a reader can choose ``mordred.db`` without unsealing the Telegram
credentials to read ``index.enc``.

Batched collectors (the IMAP mail sync) write and publish each batch with
:meth:`ImportStore.write_batch`: the batch's messages, the merge of its
conversation rows (participants are unioned, ``last_message_at`` is the
maximum, the stored title is kept, ``message_count`` is recounted from
committed rows), the run's commit and the collector's ``import_meta`` cursor in
ONE ``BEGIN IMMEDIATE`` transaction. A failed batch therefore leaves every
published row, revision and conversation field exactly as it was, and a
concurrent reader sees the state before or after the batch, never between.
A crashed writer's ``open`` runs are reclaimed with
:meth:`ImportStore.fail_open_runs`.

Mail thread reconciliation (``write_batch(..., refs=...)``): the batch's
referenced Message-IDs (``In-Reply-To``, ``References``; at most the last
``mail.merge_guard.MAX_MERGE_REFS``, the nearest ancestors) are kept in ``import_mail_refs``.
They are taken from a copy that is written (they replace the stored ones) and
from an identical copy of a stored message (same ``source_revision`` and
``content_digest``, so the same headers), which records them only when the
stored message has none yet (a row written before schema v2: a re-fetch, e.g.
``--since``, attaches them). A rejected different copy (a weaker duplicate, a
conflict) contributes no reference at all, so it can connect nothing
(:meth:`ImportStore.classify_incoming` tells the importer the same decisions
beforehand, so such a copy does not join anything while a batch is grouped
either). For every message M of the batch, the conversations of the stored
messages M references (its parents, committed or of this batch) and of the
committed messages that reference M (replies fetched in an earlier batch) are
merged with M's own into ONE survivor, in the batch's transaction
(:meth:`ImportStore.merge_conversations`: message rows repointed, participants
unioned, ``last_message_at`` the maximum, ``message_count`` recounted, the
emptied rows dropped). The batch's own reply edges were weighed by its grouping
under the same guard, and are weighed again here from the replying message's
side only. ``References`` is attacker-controlled, so the merge is guarded by
``mail.merge_guard.fold_plan`` (the same function guards a batch's grouping): a
conversation is folded only when it shares a participant with M's (a sender id
or a recipient address; the account owner, marked or recorded in
``import_accounts``, never counts), and when more than one of the
conversations to fold already holds several messages nothing is merged for M.
Each message a guard held back counts once in ``BatchResult.merge_skipped``.
The survivor is the conversation holding the earliest-dated message (unknown
dates last, then the smaller ``conv_uid``). A conversation keyed by a Gmail
thread id (``g.``, see ``mail.threading.default_thread_key``) is
authoritative and counts as established: it is never folded into another, two
of them never merge, and when it is the only established conversation involved
it is the survivor. So a reply chain fetched in any order (C, then B, then A) ends in
one conversation, and two threads that never reference each other stay apart.

Lease guards (the IMAP fetch's worker): :meth:`ImportStore.write_batch`,
:meth:`ImportStore.set_meta`, :meth:`ImportStore.run_begin` and
:meth:`ImportStore.fail_open_runs` take a ``guard`` that runs INSIDE the write
transaction, right after ``BEGIN IMMEDIATE`` (and, for ``write_batch``, before
the run state is checked): what it raises rolls the transaction back. A fetch
whose caller revoked it is thus refused by the revocation flag even while its
run is still open, and by the run state once the run is marked failed.

The lower-level pieces stay available:
:meth:`ImportStore.commit_batch` publishes a run already written with
:meth:`ImportStore.write_thread` together with a cursor, and
``write_thread(..., merge_conversation=True)`` merges a conversation row, but
each ``write_thread`` is its own transaction, so only :meth:`write_batch`
keeps a revised row and the merged metadata unpublished until the batch is.
"""

from __future__ import annotations

import contextlib
import json
import os
import re
import secrets
import sqlite3
import stat
import sys
import threading
import time
from collections import Counter
from collections.abc import Callable, Iterable, Iterator, Mapping, Sequence
from dataclasses import asdict, dataclass, replace
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final, NamedTuple, cast

from ..activity._gate import (
    ActivityRefused,
    Refusal,
    check_protection,
    keyed_opener,
    refusal,
    verify_keyed_connection,
)
from ..activity.store import BUSY_TIMEOUT_S
from . import _schema
from .records import (
    ConversationKind,
    ImportConversation,
    ImportMessage,
    ImportPart,
    OwnerClass,
    Participant,
    PartKind,
    ProvenanceQuality,
    RecordError,
    SenderKind,
    Source,
    source_of,
    validate_conversation,
    validate_message,
)

if TYPE_CHECKING:  # the mail package imports this module; the guard is imported where it is used
    from .mail.merge_guard import GroupFacts

__all__ = [
    "MAX_NEIGHBORS",
    "MAX_SEARCH_LIMIT",
    "REFUSAL_CODES",
    "RESERVED_META_KEYS",
    "SENT_EVIDENCE_RANK",
    "SUPPORTED_SCHEMA_VERSION",
    "TELEGRAM_RETIRED_ACCOUNT",
    "BatchResult",
    "ImportMeta",
    "ImportRefused",
    "ImportStore",
    "IncomingCopy",
    "ReadOnlyImportStore",
    "SearchHit",
    "StoredPart",
    "WriteGuard",
    "WriteResult",
    "open_import_store",
    "open_import_store_readonly",
    "refusal_code",
]

SUPPORTED_SCHEMA_VERSION: Final = _schema.SCHEMA_VERSION
MAX_SEARCH_LIMIT: Final = 500
MAX_NEIGHBORS: Final = 50
#: FTS5 ``trigram`` needs three characters to match; shorter terms fall back to ``LIKE``.
_TRIGRAM: Final = 3
_MAX_TERMS: Final = 32
_CHUNK: Final = 500  # bound on ``IN (...)`` parameters per statement
_COUNT_KEY_RE: Final = re.compile(r"[a-z][a-z0-9_]{0,63}")
_WRITES: Final = frozenset({"inserted", "revised"})
#: ``import_meta`` keys only the store itself writes (``store_generation`` mirrors the activity store's).
RESERVED_META_KEYS: Final = frozenset({"schema_version", "profile_home", "store_generation"})
#: Marker key: the Telegram account id (decimal) whose history is retired to ``mordred.db``.
TELEGRAM_RETIRED_ACCOUNT: Final = "telegram.retired_account"
_META_KEY_RE: Final = re.compile(r"[a-z][a-z0-9_]{0,31}(?:\.[a-z][a-z0-9_]{0,31}){0,3}")
_MAX_META_VALUE: Final = 256
#: Upper bound on participants kept on a merged conversation row.
_MAX_MERGED_PARTICIPANTS: Final = 256
#: A mail conversation keyed by a Gmail thread id (``mail.threading.default_thread_key``) is never folded away.
_GMAIL_THREAD_PREFIX: Final = "g."
_MAX_REF_CHARS: Final = 1024
#: Joins of message ``m`` onto its run ``r`` and conversation ``c``, and the scopes a reconciliation looks in:
#: parents among rows of committed runs or of the run being written, replies among committed rows (a reply
#: of the batch itself is weighed from its own side), of one source and account.
_RUN_AND_CONV: Final = (
    "JOIN import_runs r ON r.run_id = m.run_id JOIN import_conversations c ON c.conv_uid = m.conv_uid"
)
#: What :func:`_decision` weighs of a stored row ``m`` (then: written by the same run, and its run's state ``r``).
_DECISION_COLUMNS: Final = "m.source_revision, m.content_digest, m.provenance_quality, m.owner_evidence"
_IN_SCOPE: Final = "(r.state = 'committed' OR m.run_id = ?) AND c.source = ? AND c.source_account = ?"
_COMMITTED_SCOPE: Final = "r.state = 'committed' AND c.source = ? AND c.source_account = ?"
#: Owner evidence of a sent copy, by strength ("Sent evidence wins", rule 4 above): Gmail's
#: ``\Sent`` system label (the server vouches for authorship) over a generic server's sent
#: folder (it names its purpose); every other evidence ranks 0. Mirrors ``mail.owner.SENT_EVIDENCE``.
SENT_EVIDENCE_RANK: Final[Mapping[str, int]] = {"gmail_label_sent": 2, "imap_sent_folder": 1}

Opener = Callable[[Path], sqlite3.Connection]
CopyCheck = Callable[[Path], Refusal | None]

_DETAILS: Final = {
    "unsupported_platform": "the import store requires macOS database encryption",
    "busy": "the import store is busy",
    "disk_full": "the disk holding the import store is full",
    "store_unavailable": "the import store is unavailable",
    "schema_newer": "the import store was written by a newer Mordred",
    "profile_mismatch": "the import store belongs to another Hermes profile",
    "unkeyed_connection": "the import store connection is not keyed",
    "plaintext_store": "the import store is readable without the database key",
    "run_not_open": "the import run is not open",
    "conflict": "the conversation is already stored for another source account",
    "store_uninitialised": "the import store has not been created yet",
}
#: Every code an :class:`ImportRefused` of this module carries: the protection gate's, the store's own
#: (``busy``, ``disk_full``, ``store_unavailable`` and the binding/schema codes) and the read-only path's.
REFUSAL_CODES: Final = frozenset(
    {
        "unsupported_platform",
        "conversion_pending",
        "not_armed",
        "unprotected_process",
        "no_key",
        "unkeyed_connection",
        "plaintext_store",
        "profile_mismatch",
        "schema_newer",
        "busy",
        "disk_full",
        "store_unavailable",
        "store_uninitialised",
        "run_not_open",
        "conflict",
    }
)

#: Record fields in column order; ``participants`` / ``recipients`` are stored as ``*_json``.
_CONV_FIELDS: Final = (
    "conv_uid", "source", "source_account", "conversation_id", "kind", "title", "participants",
    "last_message_at", "message_count", "archived", "sync_cursor", "record_version",
)  # fmt: skip
_MESSAGE_FIELDS: Final = (
    "source_uid", "conv_uid", "message_id", "sent_at", "imported_at", "sender_kind", "sender_id", "sender_name",
    "owner_class", "owner_evidence", "recipients", "reply_to_uid", "media", "provenance_quality",
    "source_revision", "record_version", "content_digest",
)  # fmt: skip
_PART_FIELDS: Final = (
    "part_uid", "source_uid", "ordinal", "part_kind", "author_kind", "author_id", "author_name",
    "author_owner_class", "author_evidence", "original_sent_at", "original_ref", "text", "provenance_quality",
)  # fmt: skip


def _columns(fields: Sequence[str]) -> str:
    return ", ".join(f"{field}_json" if field in ("participants", "recipients") else field for field in fields)


_CONV_COLUMNS: Final = _columns(_CONV_FIELDS)
_MESSAGE_COLUMNS: Final = _columns(_MESSAGE_FIELDS)
_PART_COLUMNS: Final = _columns(_PART_FIELDS)
#: Messages whose run is committed (``FROM`` form), and the same joined onto parts ``p``.
_COMMITTED_MESSAGES: Final = "import_messages m JOIN import_runs r ON r.run_id = m.run_id AND r.state = 'committed'"
_MESSAGE_OF_PART: Final = (
    "JOIN import_messages m ON m.source_uid = p.source_uid "
    "JOIN import_runs r ON r.run_id = m.run_id AND r.state = 'committed'"
)
_COMMITTED_PARTS: Final = f"import_parts p {_MESSAGE_OF_PART}"
#: Messages of one conversation in reading order (unknown dates last), the anchor's position, and its window.
_NEIGHBOR_SQL: Final = f"""
    WITH ordered AS (
        SELECT m.source_uid, row_number() OVER (
            ORDER BY m.sent_at IS NULL, m.sent_at, CAST(m.message_id AS INTEGER), m.message_id
        ) AS pos
        FROM {_COMMITTED_MESSAGES}
        WHERE m.conv_uid = ?
    ), anchor AS (SELECT pos FROM ordered WHERE source_uid = ?)
    SELECT ordered.source_uid FROM ordered, anchor
    WHERE ordered.pos BETWEEN anchor.pos - ? AND anchor.pos + ?
    ORDER BY ordered.pos
"""


class ImportRefused(Exception):
    """The import store cannot serve this call now; ``code`` is stable and content-free."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.refusal = Refusal(code, _DETAILS.get(code) or refusal(code).detail)

    @property
    def code(self) -> str:
        return self.refusal.code


@dataclass(frozen=True)
class ImportMeta:
    schema_version: int
    profile_home: str


@dataclass(frozen=True)
class WriteResult:
    inserted: int
    duplicates: int
    revised: int
    conflicts: int


@dataclass(frozen=True)
class BatchResult:
    """What :meth:`ImportStore.write_batch` wrote; the batch is published (its run is committed)."""

    inserted: int
    duplicates: int
    revised: int
    conflicts: int
    #: Messages whose reference edges were not (all) followed: the merge guards of the module docstring.
    merge_skipped: int = 0

    def counts(self) -> dict[str, int]:
        return {
            "inserted": self.inserted,
            "duplicates": self.duplicates,
            "revised": self.revised,
            "conflicts": self.conflicts,
            "merge_skipped": self.merge_skipped,
        }


class IncomingCopy(NamedTuple):
    """What :meth:`ImportStore.classify_incoming` needs to know about a copy before it is normalised."""

    source_uid: str
    source_revision: str | None
    provenance_quality: str
    owner_evidence: str
    content_digest: str | None = None  # unknown before normalisation: an unchanged revision is then a duplicate


#: A write guard: called inside a write transaction (right after ``BEGIN IMMEDIATE``); what it raises rolls back.
WriteGuard = Callable[[], None]


@dataclass(frozen=True)
class SearchHit:
    part_uid: str
    source_uid: str
    conv_uid: str
    #: FTS5 ``bm25`` (lower is a better match); ``0.0`` when no term used the full-text index.
    rank: float


class StoredPart(NamedTuple):
    conversation: ImportConversation
    message: ImportMessage
    part: ImportPart


# --- errors -----------------------------------------------------------------------------------


def _db_errors() -> tuple[type[BaseException], ...]:
    """The stdlib's and, once installed, the SQLCipher replacement's error base classes."""
    current = sys.modules.get("sqlite3", sqlite3)
    return (sqlite3.Error, getattr(current, "Error", sqlite3.Error))


def _classify(exc: BaseException) -> str:
    text = str(exc).lower()
    if "locked" in text or "busy" in text:
        return "busy"
    if "full" in text:
        return "disk_full"
    return "store_unavailable"


@contextlib.contextmanager
def _refusing() -> Iterator[None]:
    try:
        yield
    except ActivityRefused as exc:  # the gate's opener refused an unkeyed connection
        raise ImportRefused(exc.code) from None
    except _db_errors() as exc:
        raise ImportRefused(_classify(exc)) from None


# --- row mapping ------------------------------------------------------------------------------


def _source_value(source: Source | str) -> str:
    try:
        return Source(source).value
    except ValueError:
        raise RecordError("unknown_enum") from None


def _participants_json(participants: Iterable[Participant]) -> str:
    return json.dumps([asdict(p) for p in participants], ensure_ascii=False, separators=(",", ":"))


def _participants(text: str) -> tuple[Participant, ...]:
    decode: dict[str, Callable[[Any], Any]] = {"kind": SenderKind, "owner_class": OwnerClass}
    return tuple(
        Participant(**{k: decode[k](v) if k in decode else v for k, v in item.items()}) for item in json.loads(text)
    )


def _encode(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, tuple):
        return _participants_json(value)
    return value


def _values(record: object, fields: Sequence[str]) -> tuple[Any, ...]:
    return tuple(_encode(getattr(record, field)) for field in fields)


#: Column value -> record value, where they differ.
_DECODERS: Final[Mapping[str, Callable[[Any], Any]]] = {
    "source": Source,
    "kind": ConversationKind,
    "sender_kind": SenderKind,
    "author_kind": SenderKind,
    "owner_class": OwnerClass,
    "author_owner_class": OwnerClass,
    "part_kind": PartKind,
    "provenance_quality": ProvenanceQuality,
    "participants": _participants,
    "recipients": _participants,
    "archived": bool,
}


def _decoded(fields: Sequence[str], row: Sequence[Any]) -> dict[str, Any]:
    return {
        field: _DECODERS[field](value) if field in _DECODERS else value
        for field, value in zip(fields, row, strict=True)
    }


def _marks(count: int) -> str:
    return ", ".join("?" * count)


def _select_in(conn: sqlite3.Connection, prefix: str, values: Sequence[str]) -> list[Any]:
    """``<prefix> (?, ...)`` over ``values`` in bounded chunks."""
    rows: list[Any] = []
    for start in range(0, len(values), _CHUNK):
        chunk = values[start : start + _CHUNK]
        rows.extend(conn.execute(f"{prefix} ({_marks(len(chunk))})", chunk).fetchall())
    return rows


def _meta_key(key: str) -> str:
    """A settable ``import_meta`` key: dotted lowercase words, never one of :data:`RESERVED_META_KEYS`."""
    if not isinstance(key, str) or _META_KEY_RE.fullmatch(key) is None:
        raise RecordError("bad_meta")
    if key in RESERVED_META_KEYS:
        raise RecordError("reserved_meta_key")
    return key


def _meta_value(value: object) -> str:
    """A settable ``import_meta`` value: printable text of at most :data:`_MAX_META_VALUE` characters."""
    if not isinstance(value, str) or len(value) > _MAX_META_VALUE or not value.isprintable():
        raise RecordError("bad_meta")
    return value


def _participant_key(participant: Participant) -> tuple[str, str]:
    return (str(participant.owner_class), participant.stable_id or f"name:{participant.display_name}")


def _meta_updates(updates: Mapping[str, str | None]) -> dict[str, str | None]:
    """Validated cursor updates for one transaction (``None`` deletes the key)."""
    return {_meta_key(key): None if value is None else _meta_value(value) for key, value in updates.items()}


def _decision(stored: Sequence[Any] | None, incoming: IncomingCopy) -> str:
    """``inserted`` / ``duplicates`` / ``revised`` / ``conflicts`` (the module docstring's idempotency rules).

    ``stored`` is ``(source_revision, content_digest, provenance_quality, owner_evidence,
    written by the same run, run state)`` of the stored row, or ``None``.
    """
    if stored is None:
        return "inserted"
    revision, digest, quality, evidence, same_run, state = stored
    if not same_run and state != "committed":
        return "inserted"  # left behind by an open, failed or vanished run: reclaim it
    stored_legacy = quality == ProvenanceQuality.LEGACY.value
    incoming_legacy = ProvenanceQuality(incoming.provenance_quality) is ProvenanceQuality.LEGACY
    if incoming_legacy != stored_legacy:
        return "duplicates" if incoming_legacy else "revised"
    incoming_rank = SENT_EVIDENCE_RANK.get(incoming.owner_evidence, 0)
    stored_rank = SENT_EVIDENCE_RANK.get(str(evidence), 0)
    if incoming_rank != stored_rank:  # Sent evidence wins, in both directions
        return "revised" if incoming_rank > stored_rank else "duplicates"
    if revision == incoming.source_revision:
        unchanged = incoming.content_digest is None or digest == incoming.content_digest
        return "duplicates" if unchanged else "conflicts"
    return "revised"


def _checked_refs(
    refs: Mapping[str, Sequence[str]] | None, messages: Sequence[ImportMessage]
) -> dict[str, tuple[str, ...]] | None:
    """Referenced Message-IDs per message of the batch: printable, bounded, de-duplicated; else ``bad_refs``."""
    if refs is None:
        return None
    batch = {msg.source_uid for msg in messages}
    checked: dict[str, tuple[str, ...]] = {}
    for uid, ids in refs.items():
        if uid not in batch or isinstance(ids, str):
            raise RecordError("bad_refs")
        values = tuple(dict.fromkeys(ids))
        if not all(isinstance(v, str) and 0 < len(v) <= _MAX_REF_CHARS and v.isprintable() for v in values):
            raise RecordError("bad_refs")
        checked[uid] = values
    return checked


def _counts_json(counts: Mapping[str, int]) -> str:
    """Content-free run counters only: short lowercase keys, non-negative integers."""
    for key, value in counts.items():
        valid_key = isinstance(key, str) and _COUNT_KEY_RE.fullmatch(key) is not None
        if not valid_key or isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise RecordError("bad_counts")
    return json.dumps(dict(sorted(counts.items())), separators=(",", ":"))


# --- search query -----------------------------------------------------------------------------


def _terms(query: str | None) -> list[str]:
    """Whitespace-separated terms, deduplicated and bounded; NUL characters dropped."""
    if not query:
        return []
    words = (word.replace("\x00", "") for word in query.split())
    return list(dict.fromkeys(word for word in words if word))[:_MAX_TERMS]


def _phrase(term: str) -> str:
    """An FTS5 string literal: the term can never become an operator, column filter or prefix query."""
    return '"' + term.replace('"', '""') + '"'


def _like(term: str) -> str:
    escaped = term.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"%{escaped}%"


def _search_sql(
    terms: Sequence[str],
    *,
    conv_uids: Sequence[str] | None,
    since: int | None,
    until: int | None,
    source: str | None,
    limit: int,
) -> tuple[str, list[Any]]:
    indexed = [term for term in terms if len(term) >= _TRIGRAM]
    params: list[Any] = []
    where: list[str] = []
    if indexed:
        tables = f"import_parts_fts JOIN import_parts p ON p.id = import_parts_fts.rowid {_MESSAGE_OF_PART}"
        score, order = "bm25(import_parts_fts)", "score, m.sent_at DESC, p.part_uid"
        where.append("import_parts_fts MATCH ?")
        params.append(" AND ".join(_phrase(term) for term in indexed))
    else:
        tables = _COMMITTED_PARTS
        score, order = "0.0", "m.sent_at IS NULL, m.sent_at DESC, p.part_uid"
    for term in terms:
        if len(term) < _TRIGRAM:
            where.append("p.text LIKE ? ESCAPE '\\'")
            params.append(_like(term))
    if conv_uids is not None:
        where.append(f"m.conv_uid IN ({_marks(len(conv_uids))})")
        params.extend(conv_uids)
    for clause, value in (("m.sent_at >= ?", since), ("m.sent_at < ?", until), ("c.source = ?", source)):
        if value is not None:
            where.append(clause)
            params.append(value)
    sql = (
        f"SELECT p.part_uid, p.source_uid, m.conv_uid, {score} AS score FROM {tables} "
        "JOIN import_conversations c ON c.conv_uid = m.conv_uid "
        f"WHERE {' AND '.join(where) or '1'} ORDER BY {order} LIMIT ?"
    )
    params.append(limit)
    return sql, params


# --- the store --------------------------------------------------------------------------------


class ImportStore:
    def __init__(
        self,
        path: Path,
        opener: Opener,
        *,
        copy_opener: Opener | None = None,
        verify_copy: CopyCheck | None = None,
    ) -> None:
        self.path = path
        self._opener = opener
        # Same seam as ActivityStore; copies of the file are ActivityStore.backup/restore's job.
        self._copy_opener = copy_opener or opener
        self._verify_copy = verify_copy

    # --- connections ---------------------------------------------------------------------

    @contextlib.contextmanager
    def connection(self) -> Iterator[sqlite3.Connection]:
        """One short connection; SQLite failures become content-free refusals."""
        with _refusing():
            conn = self._opener(self.path)
            try:
                conn.isolation_level = None  # explicit BEGIN / COMMIT below
                conn.execute(f"PRAGMA busy_timeout = {int(BUSY_TIMEOUT_S * 1000)}")
                yield conn
            finally:
                conn.close()

    @contextlib.contextmanager
    def _transaction(
        self, *, write: bool = True, secure_delete: bool = False, guard: WriteGuard | None = None
    ) -> Iterator[sqlite3.Connection]:
        """One transaction; a body that already ended it (a dry run's ROLLBACK) is not committed.

        ``guard`` runs first inside the transaction (module docstring, "Lease guards").
        """
        with self.connection() as conn:
            if secure_delete:
                conn.execute("PRAGMA secure_delete = ON")
            conn.execute("BEGIN IMMEDIATE" if write else "BEGIN")
            try:
                if guard is not None:
                    guard()
                yield conn
            except BaseException:
                if conn.in_transaction:
                    conn.rollback()
                raise
            if conn.in_transaction:
                conn.execute("COMMIT")

    # --- schema and binding --------------------------------------------------------------

    @staticmethod
    def _read_meta(conn: sqlite3.Connection) -> dict[str, str] | None:
        exists = conn.execute("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'import_meta'").fetchone()
        if exists is None:
            return None
        return {str(key): str(value) for key, value in conn.execute("SELECT key, value FROM import_meta")}

    def initialize(self, profile_home: Path) -> ImportMeta:
        """Create the ``import_*`` schema bound to ``profile_home``, or verify an existing one.

        An older schema bound to ``profile_home`` is upgraded in the same transaction.
        """
        bound = os.path.realpath(profile_home)
        with self._transaction() as conn:
            meta = self._read_meta(conn)
            if meta is None:
                for statement in _schema.STATEMENTS:
                    conn.execute(statement)
                meta = {"schema_version": str(SUPPORTED_SCHEMA_VERSION), "profile_home": bound}
                conn.executemany("INSERT INTO import_meta (key, value) VALUES (?, ?)", sorted(meta.items()))
            checked = self._checked_meta(meta)
            if checked.profile_home != bound:
                raise ImportRefused("profile_mismatch")
            return self._upgraded(conn, checked)

    @staticmethod
    def _upgraded(conn: sqlite3.Connection, meta: ImportMeta) -> ImportMeta:
        """Run :data:`._schema.MIGRATIONS` from ``meta.schema_version`` up to the supported version."""
        steps = range(meta.schema_version, SUPPORTED_SCHEMA_VERSION)
        if not steps:
            return meta
        if any(step not in _schema.MIGRATIONS for step in steps):
            raise ImportRefused("store_unavailable")
        for step in steps:
            for statement in _schema.MIGRATIONS[step]:
                conn.execute(statement)
        conn.execute("UPDATE import_meta SET value = ? WHERE key = 'schema_version'", (str(SUPPORTED_SCHEMA_VERSION),))
        return replace(meta, schema_version=SUPPORTED_SCHEMA_VERSION)

    @staticmethod
    def _checked_meta(meta: dict[str, str] | None) -> ImportMeta:
        if meta is None or not meta.get("schema_version", "").isdigit():
            raise ImportRefused("store_unavailable")
        version = int(meta["schema_version"])
        if version > SUPPORTED_SCHEMA_VERSION:
            # A newer Mordred wrote these tables; never recreate or downgrade them.
            raise ImportRefused("schema_newer")
        return ImportMeta(version, meta.get("profile_home", ""))

    def meta(self) -> ImportMeta:
        with self._transaction(write=False) as conn:
            return self._checked_meta(self._read_meta(conn))

    def get_meta(self, key: str) -> str | None:
        """One ``import_meta`` value (reserved keys included), or ``None`` when unset."""
        with self._transaction(write=False) as conn:
            row = conn.execute("SELECT value FROM import_meta WHERE key = ?", (key,)).fetchone()
        return None if row is None else str(row[0])

    def set_meta(self, key: str, value: str, *, guard: WriteGuard | None = None) -> None:
        """Set a content-free marker; reserved keys and malformed keys or values raise :class:`RecordError`."""
        _meta_key(key)
        _meta_value(value)
        with self._transaction(guard=guard) as conn:
            conn.execute(
                "INSERT INTO import_meta (key, value) VALUES (?, ?) "
                "ON CONFLICT (key) DO UPDATE SET value = excluded.value",
                (key, value),
            )

    def meta_items(self, prefix: str) -> dict[str, str]:
        """Every ``import_meta`` marker whose key starts with ``prefix`` (``a.b.`` form), in key order."""
        if not isinstance(prefix, str) or not prefix.endswith("."):
            raise RecordError("bad_meta")
        _meta_key(prefix[:-1])
        with self._transaction(write=False) as conn:
            rows = conn.execute(
                "SELECT key, value FROM import_meta WHERE substr(key, 1, ?) = ? ORDER BY key", (len(prefix), prefix)
            ).fetchall()
        return {str(key): str(value) for key, value in rows if key not in RESERVED_META_KEYS}

    def delete_meta(self, key: str) -> None:
        """Remove a marker set with :meth:`set_meta` (absent is fine); reserved keys raise :class:`RecordError`."""
        _meta_key(key)
        with self._transaction() as conn:
            conn.execute("DELETE FROM import_meta WHERE key = ?", (key,))

    # --- conversations ------------------------------------------------------------------

    def upsert_conversation(self, conv: ImportConversation) -> None:
        """Insert or replace one conversation row; another account's conversation is a ``conflict``."""
        validate_conversation(conv)
        with self._transaction() as conn:
            self._upsert_conversation(conn, conv)

    @staticmethod
    def _upsert_conversation(conn: sqlite3.Connection, conv: ImportConversation) -> None:
        values = _values(conv, _CONV_FIELDS)
        stored = conn.execute(
            "SELECT source, source_account FROM import_conversations WHERE conv_uid = ?", (conv.conv_uid,)
        ).fetchone()
        if stored is not None and tuple(stored) != values[1:3]:
            raise ImportRefused("conflict")
        conn.execute(
            f"INSERT OR REPLACE INTO import_conversations ({_CONV_COLUMNS}) VALUES ({_marks(len(values))})", values
        )

    # --- runs ----------------------------------------------------------------------------

    def run_begin(self, source: Source | str, *, dry_run: bool = False, guard: WriteGuard | None = None) -> str:
        """Open a run; rows written under it stay invisible to readers until :meth:`run_commit`."""
        value = _source_value(source)
        run_id = secrets.token_hex(16)
        with self._transaction(guard=guard) as conn:
            conn.execute(
                "INSERT INTO import_runs (run_id, source, started_at, finished_at, state, counts_json) "
                "VALUES (?, ?, ?, NULL, ?, '{}')",
                (run_id, value, time.time(), "dry_run" if dry_run else "open"),
            )
        return run_id

    def run_commit(self, run_id: str, counts: Mapping[str, int]) -> None:
        """Publish the run's rows (a dry run only records its counts)."""
        self._finish(run_id, counts, failed=False)

    def run_fail(self, run_id: str, counts: Mapping[str, int]) -> None:
        """Close the run without publishing; a later run reclaims its rows."""
        self._finish(run_id, counts, failed=True)

    def commit_batch(self, run_id: str, counts: Mapping[str, int], meta_updates: Mapping[str, str | None]) -> None:
        """Publish ``run_id`` and apply ``meta_updates`` (``None`` deletes a key) in ONE transaction.

        A collector's cursor therefore never moves past rows that are not published,
        and never stays behind rows that are. A dry run is refused (``run_not_open``).
        """
        payload = _counts_json(counts)
        updates = _meta_updates(meta_updates)
        with self._transaction() as conn:
            _, state = self._open_run(conn, run_id)
            if state != "open":
                raise ImportRefused("run_not_open")
            self._publish(conn, run_id, payload)
            self._apply_meta(conn, updates)

    def write_batch(
        self,
        run_id: str,
        threads: Sequence[Sequence[ImportMessage]],
        *,
        conversations: Sequence[ImportConversation],
        meta_updates: Mapping[str, str | None],
        counts: Mapping[str, int] | None = None,
        refs: Mapping[str, Sequence[str]] | None = None,
        guard: WriteGuard | None = None,
    ) -> BatchResult:
        """Write ``threads``, merge ``conversations``, commit ``run_id`` and apply ``meta_updates`` in ONE transaction.

        Each conversation is merged into its stored row (:meth:`_merged`), every
        message is decided by the idempotency rules of the module docstring, the
        run is committed with ``counts`` plus the write counts, every touched
        conversation's ``message_count`` is recounted from committed rows, and the
        cursor keys in ``meta_updates`` are set (``None`` deletes). With ``refs``
        (source uid → the Message-IDs it references; the mail collector) the
        references are stored in ``import_mail_refs`` and the conversations they
        connect are merged (the module docstring's thread reconciliation). All
        records and keys are validated before the transaction starts. Any failure
        rolls all of it back: a revised row keeps its published revision, no
        participant, date, count, reference or merge of the batch becomes
        visible, and the cursor does not move. A dry run (or a closed run) is
        refused with ``run_not_open``; ``guard`` runs inside the transaction
        before the run state is checked (module docstring, "Lease guards").
        """
        convs = list(conversations)
        for conv in convs:
            validate_conversation(conv)
        messages = [msg for thread in threads for msg in thread]
        for msg in messages:
            validate_message(msg)
        links = _checked_refs(refs, messages)
        updates = _meta_updates(meta_updates)
        extra = dict(counts or {})
        _counts_json(extra)
        with self._transaction(guard=guard) as conn:
            source, state = self._open_run(conn, run_id)
            if state != "open":
                raise ImportRefused("run_not_open")
            touched = {conv.conv_uid for conv in convs}
            for conv in convs:
                if Source(conv.source).value != source:
                    raise RecordError("source_mismatch")
                self._upsert_conversation(conn, self._merged(conn, conv))
            tally, accepted = self._write_messages(conn, run_id, source, messages, links, touched)
            skipped = 0
            if links is not None:
                survivors, dropped, skipped = self._reconcile(conn, run_id, messages, accepted)
                touched = (touched - dropped) | survivors
            result = BatchResult(tally["inserted"], tally["duplicates"], tally["revised"], tally["conflicts"], skipped)
            self._publish(conn, run_id, _counts_json({**extra, **result.counts()}))
            for conv_uid in sorted(touched):
                self._recount(conn, run_id, conv_uid)
            self._apply_meta(conn, updates)
        return result

    @staticmethod
    def _publish(conn: sqlite3.Connection, run_id: str, payload: str) -> None:
        conn.execute(
            "UPDATE import_runs SET state = 'committed', finished_at = ?, counts_json = ? WHERE run_id = ?",
            (time.time(), payload, run_id),
        )

    @staticmethod
    def _apply_meta(conn: sqlite3.Connection, updates: Mapping[str, str | None]) -> None:
        for key, value in updates.items():
            if value is None:
                conn.execute("DELETE FROM import_meta WHERE key = ?", (key,))
            else:
                conn.execute(
                    "INSERT INTO import_meta (key, value) VALUES (?, ?) "
                    "ON CONFLICT (key) DO UPDATE SET value = excluded.value",
                    (key, value),
                )

    def _write_messages(
        self,
        conn: sqlite3.Connection,
        run_id: str,
        source: str,
        messages: Sequence[ImportMessage],
        links: Mapping[str, Sequence[str]] | None,
        touched: set[str],
    ) -> tuple[Counter[str], dict[str, tuple[str, ...]]]:
        """Decide and write each message and its references; (outcome tally, the references accepted per message).

        ``touched`` gains every affected conversation. References (at most the last
        ``mail.merge_guard.MAX_MERGE_REFS``) are accepted from a written copy (they replace the
        stored ones) and from an identical copy (same ``source_revision`` and
        ``content_digest``: the same bytes, so the same headers), which records them
        when the stored message has none yet (a row written before schema v2). A
        rejected different copy (a weaker duplicate, a conflict) contributes none.
        """
        from .mail.merge_guard import nearest_refs

        tally: Counter[str] = Counter()
        accepted: dict[str, tuple[str, ...]] = {}
        for msg in messages:
            self._check_target(conn, msg, source)
            identical = self._identical_copy(conn, msg)
            outcome = self._outcome(conn, run_id, msg)
            if outcome in _WRITES:
                touched.update(self._stored_conversations(conn, msg.source_uid))
                self._store_message(conn, run_id, msg)
            if links is not None and (outcome in _WRITES or identical):
                ids = nearest_refs(links.get(msg.source_uid, ()))
                self._store_refs(conn, msg.source_uid, ids, replace=outcome in _WRITES)
                accepted[msg.source_uid] = ids
            touched.add(msg.conv_uid)
            tally[outcome] += 1
        return tally, accepted

    @staticmethod
    def _identical_copy(conn: sqlite3.Connection, msg: ImportMessage) -> bool:
        """True when a stored row of ``msg.source_uid`` has the same bytes revision and content digest."""
        if msg.source_revision is None:
            return False
        row = conn.execute(
            "SELECT 1 FROM import_messages WHERE source_uid = ? AND source_revision = ? AND content_digest = ?",
            (msg.source_uid, msg.source_revision, msg.content_digest),
        ).fetchone()
        return row is not None

    @staticmethod
    def _store_refs(conn: sqlite3.Connection, source_uid: str, ids: Sequence[str], *, replace: bool) -> None:
        """Keep ``source_uid``'s referenced ids: replaced when its row was (re)written, else set when it has none."""
        if replace:
            conn.execute("DELETE FROM import_mail_refs WHERE source_uid = ?", (source_uid,))
        elif conn.execute("SELECT 1 FROM import_mail_refs WHERE source_uid = ? LIMIT 1", (source_uid,)).fetchone():
            return  # an identical copy: the stored references are the same message's already
        conn.executemany(
            "INSERT OR IGNORE INTO import_mail_refs (source_uid, ref_message_id) VALUES (?, ?)",
            [(source_uid, ref) for ref in ids],
        )

    def _reconcile(
        self,
        conn: sqlite3.Connection,
        run_id: str,
        messages: Sequence[ImportMessage],
        links: Mapping[str, Sequence[str]],
    ) -> tuple[set[str], set[str], int]:
        """Merge the conversations the batch's reference edges connect; (survivors, dropped conv uids, skipped)."""
        from .mail.merge_guard import fold_plan

        survivors: set[str] = set()
        dropped: set[str] = set()
        skipped = 0
        facts: dict[str, GroupFacts] = {}  # per batch: a conversation changes here only by a merge
        owners: dict[tuple[str, str], frozenset[str]] = {}
        for msg in messages:
            linked = self._linked_conversations(conn, run_id, msg.source_uid, links.get(msg.source_uid, ()))
            if linked is None or len(linked[1]) < 2:
                continue
            home, involved, scope = linked
            if scope not in owners:
                owners[scope] = self._own_addresses(conn, *scope)
            for conv_uid in involved - facts.keys():
                facts[conv_uid] = self._conv_facts(conn, run_id, conv_uid, owners[scope])
            survivor, others, guarded = fold_plan(home, {uid: facts[uid] for uid in involved})
            skipped += guarded
            if others:
                self._merge_into(conn, run_id, survivor, others)
                facts[survivor] = facts[survivor].joined([facts.pop(uid) for uid in others])
                dropped.update(others)
                survivors.difference_update(others)
                survivors.add(survivor)
        return survivors, dropped, skipped

    @staticmethod
    def _own_addresses(conn: sqlite3.Connection, source: str, account: str) -> frozenset[str]:
        """The account's recorded own addresses (``import_accounts``), case-folded; empty when unreadable."""
        row = conn.execute(
            "SELECT own_addresses_json FROM import_accounts WHERE source = ? AND account = ?", (source, account)
        ).fetchone()
        try:
            value = json.loads(str(row[0])) if row is not None else []
        except ValueError:
            return frozenset()
        if not isinstance(value, list):
            return frozenset()
        return frozenset(item.casefold() for item in value if isinstance(item, str))

    @staticmethod
    def _conv_facts(conn: sqlite3.Connection, run_id: str, conv_uid: str, own: frozenset[str]) -> GroupFacts:
        """Age, Gmail key, message count and non-owner participants of ``conv_uid`` (committed rows and the run's)."""
        from .mail.merge_guard import GroupFacts

        key = conn.execute("SELECT conversation_id FROM import_conversations WHERE conv_uid = ?", (conv_uid,))
        gmail = str(key.fetchone()[0]).startswith(_GMAIL_THREAD_PREFIX)
        rows = conn.execute(
            "SELECT m.sent_at, m.sender_id, m.owner_class, m.recipients_json FROM import_messages m "
            "JOIN import_runs r ON r.run_id = m.run_id "
            "WHERE m.conv_uid = ? AND (r.state = 'committed' OR m.run_id = ?)",
            (conv_uid, run_id),
        ).fetchall()
        dates = [int(row[0]) for row in rows if row[0] is not None]
        people: set[str] = set()
        owner = OwnerClass.ACCOUNT_OWNER.value
        for _sent_at, sender_id, owner_class, recipients in rows:
            if sender_id and owner_class != owner:
                people.add(str(sender_id).casefold())
            people.update(
                item.stable_id.casefold()
                for item in _participants(str(recipients))
                if item.stable_id and item.owner_class is not OwnerClass.ACCOUNT_OWNER
            )
        return GroupFacts(
            age=(not dates, min(dates) if dates else 0, conv_uid),
            gmail=gmail,
            messages=len(rows),
            people=frozenset(people - own),
        )

    @staticmethod
    def _linked_conversations(
        conn: sqlite3.Connection, run_id: str, source_uid: str, parents: Sequence[str]
    ) -> tuple[str, set[str], tuple[str, str]] | None:
        """(``source_uid``'s conversation, it with its parents' and the committed replies', (source, account))."""
        row = conn.execute(
            "SELECT m.conv_uid, m.message_id, c.source, c.source_account FROM import_messages m "
            "JOIN import_conversations c ON c.conv_uid = m.conv_uid WHERE m.source_uid = ?",
            (source_uid,),
        ).fetchone()
        if row is None:
            return None
        conv_uid, message_id, source, account = (str(value) for value in row)
        scope = (run_id, source, account)
        involved = {conv_uid}
        if parents:
            involved.update(
                str(found[0])
                for found in conn.execute(
                    f"SELECT DISTINCT m.conv_uid FROM import_messages m {_RUN_AND_CONV} "
                    f"WHERE {_IN_SCOPE} AND m.message_id IN ({_marks(len(parents))})",
                    (*scope, *parents),
                )
            )
        involved.update(
            str(found[0])
            for found in conn.execute(
                f"SELECT DISTINCT m.conv_uid FROM import_mail_refs f "
                f"JOIN import_messages m ON m.source_uid = f.source_uid {_RUN_AND_CONV} "
                f"WHERE f.ref_message_id = ? AND {_COMMITTED_SCOPE}",
                (message_id, source, account),
            )
        )
        return conv_uid, involved, (source, account)

    def merge_conversations(self, survivor: str, others: Iterable[str]) -> int:
        """Fold ``others`` into ``survivor`` in ONE transaction; returns how many message rows moved.

        Every message row of ``others`` (whatever its run) is repointed to
        ``survivor``, the participants are unioned, ``last_message_at`` is the
        maximum, the survivor's title is kept (else the first non-empty one),
        ``message_count`` is recounted from committed rows and the emptied rows
        are dropped. :meth:`write_batch` runs the same merge inside its own
        transaction. An unknown conversation raises :class:`RecordError`; one of
        another source or account is a ``conflict``.
        """
        folded = [uid for uid in dict.fromkeys(others) if uid != survivor]
        if not folded:
            return 0
        with self._transaction() as conn:
            return self._merge_into(conn, "", survivor, folded)

    @classmethod
    def _merge_into(cls, conn: sqlite3.Connection, run_id: str, survivor: str, others: Sequence[str]) -> int:
        rows = {
            str(row[0]): ImportConversation(**_decoded(_CONV_FIELDS, row))
            for row in _select_in(
                conn, f"SELECT {_CONV_COLUMNS} FROM import_conversations WHERE conv_uid IN", [survivor, *others]
            )
        }
        target = rows.get(survivor)
        if target is None or any(uid not in rows for uid in others):
            raise RecordError("unknown_conversation")
        folded = [rows[uid] for uid in others]
        if any((conv.source, conv.source_account) != (target.source, target.source_account) for conv in folded):
            raise ImportRefused("conflict")
        people: dict[tuple[str, str], Participant] = {}
        for participant in (*target.participants, *(p for conv in folded for p in conv.participants)):
            people.setdefault(_participant_key(participant), participant)
        dates = [conv.last_message_at for conv in (target, *folded) if conv.last_message_at is not None]
        cursors = [conv.sync_cursor for conv in (target, *folded) if conv.sync_cursor is not None]
        merged = replace(
            target,
            title=target.title or next((conv.title for conv in folded if conv.title), ""),
            participants=tuple(people.values())[:_MAX_MERGED_PARTICIPANTS],
            last_message_at=max(dates) if dates else None,
            sync_cursor=cursors[0] if cursors else None,
        )
        moved = 0
        for start in range(0, len(others), _CHUNK):
            chunk = list(others[start : start + _CHUNK])
            moved += conn.execute(
                f"UPDATE import_messages SET conv_uid = ? WHERE conv_uid IN ({_marks(len(chunk))})", (survivor, *chunk)
            ).rowcount
            conn.execute(f"DELETE FROM import_conversations WHERE conv_uid IN ({_marks(len(chunk))})", chunk)
        cls._upsert_conversation(conn, merged)
        cls._recount(conn, run_id, survivor)
        return int(moved)

    @staticmethod
    def _stored_conversations(conn: sqlite3.Connection, source_uid: str) -> set[str]:
        """The conversation a stored row of ``source_uid`` belongs to (recounted when the row moves)."""
        rows = conn.execute("SELECT conv_uid FROM import_messages WHERE source_uid = ?", (source_uid,)).fetchall()
        return {str(row[0]) for row in rows}

    def fail_open_runs(self, source: Source | str, *, guard: WriteGuard | None = None) -> int:
        """Mark every ``open`` run of ``source`` failed (left by a crashed writer); returns how many.

        Call it only while holding the source's writer lock. The failed runs' rows stay
        invisible and the next write of the same ``source_uid`` reclaims them.
        """
        value = _source_value(source)
        with self._transaction(guard=guard) as conn:
            cursor = conn.execute(
                "UPDATE import_runs SET state = 'failed', finished_at = ? "
                "WHERE source = ? AND state = 'open' AND finished_at IS NULL",
                (time.time(), value),
            )
            return int(cursor.rowcount)

    def _finish(self, run_id: str, counts: Mapping[str, int], *, failed: bool) -> None:
        payload = _counts_json(counts)
        with self._transaction() as conn:
            _, state = self._open_run(conn, run_id)
            final = "failed" if failed else ("dry_run" if state == "dry_run" else "committed")
            conn.execute(
                "UPDATE import_runs SET state = ?, finished_at = ?, counts_json = ? WHERE run_id = ?",
                (final, time.time(), payload, run_id),
            )

    @staticmethod
    def _open_run(conn: sqlite3.Connection, run_id: str) -> tuple[str, str]:
        row = conn.execute(
            "SELECT source, state FROM import_runs WHERE run_id = ? AND finished_at IS NULL "
            "AND state IN ('open', 'dry_run')",
            (run_id,),
        ).fetchone()
        if row is None:
            raise ImportRefused("run_not_open")
        return str(row[0]), str(row[1])

    # --- writes --------------------------------------------------------------------------

    def write_thread(
        self,
        run_id: str,
        messages: Sequence[ImportMessage],
        *,
        conversation: ImportConversation | None = None,
        merge_conversation: bool = False,
    ) -> WriteResult:
        """Write ``messages`` (and optionally their ``conversation``) under ``run_id`` in ONE transaction.

        Every record is validated before the transaction starts; each
        message's conversation must exist (or be passed as ``conversation``).
        A dry run returns the same counts and keeps nothing. With
        ``merge_conversation`` a stored row is merged instead of replaced
        (:meth:`_merged`) and its ``message_count`` is recounted after the write.
        """
        if conversation is not None:
            validate_conversation(conversation)
        for msg in messages:
            validate_message(msg)
        counts: Counter[str] = Counter()
        with self._transaction() as conn:
            source, state = self._open_run(conn, run_id)
            if conversation is not None:
                if Source(conversation.source).value != source:
                    raise RecordError("source_mismatch")
                merged = self._merged(conn, conversation) if merge_conversation else conversation
                self._upsert_conversation(conn, merged)
            for msg in messages:
                self._check_target(conn, msg, source)
                outcome = self._outcome(conn, run_id, msg)
                if outcome in _WRITES:
                    self._store_message(conn, run_id, msg)
                counts[outcome] += 1
            if merge_conversation:
                for conv_uid in sorted({msg.conv_uid for msg in messages}):
                    self._recount(conn, run_id, conv_uid)
            if state == "dry_run":
                conn.execute("ROLLBACK")
        return WriteResult(counts["inserted"], counts["duplicates"], counts["revised"], counts["conflicts"])

    @staticmethod
    def _merged(conn: sqlite3.Connection, conv: ImportConversation) -> ImportConversation:
        """``conv`` merged with its stored row: participants unioned, newest date, the stored title kept."""
        row = conn.execute(
            f"SELECT {_CONV_COLUMNS} FROM import_conversations WHERE conv_uid = ?", (conv.conv_uid,)
        ).fetchone()
        if row is None:
            return conv
        stored = ImportConversation(**_decoded(_CONV_FIELDS, row))
        people: dict[tuple[str, str], Participant] = {}
        for participant in (*stored.participants, *conv.participants):
            people.setdefault(_participant_key(participant), participant)
        dates = [value for value in (stored.last_message_at, conv.last_message_at) if value is not None]
        return replace(
            conv,
            title=stored.title or conv.title,
            participants=tuple(people.values())[:_MAX_MERGED_PARTICIPANTS],
            last_message_at=max(dates) if dates else None,
            sync_cursor=conv.sync_cursor if conv.sync_cursor is not None else stored.sync_cursor,
        )

    @staticmethod
    def _recount(conn: sqlite3.Connection, run_id: str, conv_uid: str) -> None:
        """``message_count`` = the conversation's committed messages plus this run's."""
        conn.execute(
            "UPDATE import_conversations SET message_count = ("
            "SELECT count(*) FROM import_messages m LEFT JOIN import_runs r ON r.run_id = m.run_id "
            "WHERE m.conv_uid = ? AND (m.run_id = ? OR r.state = 'committed')) WHERE conv_uid = ?",
            (conv_uid, run_id, conv_uid),
        )

    @staticmethod
    def _check_target(conn: sqlite3.Connection, msg: ImportMessage, source: str) -> None:
        found = source_of(msg.source_uid)
        if found is None or found.value != source:
            raise RecordError("source_mismatch")
        known = conn.execute("SELECT 1 FROM import_conversations WHERE conv_uid = ?", (msg.conv_uid,)).fetchone()
        if known is None:
            raise RecordError("unknown_conversation")

    @staticmethod
    def _outcome(conn: sqlite3.Connection, run_id: str, msg: ImportMessage) -> str:
        """``inserted`` / ``duplicates`` / ``revised`` / ``conflicts`` (see the module docstring)."""
        row = conn.execute(
            f"SELECT {_DECISION_COLUMNS}, m.run_id = ?, r.state FROM import_messages m "
            "LEFT JOIN import_runs r ON r.run_id = m.run_id WHERE m.source_uid = ?",
            (run_id, msg.source_uid),
        ).fetchone()
        incoming = IncomingCopy(
            msg.source_uid, msg.source_revision, str(msg.provenance_quality), msg.owner_evidence, msg.content_digest
        )
        return _decision(row, incoming)

    @staticmethod
    def _store_message(conn: sqlite3.Connection, run_id: str, msg: ImportMessage) -> None:
        values = (*_values(msg, _MESSAGE_FIELDS), run_id)
        conn.execute(
            f"INSERT OR REPLACE INTO import_messages ({_MESSAGE_COLUMNS}, run_id) VALUES ({_marks(len(values))})",
            values,
        )
        conn.execute("DELETE FROM import_parts WHERE source_uid = ?", (msg.source_uid,))
        rows = [_values(part, _PART_FIELDS) for part in msg.parts]
        conn.executemany(f"INSERT INTO import_parts ({_PART_COLUMNS}) VALUES ({_marks(len(rows[0]))})", rows)

    def delete_source(self, source: Source | str, source_account: str) -> int:
        """Delete one account's conversations, messages, parts, references and own addresses; returns messages deleted.

        Runs with ``PRAGMA secure_delete = ON`` and the FTS index's
        ``secure-delete`` option, so freed pages are zeroed and no index tokens remain.
        ``import_mail_refs`` rows of the deleted messages go too (and any left
        without a message), so no referenced Message-ID survives.
        """
        value = _source_value(source)
        convs = "SELECT conv_uid FROM import_conversations WHERE source = ? AND source_account = ?"
        key = (value, source_account)
        with self._transaction(secure_delete=True) as conn:
            for table in ("import_parts", "import_mail_refs"):
                conn.execute(
                    f"DELETE FROM {table} WHERE source_uid IN "
                    f"(SELECT source_uid FROM import_messages WHERE conv_uid IN ({convs}))",
                    key,
                )
            deleted = conn.execute(f"DELETE FROM import_messages WHERE conv_uid IN ({convs})", key).rowcount
            conn.execute(
                "DELETE FROM import_mail_refs WHERE source_uid NOT IN (SELECT source_uid FROM import_messages)"
            )
            conn.execute("DELETE FROM import_conversations WHERE source = ? AND source_account = ?", key)
            conn.execute("DELETE FROM import_accounts WHERE source = ? AND account = ?", key)
        return int(deleted)

    # --- reads (committed runs only) -----------------------------------------------------

    def contains(self, source_uids: Iterable[str]) -> set[str]:
        """The subset of ``source_uids`` stored under a committed run."""
        uids = list(dict.fromkeys(source_uids))
        with self._transaction(write=False) as conn:
            rows = _select_in(conn, f"SELECT m.source_uid FROM {_COMMITTED_MESSAGES} WHERE m.source_uid IN", uids)
        return {str(row[0]) for row in rows}

    def classify_incoming(self, copies: Iterable[IncomingCopy]) -> dict[str, str]:
        """What a new run's write would decide for each copy now, by source uid (read-only).

        ``inserted`` / ``duplicates`` / ``revised`` / ``conflicts`` by the module docstring's
        idempotency rules. A copy without ``content_digest`` (not normalised yet) whose
        revision is unchanged is ``duplicates`` (it is not written either way). The mail
        importer keeps the copies that are not written out of its reference grouping.
        """
        incoming = {copy.source_uid: copy for copy in copies}
        with self._transaction(write=False) as conn:
            rows = _select_in(
                conn,
                f"SELECT m.source_uid, {_DECISION_COLUMNS}, 0, r.state FROM import_messages m "
                "LEFT JOIN import_runs r ON r.run_id = m.run_id WHERE m.source_uid IN",
                list(incoming),
            )
        stored = {str(row[0]): tuple(row)[1:] for row in rows}
        return {uid: _decision(stored.get(uid), copy) for uid, copy in incoming.items()}

    def find_messages(
        self,
        source: Source | str,
        source_account: str,
        *,
        message_ids: Iterable[str] | None = None,
        sender_address: str | None = None,
        sent_between: tuple[int, int] | None = None,
        owner_class: OwnerClass | str | None = None,
    ) -> list[StoredPart]:
        """Every part of one account's committed messages that match ALL the given filters.

        ``message_ids`` match the stored message id exactly, ``sender_address`` the
        sender id case-insensitively, ``sent_between=(lo, hi)`` is inclusive (unknown
        dates never match) and ``owner_class`` the message's owner class. Messages
        come in reading order (``sent_at``, unknown dates last, then source uid) and
        each message's parts by ordinal. Read-only; used by the mail collector's
        store-backed quote linker.
        """
        ids = None if message_ids is None else list(dict.fromkeys(message_ids))
        if ids is not None and not ids:
            return []
        where = ["c.source = ?", "c.source_account = ?"]
        params: list[Any] = [_source_value(source), source_account]
        if sender_address is not None:
            where.append("lower(m.sender_id) = ?")
            params.append(sender_address.lower())
        if sent_between is not None:
            where.append("m.sent_at BETWEEN ? AND ?")
            params.extend((int(sent_between[0]), int(sent_between[1])))
        if owner_class is not None:
            try:
                params.append(OwnerClass(owner_class).value)
            except ValueError:
                raise RecordError("unknown_enum") from None
            where.append("m.owner_class = ?")
        sql = (
            f"SELECT m.source_uid FROM {_COMMITTED_MESSAGES} "
            f"JOIN import_conversations c ON c.conv_uid = m.conv_uid WHERE {' AND '.join(where)}"
        )
        chunks: list[list[str]] = [[]] if ids is None else [ids[i : i + _CHUNK] for i in range(0, len(ids), _CHUNK)]
        with self._transaction(write=False) as conn:
            uids: set[str] = set()
            for chunk in chunks:
                clause = f" AND m.message_id IN ({_marks(len(chunk))})" if chunk else ""
                uids.update(str(row[0]) for row in conn.execute(sql + clause, [*params, *chunk]))
            hydrated = self._hydrate(conn, sorted(uids))
        found = sorted(
            hydrated.values(),
            key=lambda item: (item[1].sent_at is None, item[1].sent_at or 0, item[1].source_uid),
        )
        return [StoredPart(conv, msg, part) for conv, msg in found for part in msg.parts]

    def search(
        self,
        query: str | None,
        *,
        conv_uids: Sequence[str] | None = None,
        since: int | None = None,
        until: int | None = None,
        source: Source | str | None = None,
        limit: int = 20,
    ) -> list[SearchHit]:
        """Parts matching every term of ``query`` (all parts without one), filtered in SQL.

        Terms of three or more characters match through the trigram FTS index
        (substring, case-insensitive) and rank by ``bm25``; shorter terms
        match by ``LIKE``. ``since <= sent_at < until`` (unix seconds) excludes
        unknown dates. Without indexed terms the newest parts come first.
        """
        if limit <= 0 or (conv_uids is not None and not conv_uids):
            return []
        sql, params = _search_sql(
            _terms(query),
            conv_uids=None if conv_uids is None else list(dict.fromkeys(conv_uids)),
            since=since,
            until=until,
            source=None if source is None else _source_value(source),
            limit=min(limit, MAX_SEARCH_LIMIT),
        )
        with self._transaction(write=False) as conn:
            rows = conn.execute(sql, params).fetchall()
        return [
            SearchHit(str(part), str(source_uid), str(conv), float(score)) for part, source_uid, conv, score in rows
        ]

    def parts_for(self, part_uids: Iterable[str]) -> dict[str, StoredPart]:
        """Hydrate ``part_uids`` (unknown or uncommitted ones are left out) with their message and conversation."""
        uids = list(dict.fromkeys(part_uids))
        with self._transaction(write=False) as conn:
            rows = _select_in(
                conn,
                f"SELECT p.part_uid, p.source_uid FROM {_COMMITTED_PARTS} WHERE p.part_uid IN",
                uids,
            )
            owners = {str(part): str(source_uid) for part, source_uid in rows}
            hydrated = self._hydrate(conn, sorted(set(owners.values())))
        result: dict[str, StoredPart] = {}
        for uid in uids:
            found = hydrated.get(owners.get(uid, ""))
            if found is not None:
                conv, msg = found
                result[uid] = StoredPart(conv, msg, next(p for p in msg.parts if p.part_uid == uid))
        return result

    def neighbors(self, part_uid: str, n: int) -> list[StoredPart]:
        """Every part of the ``n`` messages before and after ``part_uid``'s message, and of that message.

        Reading order is ``sent_at`` (unknown dates last), then the numeric
        message id, then the id text. Unknown or uncommitted anchors give ``[]``.
        """
        span = max(0, min(n, MAX_NEIGHBORS))
        with self._transaction(write=False) as conn:
            anchor = conn.execute(
                f"SELECT m.conv_uid, m.source_uid FROM {_COMMITTED_PARTS} WHERE p.part_uid = ?",
                (part_uid,),
            ).fetchone()
            if anchor is None:
                return []
            order = [str(row[0]) for row in conn.execute(_NEIGHBOR_SQL, (anchor[0], anchor[1], span, span))]
            hydrated = self._hydrate(conn, order)
        found = [hydrated[uid] for uid in order if uid in hydrated]
        return [StoredPart(conv, msg, part) for conv, msg in found for part in msg.parts]

    @staticmethod
    def _hydrate(
        conn: sqlite3.Connection, source_uids: Sequence[str]
    ) -> dict[str, tuple[ImportConversation, ImportMessage]]:
        message_rows = _select_in(
            conn, f"SELECT {_MESSAGE_COLUMNS} FROM import_messages WHERE source_uid IN", source_uids
        )
        parts: dict[str, list[ImportPart]] = {}
        for row in _select_in(conn, f"SELECT {_PART_COLUMNS} FROM import_parts WHERE source_uid IN", source_uids):
            parts.setdefault(str(row[1]), []).append(ImportPart(**_decoded(_PART_FIELDS, row)))
        conv_uids = sorted({str(row[1]) for row in message_rows})
        convs = {
            str(row[0]): ImportConversation(**_decoded(_CONV_FIELDS, row))
            for row in _select_in(
                conn, f"SELECT {_CONV_COLUMNS} FROM import_conversations WHERE conv_uid IN", conv_uids
            )
        }
        result: dict[str, tuple[ImportConversation, ImportMessage]] = {}
        for row in message_rows:
            conv = convs.get(str(row[1]))
            if conv is None:
                continue  # write_thread never stores a message without its conversation
            own = tuple(sorted(parts.get(str(row[0]), []), key=lambda part: part.ordinal))
            result[str(row[0])] = (conv, ImportMessage(**_decoded(_MESSAGE_FIELDS, row), parts=own))
        return result

    def sources(self) -> dict[str, int]:
        """Committed message count per source; a source without committed messages is left out."""
        with self._transaction(write=False) as conn:
            rows = conn.execute(
                f"SELECT c.source, count(*) FROM {_COMMITTED_MESSAGES} "
                "JOIN import_conversations c ON c.conv_uid = m.conv_uid GROUP BY c.source ORDER BY c.source"
            ).fetchall()
        return {str(source): int(count) for source, count in rows}

    def status(self) -> dict[str, Any]:
        """Identifiers and counts only: per-source rows, runs per state, and the latest run."""
        with self._transaction(write=False) as conn:
            meta = self._checked_meta(self._read_meta(conn))
            sources: dict[str, dict[str, int]] = {}

            def add(source: str, key: str, count: int) -> None:
                empty = {"conversations": 0, "messages": 0, "parts": 0, "uncommitted_messages": 0}
                sources.setdefault(source, empty)[key] += count

            for source, count in conn.execute("SELECT source, count(*) FROM import_conversations GROUP BY source"):
                add(str(source), "conversations", int(count))
            for source, committed, count in conn.execute(
                "SELECT c.source, coalesce(r.state = 'committed', 0), count(*) FROM import_messages m "
                "JOIN import_conversations c ON c.conv_uid = m.conv_uid "
                "LEFT JOIN import_runs r ON r.run_id = m.run_id GROUP BY 1, 2"
            ):
                add(str(source), "messages" if committed else "uncommitted_messages", int(count))
            for source, count in conn.execute(
                f"SELECT c.source, count(*) FROM {_COMMITTED_PARTS} "
                "JOIN import_conversations c ON c.conv_uid = m.conv_uid GROUP BY 1"
            ):
                add(str(source), "parts", int(count))
            runs = dict(conn.execute("SELECT state, count(*) FROM import_runs GROUP BY state ORDER BY state"))
            last = conn.execute(
                "SELECT run_id, source, state, started_at, finished_at, counts_json FROM import_runs "
                "ORDER BY started_at DESC, rowid DESC LIMIT 1"
            ).fetchone()
        last_run = None
        if last is not None:
            keys = ("run_id", "source", "state", "started_at", "finished_at")
            last_run = {**dict(zip(keys, last[:5], strict=True)), "counts": json.loads(last[5])}
        return {"schema_version": meta.schema_version, "sources": sources, "runs": runs, "last_run": last_run}


def refusal_code(exc: BaseException) -> str:
    """The :data:`REFUSAL_CODES` member for ``exc``: its own code when it is one, else ``store_unavailable``."""
    code = getattr(exc, "code", None)
    return code if isinstance(code, str) and code in REFUSAL_CODES else "store_unavailable"


def open_import_store(home: Path) -> ImportStore:
    """Gate, open, verify and bind the ``import_*`` tables of ``home``'s ``mordred.db``.

    The same gate and keyed opener as :func:`mordred_hermes.activity._gate.open_store`,
    without creating or checking any activity table. Raises :class:`ImportRefused`.
    """
    found = check_protection(home)
    if found is not None:
        raise ImportRefused(found.code)
    from ..activity._paths import store_path
    from ..dbcrypt import _monitor

    try:
        path = store_path(home)
    except OSError:
        raise ImportRefused("store_unavailable") from None
    if path.is_file() and path.stat().st_size > 0 and _monitor.is_plaintext(path):
        raise ImportRefused("plaintext_store")
    store = ImportStore(path, keyed_opener)
    store.initialize(Path(os.path.realpath(home)))
    with store.connection() as conn:
        found = verify_keyed_connection(conn, path)
    if found is not None:
        raise ImportRefused(found.code)
    return store


# --- the read-only status path ----------------------------------------------------------------

#: The write and read format version bytes of a SQLite header; 2 in either means WAL mode.
_FORMAT_VERSION_BYTES: Final = slice(18, 20)
_WAL_VERSION: Final = 2


def readonly_store_path(home: Path) -> Path:
    """``<home>/plugin-data/mordred/mordred.db``, computed only (``store_path`` creates the directory)."""
    from ..activity._paths import PLUGIN_DATA_SUBPATH, STORE_NAME

    return home.joinpath(*PLUGIN_DATA_SUBPATH, STORE_NAME)


def readonly_uri(path: Path) -> str:
    """``file:<path>?mode=ro`` with the path escaped, so a ``#``, ``?`` or ``%`` cannot cut it short."""
    from urllib.parse import quote

    return f"file:{quote(path.as_posix(), safe='/')}?mode=ro"


def _sqlcipher() -> Any:
    """The SQLCipher DB-API module itself, never the process ``sqlite3`` shim (a seam for tests)."""
    import sqlcipher3.dbapi2 as sc

    return sc


def _env_database_key() -> Any:
    """The database key derived from ``HERMES_MEMORY_KEY`` as it is now; ``None`` unless it decodes to 32 bytes.

    Read once per open; no key provider runs, so nothing can unlock the vault or prompt.
    """
    from ..dbcrypt._key import derive
    from ..keyvault._memory_hook import _decode_env_key

    memory_key = _decode_env_key(os.environ)
    return None if memory_key is None else derive(memory_key)


def _readonly_gate(home: Path) -> str | None:
    """The protection checks without anything that could unlock the vault or prompt; ``None`` when they pass."""
    if sys.platform != "darwin":
        return "unsupported_platform"
    from .. import dbcrypt
    from ..dbcrypt import _migrate, _shim

    root = dbcrypt.root_home(home)
    markers = (_migrate.journal_path(root), _migrate.pending_path(root), _migrate.decrypt_pending_path(root))
    if any(path.is_file() for path in markers):
        return "conversion_pending"  # either direction
    if not dbcrypt.armed(root):
        return "not_armed"
    if not _shim.is_installed():
        return "unprotected_process"
    return None


def _open_readonly(path: Path, key: Any) -> sqlite3.Connection:
    """One connection through SQLCipher itself, keyed with ``key``: never the shim and its key provider.

    ``check_same_thread`` is off because :class:`ReadOnlyImportStore` serialises its
    single connection with its own lock across the threads that read status.
    """
    from ..dbcrypt._shim import apply_key

    conn = _sqlcipher().connect(readonly_uri(path), uri=True, timeout=BUSY_TIMEOUT_S, check_same_thread=False)
    try:
        apply_key(conn, key)
        conn.isolation_level = None  # explicit BEGIN / COMMIT, as ImportStore.connection does
        conn.execute(f"PRAGMA busy_timeout = {int(BUSY_TIMEOUT_S * 1000)}")
    except BaseException:
        conn.close()
        raise
    return cast(sqlite3.Connection, conn)


def _no_reopen(_path: Path) -> sqlite3.Connection:
    raise ImportRefused("store_unavailable")  # a read-only store never opens a second connection


class ReadOnlyImportStore(ImportStore):
    """The status view of ``mordred.db``: ONE read-only connection for the store's whole life.

    Every read runs on the connection :func:`open_import_store_readonly` opened at
    admission (a rollback-journal store; a WAL store is refused there), so nothing
    is reopened between reads. :meth:`close` (or leaving a ``with`` block, or
    dropping the object) closes it; a read after that is ``store_unavailable``.
    Writes fail (``mode=ro``).
    """

    def __init__(self, path: Path, conn: sqlite3.Connection) -> None:
        super().__init__(path, _no_reopen)
        self._conn: sqlite3.Connection | None = conn
        self._held = threading.Lock()

    @contextlib.contextmanager
    def connection(self) -> Iterator[sqlite3.Connection]:
        with self._held, _refusing():
            if self._conn is None:
                raise ImportRefused("store_unavailable")
            yield self._conn

    def close(self) -> None:
        with self._held:
            conn, self._conn = self._conn, None
        if conn is not None:
            with contextlib.suppress(Exception):
                conn.close()

    def __enter__(self) -> ReadOnlyImportStore:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def __del__(self) -> None:
        self.close()


def _lstat(path: Path) -> os.stat_result | None:
    try:
        return os.lstat(path)
    except FileNotFoundError:
        return None
    except OSError:
        raise ImportRefused("store_unavailable") from None


def open_import_store_readonly(home: Path) -> ReadOnlyImportStore:
    """Open ``home``'s ``import_*`` tables for status reads: nothing is created, initialised, upgraded or unlocked.

    Its own gate sequence (never :func:`~..activity._gate.check_protection`, never a
    key provider that could inject the vault or prompt): macOS, no database
    conversion pending in either direction, armed, the SQLCipher shim installed,
    and ``HERMES_MEMORY_KEY`` already in the environment and decoding to 32 bytes
    (``no_key`` otherwise; read once, the derived key serves every later read of
    the returned store). The path is computed without creating directories; no
    file (or an empty one) is ``store_uninitialised``. Only rollback-journal stores
    are read: a header that says WAL (either format byte is 2) is
    ``store_unavailable`` before any connection, whatever sidecars exist, because a
    ``mode=ro`` reader of a WAL file may create ``-wal``/``-shm`` when a writer
    closes between any check and the open, and no lock is shared with every
    writer (``immutable=1`` would disable locking instead). Mordred never puts
    ``mordred.db`` in WAL mode: it is created in rollback mode, and only a
    conversion keeps WAL for a file that already was. The file must not be plaintext; it is
    opened ``mode=ro`` through SQLCipher itself (not the process ``sqlite3``
    shim, whose key provider could inject the vault) with the derived key, and
    any open failure is ``store_unavailable``; ``import_meta`` is read with plain
    selects (no table: ``store_uninitialised``; a wrong key or an unreadable
    file: ``store_unavailable``; a newer schema: ``schema_newer``; another
    profile: ``profile_mismatch``; an older schema is read as it is). The
    returned :class:`ReadOnlyImportStore` keeps that one connection for its life
    and serves :meth:`ImportStore.status` and other reads on it (deferred read
    transactions, which a writer holding ``BEGIN IMMEDIATE`` does not block);
    callers close it (``with``) and never write through it. Raises :class:`ImportRefused` with a
    :data:`REFUSAL_CODES` member.
    """
    found = _readonly_gate(home)
    if found is not None:
        raise ImportRefused(found)
    key = _env_database_key()
    if key is None:
        raise ImportRefused("no_key")
    path = _readonly_file(home)
    try:
        conn = _open_readonly(path, key)
    except Exception:  # an open or sidecar failure: never stringified
        raise ImportRefused("store_unavailable") from None
    store = ReadOnlyImportStore(path, conn)
    try:
        meta = _readonly_meta(store)
        if meta is None:
            raise ImportRefused("store_uninitialised")
        if ImportStore._checked_meta(meta).profile_home != os.path.realpath(home):
            raise ImportRefused("profile_mismatch")
    except BaseException:
        store.close()
        raise
    return store


def _readonly_file(home: Path) -> Path:
    """The existing, non-empty, not-plaintext, rollback-journal store file of ``home`` (nothing is created)."""
    from ..dbcrypt import _monitor

    path = readonly_store_path(home)
    info = _lstat(path.parent)
    if info is not None and not stat.S_ISDIR(info.st_mode):
        raise ImportRefused("store_unavailable")  # a planted symlink would move the store elsewhere
    info = None if info is None else _lstat(path)
    if info is not None and not stat.S_ISREG(info.st_mode):
        raise ImportRefused("store_unavailable")
    if info is None or info.st_size == 0:
        raise ImportRefused("store_uninitialised")
    if _wal_mode(path):
        raise ImportRefused("store_unavailable")  # rollback-journal stores only: see open_import_store_readonly
    if _monitor.is_plaintext(path):
        raise ImportRefused("plaintext_store")
    return path


def _wal_mode(path: Path) -> bool:
    """Whether the header's format bytes (18-19, plaintext also in an encrypted store) say WAL."""
    try:
        with path.open("rb") as handle:
            header = handle.read(_FORMAT_VERSION_BYTES.stop)
    except OSError:
        raise ImportRefused("store_unavailable") from None
    return _WAL_VERSION in header[_FORMAT_VERSION_BYTES]


def _readonly_meta(store: ReadOnlyImportStore) -> dict[str, str] | None:
    """``import_meta`` on the store's connection (plain selects, no transaction is begun)."""
    try:
        with store.connection() as conn:
            return ImportStore._read_meta(conn)
    except ImportRefused:
        raise
    except Exception:  # SQLCipher's own errors (a wrong key reads as "not a database")
        raise ImportRefused("store_unavailable") from None
