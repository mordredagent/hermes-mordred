"""``ImportStore``: imported conversations, messages and parts in ``mordred.db`` (``import_*`` v1).

Mirrors :class:`mordred_hermes.activity.store.ActivityStore`: :func:`open_import_store`
runs the activity protection gate and passes the gate's keyed opener; tests pass
a plain-SQLite opener (the only test seam). The tables share the activity
store's encrypted file but keep their own ``import_meta``; ``activity_*`` is never touched.

Every public method runs one short connection and one transaction (``BEGIN IMMEDIATE``
for writes, busy timeout 2 s). SQLite failures become :class:`ImportRefused` (``busy``,
``disk_full``, ``store_unavailable``); nothing is retried and no exception text carries
imported content. Records are validated before any write; a record that does not fit
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
4. same ``source_revision`` and ``content_digest``: ``duplicates``;
5. a different ``source_revision``: ``revised`` (the row and all its parts are replaced);
6. same ``source_revision``, different ``content_digest``: ``conflicts``, nothing overwritten.

Backup and restore: ``ActivityStore.backup`` / ``restore`` copy the whole
``mordred.db`` file, ``import_*`` tables included; there is no second copy path.

``import_meta`` also carries small content-free markers (:meth:`ImportStore.get_meta` /
:meth:`ImportStore.set_meta`); the store's own keys (:data:`RESERVED_META_KEYS`) are never
settable that way. :data:`TELEGRAM_RETIRED_ACCOUNT` names the Telegram account whose
history lives here, so a reader can choose ``mordred.db`` without unsealing the Telegram
credentials to read ``index.enc``.
"""

from __future__ import annotations

import contextlib
import json
import os
import re
import secrets
import sqlite3
import sys
import time
from collections import Counter
from collections.abc import Callable, Iterable, Iterator, Mapping, Sequence
from dataclasses import asdict, dataclass, replace
from enum import Enum
from pathlib import Path
from typing import Any, Final, NamedTuple

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

__all__ = [
    "MAX_NEIGHBORS",
    "MAX_SEARCH_LIMIT",
    "RESERVED_META_KEYS",
    "SUPPORTED_SCHEMA_VERSION",
    "TELEGRAM_RETIRED_ACCOUNT",
    "ImportMeta",
    "ImportRefused",
    "ImportStore",
    "SearchHit",
    "StoredPart",
    "WriteResult",
    "open_import_store",
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
}

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
    def _transaction(self, *, write: bool = True, secure_delete: bool = False) -> Iterator[sqlite3.Connection]:
        """One transaction; a body that already ended it (a dry run's ROLLBACK) is not committed."""
        with self.connection() as conn:
            if secure_delete:
                conn.execute("PRAGMA secure_delete = ON")
            conn.execute("BEGIN IMMEDIATE" if write else "BEGIN")
            try:
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

    def set_meta(self, key: str, value: str) -> None:
        """Set a content-free marker; reserved keys and malformed keys or values raise :class:`RecordError`."""
        _meta_key(key)
        if not isinstance(value, str) or len(value) > _MAX_META_VALUE or not value.isprintable():
            raise RecordError("bad_meta")
        with self._transaction() as conn:
            conn.execute(
                "INSERT INTO import_meta (key, value) VALUES (?, ?) "
                "ON CONFLICT (key) DO UPDATE SET value = excluded.value",
                (key, value),
            )

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

    def run_begin(self, source: Source | str, *, dry_run: bool = False) -> str:
        """Open a run; rows written under it stay invisible to readers until :meth:`run_commit`."""
        value = _source_value(source)
        run_id = secrets.token_hex(16)
        with self._transaction() as conn:
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
    ) -> WriteResult:
        """Write ``messages`` (and optionally their ``conversation``) under ``run_id`` in ONE transaction.

        Every record is validated before the transaction starts; each
        message's conversation must exist (or be passed as ``conversation``).
        A dry run returns the same counts and keeps nothing.
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
                self._upsert_conversation(conn, conversation)
            for msg in messages:
                self._check_target(conn, msg, source)
                outcome = self._outcome(conn, run_id, msg)
                if outcome in _WRITES:
                    self._store_message(conn, run_id, msg)
                counts[outcome] += 1
            if state == "dry_run":
                conn.execute("ROLLBACK")
        return WriteResult(counts["inserted"], counts["duplicates"], counts["revised"], counts["conflicts"])

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
            "SELECT m.source_revision, m.content_digest, m.provenance_quality, m.run_id = ?, r.state "
            "FROM import_messages m LEFT JOIN import_runs r ON r.run_id = m.run_id WHERE m.source_uid = ?",
            (run_id, msg.source_uid),
        ).fetchone()
        if row is None:
            return "inserted"
        revision, digest, quality, same_run, state = row
        if not same_run and state != "committed":
            return "inserted"  # left behind by an open, failed or vanished run: reclaim it
        stored_legacy = quality == ProvenanceQuality.LEGACY.value
        incoming_legacy = ProvenanceQuality(msg.provenance_quality) is ProvenanceQuality.LEGACY
        if incoming_legacy != stored_legacy:
            return "duplicates" if incoming_legacy else "revised"
        if revision == msg.source_revision:
            return "duplicates" if digest == msg.content_digest else "conflicts"
        return "revised"

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
        """Delete one account's conversations, messages, parts and own addresses; returns messages deleted.

        Runs with ``PRAGMA secure_delete = ON`` and the FTS index's
        ``secure-delete`` option, so freed pages are zeroed and no index tokens remain.
        """
        value = _source_value(source)
        convs = "SELECT conv_uid FROM import_conversations WHERE source = ? AND source_account = ?"
        key = (value, source_account)
        with self._transaction(secure_delete=True) as conn:
            conn.execute(
                f"DELETE FROM import_parts WHERE source_uid IN "
                f"(SELECT source_uid FROM import_messages WHERE conv_uid IN ({convs}))",
                key,
            )
            deleted = conn.execute(f"DELETE FROM import_messages WHERE conv_uid IN ({convs})", key).rowcount
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
