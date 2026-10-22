"""Where a Telegram sync writes: the legacy ``.enc`` archive or ``mordred.db``.

:func:`~.client.sync_archive` drives one :class:`SyncSink` per sync:

- :class:`ArchiveSink` is the ``.enc`` archive exactly as before: legacy
  :class:`~.store.StoredMessage` rows appended per segment, the cursor in
  ``DialogInfo.last_message_id``, the index saved after every stored batch and
  every ``_INDEX_SAVE_EVERY`` advanced dialogs.
- :class:`ImportSink` writes canonical records
  (:func:`~.client.convert_import_message`) into the ``import_*`` tables of
  ``mordred.db`` under ONE import run per sync. Readers see nothing until the
  run commits, and each conversation's ``sync_cursor`` is advanced only AFTER
  that commit: a failed or interrupted run is fetched again next time
  (idempotent on ``source_uid``) instead of leaving uncommitted rows behind an
  advanced cursor.

Selection (:func:`select_sink`, called by the service before connecting):

1. an index retired to ``mordred.db`` (version 2) always uses the import store;
   when the gate or the store refuses, the sync refuses with
   ``import_store_unavailable`` and never falls back to ``.enc``;
2. an index without dialogs on macOS goes straight to ``mordred.db`` when
   :func:`~mordred_hermes.imports.store.open_import_store` succeeds, and the
   index is rewritten as version 2 at once (no dual write);
3. everything else (Linux, Windows, archives that already hold dialogs) stays
   on ``.enc`` until ``telegram migrate-store --commit``.

Every refusal becomes a content-free :class:`~.store.StoreError` code
(``import_store_unavailable``, ``account_mismatch``, ``import_record_invalid``);
the store's own code is logged, never message content.

Questions read the same place (:func:`load_ask_records`): the committed
``import_*`` rows when the index is retired, else the ``.enc`` archive mapped
on the fly by :mod:`mordred_hermes.imports.legacy_enc` (quality ``legacy``,
``out`` = account owner). A retired index never falls back to ``.enc``.
"""

from __future__ import annotations

import contextlib
import json
import logging
import sys
import time
from collections import Counter
from collections.abc import Callable, Iterable, Iterator, Sequence
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, Final, Protocol, TypeVar

from ...imports.legacy_enc import legacy_conversation, legacy_message
from ...imports.records import (
    ConversationKind,
    ImportConversation,
    ImportMessage,
    OwnerClass,
    Participant,
    PartKind,
    RecordError,
    SenderKind,
    Source,
    part_uid,
    telegram_conv_uid,
    telegram_source_uid,
    validate_message,
)
from ...imports.store import ImportRefused, ImportStore
from .ask import AskRecords, AskRequest, candidate_window
from .client import (
    PartAuthor,
    ResolvedAuthor,
    convert_dialog,
    convert_import_message,
    convert_message,
    dialog_kind,
)
from .store import RETIRED_TO_IMPORT_STORE, ArchiveIndex, ArchiveStore, DialogInfo, StoredMessage, StoreError

__all__ = [
    "ArchiveSink",
    "ImportSink",
    "ImportStoreOpener",
    "SyncSink",
    "dialog_rows",
    "forget_imported_history",
    "list_conversations",
    "load_ask_records",
    "open_history_store",
    "select_sink",
    "summary",
]

_log = logging.getLogger(__name__)

_SOURCE: Final = Source.TELEGRAM.value
#: Participants kept per conversation ("seen in archive"; never a complete roster).
_MAX_PARTICIPANTS: Final = 256
#: Authors (and texts) of recently converted messages kept per dialog for same-run quote resolution.
_MAX_REPLY_AUTHORS: Final = 4096
_CHUNK: Final = 500  # bound on ``IN (...)`` parameters per statement
_CONV_COLUMNS: Final = (
    "conv_uid, source, source_account, conversation_id, kind, title, participants_json, "
    "last_message_at, message_count, archived, sync_cursor, record_version"
)
#: Wire ``kind`` of a conversation for the dialog list (the archive's vocabulary).
_LEGACY_KINDS: Final = {
    ConversationKind.GROUP: "group",
    ConversationKind.CHANNEL: "channel",
    ConversationKind.THREAD: "group",
}

_H = TypeVar("_H")  # per-dialog handle
_R = TypeVar("_R")  # converted record

#: ``open_import_store``-shaped: gate, open and bind ``mordred.db`` for a Hermes home.
ImportStoreOpener = Callable[[Path], ImportStore]


def _platform() -> str:
    return sys.platform


class SyncSink(Protocol[_H, _R]):
    """Destination of one sync run; every method runs on one thread at a time."""

    def begin(self, index: ArchiveIndex) -> None:
        """Start the run; ``index.account_id`` is the verified logged-in account."""

    def open_dialog(self, dialog: Any, *, archived: bool) -> _H:
        """Register a dialog of this run (title/kind/folder refreshed) and return its handle."""

    def cursor(self, dialog_id: int) -> int | None:
        """Highest message id already synced for ``dialog_id`` (``None``: nothing yet)."""

    def convert(self, handle: _H, message: Any) -> _R | None:
        """One Telethon message as this sink's record; called in ascending id order."""

    def write(self, handle: _H, messages: Sequence[_R]) -> int:
        """Store one batch; return how many messages were inserted or revised."""

    def advance(self, handle: _H, seen: int) -> int:
        """Record the highest message id seen (service messages included); return the new cursor."""

    def resolve_reply(self, conv_uid: str, msg_id: int) -> PartAuthor | None:
        """Author of a stored (or earlier converted) message of the same chat, for a quote."""

    def checkpoint(self, index: ArchiveIndex) -> None:
        """Persist progress mid-run (the archive saves its index; the import store has nothing to save)."""

    def finish(self, index: ArchiveIndex) -> None:
        """Complete the run; the caller saves the index afterwards."""

    def fail(self) -> None:
        """Abandon the run after an error or cancellation; never raises."""


# -- the legacy archive -----------------------------------------------------------------------


class ArchiveSink:
    """Today's ``.enc`` behaviour: ``StoredMessage`` segments, cursors in ``DialogInfo``."""

    def __init__(self, store: ArchiveStore) -> None:
        self.store = store
        self._index = ArchiveIndex()

    def begin(self, index: ArchiveIndex) -> None:
        self._index = index

    def open_dialog(self, dialog: Any, *, archived: bool) -> DialogInfo:
        index = self._index
        info = index.dialogs.get(dialog.id) or DialogInfo(dialog_id=int(dialog.id), kind=dialog_kind(dialog), title="")
        info.title = str(dialog.name or "")
        info.kind = dialog_kind(dialog)
        info.archived = archived
        index.dialogs[info.dialog_id] = info
        return info

    def cursor(self, dialog_id: int) -> int | None:
        info = self._index.dialogs.get(dialog_id)
        return (info.last_message_id or None) if info is not None else None

    def convert(self, handle: DialogInfo, message: Any) -> StoredMessage | None:
        return convert_message(message)

    def write(self, handle: DialogInfo, messages: Sequence[StoredMessage]) -> int:
        added = self.store.append_messages(handle.dialog_id, list(messages))
        handle.last_message_id = max(handle.last_message_id, messages[-1].id)
        if added:
            handle.message_count += added
            handle.last_date = max(handle.last_date, messages[-1].date)
        return added

    def advance(self, handle: DialogInfo, seen: int) -> int:
        handle.last_message_id = max(handle.last_message_id, seen)
        return handle.last_message_id

    def resolve_reply(self, conv_uid: str, msg_id: int) -> PartAuthor | None:
        return None  # the archive does not separate quotes

    def checkpoint(self, index: ArchiveIndex) -> None:
        self.store.save_index(index)

    def finish(self, index: ArchiveIndex) -> None:
        return None

    def fail(self) -> None:
        return None


# -- mordred.db ------------------------------------------------------------------------------


@contextlib.contextmanager
def _refused() -> Iterator[None]:
    """Import-store refusals and record errors as content-free archive codes."""
    try:
        yield
    except ImportRefused as exc:
        _log.warning("telegram import store refused (%s)", exc.code)
        code = "account_mismatch" if exc.code == "conflict" else "import_store_unavailable"
        raise StoreError(code) from None
    except RecordError as exc:
        _log.warning("telegram import record rejected (%s)", exc.code)
        raise StoreError("import_record_invalid") from None


def _participant_key(participant: Participant) -> tuple[str, str]:
    ident = participant.stable_id if participant.stable_id else f"name:{participant.display_name}"
    return str(participant.owner_class), ident


def _cursor_value(value: str | None) -> int:
    return int(value) if value is not None and value.isdigit() else 0


@dataclass
class _ImportDialog:
    dialog_id: int
    conv: ImportConversation
    cursor: int  # committed cursor at the start of the run
    seen: int
    participants: dict[tuple[str, str], Participant] = field(default_factory=dict)
    authors: dict[int, ResolvedAuthor] = field(default_factory=dict)


class ImportSink:
    """Canonical records into ``mordred.db`` under one import run per sync."""

    def __init__(self, store: ImportStore, *, clock: Callable[[], float] = time.time) -> None:
        self.store = store
        self._clock = clock
        self._run_id: str | None = None
        self._committed = False
        self._owner_id = 0
        self._owner_label = ""
        self._account = ""
        self._imported_at = 0
        self._stored: dict[str, ImportConversation] = {}
        self._dialogs: dict[str, _ImportDialog] = {}
        self._counts: Counter[str] = Counter()

    @property
    def run_id(self) -> str | None:
        return self._run_id

    def begin(self, index: ArchiveIndex) -> None:
        if index.account_id <= 0:
            raise StoreError("account_mismatch")
        self._owner_id = index.account_id
        self._owner_label = index.account_label
        self._account = str(index.account_id)
        self._imported_at = int(self._clock())
        with _refused():
            self._stored = stored_conversations(self.store, self._account)
            self._run_id = self.store.run_begin(Source.TELEGRAM)

    def open_dialog(self, dialog: Any, *, archived: bool) -> _ImportDialog:
        fresh = convert_dialog(dialog, account=self._account, archived=archived)
        stored = self._stored.get(fresh.conv_uid)
        conv = fresh
        if stored is not None:
            conv = replace(
                fresh,
                participants=stored.participants,
                last_message_at=stored.last_message_at,
                message_count=stored.message_count,
                sync_cursor=stored.sync_cursor,
            )
        cursor = _cursor_value(conv.sync_cursor)
        handle = _ImportDialog(
            dialog_id=int(dialog.id),
            conv=conv,
            cursor=cursor,
            seen=cursor,
            participants={_participant_key(p): p for p in conv.participants},
        )
        self._dialogs[conv.conv_uid] = handle
        return handle

    def cursor(self, dialog_id: int) -> int | None:
        stored = self._stored.get(telegram_conv_uid(dialog_id))
        return (_cursor_value(stored.sync_cursor) or None) if stored is not None else None

    def convert(self, handle: _ImportDialog, message: Any) -> ImportMessage | None:
        conv_uid = handle.conv.conv_uid
        try:
            record = convert_import_message(
                message,
                owner_id=self._owner_id,
                conv=handle.conv,
                imported_at=self._imported_at,
                resolve_reply=lambda msg_id: self.resolve_reply(conv_uid, msg_id),
            )
            if record is not None:
                validate_message(record)
        except RecordError as exc:
            _log.warning("telegram message skipped (%s)", exc.code)
            self._counts["invalid"] += 1
            return None
        if record is None:
            self._counts["skipped"] += 1
            return None
        self._remember(handle, record)
        return record

    def _remember(self, handle: _ImportDialog, record: ImportMessage) -> None:
        handle.authors[int(record.message_id)] = ResolvedAuthor.of(record.parts[0])  # the text, too
        if len(handle.authors) > _MAX_REPLY_AUTHORS:
            del handle.authors[next(iter(handle.authors))]  # oldest first: ids arrive ascending
        if record.owner_class is OwnerClass.UNKNOWN or len(handle.participants) >= _MAX_PARTICIPANTS:
            return
        owner = record.owner_class is OwnerClass.ACCOUNT_OWNER
        participant = Participant(
            kind=SenderKind(record.sender_kind),
            stable_id=record.sender_id,
            display_name=(record.sender_name or self._owner_label) if owner else record.sender_name,
            owner_class=OwnerClass(record.owner_class),
        )
        handle.participants.setdefault(_participant_key(participant), participant)

    def write(self, handle: _ImportDialog, messages: Sequence[ImportMessage]) -> int:
        if self._run_id is None:
            raise StoreError("import_store_unavailable")
        # The conversation row keeps its committed cursor and counts until finish().
        conv = replace(handle.conv, participants=tuple(handle.participants.values()))
        with _refused():
            result = self.store.write_thread(self._run_id, messages, conversation=conv)
        handle.conv = conv
        self._counts.update(
            inserted=result.inserted, duplicates=result.duplicates, revised=result.revised, conflicts=result.conflicts
        )
        return result.inserted + result.revised

    def advance(self, handle: _ImportDialog, seen: int) -> int:
        handle.seen = max(handle.seen, seen)
        return handle.seen

    def resolve_reply(self, conv_uid: str, msg_id: int) -> ResolvedAuthor | None:
        """Author and text of the replied-to ``#a`` / ``#f1`` part: this run's cache first, then the store.

        The text is what :func:`~.client.convert_import_message` checks a quote
        against before crediting it to this author.
        """
        handle = self._dialogs.get(conv_uid)
        if handle is not None and msg_id in handle.authors:
            return handle.authors[msg_id]
        if handle is None:
            return None
        source_uid = telegram_source_uid(handle.dialog_id, msg_id)
        uids = [part_uid(source_uid, PartKind.AUTHORED), part_uid(source_uid, PartKind.FORWARDED, 1)]
        with _refused():
            found = self.store.parts_for(uids)
        for uid in uids:
            if uid in found:
                return ResolvedAuthor.of(found[uid].part)
        return None

    def checkpoint(self, index: ArchiveIndex) -> None:
        return None  # nothing is visible before the run commits

    def finish(self, index: ArchiveIndex) -> None:
        if self._run_id is None:
            raise StoreError("import_store_unavailable")
        counts = {"dialogs": len(self._dialogs), **self._counts}
        with _refused():
            self.store.run_commit(self._run_id, counts)
            self._committed = True
            stats = committed_stats(self.store, [h.conv.conv_uid for h in self._dialogs.values()])
            for handle in self._dialogs.values():
                count, last = stats.get(handle.conv.conv_uid, (0, None))
                cursor = max(handle.cursor, handle.seen)
                final = replace(
                    handle.conv,
                    participants=tuple(handle.participants.values()),
                    message_count=count,
                    last_message_at=last,
                    sync_cursor=str(cursor) if cursor > 0 else None,
                )
                if final != self._stored.get(final.conv_uid):
                    self.store.upsert_conversation(final)

    def fail(self) -> None:
        if self._run_id is None or self._committed:
            return
        with contextlib.suppress(ImportRefused, RecordError):
            self.store.run_fail(self._run_id, {"dialogs": len(self._dialogs), **self._counts})


# -- reads the ImportStore does not offer (yet) -------------------------------------------------


def _conversation(row: Sequence[Any]) -> ImportConversation:
    participants = tuple(
        Participant(
            kind=SenderKind(item["kind"]),
            stable_id=item["stable_id"],
            display_name=item["display_name"],
            owner_class=OwnerClass(item["owner_class"]),
        )
        for item in json.loads(row[6])
    )
    return ImportConversation(
        conv_uid=str(row[0]),
        source=Source(row[1]),
        source_account=str(row[2]),
        conversation_id=str(row[3]),
        kind=ConversationKind(row[4]),
        title=str(row[5]),
        participants=participants,
        last_message_at=row[7],
        message_count=int(row[8]),
        archived=bool(row[9]),
        sync_cursor=row[10],
        record_version=int(row[11]),
    )


def stored_conversations(store: ImportStore, account: str) -> dict[str, ImportConversation]:
    """Every Telegram conversation row of ``account`` (cursors and counts as last committed)."""
    with store.connection() as conn:
        rows = conn.execute(
            f"SELECT {_CONV_COLUMNS} FROM import_conversations WHERE source = ? AND source_account = ?",
            (_SOURCE, account),
        ).fetchall()
    try:
        convs = [_conversation(row) for row in rows]
    except (KeyError, TypeError, ValueError):
        raise ImportRefused("store_unavailable") from None
    return {conv.conv_uid: conv for conv in convs}


def committed_stats(store: ImportStore, conv_uids: Iterable[str]) -> dict[str, tuple[int, int | None]]:
    """``conv_uid -> (committed message count, newest sent_at)``."""
    uids = list(dict.fromkeys(conv_uids))
    stats: dict[str, tuple[int, int | None]] = {}
    with store.connection() as conn:
        for start in range(0, len(uids), _CHUNK):
            chunk = uids[start : start + _CHUNK]
            marks = ", ".join("?" * len(chunk))
            for conv_uid, count, last in conn.execute(
                "SELECT m.conv_uid, count(*), max(m.sent_at) FROM import_messages m "
                "JOIN import_runs r ON r.run_id = m.run_id AND r.state = 'committed' "
                f"WHERE m.conv_uid IN ({marks}) GROUP BY m.conv_uid",
                chunk,
            ):
                stats[str(conv_uid)] = (int(count), None if last is None else int(last))
    return stats


# -- selection and the service's reads ------------------------------------------------------------


def _default_opener(home: Path) -> ImportStore:
    from ...imports.store import open_import_store

    return open_import_store(home)


def open_history_store(home: Path, opener: ImportStoreOpener | None = None) -> ImportStore:
    """The gated import store for a retired index; any refusal is ``import_store_unavailable``."""
    try:
        return (opener or _default_opener)(home)
    except ImportRefused as exc:
        _log.warning("telegram import store unavailable (%s)", exc.code)
    except Exception as exc:  # the gate also touches the filesystem; never a fallback to .enc
        _log.warning("telegram import store unavailable (%s)", type(exc).__name__)
    raise StoreError("import_store_unavailable")


def select_sink(
    archive: ArchiveStore,
    index: ArchiveIndex,
    *,
    home: Path,
    opener: ImportStoreOpener | None = None,
    clock: Callable[[], float] = time.time,
) -> ArchiveSink | ImportSink:
    """The sink for this sync (see the module docstring); may rewrite a fresh index as version 2."""
    if index.retired_to is not None:
        return ImportSink(open_history_store(home, opener), clock=clock)
    if index.dialogs or _platform() != "darwin":
        return ArchiveSink(archive)
    try:
        store = (opener or _default_opener)(home)
    except Exception as exc:  # gate refused (not armed, no key, ...): this account stays on .enc
        _log.info("telegram sync stays on the archive (%s)", getattr(exc, "code", type(exc).__name__))
        return ArchiveSink(archive)
    index.retired_to = RETIRED_TO_IMPORT_STORE
    archive.save_index(index)  # version 2 before the first write: an older Mordred refuses this account
    return ImportSink(store, clock=clock)


def list_conversations(store: ImportStore, index: ArchiveIndex) -> list[ImportConversation]:
    """The account's conversations, newest activity first (unknown dates last)."""
    if index.account_id <= 0:
        return []
    with _refused():
        convs = list(stored_conversations(store, str(index.account_id)).values())
    return sorted(convs, key=lambda c: (c.last_message_at is None, -(c.last_message_at or 0), c.conv_uid))


def _legacy_kind(conv: ImportConversation) -> str:
    if conv.kind == ConversationKind.DIRECT:
        bots = (p.kind == SenderKind.BOT for p in conv.participants if p.owner_class != OwnerClass.ACCOUNT_OWNER)
        return "bot" if any(bots) else "user"
    return _LEGACY_KINDS[ConversationKind(conv.kind)]


def dialog_rows(convs: Sequence[ImportConversation]) -> list[dict[str, Any]]:
    """The service's dialog-list entries (same keys as the archive's, plus ``conv_uid``)."""
    return [
        {
            "id": conv.conversation_id,
            "conv_uid": conv.conv_uid,
            "kind": _legacy_kind(conv),
            "title": conv.title,
            "message_count": conv.message_count,
            "last_date": conv.last_message_at or 0,
            "last_message_at": conv.last_message_at,
            "archived": conv.archived,
        }
        for conv in convs
    ]


def summary(convs: Sequence[ImportConversation], index: ArchiveIndex) -> dict[str, Any]:
    """Counts for ``status()`` (no content), from the import store's conversations."""
    return {
        "last_sync": index.last_sync,
        "dialog_count": len(convs),
        "message_count": sum(conv.message_count for conv in convs),
        "account_label": index.account_label,
    }


# -- what a question reads -----------------------------------------------------------------------


def _reading_order(msg: ImportMessage) -> tuple[bool, int, int, str]:
    """``sent_at`` (unknown dates last), then the numeric message id: the store's reading order."""
    numeric = int(msg.message_id) if msg.message_id.isdigit() else 0
    return msg.sent_at is None, msg.sent_at or 0, numeric, msg.message_id


def _committed_messages(
    store: ImportStore, conv_uids: Sequence[str], since: int | None, until: int | None
) -> dict[str, list[ImportMessage]]:
    """Committed messages of ``conv_uids`` with ``since <= sent_at < until`` (either bound optional).

    The ``ImportStore`` has no per-conversation read, so this selects one part
    uid per committed message through :meth:`ImportStore.connection` and
    hydrates the messages with the public :meth:`ImportStore.parts_for`.
    """
    bounds = [("m.sent_at >= ?", since), ("m.sent_at < ?", until)]
    clauses = "".join(f" AND {clause}" for clause, value in bounds if value is not None)
    values = [value for _clause, value in bounds if value is not None]
    anchors: list[str] = []
    with store.connection() as conn:
        for start in range(0, len(conv_uids), _CHUNK):
            chunk = list(conv_uids[start : start + _CHUNK])
            sql = (
                "SELECT min(p.part_uid) FROM import_messages m "
                "JOIN import_runs r ON r.run_id = m.run_id AND r.state = 'committed' "
                "JOIN import_parts p ON p.source_uid = m.source_uid "
                f"WHERE m.conv_uid IN ({', '.join('?' * len(chunk))}){clauses} GROUP BY m.source_uid"
            )
            anchors.extend(str(row[0]) for row in conn.execute(sql, [*chunk, *values]))
    messages = {found.message.source_uid: found.message for found in store.parts_for(anchors).values()}
    by_conv: dict[str, list[ImportMessage]] = {}
    for msg in sorted(messages.values(), key=_reading_order):
        by_conv.setdefault(msg.conv_uid, []).append(msg)
    return by_conv


def _stored_ask_records(store: ImportStore, index: ArchiveIndex, request: AskRequest) -> AskRecords:
    convs = list_conversations(store, index)
    window = candidate_window(convs, request)
    wanted = [conv.conv_uid for conv in convs if window.may_hold(conv)]
    with _refused():
        found = _committed_messages(store, wanted, window.since, window.until) if wanted else {}
    return [(conv, found.get(conv.conv_uid, [])) for conv in convs]


def _legacy_rows(info: DialogInfo, stored: Sequence[StoredMessage], imported_at: int) -> list[ImportMessage]:
    rows: list[ImportMessage] = []
    for message in stored:
        try:
            rows.append(legacy_message(info, message, imported_at=imported_at))
        except RecordError as exc:
            _log.warning("telegram archive row skipped (%s)", exc.code)
    return rows


def _legacy_ask_records(
    archive: ArchiveStore, index: ArchiveIndex, request: AskRequest, *, imported_at: int
) -> AskRecords:
    dialogs: list[tuple[DialogInfo, ImportConversation]] = []
    for info in index.dialogs.values():
        try:
            dialogs.append((info, legacy_conversation(info, index)))
        except RecordError as exc:
            _log.warning("telegram archive dialog skipped (%s)", exc.code)
    window = candidate_window((conv for _info, conv in dialogs), request)
    records: list[tuple[ImportConversation, Sequence[ImportMessage]]] = []
    for info, conv in dialogs:
        # A chat with nothing in range is listed but never decrypted.
        stored = archive.load_messages(info.dialog_id) if window.may_hold(conv) else []
        rows = _legacy_rows(info, stored, imported_at)
        records.append((conv, [row for row in rows if window.contains(row.sent_at)]))
    return records


def load_ask_records(
    archive: ArchiveStore,
    index: ArchiveIndex,
    request: AskRequest,
    *,
    home: Path | None = None,
    opener: ImportStoreOpener | None = None,
    clock: Callable[[], float] = time.time,
) -> AskRecords:
    """Every conversation a question may read, with the messages it can use, in reading order.

    The source follows the index: ``mordred.db`` (committed runs only) when it
    is retired there, which needs ``home`` and never falls back to ``.enc``;
    otherwise the ``.enc`` archive, mapped to canonical records on the fly
    (one ``#a`` part of quality ``legacy`` per row). Conversations outside
    ``request.dialog_ids`` or the question's period come back without
    messages, unloaded; :func:`.ask.select_context` applies the same window.
    """
    if index.retired_to is not None:
        if home is None:
            raise StoreError("import_store_unavailable")
        return _stored_ask_records(open_history_store(home, opener), index, request)
    return _legacy_ask_records(archive, index, request, imported_at=int(clock()))


def forget_imported_history(
    archive: ArchiveStore, *, home: Path, opener: ImportStoreOpener | None = None
) -> str | None:
    """``logout --forget``: delete the account's Telegram ``import_*`` rows when the index is retired.

    Returns ``None`` when there was nothing to delete or the rows are gone, and a
    content-free code when the store could not be reached; the caller still wipes
    the ``.enc`` files either way. Must run before the archive (and its index) is wiped.
    """
    try:
        index = archive.load_index()
    except StoreError as exc:
        return exc.code
    if index.retired_to is None or index.account_id <= 0:
        return None
    try:
        store = open_history_store(home, opener)
        with _refused():
            store.delete_source(Source.TELEGRAM, str(index.account_id))
    except StoreError as exc:
        return exc.code
    return None
