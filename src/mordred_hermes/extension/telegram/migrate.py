"""``hermes-mordred telegram migrate-store``: move the legacy ``.enc`` archive into ``mordred.db``.

The archive (:mod:`.store`) holds legacy rows; the import store
(:mod:`mordred_hermes.imports.store`) holds canonical records. The mapping is
:mod:`mordred_hermes.imports.legacy_enc` (``out`` is the account owner, a named
sender is ``other``, an empty sender is ``unknown``; quality ``legacy``).

- :func:`plan_migration` reads every dialog and reports what a commit would do.
  It writes nothing: :meth:`ImportStore.contains` decides would-insert vs present.
- :func:`run_migration` writes every dialog (ascending dialog id, messages in
  ascending id order) with one ``write_thread`` transaction per dialog under ONE
  import run. ``commit=False`` is the store's dry-run run (every write rolled
  back); ``commit=True`` commits the run, then rewrites ``index.enc`` as version
  2 with ``retired_to: mordred.db`` (account id, label, dialogs and cursors kept),
  so an older Mordred refuses the archive instead of syncing into ``.enc``.
- :func:`finalize` checks, for every indexed dialog, that every archived message
  is committed in ``mordred.db`` and only then deletes the ``dialogs/*.enc``
  segment files; ``index.enc`` stays as the retirement marker. Any mismatch
  (missing rows, unreadable segments) refuses with ``finalize_mismatch`` and
  deletes nothing.

Rows are re-read from the archive with ESC characters replaced (as a live sync
does; the record contract refuses them). A row that still does not form a valid
record is counted ``invalid`` and skipped, so ``finalize`` keeps refusing until
it is resolved. A conversation this account already has in ``mordred.db`` is
never overwritten: a later sync may have advanced its cursor.

Everything reported is a count or a code, never a dialog id, title, name or
text. Commit and finalize hold the archive's sync lock (``sync_in_progress``
while a sync runs). The import store is macOS-only, so the store gate refuses
every step elsewhere (``unsupported_platform``); :func:`finalize` checks again.
"""

from __future__ import annotations

import contextlib
import logging
import re
import sys
import time
from collections import Counter
from collections.abc import Callable, Mapping, Sequence
from dataclasses import asdict, dataclass, replace
from pathlib import Path
from typing import Any, Final

from ...imports.legacy_enc import legacy_conversation, legacy_message
from ...imports.records import (
    ImportConversation,
    ImportMessage,
    OwnerClass,
    RecordError,
    Source,
    telegram_source_uid,
    validate_conversation,
    validate_message,
)
from ...imports.store import ImportRefused, ImportStore
from .history import committed_stats, stored_conversations
from .store import RETIRED_TO_IMPORT_STORE, ArchiveIndex, ArchiveStore, DialogInfo, StoredMessage, StoreError

__all__ = [
    "AUDIT_EVENT",
    "DialogCounts",
    "FinalizeResult",
    "MigrationError",
    "MigrationPlan",
    "MigrationResult",
    "Outcome",
    "audit_event",
    "error_code",
    "execute",
    "finalize",
    "open_store",
    "plan_migration",
    "run_migration",
]

_log = logging.getLogger(__name__)

AUDIT_EVENT: Final = "telegram.migrate_store"
#: Per-dialog counters read from the archive, in report order.
_READ_KEYS: Final = ("messages", "owner", "other", "unknown", "empty_sender", "unreadable_segments", "invalid")
_WRITE_KEYS: Final = ("inserted", "duplicates", "revised", "conflicts")
_RUN_KEYS: Final = ("dialogs", "invalid_dialogs", *_READ_KEYS, *_WRITE_KEYS)
_OWNER_KEYS: Final = {OwnerClass.ACCOUNT_OWNER: "owner", OwnerClass.OTHER: "other", OwnerClass.UNKNOWN: "unknown"}
_SEGMENT_SUFFIXES: Final = frozenset({".enc", ".tmp"})
#: A stable refusal code (``not_armed``, ``finalize_mismatch``): never message text.
_CODE_RE: Final = re.compile(r"[a-z][a-z0-9_]{0,63}")


class MigrationError(Exception):
    """A content-free refusal; ``counts`` (when given) explain it in numbers only."""

    def __init__(self, code: str, counts: Mapping[str, int] | None = None) -> None:
        super().__init__(code)
        self.code = code
        self.counts: dict[str, int] = dict(counts or {})


def _platform() -> str:
    return sys.platform


# -- results ----------------------------------------------------------------------------------


@dataclass(frozen=True)
class DialogCounts:
    """One dialog's counts. ``kind`` is the archive's category (user/bot/group/channel), never an id or title."""

    kind: str
    messages: int = 0
    owner: int = 0
    other: int = 0
    unknown: int = 0
    empty_sender: int = 0
    unreadable_segments: int = 0
    invalid: int = 0
    would_insert: int = 0
    present: int = 0
    #: The dialog itself does not form a valid conversation record (all its rows are ``invalid``).
    invalid_dialog: bool = False


@dataclass(frozen=True)
class MigrationPlan:
    retired: bool  # ``index.enc`` is already version 2
    dialogs: tuple[DialogCounts, ...]

    def totals(self) -> dict[str, int]:
        totals = {"dialogs": len(self.dialogs), "invalid_dialogs": sum(d.invalid_dialog for d in self.dialogs)}
        for key in (*_READ_KEYS, "would_insert", "present"):
            totals[key] = sum(int(getattr(d, key)) for d in self.dialogs)
        return totals


@dataclass(frozen=True)
class MigrationResult:
    committed: bool
    retired: bool  # ``index.enc`` is version 2 after this run
    counts: dict[str, int]


@dataclass(frozen=True)
class FinalizeResult:
    dialogs: int
    messages: int  # archived messages verified as committed in mordred.db
    segments_deleted: int


@dataclass(frozen=True)
class Outcome:
    """What one ``migrate-store`` invocation did: the CLI prints it, the audit event carries its counts."""

    mode: str  # dry_run | commit | finalize
    decision: str  # dry_run | committed | finalized | failed
    counts: dict[str, int]
    error: str | None = None
    retired: bool = False
    dialogs: tuple[DialogCounts, ...] = ()

    def as_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {"mode": self.mode, "decision": self.decision, "counts": dict(self.counts)}
        if self.error is not None:
            payload["error"] = self.error
        if self.mode != "finalize" and self.error is None:
            payload["retired"] = self.retired
        if self.dialogs:
            payload["dialogs"] = [asdict(d) for d in self.dialogs]
        return payload

    def lines(self) -> list[str]:
        """Plain-text report (counts and categories only); a refusal without counts prints nothing here."""
        if self.error is not None and not self.counts:
            return []
        lines = [_HEADINGS[self.mode if self.error is None else "failed"]]
        lines.extend(f"  {key}: {value}" for key, value in self.counts.items())
        for position, dialog in enumerate(self.dialogs, start=1):
            fields = " ".join(f"{key}={value}" for key, value in asdict(dialog).items() if key != "kind")
            lines.append(f"  dialog {position} ({dialog.kind}): {fields}")
        if self.error is None:
            lines.extend(self._next_steps())
        return lines

    def _next_steps(self) -> list[str]:
        unmigrated = self.counts.get("invalid", 0) + self.counts.get("unreadable_segments", 0)
        if self.mode == "dry_run":
            done = "index.enc is already retired to mordred.db; " if self.retired else ""
            return [f"{done}run `hermes-mordred telegram migrate-store --commit` to write these rows."]
        if self.mode == "commit":
            steps = [
                "index.enc is now version 2 (retired_to: mordred.db): new messages sync into mordred.db, "
                "and an older Mordred refuses the archive instead of syncing into .enc."
            ]
            if unmigrated:
                steps.append(f"{unmigrated} row(s)/segment(s) were not migrated; --finalize refuses until they are.")
            steps.append(
                "Next: `hermes-mordred telegram migrate-store --finalize --yes` deletes the .enc message files "
                "once every archived message is verified in mordred.db."
            )
            return steps
        return ["index.enc (version 2) is kept as the retirement marker."]


_HEADINGS: Final = {
    "dry_run": "Telegram migrate-store dry run: nothing was written (counts only).",
    "commit": "Telegram archive migrated into mordred.db under one import run.",
    "finalize": "Every archived message is committed in mordred.db; deleted the archive's .enc message files.",
    "failed": "Telegram migrate-store refused; nothing was deleted:",
}


# -- reading the archive ----------------------------------------------------------------------


def _clean(text: str) -> str:
    """The record contract refuses ESC; replace it exactly like a live sync does."""
    return text.replace("\x1b", "�")


def _clean_row(row: StoredMessage) -> StoredMessage:
    media = None if row.media is None else _clean(row.media)
    return replace(row, text=_clean(row.text), sender=_clean(row.sender), media=media)


def _segments(archive: ArchiveStore, dialog_id: int) -> tuple[list[StoredMessage], int]:
    """Every readable segment's rows, and how many segments do not decrypt.

    Segment by segment (``ArchiveStore`` has no public per-segment read): one
    damaged file must not hide the rows of the others. Anything but an
    undecryptable segment (an unsafe path, an I/O error) is raised.
    """
    rows: list[StoredMessage] = []
    unreadable = 0
    segment = 0
    while True:
        try:
            chunk = archive._load_segment(dialog_id, segment)
        except StoreError as exc:
            if exc.code != "store_undecryptable":
                raise
            unreadable += 1
        else:
            if chunk is None:
                return rows, unreadable
            rows.extend(chunk)
        segment += 1


@dataclass
class _Dialog:
    kind: str
    conversation: ImportConversation | None
    records: list[ImportMessage]
    counts: Counter[str]


def _records(info: DialogInfo, rows: Sequence[StoredMessage], counts: Counter[str], stamp: int) -> list[ImportMessage]:
    records: list[ImportMessage] = []
    for row in rows:
        try:
            record = legacy_message(info, row, imported_at=stamp)
            validate_message(record)
        except (RecordError, TypeError, ValueError):
            counts["invalid"] += 1
            continue
        counts[_OWNER_KEYS.get(OwnerClass(record.owner_class), "unknown")] += 1
        records.append(record)
    return records


def _read_dialog(archive: ArchiveStore, index: ArchiveIndex, info: DialogInfo, *, stamp: int) -> _Dialog:
    raw, unreadable = _segments(archive, info.dialog_id)
    rows = sorted((_clean_row(row) for row in raw), key=lambda row: row.id)
    counts: Counter[str] = Counter(messages=len(rows), unreadable_segments=unreadable)
    counts["empty_sender"] = sum(1 for row in rows if not row.sender)
    clean = replace(info, title=_clean(info.title))
    try:
        conversation = legacy_conversation(clean, index, messages=rows)
        validate_conversation(conversation)
    except (RecordError, TypeError, ValueError):
        counts["invalid"] = len(rows)
        return _Dialog(info.kind, None, [], counts)
    return _Dialog(info.kind, conversation, _records(clean, rows, counts, stamp), counts)


def _migratable(index: ArchiveIndex) -> ArchiveIndex:
    """The index as read for mapping (account label cleaned); refuses an archive without an account."""
    if index.account_id <= 0:
        raise MigrationError("account_unknown" if index.dialogs else "archive_empty")
    return replace(index, account_label=_clean(index.account_label))


def _dialog_counts(dialog: _Dialog, *, present: int) -> DialogCounts:
    counts = dialog.counts
    return DialogCounts(
        kind=dialog.kind,
        messages=counts["messages"],
        owner=counts["owner"],
        other=counts["other"],
        unknown=counts["unknown"],
        empty_sender=counts["empty_sender"],
        unreadable_segments=counts["unreadable_segments"],
        invalid=counts["invalid"],
        would_insert=len(dialog.records) - present,
        present=present,
        invalid_dialog=dialog.conversation is None,
    )


# -- plan / commit ----------------------------------------------------------------------------


def plan_migration(
    archive: ArchiveStore, store: ImportStore, *, clock: Callable[[], float] = time.time
) -> MigrationPlan:
    """What a commit would write, per dialog; nothing is written (not even an import run)."""
    index = archive.load_index()
    view = _migratable(index)
    stamp = int(clock())
    dialogs: list[DialogCounts] = []
    for dialog_id in sorted(view.dialogs):
        dialog = _read_dialog(archive, view, view.dialogs[dialog_id], stamp=stamp)
        uids = [record.source_uid for record in dialog.records]
        present = len(store.contains(uids)) if uids else 0
        dialogs.append(_dialog_counts(dialog, present=present))
    return MigrationPlan(retired=index.retired_to is not None, dialogs=tuple(dialogs))


def _run_counts(totals: Counter[str]) -> dict[str, int]:
    return {key: int(totals[key]) for key in _RUN_KEYS}


def _write_dialogs(
    archive: ArchiveStore, store: ImportStore, index: ArchiveIndex, run_id: str, *, stamp: int
) -> tuple[Counter[str], dict[str, ImportConversation]]:
    """One ``write_thread`` per dialog; returns the run's counters and the conversations it created."""
    stored = stored_conversations(store, str(index.account_id))
    totals: Counter[str] = Counter()
    created: dict[str, ImportConversation] = {}
    for dialog_id in sorted(index.dialogs):
        dialog = _read_dialog(archive, index, index.dialogs[dialog_id], stamp=stamp)
        totals.update(dialog.counts)
        totals["dialogs"] += 1
        if dialog.conversation is None:
            totals["invalid_dialogs"] += 1
            continue
        fresh = dialog.conversation.conv_uid not in stored
        if not dialog.records and not fresh:
            continue
        result = store.write_thread(run_id, dialog.records, conversation=dialog.conversation if fresh else None)
        totals.update(
            inserted=result.inserted, duplicates=result.duplicates, revised=result.revised, conflicts=result.conflicts
        )
        if fresh:
            created[dialog.conversation.conv_uid] = dialog.conversation
    return totals, created


def _settle_counts(store: ImportStore, created: Mapping[str, ImportConversation]) -> None:
    """A conversation this run created reports its committed count (skipped rows are not in it).

    Best effort: the rows are already committed; a refusal here only leaves the
    archive's own count on the conversation row, and the next sync recounts it.
    """
    if not created:
        return
    try:
        stats = committed_stats(store, created)
        for conv_uid, conv in created.items():
            count = stats.get(conv_uid, (0, None))[0]
            if count != conv.message_count:
                store.upsert_conversation(replace(conv, message_count=count))
    except ImportRefused as exc:
        _log.warning("telegram migration kept the archive's message counts (%s)", exc.code)


def run_migration(
    archive: ArchiveStore, store: ImportStore, *, commit: bool, clock: Callable[[], float] = time.time
) -> MigrationResult:
    """Write the archive under ONE import run; ``commit=True`` publishes it and retires ``index.enc``."""
    with contextlib.ExitStack() as stack:
        if commit:
            stack.enter_context(archive.locked())  # no sync appends to .enc meanwhile
        index = archive.load_index()
        view = _migratable(index)
        run_id = store.run_begin(Source.TELEGRAM, dry_run=not commit)
        totals: Counter[str] = Counter()
        try:
            totals, created = _write_dialogs(archive, store, view, run_id, stamp=int(clock()))
            store.run_commit(run_id, _run_counts(totals))  # a dry run only records its counts
        except BaseException:
            with contextlib.suppress(Exception):
                store.run_fail(run_id, _run_counts(totals))
            raise
        retired = index.retired_to is not None
        if commit:
            _settle_counts(store, created)
            if not retired:
                archive.save_index(replace(index, retired_to=RETIRED_TO_IMPORT_STORE))
                retired = True
    return MigrationResult(committed=commit, retired=retired, counts=_run_counts(totals))


# -- finalize ---------------------------------------------------------------------------------


def _verify(archive: ArchiveStore, store: ImportStore, index: ArchiveIndex) -> dict[str, int]:
    """Per dialog: every archived message committed in mordred.db, and every segment readable."""
    counts: Counter[str] = Counter(dialogs=0, messages=0, missing=0, mismatched_dialogs=0, unreadable_segments=0)
    for dialog_id in sorted(index.dialogs):
        rows, unreadable = _segments(archive, dialog_id)
        uids: set[str] = set()
        bad = 0
        for row in rows:
            try:
                uids.add(telegram_source_uid(dialog_id, row.id))
            except (RecordError, TypeError, ValueError):
                bad += 1
        missing = len(uids) - (len(store.contains(uids)) if uids else 0) + bad
        counts.update(dialogs=1, messages=len(uids) + bad, missing=missing, unreadable_segments=unreadable)
        if missing or unreadable:
            counts["mismatched_dialogs"] += 1
    return dict(counts)


def _delete_segments(root: Path) -> int:
    """Delete ``dialogs/*.enc`` (and stale ``*.tmp``) under the held lock; ``index.enc`` is untouched."""
    dialogs = root / "dialogs"
    if dialogs.is_symlink() or not dialogs.is_dir():
        return 0
    deleted = 0
    for child in dialogs.iterdir():
        if child.is_file() and not child.is_symlink() and child.suffix in _SEGMENT_SUFFIXES:
            child.unlink()
            deleted += child.suffix == ".enc"
    if not any(dialogs.iterdir()):
        dialogs.rmdir()
    return deleted


def finalize(archive: ArchiveStore, store: ImportStore) -> FinalizeResult:
    """Delete the ``.enc`` message segments once mordred.db holds every archived message."""
    if _platform() == "win32":
        raise MigrationError("unsupported_platform")  # the import store is macOS-only
    with archive.locked():
        index = archive.load_index()
        if index.retired_to is None:
            raise MigrationError("not_migrated")
        counts = _verify(archive, store, index)
        if counts["mismatched_dialogs"]:
            raise MigrationError("finalize_mismatch", counts)
        deleted = _delete_segments(archive._root)
    return FinalizeResult(dialogs=counts["dialogs"], messages=counts["messages"], segments_deleted=deleted)


# -- the command ------------------------------------------------------------------------------


def open_store(home: Path) -> ImportStore:
    """The gated import store; a refusal keeps the gate's code (``unsupported_platform``, ``not_armed``, ...)."""
    from ...imports import store as store_module

    return store_module.open_import_store(home)


def error_code(exc: BaseException) -> str:
    """A content-free code: a known exception's stable ``code``, else its class name."""
    code = getattr(exc, "code", None)
    known = isinstance(exc, MigrationError | StoreError | RecordError | ImportRefused)
    if not known or not isinstance(code, str) or _CODE_RE.fullmatch(code) is None:
        return type(exc).__name__
    return "account_mismatch" if isinstance(exc, ImportRefused) and code == "conflict" else code


def audit_event(decision: str, counts: Mapping[str, int], *, mode: str, error: str | None = None) -> None:
    """One best-effort ``telegram.migrate_store`` entry through the shared audit writer (counts and codes only)."""
    try:
        from ..._audit_support import build_audit_writer, safe_audit_append
        from ..._home import hermes_home

        entry: dict[str, Any] = {"event": AUDIT_EVENT, "decision": decision, "reason": None, "mode": mode, **counts}
        if error is not None:
            entry["error"] = error
        writer = build_audit_writer(hermes_home() / "mordred" / "audit.log")
        safe_audit_append(writer, entry, logger=_log)
    except Exception as exc:
        _log.debug("telegram migrate-store audit append failed (%s)", type(exc).__name__)


def _dry_run(archive: ArchiveStore, store: ImportStore) -> Outcome:
    plan = plan_migration(archive, store)
    return Outcome("dry_run", "dry_run", plan.totals(), retired=plan.retired, dialogs=plan.dialogs)


def _commit(archive: ArchiveStore, store: ImportStore) -> Outcome:
    result = run_migration(archive, store, commit=True)
    return Outcome("commit", "committed", result.counts, retired=result.retired)


def _finalize(archive: ArchiveStore, store: ImportStore) -> Outcome:
    result = finalize(archive, store)
    return Outcome("finalize", "finalized", asdict(result), retired=True)


_MODES: Final[Mapping[str, Callable[[ArchiveStore, ImportStore], Outcome]]] = {
    "dry_run": _dry_run,
    "commit": _commit,
    "finalize": _finalize,
}


def execute(mode: str, archive: ArchiveStore, store: ImportStore) -> Outcome:
    """Run one mode and write its one audit event; failures become a content-free ``Outcome.error``."""
    try:
        outcome = _MODES[mode](archive, store)
    except Exception as exc:
        code = error_code(exc)
        counts = exc.counts if isinstance(exc, MigrationError) else {}
        _log.warning("telegram migrate-store refused (%s)", code)
        audit_event("failed", counts, mode=mode, error=code)
        return Outcome(mode, "failed", counts, error=code)
    except BaseException as exc:  # an interrupt is audited, then re-raised
        audit_event("failed", {}, mode=mode, error=type(exc).__name__)
        raise
    audit_event(outcome.decision, outcome.counts, mode=mode)
    return outcome
