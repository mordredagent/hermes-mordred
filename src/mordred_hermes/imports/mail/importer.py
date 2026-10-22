"""Two-pass planning of a file-based mail import (no store writes; PR 10 writes).

Pass 1 reads every source once (headers only, plus the authored text of owner
records) to build:

- the copy table: one chosen copy per source uid. A Sent-labelled copy always
  wins over a received copy of the same Message-ID (a received copy never
  replaces its classification); otherwise the first copy wins. A second copy
  with identical bytes is a ``duplicate``, with different bytes a
  ``conflict`` — never an overwrite;
- the :class:`~.link.MetadataIndex` (Message-ID, address, date and
  authored-text key of true Sent copies only — owner evidence in
  :data:`~.link.ANCHOR_EVIDENCE`) so a quote can link to an owner message
  that appears later in the file. An ``own_address`` or ``list_rewrite``
  record is the owner for display but never anchors a quote link: its
  ``From``/``X-Original-From`` is a header anyone can type;
- the threads (:func:`.threading.build_threads`). With a ``thread_resolver``
  (the IMAP fetch plans one batch at a time) a thread that is not a Gmail
  thread joins the stored conversation of a committed message it contains or
  references (``Message-ID``, ``In-Reply-To``, ``References``), so a reply
  chain A→B→C split across batches stays one conversation; threads of the
  plan that resolve to the same stored conversation are merged. That only
  sees parents already stored; :attr:`ImportPlan.refs` (every planned
  message's referenced ids) lets the store merge the conversations of
  replies fetched BEFORE their parent (``ImportStore.write_batch(refs=...)``).

Pass 2 reads the sources again and normalises the chosen copies into
:class:`PlannedThread` objects (one :class:`~..records.ImportConversation`
plus its messages). The :class:`~.report.DryRunReport` holds counts only.
Nothing is logged and no temporary file is written.
"""

from __future__ import annotations

import hashlib
import time
from collections import Counter
from collections.abc import Callable, Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field, replace

from ..records import (
    ConversationKind,
    ImportConversation,
    ImportMessage,
    OwnerClass,
    Participant,
    PartKind,
    Source,
    mail_conv_uid,
    validate_conversation,
)
from ..render import conversation_label, render_part
from ._text import clean_line, link_key
from .headers import MailHeaders, parse_headers
from .link import ANCHOR_EVIDENCE, IndexEntry, Linker, MetadataIndex, chain_linkers
from .normalize import (
    NormalizeContext,
    NormalizedMessage,
    Skipped,
    fold_name,
    message_identity,
    normalize,
    parse_mail,
    thread_input,
    with_trusted,
)
from .owner import SENT_EVIDENCE, Classification, OwnAddresses, classify
from .report import DryRunReport
from .source import MailSource, RawMessage, iter_raw
from .threading import Thread, ThreadInput, build_threads, normalize_subject

__all__ = ["ImportPlan", "PlannedThread", "ThreadResolver", "plan_import"]

#: Message ids → the thread key (conversation id) of the committed message with that id.
ThreadResolver = Callable[[Sequence[str]], Mapping[str, str]]


@dataclass(frozen=True, kw_only=True)
class PlannedThread:
    conversation: ImportConversation
    messages: list[ImportMessage]
    method: str
    partial: bool


@dataclass(frozen=True)
class ImportPlan:
    account: str
    threads: tuple[PlannedThread, ...]
    report: DryRunReport
    #: source uid → the normalised Message-IDs it references (``In-Reply-To``, then ``References``).
    refs: Mapping[str, tuple[str, ...]] = field(default_factory=dict)

    def __repr__(self) -> str:
        return f"ImportPlan(threads={len(self.threads)}, messages={self.report.parsed})"

    def messages(self) -> Iterator[ImportMessage]:
        for thread in self.threads:
            yield from thread.messages

    def preview(self, n: int, *, lang: str = "en", tz_offset_minutes: int | None = None) -> list[str]:
        """Conversation labels and part head lines of the first ``n`` threads — never bodies."""
        lines: list[str] = []
        for planned in self.threads[: max(n, 0)]:
            conv = planned.conversation
            lines.append(conversation_label(conv, lang=lang))
            for msg in planned.messages:
                lines.extend(
                    render_part(conv, msg, part, lang=lang, tz_offset_minutes=tz_offset_minutes).head
                    for part in msg.parts
                )
        return lines


@dataclass
class _Copy:
    location: tuple[int, int]
    raw_digest: str
    sent: bool
    thread: ThreadInput
    entry: IndexEntry | None
    owner_name: str


@dataclass
class _Indexer:
    """Pass 1: copy table, metadata index and thread inputs."""

    account: str
    own: OwnAddresses
    sent_label: str
    imported_at: int
    copies: dict[str, _Copy] = field(default_factory=dict)
    skipped: Counter[str] = field(default_factory=Counter)
    labels: Counter[str] = field(default_factory=Counter)
    sent_from_not_own: set[str] = field(default_factory=set)
    duplicates: int = 0
    conflicts: int = 0
    order: int = 0
    scratch: Counter[str] = field(default_factory=Counter)  # pass-2 counts are the reported ones

    def add(self, raw: RawMessage, source_index: int) -> None:
        self.order += 1
        try:
            headers = with_trusted(parse_headers(parse_mail(raw.data, headers_only=True), self.scratch), raw.trusted)
        except Exception:  # untrusted input; counted, never logged
            self.skipped["parse_error"] += 1
            return
        self.labels.update(headers.labels)
        cls = classify(headers, self.own, sent_label=self.sent_label, trusted=raw.trusted)
        if cls.skip_reason is not None:
            self.skipped[cls.skip_reason] += 1
            return
        sent = cls.evidence_code in SENT_EVIDENCE
        sender = headers.sender
        if sent and sender is not None and sender.address not in self.own:
            self.sent_from_not_own.add(sender.address)
        uid, _message_id = message_identity(headers, self.account, raw.data)
        digest = hashlib.sha256(raw.data).hexdigest()
        existing = self.copies.get(uid)
        if existing is not None:
            if existing.raw_digest == digest:
                self.duplicates += 1
            else:
                self.conflicts += 1
            if not sent or existing.sent:
                return  # a received copy never replaces a Sent-labelled one; first copy otherwise
        entry, name = (None, "")
        if cls.owner_class is OwnerClass.ACCOUNT_OWNER:
            entry, name = self._owner_entry(raw, headers, cls)
            if cls.evidence_code not in ANCHOR_EVIDENCE:
                entry = None  # owner for display only: a header claim never anchors a quote link
        self.copies[uid] = _Copy(
            (source_index, raw.origin_index), digest, sent, thread_input(headers, uid, self.order), entry, name
        )

    def _owner_entry(self, raw: RawMessage, headers: MailHeaders, cls: Classification) -> tuple[IndexEntry | None, str]:
        ctx = NormalizeContext(
            account=self.account,
            own_addresses=self.own,
            imported_at=self.imported_at,
            sent_label=self.sent_label,
            stats=self.scratch,
        )
        result = normalize(raw, ctx)
        if not isinstance(result, NormalizedMessage):
            return None, ""
        msg = result.message
        authored = next((part.text for part in msg.parts if part.part_kind == PartKind.AUTHORED), "")
        entry = IndexEntry(
            source_uid=msg.source_uid,
            message_id=headers.message_id,
            owner_class=cls.owner_class,
            sender_kind=msg.sender_kind,
            address=msg.sender_id,
            name=msg.sender_name,
            sent_at=msg.sent_at,
            text_key=link_key(authored),
        )
        return entry, msg.sender_name

    def index(self) -> MetadataIndex:
        index = MetadataIndex()
        for copy in self.copies.values():
            if copy.entry is not None:
                index.add(copy.entry)
        return index

    def owner_names(self) -> frozenset[str]:
        return frozenset(folded for copy in self.copies.values() if (folded := fold_name(copy.owner_name)))


@dataclass
class _Tally:
    tallies: dict[str, Counter[str]] = field(default_factory=dict)
    scalars: Counter[str] = field(default_factory=Counter)

    def count(self, name: str, key: str, value: int = 1) -> None:
        self.tallies.setdefault(name, Counter())[key] += value

    def message(self, msg: ImportMessage) -> None:
        self.scalars["parsed"] += 1
        self.count("owner_classes", f"{msg.owner_class}:{msg.owner_evidence}")
        self.count("sender_kinds", str(msg.sender_kind))
        for part in msg.parts:
            self.count("parts_by_kind", str(part.part_kind))
            if part.part_kind == PartKind.AUTHORED:
                continue
            self.count("part_authors", f"{part.part_kind}:{part.author_evidence}")
            self.scalars["quote_forward_parts"] += 1
            self.scalars["unknown_author_quote_forward_parts"] += part.author_owner_class == OwnerClass.UNKNOWN


def _participants(messages: Sequence[ImportMessage]) -> tuple[Participant, ...]:
    seen: dict[tuple[str, str], Participant] = {}
    for msg in messages:
        key = (str(msg.owner_class), msg.sender_id or f"name:{msg.sender_name}")
        seen.setdefault(
            key,
            Participant(
                kind=msg.sender_kind, stable_id=msg.sender_id, display_name=msg.sender_name, owner_class=msg.owner_class
            ),
        )
    return tuple(seen.values())


def _title(normalized: Sequence[NormalizedMessage]) -> str:
    for item in normalized:
        title = clean_line(normalize_subject(item.headers.subject))
        if title:
            return title
    return ""


def _conversation(account: str, thread: Thread, normalized: Sequence[NormalizedMessage]) -> ImportConversation:
    messages = [item.message for item in normalized]
    dates = [msg.sent_at for msg in messages if msg.sent_at is not None]
    conv = ImportConversation(
        conv_uid=mail_conv_uid(account, thread.thread_key),
        source=Source.MAIL,
        source_account=account,
        conversation_id=thread.thread_key,
        kind=ConversationKind.THREAD,
        title=_title(normalized),
        participants=_participants(messages),
        last_message_at=max(dates) if dates else None,
        message_count=len(messages),
        archived=False,
        sync_cursor=None,
    )
    validate_conversation(conv)
    return conv


def _normalize_pass(
    sources: Sequence[MailSource], indexer: _Indexer, ctx: NormalizeContext
) -> dict[str, NormalizedMessage]:
    locations = {copy.location: uid for uid, copy in indexer.copies.items()}
    normalized: dict[str, NormalizedMessage] = {}
    for source_index, source in enumerate(sources):
        for raw in iter_raw(source, Counter()):
            uid = locations.get((source_index, raw.origin_index))
            if uid is None:
                continue
            result = normalize(raw, ctx)
            if isinstance(result, Skipped):
                indexer.skipped[result.reason] += 1
            elif result.message.source_uid != uid:
                indexer.skipped["source_changed"] += 1
            else:
                normalized[uid] = result
    return normalized


def _thread_ids(thread: Thread, inputs: Mapping[str, ThreadInput]) -> tuple[list[str], list[str]]:
    """(the members' own message ids, the ids they reference)."""
    items = [inputs[uid] for uid in thread.members if uid in inputs]
    own = [item.message_id for item in items if item.message_id]
    refs = [ref for item in items for ref in (*item.in_reply_to, *item.references)]
    return own, refs


def _join_stored(threads: list[Thread], indexer: _Indexer, resolver: ThreadResolver) -> list[Thread]:
    """Threads re-keyed onto the stored conversation they continue (see the module docstring)."""
    inputs = {copy.thread.key: copy.thread for copy in indexer.copies.values()}
    open_threads = [thread for thread in threads if thread.method != "gmail_thrid"]
    wanted = sorted({ident for thread in open_threads for ids in _thread_ids(thread, inputs) for ident in ids})
    stored = resolver(wanted) if wanted else {}
    if not stored:
        return threads
    grouped: dict[str, list[Thread]] = {}
    for thread in threads:
        key = thread.thread_key
        if thread.method != "gmail_thrid":
            own, refs = _thread_ids(thread, inputs)
            found = sorted({stored[i] for i in own if i in stored}) or sorted({stored[r] for r in refs if r in stored})
            key = found[0] if found else key
        grouped.setdefault(key, []).append(thread)
    joined: list[Thread] = []
    for key, group in grouped.items():
        if len(group) == 1:
            joined.append(replace(group[0], thread_key=key))
            continue
        members = sorted(
            {uid for thread in group for uid in thread.members},
            key=lambda uid: (inputs[uid].sent_at is None, inputs[uid].sent_at or 0, inputs[uid].order),
        )
        joined.append(Thread(key, "references", tuple(members), any(thread.partial for thread in group)))
    return sorted(joined, key=lambda thread: thread.thread_key)


def plan_import(
    sources: Iterable[MailSource],
    *,
    account: str,
    own_addresses: Iterable[str],
    sent_label: str = "Sent",
    linker: Linker | None = None,
    imported_at: int | None = None,
    thread_resolver: ThreadResolver | None = None,
) -> ImportPlan:
    """Plan an import of ``sources`` (read twice, never written).

    ``linker`` (e.g. the store-backed linker of the CLI) is consulted after the
    in-plan index for quotes that do not link to a record of this import.
    ``thread_resolver`` (the IMAP fetch's store lookup) attaches threads to the
    stored conversations they continue; what it raises propagates.
    Raises :class:`~.source.SourceError` for an unreadable source,
    :class:`~..records.RecordError` (``bad_account``) for an invalid account
    label and ``ValueError("bad_own_address")`` for an invalid own address.
    """
    mail_conv_uid(account, "probe")  # validates the account label up front
    source_list = list(sources)
    own = OwnAddresses.of(own_addresses)
    stamp = int(time.time()) if imported_at is None else imported_at
    indexer = _Indexer(account=account, own=own, sent_label=sent_label, imported_at=stamp)
    source_stats: Counter[str] = Counter()
    for source_index, source in enumerate(source_list):
        for raw in iter_raw(source, source_stats):
            indexer.add(raw, source_index)
    threads = build_threads([copy.thread for copy in indexer.copies.values()])
    if thread_resolver is not None:
        threads = _join_stored(threads, indexer, thread_resolver)
    stats: Counter[str] = Counter()
    ctx = NormalizeContext(
        account=account,
        own_addresses=own,
        imported_at=stamp,
        sent_label=sent_label,
        linker=chain_linkers(indexer.index(), linker),
        owner_names=indexer.owner_names(),
        thread_keys={uid: thread.thread_key for thread in threads for uid in thread.members},
        stats=stats,
    )
    normalized = _normalize_pass(source_list, indexer, ctx)
    return _assemble(account, threads, normalized, indexer, stats, source_stats)


def _references(indexer: _Indexer, planned: Iterable[str]) -> dict[str, tuple[str, ...]]:
    """The referenced ids of every planned message that has any."""
    refs: dict[str, tuple[str, ...]] = {}
    for uid in planned:
        thread = indexer.copies[uid].thread
        ids = tuple(dict.fromkeys((*thread.in_reply_to, *thread.references)))
        if ids:
            refs[uid] = ids
    return refs


def _assemble(
    account: str,
    threads: Sequence[Thread],
    normalized: dict[str, NormalizedMessage],
    indexer: _Indexer,
    stats: Counter[str],
    source_stats: Counter[str],
) -> ImportPlan:
    tally = _Tally()
    planned: list[PlannedThread] = []
    for thread in threads:
        members = [normalized[uid] for uid in thread.members if uid in normalized]
        if not members:
            continue
        planned.append(
            PlannedThread(
                conversation=_conversation(account, thread, members),
                messages=[item.message for item in members],
                method=thread.method,
                partial=thread.partial,
            )
        )
        tally.count("threads_by_method", thread.method)
        tally.scalars["partial_threads"] += thread.partial
        for item in members:
            tally.message(item.message)
    skipped = indexer.skipped + Counter(
        {key.removeprefix("skipped_"): value for key, value in source_stats.items() if key.startswith("skipped_")}
    )
    tally.tallies["skipped"] = skipped
    tally.scalars.update(conversations=len(planned), duplicates=indexer.duplicates, conflicts=indexer.conflicts)
    report = DryRunReport.from_counts(
        stats=stats,
        tallies=tally.tallies,
        labels=indexer.labels,
        sent_from_not_own=indexer.sent_from_not_own,
        scalars=tally.scalars,
    )
    planned_uids = [msg.source_uid for thread in planned for msg in thread.messages]
    return ImportPlan(account, tuple(planned), report, _references(indexer, planned_uids))
