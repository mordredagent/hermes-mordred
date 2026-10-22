"""``mordred_history_search``: deterministic search over the imported history (no model involved).

The Hermes model receives the matching message *parts* themselves, each
rendered by :func:`mordred_hermes.imports.render.render_part`: one head line
built by code from stored provenance (evidence id first, ``speaker:``,
quoted/forwarded qualifiers, chat, date), then the text indented two spaces.

Where the parts come from follows the Telegram index, exactly like
:func:`.history.load_ask_records`:

- **``fts``** — the index is retired to ``mordred.db``: the gated import store
  is opened afresh for every call (never cached) and searched with
  :meth:`~mordred_hermes.imports.store.ImportStore.search` (trigram FTS, an
  escaped ``LIKE`` for terms under three characters) plus SQL filters, then
  hydrated with ``parts_for``; ``around_evidence_id`` uses ``neighbors``. The
  store is source-neutral: imported mail is searched too.
- **``legacy``** — the ``.enc`` archive, mapped to canonical records on the fly
  (one ``#a`` part of quality ``legacy`` per row) and matched by case-folded
  substring over each part's text, bounded by :data:`_MAX_LEGACY_SCAN`.

Both paths return the same item shape. Bodies are capped at
:data:`MAX_BODY_CHARS` with the renderer's truncation marker, and the whole
result at about :data:`MAX_RESULT_CHARS` by dropping trailing items
(``truncated``). Nothing here logs content; failures are content-free codes.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final

from ...imports.aliases import IdentityAliases
from ...imports.records import (
    ImportConversation,
    ImportMessage,
    ImportPart,
    OwnerClass,
    PartKind,
    ProvenanceQuality,
    RecordError,
    is_part_uid,
    telegram_conv_uid,
)
from ...imports.render import conversation_label, render_part, truncate_part
from ...imports.store import MAX_SEARCH_LIMIT, ImportRefused, ImportStore, StoredPart
from .ask import AskError, AskRecords, AskRequest, local_day_bounds
from .store import StoreError

if TYPE_CHECKING:
    from .history import ImportStoreOpener
    from .service import TelegramService
    from .store import ArchiveStore

__all__ = [
    "DEFAULT_LIMIT",
    "MAX_BODY_CHARS",
    "MAX_CHAT_IDS",
    "MAX_LIMIT",
    "MAX_RESULT_CHARS",
    "SearchError",
    "SearchItem",
    "SearchRequest",
    "SearchResult",
    "parse_request",
    "search_history",
    "search_service",
]

_log = logging.getLogger(__name__)

MAX_CHAT_IDS: Final = 20
MAX_LIMIT: Final = 40
DEFAULT_LIMIT: Final = 20
MAX_BODY_CHARS: Final = 1200
#: Approximate size of the whole tool result (JSON characters).
MAX_RESULT_CHARS: Final = 12_000
#: Room kept for the note, reading rules, coverage and search blocks around the items.
ENVELOPE_CHARS: Final = 2_500
#: Messages before and after the anchor's message for ``around_evidence_id``.
NEIGHBOR_MESSAGES: Final = 2
_MAX_QUERY_CHARS: Final = 1000
_MAX_TERMS: Final = 32
#: Matches counted before ranking stops (the store's own search bound).
_MAX_CANDIDATES: Final = MAX_SEARCH_LIMIT
#: Parts examined on the legacy path before the scan stops (``complete`` is then false).
_MAX_LEGACY_SCAN: Final = 200_000
_TG_DIALOG_RE: Final = re.compile(r"tg:(-?\d+):\d+#")


class SearchError(ValueError):
    """Invalid arguments; ``code`` is stable and content-free."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class SearchRequest:
    query: str | None = None
    chat_ids: tuple[int, ...] = ()
    since: int | None = None  # unix seconds, inclusive (from ``start_date``)
    until: int | None = None  # unix seconds, exclusive (the day after ``end_date``)
    around_evidence_id: str | None = None
    limit: int = DEFAULT_LIMIT
    pseudonymize: bool = False


@dataclass(frozen=True)
class SearchItem:
    evidence_id: str
    conv_uid: str
    speaker_class: str
    part_kind: str
    provenance_quality: str
    #: Head line, newline, indented body (body capped at :data:`MAX_BODY_CHARS`).
    text: str

    def as_json(self) -> dict[str, str]:
        return {
            "evidence_id": self.evidence_id,
            "speaker_class": self.speaker_class,
            "part_kind": self.part_kind,
            "provenance_quality": self.provenance_quality,
            "text": self.text,
        }


@dataclass(frozen=True)
class SearchResult:
    mode: str  # "fts" | "legacy"
    #: Parts that matched (bounded by the search; ``complete`` is false at the bound).
    candidates: int
    items: tuple[SearchItem, ...]
    #: ``(conv_uid, label)`` of every conversation an item belongs to, once each.
    conversations: tuple[tuple[str, str], ...]
    #: Trailing items were dropped to keep the result near :data:`MAX_RESULT_CHARS`.
    truncated: bool
    #: Every matching part is in ``items`` (no bound, limit or size cut).
    complete: bool

    def search_json(self) -> dict[str, Any]:
        return {
            "mode": self.mode,
            "candidates": self.candidates,
            "returned": len(self.items),
            "truncated": self.truncated,
            "complete": self.complete,
        }

    def conversations_json(self) -> list[dict[str, str]]:
        return [{"conv_uid": uid, "label": label} for uid, label in self.conversations]


@dataclass(frozen=True)
class _Found:
    """Matching parts in result order, plus how they were found."""

    parts: Sequence[StoredPart]
    candidates: int
    #: The search stopped at a bound or covered only part of the history.
    partial: bool


# -- arguments -----------------------------------------------------------------------------------


def _query(value: object) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or len(value) > _MAX_QUERY_CHARS:
        raise SearchError("invalid_request")
    return value.strip() or None


def _chat_ids(value: object) -> tuple[int, ...]:
    if value is None:
        return ()
    if not isinstance(value, list) or len(value) > MAX_CHAT_IDS:
        raise SearchError("invalid_request")
    ids: list[int] = []
    for raw in value:
        if isinstance(raw, bool) or not isinstance(raw, int | str):
            raise SearchError("invalid_request")
        try:
            dialog = int(raw)
            telegram_conv_uid(dialog)
        except (ValueError, RecordError):
            raise SearchError("invalid_request") from None
        ids.append(dialog)
    return tuple(dict.fromkeys(ids))


def _day(value: object) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise SearchError("invalid_date")
    return value or None


def _dates(start: object, end: object) -> tuple[int | None, int | None]:
    try:
        return local_day_bounds(_day(start), _day(end))
    except AskError as exc:
        raise SearchError(exc.code) from None


def _evidence_id(value: object) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not is_part_uid(value.strip()):
        raise SearchError("invalid_evidence_id")
    return value.strip()


def _limit(value: object) -> int:
    if value is None:
        return DEFAULT_LIMIT
    if isinstance(value, bool) or not isinstance(value, int):
        raise SearchError("invalid_request")
    return max(1, min(value, MAX_LIMIT))


def _flag(value: object) -> bool:
    if value is None:
        return False
    if not isinstance(value, bool):
        raise SearchError("invalid_request")
    return value


def parse_request(args: Mapping[str, Any]) -> SearchRequest:
    """Validate the tool arguments (same date grammar as ``telegram_ask``); raises :class:`SearchError`."""
    since, until = _dates(args.get("start_date"), args.get("end_date"))
    return SearchRequest(
        query=_query(args.get("query")),
        chat_ids=_chat_ids(args.get("chat_ids")),
        since=since,
        until=until,
        around_evidence_id=_evidence_id(args.get("around_evidence_id")),
        limit=_limit(args.get("limit")),
        pseudonymize=_flag(args.get("pseudonymize")),
    )


# -- the import store (index retired to mordred.db) ----------------------------------------------


def _centered(parts: Sequence[StoredPart], anchor: str, limit: int) -> list[StoredPart]:
    """At most ``limit`` parts in reading order, centred on the anchor part."""
    if len(parts) <= limit:
        return list(parts)
    at = next((i for i, found in enumerate(parts) if found.part.part_uid == anchor), 0)
    start = max(0, min(at - limit // 2, len(parts) - limit))
    return list(parts[start : start + limit])


def _store_found(store: ImportStore, request: SearchRequest) -> _Found:
    try:
        if request.around_evidence_id is not None:
            near = store.neighbors(request.around_evidence_id, NEIGHBOR_MESSAGES)
            chosen = _centered(near, request.around_evidence_id, request.limit)
            return _Found(chosen, len(near), partial=False)
        conv_uids = [telegram_conv_uid(dialog) for dialog in request.chat_ids] or None
        hits = store.search(
            request.query, conv_uids=conv_uids, since=request.since, until=request.until, limit=_MAX_CANDIDATES
        )
        wanted = [hit.part_uid for hit in hits[: request.limit]]
        hydrated = store.parts_for(wanted)
    except ImportRefused as exc:
        _log.warning("history search: import store refused (%s)", exc.code)
        raise StoreError("import_store_unavailable") from None
    parts = [hydrated[uid] for uid in wanted if uid in hydrated]
    return _Found(parts, len(hits), partial=len(hits) >= _MAX_CANDIDATES)


# -- the legacy .enc archive ---------------------------------------------------------------------


def _terms(query: str | None) -> list[str]:
    """Whitespace-separated, case-folded terms (the store's term rule); NUL characters dropped."""
    if not query:
        return []
    words = (word.replace("\x00", "").casefold() for word in query.split())
    return list(dict.fromkeys(word for word in words if word))[:_MAX_TERMS]


def _flat(records: AskRecords) -> list[tuple[ImportConversation, ImportMessage, ImportPart]]:
    return [(conv, msg, part) for conv, messages in records for msg in messages for part in msg.parts]


def _newest_first(item: StoredPart) -> tuple[bool, int, str]:
    sent_at = item.message.sent_at
    return sent_at is None, -(sent_at or 0), item.part.part_uid


def _legacy_matches(records: AskRecords, request: SearchRequest) -> _Found:
    terms = _terms(request.query)
    scanned, matched = 0, []
    for conv, msg, part in _flat(records):
        scanned += 1
        if scanned > _MAX_LEGACY_SCAN:
            break
        folded = part.text.casefold()
        if all(term in folded for term in terms):
            matched.append(StoredPart(conv, msg, part))
    matched.sort(key=_newest_first)
    # Without words, chats or dates the archive is read for its most recent week only.
    recent_only = not terms and not request.chat_ids and request.since is None and request.until is None
    return _Found(matched[: request.limit], len(matched), partial=scanned > _MAX_LEGACY_SCAN or recent_only)


def _legacy_around(records: AskRecords, request: SearchRequest) -> _Found:
    anchor = request.around_evidence_id or ""
    for conv, messages in records:
        position = next((i for i, msg in enumerate(messages) if any(p.part_uid == anchor for p in msg.parts)), None)
        if position is None:
            continue
        window = messages[max(0, position - NEIGHBOR_MESSAGES) : position + NEIGHBOR_MESSAGES + 1]
        near = [StoredPart(conv, msg, part) for msg in window for part in msg.parts]
        return _Found(_centered(near, anchor, request.limit), len(near), partial=False)
    return _Found((), 0, partial=False)


def legacy_ask_request(request: SearchRequest) -> AskRequest:
    """The :class:`.ask.AskRequest` whose window loads what ``request`` can match from ``.enc``."""
    if request.around_evidence_id is not None:
        found = _TG_DIALOG_RE.match(request.around_evidence_id)
        dialogs = (int(found.group(1)),) if found else ()
        # A mail id names no Telegram chat: 0 is no dialog id, so the window loads nothing.
        return AskRequest(question="", dialog_ids=dialogs or (0,))
    return AskRequest(
        question=request.query or "",
        dialog_ids=request.chat_ids,
        since=request.since,
        until=request.until,
        pseudonymize=request.pseudonymize,
    )


# -- rendering and the size cap ------------------------------------------------------------------


def _item(found: StoredPart, aliases: IdentityAliases, lang: str) -> SearchItem | None:
    conv, msg, part = found
    try:
        rendered = truncate_part(render_part(conv, msg, part, aliases=aliases, lang=lang), MAX_BODY_CHARS)
    except RecordError as exc:  # a malformed stored row: left out, never rendered loosely
        _log.warning("history search: part skipped (%s)", exc.code)
        return None
    return SearchItem(
        evidence_id=rendered.evidence_id,
        conv_uid=conv.conv_uid,
        speaker_class=OwnerClass(part.author_owner_class).value,
        part_kind=PartKind(part.part_kind).value,
        provenance_quality=ProvenanceQuality(part.provenance_quality).value,
        text=rendered.text,
    )


def _json_size(value: object) -> int:
    return len(json.dumps(value, ensure_ascii=False)) + 2  # separator and indentation slack


def _assemble(found: _Found, request: SearchRequest, *, mode: str, lang: str, budget: int) -> SearchResult:
    aliases = IdentityAliases(enabled=request.pseudonymize)
    items: list[SearchItem] = []
    labels: dict[str, str] = {}
    used, truncated = 0, False
    for stored in found.parts:
        item = _item(stored, aliases, lang)
        if item is None:
            continue
        cost = _json_size(item.as_json())
        label = labels.get(item.conv_uid)
        if label is None:
            label = conversation_label(stored.conversation, aliases=aliases, lang=lang)
            cost += _json_size({"conv_uid": item.conv_uid, "label": label})
        if used + cost > budget:
            truncated = True
            break
        used += cost
        labels[item.conv_uid] = label
        items.append(item)
    complete = not (found.partial or truncated) and len(items) == found.candidates
    return SearchResult(
        mode=mode,
        candidates=found.candidates,
        items=tuple(items),
        conversations=tuple(labels.items()),
        truncated=truncated,
        complete=complete,
    )


def search_history(
    source: ImportStore | AskRecords,
    request: SearchRequest,
    *,
    lang: str = "en",
    budget: int = MAX_RESULT_CHARS - ENVELOPE_CHARS,
) -> SearchResult:
    """Search ``mordred.db`` (an :class:`ImportStore`, mode ``fts``) or legacy records (mode ``legacy``).

    ``budget`` bounds the JSON size of the items plus their conversation
    labels; the caller's envelope (note, rules, coverage) is the rest of
    :data:`MAX_RESULT_CHARS`. Raises :class:`~.store.StoreError` when the store
    refuses a read.
    """
    if isinstance(source, ImportStore):
        return _assemble(_store_found(source, request), request, mode="fts", lang=lang, budget=budget)
    finder = _legacy_around if request.around_evidence_id is not None else _legacy_matches
    return _assemble(finder(source, request), request, mode="legacy", lang=lang, budget=budget)


# -- the service's archive ------------------------------------------------------------------------


def _search_archive(
    archive: ArchiveStore, request: SearchRequest, home: Path, opener: ImportStoreOpener | None
) -> SearchResult:
    """Worker thread: read the index, then search the store it names (never a fallback to ``.enc``)."""
    from .history import load_ask_records, open_history_store
    from .service import _label_language

    index = archive.load_index()
    lang = _label_language(home)
    if index.retired_to is not None:
        # A fresh gate check and store open for every call; nothing is cached.
        return search_history(open_history_store(home, opener), request, lang=lang)
    records = load_ask_records(archive, index, legacy_ask_request(request), clock=time.time)
    return search_history(records, request, lang=lang)


async def search_service(service: TelegramService, request: SearchRequest) -> SearchResult:
    """Run ``request`` with the service's credentials and stores, like :meth:`.TelegramService.ask` without a model.

    The memory guard runs first and the credentials are unwrapped afresh
    (Touch ID unless disabled); only the archive handle outlives the unwrap.
    """
    from .service import TelegramServiceError

    await asyncio.to_thread(service._memory_guard)
    value = await service._load_secrets(fresh=True)
    if value is None:
        raise TelegramServiceError("telegram_not_configured")
    archive = service._archive(value)
    del value
    home = service._profile_home()
    return await asyncio.to_thread(_search_archive, archive, request, home, service._import_store_opener)
