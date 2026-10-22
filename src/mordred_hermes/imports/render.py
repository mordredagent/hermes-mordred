"""Deterministic rendering of imported parts: one head line, then indented text.

Security contract:

- Every part renders as exactly one *head line* followed by its *body*. The
  head is built by code from stored records only::

    [Telegram tg:-100123:4567#f1] speaker: 田中 太郎 (forwarded text; original date
    2026-10-01 09:00 +09:00; forwarded by account owner) → chat: ⟦C1⟧ / 2026-10-15 14:02 +09:00

  (one line in practice). The evidence id sits in the leading bracket, right
  after the source label, so it survives any truncation of the tail.
- The speaker is ``account owner`` only when the part's author was classified
  ``account_owner`` at import; ``unknown`` renders ``unknown sender``, except a
  named channel or bot, which renders ``<name> (channel)`` / ``<name> (bot)``;
  anyone else renders their display name through
  :func:`~mordred_hermes.imports.aliases.safe_display`, which cannot produce a
  reserved label, a newline, or head-line grammar characters.
- Quoted and forwarded parts always name their kind and the container's
  speaker, so the quoter or forwarder is never presented as the author.
- Body text is neutralized (no forged alias tokens), optionally scrubbed of
  e-mail addresses and phone numbers, and every body line is indented two
  spaces. A forged head line inside imported text therefore never starts at
  column 0. Truncation only ever shortens the body.
- No model is involved; no content is logged.
"""

from __future__ import annotations

import datetime as _dt
import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, replace
from enum import StrEnum
from typing import Final

from ._labels import LABELS, labels_for
from .aliases import ALIAS_CLOSE, ALIAS_OPEN, IdentityAliases, clean_display, neutralize, safe_display
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
    is_part_uid,
)

__all__ = [
    "BODY_INDENT",
    "DEFAULT_HEAD_STYLE",
    "LABELS",
    "SOURCE_ICONS",
    "SOURCE_LABELS",
    "TRUNCATION_MARKER",
    "HeadStyle",
    "RenderedPart",
    "RenderedPartRef",
    "conversation_label",
    "format_date",
    "part_ref",
    "render_part",
    "render_selection",
    "truncate_part",
]

SOURCE_LABELS: Final = {Source.TELEGRAM: "Telegram", Source.MAIL: "Mail"}
SOURCE_ICONS: Final = {Source.TELEGRAM: "✈", Source.MAIL: "✉"}
BODY_INDENT: Final = "  "
TRUNCATION_MARKER: Final = "…[truncated]"
_MAX_LISTED_NAMES: Final = 3
_MAX_MEDIA_CHARS: Final = 64
#: Label key qualifying a named sender whose owner class is ``unknown``.
_KIND_QUALIFIERS: Final = {SenderKind.CHANNEL: "channel", SenderKind.BOT: "bot"}
# C0/C1 controls left after splitlines(); tab is kept.
_BODY_CONTROL_RE: Final = re.compile(r"[\x00-\x08\x0e-\x1f\x7f-\x9f]")


class HeadStyle(StrEnum):
    """Head-line variants compared by the provenance evaluation (not user config)."""

    PER_PART_EN = "per_part_en"
    PER_PART_JA = "per_part_ja"

    @property
    def lang(self) -> str:
        return self.value.rsplit("_", 1)[1]


DEFAULT_HEAD_STYLE: Final = HeadStyle.PER_PART_EN


@dataclass(frozen=True)
class RenderedPart:
    evidence_id: str
    head: str
    body: str
    text: str


@dataclass(frozen=True, kw_only=True)
class RenderedPartRef:
    """Stored facts about one rendered part, used to validate citations and build cards.

    Every field comes from the canonical records (labels de-aliased), never from
    a model.
    """

    evidence_id: str
    speaker: str
    speaker_class: OwnerClass
    part_kind: PartKind
    chat: str
    sent_at: int | None
    original_sent_at: int | None
    text: str
    provenance_quality: ProvenanceQuality


def format_date(ts: int | None, *, tz_offset_minutes: int | None = None, unknown: str = "date unknown") -> str:
    """``YYYY-MM-DD HH:MM ±HH:MM``; ``unknown`` when ``ts`` is missing or unrepresentable.

    ``tz_offset_minutes=None`` uses this machine's local zone.
    """
    zone = None if tz_offset_minutes is None else _dt.timezone(_dt.timedelta(minutes=tz_offset_minutes))
    if ts is None:
        return unknown
    try:
        moment = _dt.datetime.fromtimestamp(ts, tz=_dt.UTC).astimezone(zone)
    except (OverflowError, OSError, ValueError):
        return unknown
    offset = moment.utcoffset() or _dt.timedelta(0)
    minutes = int(offset.total_seconds()) // 60
    sign = "+" if minutes >= 0 else "-"
    hours, mins = divmod(abs(minutes), 60)
    return f"{moment:%Y-%m-%d %H:%M} {sign}{hours:02d}:{mins:02d}"


def _resolve_lang(lang: str, style: HeadStyle | str | None) -> str:
    return lang if style is None else HeadStyle(style).lang


@dataclass(frozen=True)
class _Ctx:
    source: Source
    aliases: IdentityAliases | None
    lang: str
    labels: dict[str, str]

    @classmethod
    def create(
        cls, conv: ImportConversation, aliases: IdentityAliases | None, lang: str, style: HeadStyle | str | None
    ) -> _Ctx:
        resolved = _resolve_lang(lang, style)
        return cls(Source(conv.source), aliases, resolved, labels_for(resolved))

    def person(
        self, owner_class: OwnerClass, ident: str | None, name: str | None, kind: SenderKind | None = None
    ) -> str:
        if owner_class == OwnerClass.ACCOUNT_OWNER:
            return self.labels["owner"]
        if owner_class == OwnerClass.OTHER:
            # A mail sender without a display name is still identified by address.
            return self._named(ident, name or (ident if self.source is Source.MAIL and ident else ""))
        qualifier = None if kind is None else _KIND_QUALIFIERS.get(kind)
        if qualifier is None or not clean_display(name):
            return self.labels["unknown_sender"]
        # A named channel or bot whose owner is unknown (a broadcast post, an
        # anonymous admin) is still that channel or bot, never the owner.
        return f"{self._named(ident, name)} ({self.labels[qualifier]})"

    def _named(self, ident: str | None, raw: str | None) -> str:
        display = safe_display(raw, lang=self.lang)
        if self.aliases is None or not (clean_display(raw) or ident):
            return display
        key = f"{self.source}:id:{ident}" if ident else f"{self.source}:name:{display}"
        return self.aliases.alias("P", key, display)

    def participant(self, participant: Participant) -> str:
        return self.person(participant.owner_class, participant.stable_id, participant.display_name, participant.kind)

    def listed(self, participants: Sequence[Participant]) -> str:
        """Up to three names, others first, the owner last, then ``(+N)``."""
        others = [p for p in participants if p.owner_class != OwnerClass.ACCOUNT_OWNER]
        has_owner = len(others) != len(participants)
        # No de-duplication by rendered name: two people who share a name stay two.
        names = [self.participant(p) for p in others]
        room = _MAX_LISTED_NAMES - 1 if has_owner else _MAX_LISTED_NAMES
        shown = names[:room] + ([self.labels["owner"]] if has_owner else [])
        hidden = len(names) - len(names[:room])
        text = ", ".join(shown) if shown else self.labels["unknown"]
        return f"{text} (+{hidden})" if hidden else text

    def chat_title(self, conv: ImportConversation) -> str:
        title = neutralize(clean_display(conv.title) or clean_display(conv.conversation_id))
        if not title:
            return self.labels["unknown"]
        return title if self.aliases is None else self.aliases.alias("C", conv.conv_uid, title)


def _qualifier(ctx: _Ctx, msg: ImportMessage, part: ImportPart, tz_offset_minutes: int | None) -> str:
    labels = ctx.labels
    items: list[str] = []
    if part.part_kind != PartKind.AUTHORED:
        container = ctx.person(msg.owner_class, msg.sender_id, msg.sender_name, msg.sender_kind)
        if part.part_kind == PartKind.FORWARDED:
            original = format_date(
                part.original_sent_at, tz_offset_minutes=tz_offset_minutes, unknown=labels["unknown"]
            )
            items += [
                labels["forwarded"],
                f"{labels['original_date']} {original}",
                f"{labels['forwarded_by']} {container}",
            ]
        else:
            items += [labels["quoted"], f"{labels['quoted_by']} {container}"]
    if part.provenance_quality == ProvenanceQuality.LEGACY:
        items.append(labels["legacy_qualifier"])
    return f" ({'; '.join(items)})" if items else ""


def _primary_part_uid(msg: ImportMessage) -> str | None:
    """Media belongs to the authored part, else to the first part."""
    for part in msg.parts:
        if part.part_kind == PartKind.AUTHORED:
            return part.part_uid
    return min(msg.parts, key=lambda p: p.ordinal).part_uid if msg.parts else None


def _body(msg: ImportMessage, part: ImportPart, aliases: IdentityAliases | None) -> str:
    text = neutralize(part.text)
    if aliases is not None:
        text = aliases.scrub_text(text)
    if msg.media and _primary_part_uid(msg) == part.part_uid:
        media = " ".join(_BODY_CONTROL_RE.sub(" ", neutralize(msg.media)).split())[:_MAX_MEDIA_CHARS]
        if media:
            text = f"{text} [{media}]".strip()
    lines = text.splitlines() or [""]
    return "\n".join(BODY_INDENT + _BODY_CONTROL_RE.sub("�", line) for line in lines)


def _check_part_uid(msg: ImportMessage, part: ImportPart) -> None:
    if not is_part_uid(part.part_uid) or not part.part_uid.startswith(f"{msg.source_uid}#"):
        raise RecordError("bad_part_uid")


def render_part(
    conv: ImportConversation,
    msg: ImportMessage,
    part: ImportPart,
    *,
    aliases: IdentityAliases | None = None,
    lang: str = "en",
    tz_offset_minutes: int | None = None,
    style: HeadStyle | str | None = None,
) -> RenderedPart:
    """Render one part as ``head + "\\n" + body``.

    ``style`` (evaluation only) overrides ``lang``. Pass
    ``IdentityAliases(enabled=False)`` to keep real names but still tell apart
    two people who share one (``<name> (2)``).
    """
    _check_part_uid(msg, part)
    ctx = _Ctx.create(conv, aliases, lang, style)
    labels = ctx.labels
    speaker = ctx.person(part.author_owner_class, part.author_id, part.author_name, part.author_kind)
    qualifier = _qualifier(ctx, msg, part, tz_offset_minutes)
    if ctx.source is Source.MAIL:
        destination = f"{labels['to']}: {ctx.listed(msg.recipients)}"
    else:
        destination = f"{labels['chat']}: {ctx.chat_title(conv)}"
    date = format_date(msg.sent_at, tz_offset_minutes=tz_offset_minutes, unknown=labels["date_unknown"])
    head = (
        f"[{SOURCE_LABELS[ctx.source]} {part.part_uid}] "
        f"{labels['speaker']}: {speaker}{qualifier} → {destination} / {date}"
    )
    body = _body(msg, part, aliases)
    return RenderedPart(evidence_id=part.part_uid, head=head, body=body, text=f"{head}\n{body}")


def part_ref(
    conv: ImportConversation,
    msg: ImportMessage,
    part: ImportPart,
    *,
    aliases: IdentityAliases | None = None,
    lang: str = "en",
    style: HeadStyle | str | None = None,
) -> RenderedPartRef:
    """Stored facts for :func:`mordred_hermes.imports.evidence.validate` (real, de-aliased labels)."""
    _check_part_uid(msg, part)
    ctx = _Ctx.create(conv, aliases, lang, style)
    speaker = ctx.person(part.author_owner_class, part.author_id, part.author_name, part.author_kind)
    chat = ctx.chat_title(conv)
    if aliases is not None:
        speaker, chat = aliases.dealias(speaker), aliases.dealias(chat)
    return RenderedPartRef(
        evidence_id=part.part_uid,
        speaker=speaker,
        speaker_class=OwnerClass(part.author_owner_class),
        part_kind=PartKind(part.part_kind),
        chat=chat,
        sent_at=msg.sent_at,
        original_sent_at=part.original_sent_at,
        text=part.text,
        provenance_quality=ProvenanceQuality(part.provenance_quality),
    )


def conversation_label(
    conv: ImportConversation,
    *,
    aliases: IdentityAliases | None = None,
    lang: str = "en",
    style: HeadStyle | str | None = None,
) -> str:
    """Deterministic title with participants; group lists never claim completeness."""
    ctx = _Ctx.create(conv, aliases, lang, style)
    icon = SOURCE_ICONS[ctx.source]
    title = ctx.chat_title(conv)
    if ctx.source is Source.MAIL or conv.kind == ConversationKind.DIRECT:
        others = [p for p in conv.participants if p.owner_class != OwnerClass.ACCOUNT_OWNER]
        return f"{icon} {title} · {ctx.listed(others)} ⇄ {ctx.labels['owner']}"
    return f"{icon} {title} · {ctx.labels['seen_in_archive']}: {ctx.listed(conv.participants)}"


def truncate_part(item: RenderedPart, max_body_chars: int | None) -> RenderedPart:
    """Shorten the body to ``max_body_chars`` plus a marker; the head is never cut."""
    if max_body_chars is None or len(item.body) <= max_body_chars:
        return item
    kept = item.body[: max(max_body_chars, 0)]
    opened = kept.rfind(ALIAS_OPEN)
    if opened != -1 and ALIAS_CLOSE not in kept[opened:]:
        kept = kept[:opened]  # never leave half an alias token
    kept = kept.rstrip()
    body = f"{kept or BODY_INDENT}{TRUNCATION_MARKER}"
    return replace(item, body=body, text=f"{item.head}\n{body}")


def render_selection(items: Iterable[RenderedPart], *, max_body_chars: int | None = None) -> str:
    """Join rendered parts, truncating each body (never a head) to ``max_body_chars``."""
    return "\n".join(truncate_part(item, max_body_chars).text for item in items)
