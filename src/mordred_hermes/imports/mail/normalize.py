"""Turn one raw mail message into a canonical :class:`~..records.ImportMessage`.

- The container's own text (``#a``) is attributed to the sender as classified
  by :func:`.owner.classify`. Every quoted (``#q<n>``) and forwarded
  (``#f<n>``) span is a separate part whose author comes from a
  :data:`~.link.Linker` (owner only when linked) or else from the span's claim:
  an own address merely claimed is ``unknown`` (``claimed_own_unlinked``), a
  missing attribution is ``unknown`` (``no_attribution``). The transport
  sender is never the author of a quote or forward it carries.
- ``source_revision`` is the SHA-256 of the raw bytes. A message without a
  usable Message-ID gets the fallback uid ``mail:<account>:h:<32 hex>`` over its
  Date, From, To, Subject and raw body.
- ``sent_at`` is the ``Date`` header or ``None``; never the import time.
- Every produced record passes :func:`~..records.validate_message`. Failures
  become :class:`Skipped` with content-free reason codes; nothing is logged.
"""

from __future__ import annotations

import hashlib
import unicodedata
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from email import policy
from email.message import Message
from email.parser import BytesParser
from typing import Final

from ..records import (
    ImportMessage,
    ImportPart,
    OwnerClass,
    Participant,
    PartKind,
    ProvenanceQuality,
    RecordError,
    SenderKind,
    content_digest,
    mail_conv_uid,
    mail_fallback_uid,
    mail_source_uid,
    part_uid,
    validate_message,
)
from ._text import cap_utf8, clean_line, link_key
from .body import BodyResult, ForwardedMail, extract_body
from .headers import Address, MailHeaders, parse_headers
from .link import Linker, QuoteClaim, text_digest
from .owner import Classification, OwnAddresses, classify, is_noreply
from .segment import MAX_PARTS, Attribution, Segment, segment_body
from .source import RawMessage
from .threading import ThreadInput, default_thread_key, subject_key

__all__ = [
    "NormalizeContext",
    "NormalizedMessage",
    "Skipped",
    "fold_name",
    "message_identity",
    "normalize",
    "parse_mail",
    "thread_input",
]

_PARSER: Final = BytesParser(policy=policy.default)
_UNKNOWN_SENDER: Final[tuple[SenderKind, None, str]] = (SenderKind.UNKNOWN, None, "")


@dataclass(frozen=True, kw_only=True)
class NormalizeContext:
    account: str
    own_addresses: OwnAddresses
    imported_at: int
    sent_label: str = "Sent"
    linker: Linker | None = None
    #: Folded display names seen on owner records; a name-only quote claim
    #: matching one is downgraded to ``unknown`` (a name never upgrades).
    owner_names: frozenset[str] = frozenset()
    #: source uid → thread key decided by the importer's threading pass.
    thread_keys: Mapping[str, str] = field(default_factory=dict)
    stats: Counter[str] = field(default_factory=Counter, compare=False)


@dataclass(frozen=True, kw_only=True)
class NormalizedMessage:
    message: ImportMessage
    headers: MailHeaders
    classification: Classification
    thread: ThreadInput
    body: BodyResult
    truncated: bool


@dataclass(frozen=True)
class Skipped:
    reason: str
    origin_index: int


@dataclass(frozen=True, kw_only=True)
class _Author:
    owner_class: OwnerClass
    kind: SenderKind
    ident: str | None
    name: str
    evidence: str
    quality: ProvenanceQuality
    original_sent_at: int | None = None
    original_ref: str | None = None


def fold_name(name: str) -> str:
    return " ".join(unicodedata.normalize("NFKC", name).casefold().split())


def parse_mail(data: bytes, *, headers_only: bool = False) -> Message:
    """Parse with ``policy.default`` (headers keep their raw values for :mod:`.headers`)."""
    return _PARSER.parsebytes(data, headersonly=headers_only)


def _raw_body(data: bytes) -> bytes:
    cuts = [index for index in (data.find(b"\r\n\r\n"), data.find(b"\n\n")) if index != -1]
    return data[min(cuts) :] if cuts else b""


def message_identity(headers: MailHeaders, account: str, data: bytes) -> tuple[str, str]:
    """(source uid, stored message id); the fallback id is ``h:<32 hex>``."""
    if headers.message_id:
        try:
            return mail_source_uid(account, headers.message_id), headers.message_id
        except RecordError:
            pass
    hasher = hashlib.sha256()
    for value in headers.raw_identity:
        hasher.update(value.encode("utf-8", errors="surrogateescape") + b"\0")
    hasher.update(_raw_body(data))
    digest = hasher.hexdigest()
    return mail_fallback_uid(account, digest), f"h:{digest[:32]}"


def thread_input(headers: MailHeaders, source_uid: str, order: int) -> ThreadInput:
    addresses = (*headers.from_, *headers.to, *headers.cc)
    return ThreadInput(
        key=source_uid,
        message_id=headers.message_id,
        in_reply_to=headers.in_reply_to,
        references=headers.references,
        gm_thread_id=headers.gm_thread_id,
        subject_key=subject_key(headers.subject),
        participants=frozenset(item.address for item in addresses if item.address),
        sent_at=headers.date,
        order=order,
    )


def _owner_address(headers: MailHeaders, own: OwnAddresses) -> Address | None:
    for item in (*headers.x_original_from, *headers.reply_to):
        if item.address in own:
            return item
    return None


def _sender(headers: MailHeaders, cls: Classification, own: OwnAddresses) -> tuple[SenderKind, str | None, str]:
    if cls.owner_class is OwnerClass.UNKNOWN:
        return _UNKNOWN_SENDER
    sender = headers.sender
    if cls.evidence_code == "list_rewrite":
        sender = _owner_address(headers, own) or sender
    if sender is None:
        return cls.sender_kind, None, ""
    return cls.sender_kind, sender.address or None, sender.name


def _recipients(headers: MailHeaders, own: OwnAddresses) -> tuple[Participant, ...]:
    result: list[Participant] = []
    for item in (*headers.to, *headers.cc):
        if item.address:
            owner = OwnerClass.ACCOUNT_OWNER if item.address in own else OwnerClass.OTHER
        else:
            owner = OwnerClass.UNKNOWN  # a name alone never decides identity
        result.append(
            Participant(kind=SenderKind.USER, stable_id=item.address or None, display_name=item.name, owner_class=owner)
        )
    return tuple(result)


def _media(kinds: Sequence[str]) -> str | None:
    if not kinds:
        return None
    counts = sorted(Counter(kinds).items())
    return "attachments: " + ", ".join(kind if count == 1 else f"{kind} x{count}" for kind, count in counts)


def _forward_attribution(mail: ForwardedMail) -> Attribution:
    sender = mail.headers.sender
    return Attribution(
        address=sender.address if sender else None,
        name=sender.name if sender else "",
        sent_at=mail.headers.date,
        source="rfc822",
        locale="neutral",
        message_id=mail.headers.message_id,
    )


def _segments(headers: MailHeaders, body: BodyResult, stats: Counter[str]) -> list[Segment]:
    results = [segment_body(body.text, tz_offset_minutes=headers.tz_offset_minutes)]
    for mail in body.forwarded:
        stats["marker:rfc822:neutral"] += 1
        results.append(
            segment_body(
                mail.text,
                tz_offset_minutes=mail.headers.tz_offset_minutes or headers.tz_offset_minutes,
                base_kind=PartKind.FORWARDED,
                base_attribution=_forward_attribution(mail),
                base_depth=mail.depth,
            )
        )
    segments: list[Segment] = []
    for result in results:
        segments.extend(result.segments)
        stats.update({f"marker:{key}": value for key, value in result.markers.items()})
        stats["part_limit"] += result.part_limit
        stats["depth_limit"] += result.depth_limit
    return _limit(segments, stats)


def _limit(segments: list[Segment], stats: Counter[str]) -> list[Segment]:
    """At most MAX_PARTS parts: overflow quotes/forwards merge into one unattributed quote."""
    others = [segment for segment in segments if segment.kind is not PartKind.AUTHORED]
    if len(others) <= MAX_PARTS - 1:
        return segments
    stats["part_limit"] += 1
    keep = {id(segment) for segment in others[: MAX_PARTS - 2]}
    overflow = [segment for segment in others if id(segment) not in keep]
    merged = Segment(
        kind=PartKind.QUOTED,
        text="\n".join(segment.text for segment in overflow),
        depth=overflow[0].depth,
        attribution=None,
    )
    kept = [segment for segment in segments if segment.kind is PartKind.AUTHORED or id(segment) in keep]
    return [*kept, merged]


def _claim(segment: Segment, text: str, source_uid: str, headers: MailHeaders) -> QuoteClaim:
    attribution = segment.attribution
    key = link_key(text)
    replies = tuple(dict.fromkeys((*headers.in_reply_to, *reversed(headers.references))))
    return QuoteClaim(
        container_uid=source_uid,
        kind=segment.kind,
        claimed_address=attribution.address if attribution else None,
        claimed_name=attribution.name if attribution else "",
        claimed_at=attribution.sent_at if attribution else None,
        claimed_message_id=attribution.message_id if attribution else None,
        reply_message_ids=replies,
        text=text,
        text_key=key,
        text_digest=text_digest(key),
    )


def _unknown_author(evidence: str, original_sent_at: int | None = None) -> _Author:
    return _Author(
        owner_class=OwnerClass.UNKNOWN,
        kind=SenderKind.UNKNOWN,
        ident=None,
        name="",
        evidence=evidence,
        quality=ProvenanceQuality.UNKNOWN,
        original_sent_at=original_sent_at,
    )


def _claimed_author(attribution: Attribution | None, ctx: NormalizeContext) -> _Author:
    if attribution is None:
        return _unknown_author("no_attribution")
    claimed_own = (attribution.address is not None and attribution.address in ctx.own_addresses) or (
        attribution.address is None and fold_name(attribution.name) in ctx.owner_names
    )
    if claimed_own:
        return _unknown_author("claimed_own_unlinked", attribution.sent_at)
    if attribution.address is None:
        return _Author(
            owner_class=OwnerClass.OTHER,
            kind=SenderKind.USER,
            ident=None,
            name=attribution.name,
            evidence="attribution_name",
            quality=ProvenanceQuality.HEURISTIC,
            original_sent_at=attribution.sent_at,
        )
    evidence = "attribution_address" if attribution.source == "attribution" else attribution.source
    return _Author(
        owner_class=OwnerClass.OTHER,
        kind=SenderKind.BOT if is_noreply(attribution.address) else SenderKind.USER,
        ident=attribution.address,
        name=attribution.name,
        evidence=evidence,
        quality=ProvenanceQuality.SOURCE_CLAIMED,
        original_sent_at=attribution.sent_at,
    )


def _author(segment: Segment, claim: QuoteClaim, ctx: NormalizeContext) -> _Author:
    linked = ctx.linker(claim) if ctx.linker is not None else None
    if linked is None:
        return _claimed_author(segment.attribution, ctx)
    return _Author(
        owner_class=linked.owner_class,
        kind=linked.sender_kind,
        ident=linked.author_id,
        name=linked.author_name,
        evidence=linked.evidence_code,
        quality=ProvenanceQuality.SOURCE_CLAIMED,
        original_sent_at=claim.claimed_at if claim.claimed_at is not None else linked.original_sent_at,
        original_ref=linked.original_ref,
    )


def _part(source_uid: str, kind: PartKind, n: int, ordinal: int, author: _Author, text: str) -> ImportPart:
    return ImportPart(
        part_uid=part_uid(source_uid, kind, n),
        source_uid=source_uid,
        ordinal=ordinal,
        part_kind=kind,
        author_kind=author.kind,
        author_id=author.ident,
        author_name=clean_line(author.name),
        author_owner_class=author.owner_class,
        author_evidence=author.evidence,
        original_sent_at=author.original_sent_at,
        original_ref=author.original_ref,
        text=text,
        provenance_quality=author.quality,
    )


@dataclass
class _PartBuilder:
    source_uid: str
    headers: MailHeaders
    ctx: NormalizeContext
    sender: _Author
    parts: list[ImportPart | None] = field(default_factory=list)
    authored: list[str] = field(default_factory=list)
    authored_slot: int | None = None
    counters: Counter[PartKind] = field(default_factory=Counter)
    truncated: bool = False

    def capped(self, text: str) -> str:
        value, cut = cap_utf8(text)
        self.truncated |= cut
        return value

    def add(self, segment: Segment) -> None:
        if segment.kind is PartKind.AUTHORED:
            if self.authored_slot is None:
                self.authored_slot = len(self.parts)
                self.parts.append(None)
            self.authored.append(segment.text)
            return
        text = self.capped(segment.text)
        author = _author(segment, _claim(segment, text, self.source_uid, self.headers), self.ctx)
        self.counters[segment.kind] += 1
        n = self.counters[segment.kind]
        self.parts.append(_part(self.source_uid, segment.kind, n, len(self.parts), author, text))

    def build(self) -> tuple[ImportPart, ...]:
        if self.authored_slot is None and not self.parts:
            self.authored_slot = 0
            self.parts.append(None)
        if self.authored_slot is not None:
            text = self.capped("\n".join(self.authored))
            self.parts[self.authored_slot] = _part(
                self.source_uid, PartKind.AUTHORED, 1, self.authored_slot, self.sender, text
            )
        return tuple(part for part in self.parts if part is not None)


def _record_stats(normalized: NormalizedMessage, stats: Counter[str]) -> None:
    stats["html_only"] += normalized.body.html_only
    stats["truncated"] += normalized.truncated or normalized.body.truncated
    stats["unknown_date"] += normalized.message.sent_at is None
    stats.update(f"attachment:{kind}" for kind in normalized.body.attachments)


def _build(raw: RawMessage, ctx: NormalizeContext) -> NormalizedMessage | Skipped:
    msg = parse_mail(raw.data)
    headers = parse_headers(msg, ctx.stats)
    cls = classify(headers, ctx.own_addresses, sent_label=ctx.sent_label)
    if cls.skip_reason is not None:
        return Skipped(cls.skip_reason, raw.origin_index)
    source_uid, message_id = message_identity(headers, ctx.account, raw.data)
    body = extract_body(msg, ctx.stats)
    kind, ident, name = _sender(headers, cls, ctx.own_addresses)
    sender = _Author(
        owner_class=cls.owner_class,
        kind=kind,
        ident=ident,
        name=name,
        evidence=cls.evidence_code,
        quality=cls.provenance_quality,
    )
    builder = _PartBuilder(source_uid, headers, ctx, sender)
    for segment in _segments(headers, body, ctx.stats):
        builder.add(segment)
    parts = builder.build()
    thread = thread_input(headers, source_uid, raw.origin_index)
    reply_to = _reply_uid(headers, ctx.account)
    message = ImportMessage(
        source_uid=source_uid,
        conv_uid=mail_conv_uid(ctx.account, ctx.thread_keys.get(source_uid) or default_thread_key(thread)),
        message_id=message_id,
        sent_at=headers.date,
        imported_at=ctx.imported_at,
        sender_kind=kind,
        sender_id=ident,
        sender_name=clean_line(name),
        owner_class=cls.owner_class,
        owner_evidence=cls.evidence_code,
        reply_to_uid=reply_to,
        media=_media(body.attachments),
        provenance_quality=cls.provenance_quality,
        source_revision=hashlib.sha256(raw.data).hexdigest(),
        content_digest=content_digest("".join(part.text for part in parts)),
        parts=parts,
        recipients=_recipients(headers, ctx.own_addresses),
    )
    validate_message(message)
    return NormalizedMessage(
        message=message, headers=headers, classification=cls, thread=thread, body=body, truncated=builder.truncated
    )


def _reply_uid(headers: MailHeaders, account: str) -> str | None:
    if not headers.in_reply_to:
        return None
    try:
        return mail_source_uid(account, headers.in_reply_to[0])
    except RecordError:
        return None


def normalize(raw: RawMessage, ctx: NormalizeContext) -> NormalizedMessage | Skipped:
    """Normalise one raw message; never raises for bad input (content-free reason codes)."""
    try:
        result = _build(raw, ctx)
    except RecordError as exc:
        ctx.stats[f"invalid_record:{exc.code}"] += 1
        return Skipped("invalid_record", raw.origin_index)
    except Exception as exc:  # untrusted input: count the class, never the content
        ctx.stats[f"error:{type(exc).__name__}"] += 1
        return Skipped("parse_error", raw.origin_index)
    if isinstance(result, NormalizedMessage):
        _record_stats(result, ctx.stats)
    return result
