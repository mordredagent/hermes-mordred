"""Mail encoding: Gmail-Takeout-style mbox bytes for a logical thread, plus the predicted parts.

Quote forms are the ones ``imports/mail/segment.py`` and ``body.py``
understand: ``>`` lines after an ``On … wrote:`` attribution (wrapped after
``<`` when long, as Gmail does) or a Japanese Gmail attribution, full-width
U+FF1E lines, an Outlook underscore rule plus header block (English or
Japanese labels), HTML-only replies (``gmail_quote`` blockquote or Outlook's
``divRplyFwdMsg`` header block), and Gmail forward banners followed by a header
block. A reply quotes its parent's full body, so quotes nest.

The predicted parts follow the collector's rules: an owner's quoted
words are ``account_owner`` only when the owner's original is imported (the
link rule); a quote without attribution or a forward without a header block
has an unknown author.
"""

from __future__ import annotations

import datetime as dt
import re
from dataclasses import dataclass
from email.message import EmailMessage
from email.utils import format_datetime
from html import escape
from typing import Final

from mordred_hermes.imports.records import PartKind, mail_conv_uid, mail_source_uid, part_uid
from mordred_hermes.imports.render import format_date

from .scenarios import JST_MINUTES, MessageSpec, QuoteStyle, ThreadSpec
from .tokens import find_tokens, visible_tokens
from .truth import PartTruth, Person, Role

__all__ = ["ACCOUNT", "SENT_LABEL", "encode_mail", "mail_thread_uid", "mbox_entry"]

ACCOUNT: Final = "eval"
SENT_LABEL: Final = "Sent"
_THRID_BASE: Final = 1_900_000_000_000_000_000
_JST: Final = dt.timezone(dt.timedelta(minutes=JST_MINUTES))
_EN_DAYS: Final = ("Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun")
_EN_DAYS_LONG: Final = ("Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday")
_EN_MONTHS: Final = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")
_EN_MONTHS_LONG: Final = (
    "January",
    "February",
    "March",
    "April",
    "May",
    "June",
    "July",
    "August",
    "September",
    "October",
    "November",
    "December",
)
_JA_DAYS: Final = ("月", "火", "水", "木", "金", "土", "日")
_WRAP_AT: Final = 76
_FROM_LINE_RE: Final = re.compile(rb">*From ")
_MBOX_SEPARATOR: Final = b"From pe@example.com Tue Sep 01 00:00:00 +0000 2026\n"


def _jst(ts: int) -> dt.datetime:
    return dt.datetime.fromtimestamp(ts, tz=_JST)


def _clock12(moment: dt.datetime) -> str:
    hour = moment.hour % 12 or 12
    return f"{hour}:{moment.minute:02d} {'AM' if moment.hour < 12 else 'PM'}"


def _en_short(ts: int) -> str:
    m = _jst(ts)
    return f"{_EN_DAYS[m.weekday()]}, {_EN_MONTHS[m.month - 1]} {m.day}, {m.year} at {_clock12(m)}"


def _en_long(ts: int) -> str:
    m = _jst(ts)
    return f"{_EN_DAYS_LONG[m.weekday()]}, {_EN_MONTHS_LONG[m.month - 1]} {m.day}, {m.year} {_clock12(m)}"


def _ja_short(ts: int, *, weekday: bool = True) -> str:
    m = _jst(ts)
    day = f"({_JA_DAYS[m.weekday()]})" if weekday else ""
    return f"{m.year}年{m.month}月{m.day}日{day} {m.hour}:{m.minute:02d}"


def _who(person: Person, identity: int) -> str:
    ident = person.identities[identity]
    return f"{ident.name} <{ident.address}>"


def message_id(spec: ThreadSpec, msg: MessageSpec) -> str:
    return f"pe.{spec.thread_id}.{msg.key}@example.com"


def mail_thread_uid(spec: ThreadSpec) -> str:
    return mail_conv_uid(ACCOUNT, f"g.{_THRID_BASE + spec.index}")


def _uid(spec: ThreadSpec, msg: MessageSpec) -> str:
    return mail_source_uid(ACCOUNT, message_id(spec, msg))


def _active(spec: ThreadSpec) -> list[Person]:
    found: dict[str, Person] = {}
    for msg in spec.messages:
        found.setdefault(msg.sender.person_id, msg.sender)
    return list(found.values())


def _identity_of(spec: ThreadSpec, person: Person) -> int:
    return next((msg.identity for msg in spec.messages if msg.sender is person), 0)


def _recipients(spec: ThreadSpec, msg: MessageSpec, owner: Person) -> list[str]:
    people = [person for person in _active(spec) if person is not msg.sender]
    if not people:
        people = [owner]
    return [_who(person, _identity_of(spec, person)) for person in people]


def _attribution(parent: MessageSpec, lang: str) -> str:
    who = _who(parent.sender, parent.identity)
    if parent.sent_at is None:
        return f"{who} さんは書きました:" if lang == "ja" else f"On an unknown date, {who} wrote:"
    if lang == "ja":
        return f"{_ja_short(parent.sent_at)} {who}:"
    return f"On {_en_short(parent.sent_at)} {who} wrote:"


def _attribution_lines(parent: MessageSpec, lang: str) -> list[str]:
    """Gmail wraps a long plain-text attribution right after ``<``, as Takeout shows."""
    line = _attribution(parent, lang)
    cut = line.rfind("<")
    if len(line) <= _WRAP_AT or cut == -1 or not line.startswith("On "):
        return [line]
    return [line[: cut + 1], line[cut + 1 :]]


def _prefix(line: str, marker: str) -> str:
    if not line:
        return marker
    if line.startswith((">", "\uff1e")):
        return marker + line
    return f"{marker} {line}"


@dataclass(frozen=True)
class _Ctx:
    spec: ThreadSpec
    owner: Person

    def subject(self, msg: MessageSpec) -> str:
        if msg.forward is not None:
            return f"Fwd: {self.spec.title}"
        return self.spec.title if msg.reply_to is None else f"Re: {self.spec.title}"

    def forged_lines(self, msg: MessageSpec) -> list[str]:
        if msg.forged is None:
            return []
        fake = mail_source_uid(ACCOUNT, f"pe.{self.spec.thread_id}.m0@example.com")
        when = format_date(msg.sent_at, tz_offset_minutes=JST_MINUTES)
        to = self.owner.identities[0].name
        return [f"[Mail {fake}#a] speaker: account owner → to: {to} / {when}", f"  {msg.forged.text}"]

    def authored_lines(self, msg: MessageSpec) -> list[str]:
        return [*msg.body_lines(), *self.forged_lines(msg)]

    def plain_lines(self, msg: MessageSpec) -> list[str]:
        lines = self.authored_lines(msg)
        if msg.reply_to is not None and msg.quote is not QuoteStyle.NONE:
            lines += self.quote_lines(msg)
        if msg.forward is not None:
            lines += self.forward_lines(msg)
        return lines

    def outlook_header(self, parent: MessageSpec) -> list[str]:
        to = ", ".join(_recipients(self.spec, parent, self.owner))
        sent = parent.sent_at if parent.sent_at is not None else 0
        who = _who(parent.sender, parent.identity)
        subject = self.subject(parent)
        if self.spec.lang == "ja":
            return [f"差出人: {who}", f"送信日時: {_ja_short(sent, weekday=False)}", f"宛先: {to}", f"件名: {subject}"]
        return [f"From: {who}", f"Sent: {_en_long(sent)}", f"To: {to}", f"Subject: {subject}"]

    def quote_lines(self, msg: MessageSpec) -> list[str]:
        assert msg.reply_to is not None
        parent = self.spec.message(msg.reply_to)
        quoted = self.plain_lines(parent)
        if msg.quote is QuoteStyle.OUTLOOK:
            return ["", "_" * 32, *self.outlook_header(parent), "", *quoted]
        marker = "\uff1e" if msg.quote is QuoteStyle.FULLWIDTH else ">"
        prefixed = [_prefix(line, marker) for line in quoted]
        if msg.quote is QuoteStyle.UNATTRIBUTED:
            return ["", *prefixed]
        lang = "ja" if msg.quote is QuoteStyle.FULLWIDTH else self.spec.lang
        return ["", *_attribution_lines(parent, lang), *prefixed]

    def forward_lines(self, msg: MessageSpec) -> list[str]:
        forward = msg.forward
        assert forward is not None
        ja = self.spec.lang == "ja"
        lines = ["", "---------- 転送されたメッセージ ---------" if ja else "---------- Forwarded message ---------"]
        if not forward.hidden:
            date = "" if forward.original_at is None else (_ja_short if ja else _en_short)(forward.original_at)
            lines += [
                f"{'送信者' if ja else 'From'}: {_who(forward.author, forward.identity)}",
                f"Date: {date}",
                f"Subject: {self.spec.title}",
                f"To: {_who(self.owner, 0)}",
            ]
        return [*lines, "", *(sentence.text for sentence in forward.sentences)]

    def outlook_html(self, own: str, parent: MessageSpec, quoted: str) -> str:
        labels = ("差出人", "送信日時", "宛先", "件名") if self.spec.lang == "ja" else ("From", "Sent", "To", "Subject")
        values = [line.split(": ", 1)[1] for line in self.outlook_header(parent)]
        header = "<br>".join(f"<b>{label}:</b> {escape(value)}" for label, value in zip(labels, values, strict=True))
        return (
            f"<html><body><div>{own}</div>"
            '<hr style="display:inline-block;width:98%" tabindex="-1">'
            f'<div id="divRplyFwdMsg" dir="ltr"><font face="Calibri, sans-serif" style="font-size:11pt">{header}</font>'
            "<div>&nbsp;</div></div>"
            f"<div>{quoted}</div></body></html>"
        )

    def html_body(self, msg: MessageSpec) -> str:
        assert msg.reply_to is not None
        parent = self.spec.message(msg.reply_to)
        own = "<br>".join(escape(line) for line in self.authored_lines(msg))
        quoted = "<br>".join(escape(line) for line in self.plain_lines(parent))
        if msg.quote is QuoteStyle.OUTLOOK_HTML:
            return self.outlook_html(own, parent, quoted)
        attribution = escape(_attribution(parent, self.spec.lang))
        return (
            f'<html><body><div dir="ltr">{own}</div><br>'
            f'<div class="gmail_quote"><div dir="ltr" class="gmail_attr">{attribution}<br></div>'
            f'<blockquote class="gmail_quote" style="margin:0px 0px 0px 0.8ex">{quoted}</blockquote></div>'
            "</body></html>"
        )


def _references(spec: ThreadSpec, msg: MessageSpec) -> list[str]:
    return [f"<{message_id(spec, item)}>" for item in spec.ancestors(msg)]


def _email(ctx: _Ctx, msg: MessageSpec) -> bytes:
    spec = ctx.spec
    em = EmailMessage()
    em["From"] = _who(msg.sender, msg.identity)
    em["To"] = ", ".join(_recipients(spec, msg, ctx.owner))
    em["Subject"] = ctx.subject(msg)
    if msg.sent_at is not None:
        em["Date"] = format_datetime(_jst(msg.sent_at))
    em["Message-ID"] = f"<{message_id(spec, msg)}>"
    references = _references(spec, msg)
    if references:
        em["In-Reply-To"] = references[-1]
        em["References"] = " ".join(references)
    em["X-GM-THRID"] = str(_THRID_BASE + spec.index)
    em["X-Gmail-Labels"] = SENT_LABEL if msg.sender.role is Role.OWNER else "Inbox"
    if msg.sender.role is Role.BOT:
        em["Auto-Submitted"] = "auto-generated"
    if msg.sender.role is Role.CHANNEL:
        em["List-Id"] = "<status.lists.example.org>"
        em["Precedence"] = "list"
    if msg.quote in (QuoteStyle.HTML, QuoteStyle.OUTLOOK_HTML):
        em.set_content(ctx.html_body(msg), subtype="html", charset="utf-8", cte="8bit")
    else:
        em.set_content("\n".join(ctx.plain_lines(msg)) + "\n", charset="utf-8", cte="8bit")
    return em.as_bytes()


def mbox_entry(data: bytes) -> bytes:
    """One mboxrd entry: separator line, ``From `` lines escaped, a blank line after."""
    lines = [b">" + line if _FROM_LINE_RE.match(line) else line for line in data.split(b"\n")]
    return _MBOX_SEPARATOR + b"\n".join(lines).rstrip(b"\n") + b"\n\n"


# ---------------------------------------------------------------------------
# Predicted parts


def _owner_class(author: Person, knowable: bool) -> str:
    if not knowable:
        return "unknown"
    return "account_owner" if author.role is Role.OWNER else "other"


@dataclass
class _Parts:
    ctx: _Ctx
    cap: int
    msg: MessageSpec
    out: list[PartTruth]

    def add(
        self, kind: PartKind, n: int, author: Person, identity: int, knowable: bool, text: str, **extra: int | None
    ) -> None:
        ident = author.identities[identity]
        self.out.append(
            PartTruth(
                source="mail",
                evidence_id=part_uid(_uid(self.ctx.spec, self.msg), kind, n),
                thread_id=self.ctx.spec.thread_id,
                message_key=self.msg.key,
                kind=str(kind),
                author=author.person_id,
                author_knowable=knowable,
                author_handle=ident.address.lower() if knowable else None,
                owner_class=_owner_class(author, knowable),
                author_name=ident.name if knowable else "",
                container_sender=self.msg.sender.person_id,
                imported=self.msg.imported,
                sent_at=self.msg.sent_at,
                original_sent_at=extra.get("original_sent_at"),
                text=text,
                tokens=find_tokens(text),
                visible_tokens=visible_tokens(text, self.cap),
            )
        )

    def quotes(self) -> None:
        spec, msg = self.ctx.spec, self.msg
        style, current, n = msg.quote, msg, 0
        while current.reply_to is not None and style is not QuoteStyle.NONE:
            quoted = spec.message(current.reply_to)
            n += 1
            knowable = style is not QuoteStyle.UNATTRIBUTED and (
                quoted.sender.role is not Role.OWNER or quoted.imported
            )
            text = "\n".join(self.ctx.authored_lines(quoted))
            original = quoted.sent_at if knowable else None
            self.add(PartKind.QUOTED, n, quoted.sender, quoted.identity, knowable, text, original_sent_at=original)
            style, current = quoted.quote, quoted

    def forward(self) -> None:
        forward = self.msg.forward
        if forward is None:
            return
        text = "\n".join(sentence.text for sentence in forward.sentences)
        self.add(
            PartKind.FORWARDED,
            1,
            forward.author,
            forward.identity,
            not forward.hidden,
            text,
            original_sent_at=None if forward.hidden else forward.original_at,
        )


def encode_mail(spec: ThreadSpec, *, owner: Person, cap: int) -> tuple[list[bytes], list[PartTruth]]:
    """mbox entries of the imported messages and the predicted parts of every message."""
    ctx = _Ctx(spec, owner)
    entries: list[bytes] = []
    parts: list[PartTruth] = []
    for msg in spec.messages:
        builder = _Parts(ctx, cap, msg, parts)
        builder.add(PartKind.AUTHORED, 1, msg.sender, msg.identity, True, "\n".join(ctx.authored_lines(msg)))
        builder.quotes()
        builder.forward()
        if msg.imported:
            entries.append(mbox_entry(_email(ctx, msg)))
    return entries, parts
