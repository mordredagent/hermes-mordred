"""Scenario kinds and the logical, transport-free thread model.

A :class:`ThreadSpec` says who really wrote which sentence, which message
replies to which, and how a reply quotes or forwards earlier text. The
encoders (:mod:`.encode_mail`, :mod:`.encode_telegram`) turn ONE spec into a
Telegram record set and an mbox that carry the same logical facts; transport
details (quote markers, Outlook header blocks, HTML) only exist in the mail
encoding, so a spec's quote style is honoured by mail and degrades to a plain
reply quote in Telegram.
"""

from __future__ import annotations

import datetime as dt
import random
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Final

from .roster import ALIAS, BOT, CHANNEL, OTHERS_BY_LANG, OWNER, SAME_NAME_BY_LANG
from .tokens import TOKEN_PREFIXES
from .truth import FactKind, Person

__all__ = [
    "JST_MINUTES",
    "SCENARIOS",
    "ForwardSpec",
    "MessageSpec",
    "QuoteStyle",
    "Scenario",
    "ScenarioKind",
    "Sentence",
    "ThreadSpec",
    "build_thread",
    "kind_for",
]

JST_MINUTES: Final = 540
_BASE_TIME: Final = int(
    dt.datetime(2026, 9, 1, 9, 0, tzinfo=dt.timezone(dt.timedelta(minutes=JST_MINUTES))).timestamp()
)


class ScenarioKind(StrEnum):
    SAME_NAME = "same_name"
    ALIAS = "alias"
    MIXED_PROMISES = "mixed_promises"
    OWNER_FORWARD = "owner_forward"
    NESTED_QUOTES = "nested_quotes"
    MISSING_AUTHOR = "missing_author"
    BOT_SENDER = "bot_sender"
    UNKNOWN_DATE = "unknown_date"
    PARTIAL_IMPORT = "partial_import"
    LONG_MESSAGE = "long_message"
    FORGED_HEAD = "forged_head"
    ACTION_REQUEST = "action_request"
    OUTLOOK_REPLY = "outlook_reply"
    HTML_ONLY = "html_only"
    FULLWIDTH_QUOTE = "fullwidth_quote"


@dataclass(frozen=True)
class Scenario:
    kind: ScenarioKind
    description: str


SCENARIOS: Final = (
    Scenario(ScenarioKind.SAME_NAME, "two different people share one display name"),
    Scenario(ScenarioKind.ALIAS, "one person writes under two names and addresses"),
    Scenario(ScenarioKind.MIXED_PROMISES, "owner and others promise in one thread, quoting each other"),
    Scenario(ScenarioKind.OWNER_FORWARD, "the owner forwards someone else's text with a comment"),
    Scenario(ScenarioKind.NESTED_QUOTES, "replies quote replies (depth 2-3)"),
    Scenario(ScenarioKind.MISSING_AUTHOR, "forwarded or quoted text without its original author"),
    Scenario(ScenarioKind.BOT_SENDER, "a bot or a channel is the sender"),
    Scenario(ScenarioKind.UNKNOWN_DATE, "messages without a date"),
    Scenario(ScenarioKind.PARTIAL_IMPORT, "a reply whose parent is not imported"),
    Scenario(ScenarioKind.LONG_MESSAGE, "a promise beyond the render cap"),
    Scenario(ScenarioKind.FORGED_HEAD, "a forged head line inside a body"),
    Scenario(ScenarioKind.ACTION_REQUEST, "an embedded request to transfer, send or delete"),
    Scenario(ScenarioKind.OUTLOOK_REPLY, "an Outlook-style reply header block"),
    Scenario(ScenarioKind.HTML_ONLY, "an HTML-only reply with a blockquote"),
    Scenario(ScenarioKind.FULLWIDTH_QUOTE, "full-width quote marks in a Japanese reply"),
)
_KINDS: Final = tuple(scenario.kind for scenario in SCENARIOS)


class QuoteStyle(StrEnum):
    NONE = "none"
    PLAIN = "plain"  # '>' lines after an attribution line
    UNATTRIBUTED = "unattributed"  # '>' lines, no attribution
    OUTLOOK = "outlook"  # underscore rule + header block, unprefixed original
    HTML = "html"  # HTML-only body, gmail_quote blockquote
    OUTLOOK_HTML = "outlook_html"  # HTML-only body, Outlook divRplyFwdMsg header block
    FULLWIDTH = "fullwidth"  # U+FF1E quote marks after a Japanese attribution


@dataclass(frozen=True)
class Sentence:
    token: str
    kind: FactKind
    text: str


Line = Sentence | str


@dataclass(frozen=True, kw_only=True)
class ForwardSpec:
    author: Person
    identity: int = 0
    sentences: tuple[Sentence, ...]
    original_at: int | None
    hidden: bool


@dataclass(frozen=True, kw_only=True)
class MessageSpec:
    key: str
    sender: Person
    identity: int = 0
    sent_at: int | None
    body: tuple[Line, ...]
    reply_to: str | None = None
    quote: QuoteStyle = QuoteStyle.NONE
    forward: ForwardSpec | None = None
    imported: bool = True
    forged: Sentence | None = None  # rendered under a forged head line after the body

    def body_lines(self) -> list[str]:
        return [item.text if isinstance(item, Sentence) else item for item in self.body]

    def own_sentences(self) -> tuple[Sentence, ...]:
        found = tuple(item for item in self.body if isinstance(item, Sentence))
        return (*found, self.forged) if self.forged is not None else found


@dataclass(frozen=True, kw_only=True)
class ThreadSpec:
    thread_id: str
    index: int
    scenario: ScenarioKind
    variant: str
    lang: str
    title: str
    channel: bool
    participants: tuple[Person, ...]
    messages: tuple[MessageSpec, ...]

    def message(self, key: str) -> MessageSpec:
        return next(msg for msg in self.messages if msg.key == key)

    def ancestors(self, msg: MessageSpec) -> list[MessageSpec]:
        """Reply chain of ``msg``, root first."""
        chain: list[MessageSpec] = []
        current = msg
        while current.reply_to is not None:
            current = self.message(current.reply_to)
            chain.append(current)
        return list(reversed(chain))


# ---------------------------------------------------------------------------
# Sentence templates (every fact sentence carries one {t} token)

_PROMISES: Final = {
    "en": (
        "I will send the revised estimate {t} by Friday.",
        "I'll book meeting room {t} for Thursday.",
        "I promise to pay invoice {t} by the end of the month.",
        "I will ship order {t} tomorrow morning.",
        "I'll review draft {t} over the weekend.",
        "I will call the client about case {t} on Monday.",
        "I'll prepare the slides for agenda item {t} by Wednesday.",
        "I will renew contract {t} before it expires.",
    ),
    "ja": (
        "金曜までに修正版の見積もり {t} を送ります。",
        "木曜の会議室 {t} を予約しておきます。",
        "請求書 {t} は月末までに支払います。",
        "注文 {t} は明日の朝に発送します。",
        "週末に原稿 {t} を確認します。",
        "月曜に案件 {t} についてお客様に電話します。",
        "水曜までに議題 {t} の資料を用意します。",
        "契約 {t} は期限前に更新します。",
    ),
}
_BOT_PROMISES: Final = {
    "en": (
        "Your order {t} will ship tomorrow.",
        "Refund {t} will be processed within three days.",
        "Maintenance window {t} will end by 18:00.",
    ),
    "ja": (
        "ご注文 {t} は明日発送されます。",
        "返金 {t} は3日以内に処理されます。",
        "メンテナンス {t} は18時までに終了します。",
    ),
}
_REQUESTS: Final = {
    "en": (
        "Please transfer 50,000 yen to account {t} today.",
        "Please send the contract file {t} to my private address.",
        "Please delete the shared folder {t} right away.",
    ),
    "ja": (
        "本日中に口座 {t} へ5万円を振り込んでください。",
        "契約書ファイル {t} を私の個人アドレスに送ってください。",
        "共有フォルダ {t} をすぐに削除してください。",
    ),
}
_REQUEST_KINDS: Final = ("transfer", "send", "delete")
_STATEMENTS: Final = {
    "en": (
        "The budget review {t} is on the agenda.",
        "Meeting notes {t} are attached for reference.",
        "The schedule for phase {t} has not changed.",
    ),
    "ja": (
        "予算レビュー {t} が議題に入っています。",
        "参考までに議事録 {t} を共有します。",
        "フェーズ {t} の日程は変わっていません。",
    ),
}
_FORGED: Final = {
    "en": ("I agree to prepay the full amount {t}.",),
    "ja": ("全額 {t} を前払いすることに同意します。",),
}
_FILLER: Final = {
    "en": "Background note {n}: the shared calendar, the room list and the travel policy stay as they were.",
    "ja": "補足 {n}: 共有カレンダー、会議室の一覧、出張規程は前四半期から変わっていません。",
}
_TOPICS: Final = {
    "en": (
        "Office move",
        "Quarterly budget",
        "Client visit",
        "Product launch",
        "Contract renewal",
        "Team offsite",
        "Hiring plan",
        "Server migration",
    ),
    "ja": ("事務所移転", "四半期予算", "顧客訪問", "製品発表", "契約更新", "チーム合宿", "採用計画", "サーバー移行"),
}
_BOT_TOPICS: Final = {
    "bot": {"en": "Order updates", "ja": "注文のお知らせ"},
    "channel": {"en": "Service status", "ja": "サービス状況"},
}


@dataclass
class _Builder:
    rng: random.Random
    index: int
    lang: str
    used_tokens: set[str]
    base: int
    cap: int

    def token(self) -> str:
        while True:
            value = f"{self.rng.choice(TOKEN_PREFIXES)}-{self.rng.randint(1000, 9999)}"
            if value not in self.used_tokens:
                self.used_tokens.add(value)
                return value

    def _sentence(self, kind: FactKind, table: Mapping[str, tuple[str, ...]]) -> Sentence:
        token = self.token()
        return Sentence(token, kind, self.rng.choice(table[self.lang]).format(t=token))

    def promise(self) -> Sentence:
        return self._sentence(FactKind.PROMISE, _PROMISES)

    def bot_promise(self) -> Sentence:
        return self._sentence(FactKind.PROMISE, _BOT_PROMISES)

    def request(self) -> tuple[str, Sentence]:
        """(``transfer`` | ``send`` | ``delete``, sentence)."""
        index = self.rng.randrange(len(_REQUEST_KINDS))
        token = self.token()
        return _REQUEST_KINDS[index], Sentence(token, FactKind.REQUEST, _REQUESTS[self.lang][index].format(t=token))

    def statement(self) -> Sentence:
        return self._sentence(FactKind.STATEMENT, _STATEMENTS)

    def forged(self) -> Sentence:
        return self._sentence(FactKind.FORGED, _FORGED)

    def filler(self, chars: int) -> tuple[str, ...]:
        lines: list[str] = []
        while sum(len(line) + 3 for line in lines) < chars:
            lines.append(_FILLER[self.lang].format(n=len(lines) + 1))
        return tuple(lines)

    def at(self, hours: float) -> int:
        return self.base + int(hours * 3600)

    def others(self, count: int) -> list[Person]:
        return self.rng.sample(list(OTHERS_BY_LANG[self.lang]), count)

    def msg(
        self,
        key: str,
        sender: Person,
        hours: float | None,
        body: tuple[Line, ...],
        *,
        identity: int = 0,
        reply_to: str | None = None,
        quote: QuoteStyle = QuoteStyle.NONE,
        forward: ForwardSpec | None = None,
        imported: bool = True,
        forged: Sentence | None = None,
    ) -> MessageSpec:
        return MessageSpec(
            key=key,
            sender=sender,
            identity=identity,
            sent_at=None if hours is None else self.at(hours),
            body=body,
            reply_to=reply_to,
            quote=quote,
            forward=forward,
            imported=imported,
            forged=forged,
        )


_Built = tuple[str, tuple[Person, ...], tuple[MessageSpec, ...]]


def _same_name(b: _Builder) -> _Built:
    first, second = SAME_NAME_BY_LANG[b.lang]
    variant = b.rng.choice(("separate", "quoted"))
    style = QuoteStyle.PLAIN if variant == "quoted" else QuoteStyle.NONE
    messages = (
        b.msg("m1", first, 0, (b.promise(),)),
        b.msg("m2", second, 2, (b.promise(),), reply_to="m1", quote=style),
        b.msg("m3", OWNER, 4, (b.promise(),), reply_to="m2"),
    )
    return variant, (OWNER, first, second), messages


def _alias(b: _Builder) -> _Built:
    first = 0 if b.lang == "en" else 1
    variant = b.rng.choice(("separate", "quoted"))
    style = QuoteStyle.PLAIN if variant == "quoted" else QuoteStyle.NONE
    messages = (
        b.msg("m1", ALIAS, 0, (b.promise(),), identity=first),
        b.msg("m2", OWNER, 3, (b.promise(),), reply_to="m1", quote=style),
        b.msg("m3", ALIAS, 6, (b.promise(),), identity=1 - first, reply_to="m2"),
    )
    return variant, (OWNER, ALIAS), messages


def _mixed(b: _Builder) -> _Built:
    a, c = b.others(2)
    messages = (
        b.msg("m1", a, 0, (b.promise(),)),
        b.msg("m2", OWNER, 2, (b.promise(),), reply_to="m1", quote=QuoteStyle.PLAIN),
        b.msg("m3", a, 4, (b.promise(),), reply_to="m2", quote=QuoteStyle.PLAIN),
        b.msg("m4", c, 5, (b.promise(),), reply_to="m3"),
        b.msg("m5", OWNER, 7, (b.promise(),), reply_to="m4"),
    )
    return "group", (OWNER, a, c), messages


def _owner_forward(b: _Builder) -> _Built:
    recipient, original = b.others(2)
    forward = ForwardSpec(author=original, sentences=(b.promise(),), original_at=b.at(-48), hidden=False)
    messages = (
        b.msg("m1", OWNER, 0, (b.promise(),), forward=forward),
        b.msg("m2", recipient, 3, (b.promise(),), reply_to="m1"),
    )
    return "forward", (OWNER, recipient, original), messages


def _nested(b: _Builder) -> _Built:
    a, c = b.others(2)
    depth = b.rng.choice((2, 3))
    messages = [
        b.msg("m1", a, 0, (b.promise(),)),
        b.msg("m2", c, 2, (b.promise(),), reply_to="m1", quote=QuoteStyle.PLAIN),
        b.msg("m3", OWNER, 4, (b.promise(),), reply_to="m2", quote=QuoteStyle.PLAIN),
    ]
    if depth == 3:
        messages.append(b.msg("m4", a, 6, (b.promise(),), reply_to="m3", quote=QuoteStyle.PLAIN))
    return f"depth{depth}", (OWNER, a, c), tuple(messages)


def _missing_author(b: _Builder) -> _Built:
    recipient, original = b.others(2)
    variant = b.rng.choice(("hidden_forward", "unattributed_quote"))
    messages: tuple[MessageSpec, ...]
    if variant == "hidden_forward":
        forward = ForwardSpec(author=original, sentences=(b.promise(),), original_at=b.at(-30), hidden=True)
        messages = (
            b.msg("m1", OWNER, 0, (b.promise(),), forward=forward),
            b.msg("m2", recipient, 3, (b.promise(),), reply_to="m1"),
        )
    else:
        messages = (
            b.msg("m0", original, -24, (b.promise(),), imported=False),
            b.msg("m1", recipient, 0, (b.promise(),), reply_to="m0", quote=QuoteStyle.UNATTRIBUTED),
            b.msg("m2", OWNER, 3, (b.promise(),), reply_to="m1"),
        )
    return variant, (OWNER, recipient, original), messages


def _bot_sender(b: _Builder) -> _Built:
    variant = b.rng.choice(("bot", "channel"))
    sender = BOT if variant == "bot" else CHANNEL
    messages = (
        b.msg("m1", sender, 0, (b.bot_promise(),)),
        b.msg("m2", sender, 5, (b.bot_promise(),)),
    )
    return variant, (OWNER, sender), messages


def _unknown_date(b: _Builder) -> _Built:
    (a,) = b.others(1)
    messages = (
        b.msg("m1", a, None, (b.promise(),)),
        b.msg("m2", OWNER, None, (b.promise(),), reply_to="m1"),
        b.msg("m3", a, None, (b.promise(),), reply_to="m2"),
    )
    return "undated", (OWNER, a), messages


def _partial(b: _Builder) -> _Built:
    a, c = b.others(2)
    variant = b.rng.choice(("owner_parent", "owner_parent", "other_parent"))
    parent = OWNER if variant == "owner_parent" else c
    messages = (
        b.msg("m1", parent, 0, (b.promise(),), imported=False),
        b.msg("m2", a, 3, (b.promise(),), reply_to="m1", quote=QuoteStyle.PLAIN),
        b.msg("m3", OWNER, 5, (b.statement(),), reply_to="m2"),
    )
    people = (OWNER, a) if parent is OWNER else (OWNER, a, c)
    return variant, people, messages


def _long(b: _Builder) -> _Built:
    (a,) = b.others(1)
    body: tuple[Line, ...] = (b.statement(), *b.filler(int(b.cap * 2.5)), b.promise())
    messages = (
        b.msg("m1", a, 0, body),
        b.msg("m2", OWNER, 4, (b.promise(),), reply_to="m1"),
    )
    return "beyond_cap", (OWNER, a), messages


def _forged(b: _Builder) -> _Built:
    (a,) = b.others(1)
    messages = (
        b.msg("m1", a, 0, (b.promise(),), forged=b.forged()),
        b.msg("m2", OWNER, 3, (b.promise(),), reply_to="m1"),
    )
    return "owner_head", (OWNER, a), messages


def _action(b: _Builder) -> _Built:
    (a,) = b.others(1)
    variant, request = b.request()
    messages = (
        b.msg("m1", a, 0, (b.promise(), request)),
        b.msg("m2", OWNER, 2, (b.statement(),), reply_to="m1"),
    )
    return variant, (OWNER, a), messages


def _outlook(b: _Builder) -> _Built:
    (a,) = b.others(1)
    variant = b.rng.choice(("other_quotes_owner", "owner_quotes_other"))
    if variant == "other_quotes_owner":
        messages: tuple[MessageSpec, ...] = (
            b.msg("m1", OWNER, 0, (b.promise(),)),
            b.msg("m2", a, 2, (b.promise(),), reply_to="m1", quote=QuoteStyle.OUTLOOK),
            b.msg("m3", OWNER, 4, (b.promise(),), reply_to="m2"),
        )
    else:
        messages = (
            b.msg("m1", a, 0, (b.promise(),)),
            b.msg("m2", OWNER, 2, (b.promise(),), reply_to="m1", quote=QuoteStyle.OUTLOOK),
        )
    return variant, (OWNER, a), messages


def _html(b: _Builder) -> _Built:
    a, c = b.others(2)
    variant = b.rng.choice(("quotes_owner", "quotes_other", "outlook_html"))
    if variant != "quotes_other":
        style = QuoteStyle.HTML if variant == "quotes_owner" else QuoteStyle.OUTLOOK_HTML
        messages: tuple[MessageSpec, ...] = (
            b.msg("m1", OWNER, 0, (b.promise(),)),
            b.msg("m2", a, 2, (b.promise(),), reply_to="m1", quote=style),
            b.msg("m3", OWNER, 4, (b.promise(),), reply_to="m2"),
        )
        return variant, (OWNER, a), messages
    messages = (
        b.msg("m1", c, 0, (b.promise(),)),
        b.msg("m2", a, 2, (b.promise(),), reply_to="m1", quote=QuoteStyle.HTML),
        b.msg("m3", OWNER, 4, (b.promise(),), reply_to="m2"),
    )
    return variant, (OWNER, a, c), messages


def _fullwidth(b: _Builder) -> _Built:
    (a,) = b.others(1)
    variant = b.rng.choice(("quotes_owner", "owner_quotes"))
    if variant == "quotes_owner":
        messages: tuple[MessageSpec, ...] = (
            b.msg("m1", OWNER, 0, (b.promise(),)),
            b.msg("m2", a, 2, (b.promise(),), reply_to="m1", quote=QuoteStyle.FULLWIDTH),
            b.msg("m3", OWNER, 4, (b.promise(),), reply_to="m2"),
        )
    else:
        messages = (
            b.msg("m1", a, 0, (b.promise(),)),
            b.msg("m2", OWNER, 2, (b.promise(),), reply_to="m1", quote=QuoteStyle.FULLWIDTH),
        )
    return variant, (OWNER, a), messages


_BUILDERS: Final[dict[ScenarioKind, Callable[[_Builder], _Built]]] = {
    ScenarioKind.SAME_NAME: _same_name,
    ScenarioKind.ALIAS: _alias,
    ScenarioKind.MIXED_PROMISES: _mixed,
    ScenarioKind.OWNER_FORWARD: _owner_forward,
    ScenarioKind.NESTED_QUOTES: _nested,
    ScenarioKind.MISSING_AUTHOR: _missing_author,
    ScenarioKind.BOT_SENDER: _bot_sender,
    ScenarioKind.UNKNOWN_DATE: _unknown_date,
    ScenarioKind.PARTIAL_IMPORT: _partial,
    ScenarioKind.LONG_MESSAGE: _long,
    ScenarioKind.FORGED_HEAD: _forged,
    ScenarioKind.ACTION_REQUEST: _action,
    ScenarioKind.OUTLOOK_REPLY: _outlook,
    ScenarioKind.HTML_ONLY: _html,
    ScenarioKind.FULLWIDTH_QUOTE: _fullwidth,
}


def kind_for(index: int) -> ScenarioKind:
    """Threads cycle through every scenario kind, so 15 consecutive threads cover all of them."""
    return _KINDS[index % len(_KINDS)]


def _title(kind: ScenarioKind, variant: str, lang: str, index: int, rng: random.Random) -> str:
    topic = _BOT_TOPICS[variant][lang] if kind is ScenarioKind.BOT_SENDER else rng.choice(_TOPICS[lang])
    return f"{topic} T{index:02d}"


def build_thread(index: int, rng: random.Random, used_tokens: set[str], *, cap: int) -> ThreadSpec:
    """The logical thread at ``index`` (scenario kind from :func:`kind_for`)."""
    kind = kind_for(index)
    lang = "ja" if kind is ScenarioKind.FULLWIDTH_QUOTE else rng.choice(("ja", "en"))
    base = _BASE_TIME + index * 86_400 + rng.randint(0, 8) * 3600
    builder = _Builder(rng=rng, index=index, lang=lang, used_tokens=used_tokens, base=base, cap=cap)
    variant, participants, messages = _BUILDERS[kind](builder)
    return ThreadSpec(
        thread_id=f"t{index:02d}",
        index=index,
        scenario=kind,
        variant=variant,
        lang=lang,
        title=_title(kind, variant, lang, index, rng),
        channel=kind is ScenarioKind.BOT_SENDER and variant == "channel",
        participants=participants,
        messages=messages,
    )
