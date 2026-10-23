"""Versioned ground truth of a generated dataset and its JSON form.

The truth describes the *logical* conversation (who really said what) and, per
encoding (``telegram`` / ``mail``), every part the importer should produce:
its evidence id, kind, true author and whether that author is knowable from
the encoding alone. A fact is *knowable* in a source when some imported part
shows its token within the render cap with the correct, knowable author.

``truth.json`` carries ``version``; :func:`Truth.from_json` refuses any other
version. Everything here is synthetic (RFC 2606 addresses only).
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import asdict, dataclass, field
from enum import StrEnum
from functools import cached_property
from typing import Final

from ._json import (
    FormatError,
    read_bool,
    read_bool_map,
    read_enum,
    read_int,
    read_list,
    read_obj,
    read_opt_int,
    read_opt_str,
    read_str,
    read_str_map,
    read_strs,
)

__all__ = [
    "SOURCES",
    "TRUTH_VERSION",
    "AdversarialItem",
    "Expected",
    "FactKind",
    "FactTruth",
    "Identity",
    "PartTruth",
    "Person",
    "Question",
    "Role",
    "Template",
    "ThreadTruth",
    "Truth",
    "TruthError",
]

TRUTH_VERSION: Final = 1
SOURCES: Final = ("telegram", "mail")
#: A ``truth.json`` that is malformed or of an unsupported version.
TruthError = FormatError


class Role(StrEnum):
    OWNER = "owner"
    OTHER = "other"
    BOT = "bot"
    CHANNEL = "channel"


class FactKind(StrEnum):
    PROMISE = "promise"
    REQUEST = "request"
    FORGED = "forged"  # text inside a forged head line: the sender's words, never a promise
    STATEMENT = "statement"


class Expected(StrEnum):
    FACTS = "facts"
    NONE = "none"
    ABSTAIN = "abstain"
    CLARIFY = "clarify"


class Template(StrEnum):
    PROMISE_BY = "promise_by"
    PROMISE_BY_QUALIFIED = "promise_by_qualified"
    PROMISE_BY_OWNER = "promise_by_owner"
    WHO_WROTE = "who_wrote"
    WHEN_SAID = "when_said"
    ACT = "act_on_thread"


@dataclass(frozen=True, kw_only=True)
class Identity:
    name: str
    address: str


@dataclass(frozen=True, kw_only=True)
class Person:
    person_id: str
    role: Role
    identities: tuple[Identity, ...]
    telegram_id: int
    short_names: tuple[str, ...] = ()

    @property
    def names(self) -> tuple[str, ...]:
        return tuple(dict.fromkeys(identity.name for identity in self.identities))

    @property
    def addresses(self) -> tuple[str, ...]:
        return tuple(identity.address for identity in self.identities)


@dataclass(frozen=True, kw_only=True)
class ThreadTruth:
    thread_id: str
    index: int
    scenario: str
    variant: str
    lang: str
    title: str
    participants: tuple[str, ...]
    telegram_conv_uid: str
    mail_conv_uid: str


@dataclass(frozen=True, kw_only=True)
class PartTruth:
    source: str
    evidence_id: str
    thread_id: str
    message_key: str
    kind: str  # authored | quoted | forwarded
    author: str  # true author (person id)
    author_knowable: bool  # the encoding alone lets a correct importer name the author
    author_handle: str | None  # address / Telegram id the author appears under; None when not knowable
    owner_class: str  # the record's expected author owner class: account_owner | other | unknown
    author_name: str  # display name the author appears under ("" when not knowable)
    container_sender: str  # person id of the message's transport sender (quoter / forwarder)
    imported: bool
    sent_at: int | None  # the container message's date
    original_sent_at: int | None
    text: str
    tokens: tuple[str, ...]
    visible_tokens: tuple[str, ...]  # tokens inside the render cap


@dataclass(frozen=True, kw_only=True)
class FactTruth:
    token: str
    thread_id: str
    speaker: str
    kind: FactKind
    text: str
    said_at: int | None  # when the speaker originally said it (None = unknown)
    handles: dict[str, str] = field(default_factory=dict)  # source -> handle the speaker used
    in_parts: tuple[str, ...] = ()  # evidence ids (both sources) whose text carries the token
    knowable: dict[str, bool] = field(default_factory=dict)  # source -> knowable
    visible: dict[str, bool] = field(default_factory=dict)  # source -> shown within the cap


@dataclass(frozen=True, kw_only=True)
class AdversarialItem:
    item_id: str
    thread_id: str
    kind: str  # action_request | forged_head
    token: str
    text: str
    forbidden_tools: tuple[str, ...]


@dataclass(frozen=True, kw_only=True)
class Question:
    qid: str
    source: str
    thread_id: str
    template: Template
    lang: str
    text: str
    expected: Expected
    expected_tokens: tuple[str, ...] = ()
    target_person: str | None = None  # the asked person (owner for "what did I promise?")
    target_handle: str | None = None  # mail: the address the expected facts were said under
    target_name: str | None = None
    expected_speaker: str | None = None  # who_wrote
    expected_date: str | None = None  # when_said, YYYY-MM-DD in the dataset zone
    subject_token: str | None = None  # who_wrote / when_said
    forbidden_tools: tuple[str, ...] = ()

    @property
    def answerable(self) -> bool:
        return self.expected in (Expected.FACTS, Expected.NONE)


@dataclass(frozen=True, kw_only=True)
class Truth:
    version: int
    seed: int
    n_threads: int
    account: str
    own_addresses: tuple[str, ...]
    owner_id: str
    owner_telegram_id: int
    render_cap: int
    tz_offset_minutes: int
    people: tuple[Person, ...]
    threads: tuple[ThreadTruth, ...]
    parts: tuple[PartTruth, ...]
    facts: tuple[FactTruth, ...]
    adversarial: tuple[AdversarialItem, ...]
    questions: tuple[Question, ...] = ()

    # -- lookups -------------------------------------------------------------

    @cached_property
    def _people(self) -> dict[str, Person]:
        return {person.person_id: person for person in self.people}

    @cached_property
    def _facts(self) -> dict[str, FactTruth]:
        return {fact.token: fact for fact in self.facts}

    @cached_property
    def _parts(self) -> dict[str, PartTruth]:
        return {part.evidence_id: part for part in self.parts}

    @cached_property
    def _handles(self) -> dict[tuple[str, str], str]:
        table: dict[tuple[str, str], str] = {}
        for person in self.people:
            table[("telegram", str(person.telegram_id))] = person.person_id
            for address in person.addresses:
                table[("mail", address.lower())] = person.person_id
        for part in self.parts:  # e.g. a Telegram channel post's sender id is the channel's chat id
            if part.author_knowable and part.author_handle:
                table.setdefault((part.source, part.author_handle), part.author)
        return table

    def person(self, person_id: str) -> Person:
        return self._people[person_id]

    def fact(self, token: str) -> FactTruth | None:
        return self._facts.get(token)

    def part(self, evidence_id: str) -> PartTruth | None:
        return self._parts.get(evidence_id)

    def thread(self, thread_id: str) -> ThreadTruth:
        return next(thread for thread in self.threads if thread.thread_id == thread_id)

    def person_for_handle(self, source: str, handle: str | None) -> str | None:
        if not handle:
            return None
        return self._handles.get((source, handle.lower() if source == "mail" else handle))

    def parts_for(self, source: str, thread_id: str) -> list[PartTruth]:
        return [part for part in self.parts if part.source == source and part.thread_id == thread_id]

    def facts_for(self, thread_id: str) -> list[FactTruth]:
        return [fact for fact in self.facts if fact.thread_id == thread_id]

    def is_owner(self, person_id: str | None) -> bool:
        return person_id is not None and person_id == self.owner_id

    # -- JSON ------------------------------------------------------------------

    def to_json(self) -> str:
        data = {name: value for name, value in asdict(self).items() if not name.startswith("_")}
        return json.dumps(data, ensure_ascii=False, indent=1, sort_keys=True) + "\n"

    @classmethod
    def from_json(cls, text: str) -> Truth:
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise TruthError("not_json") from exc
        return _truth(read_obj(data))


# ---------------------------------------------------------------------------
# JSON readers


def _person(data: Mapping[str, object]) -> Person:
    identities = tuple(
        Identity(name=read_str(item, "name"), address=read_str(item, "address"))
        for item in (read_obj(raw) for raw in read_list(data, "identities"))
    )
    return Person(
        person_id=read_str(data, "person_id"),
        role=read_enum(data, "role", Role),
        identities=identities,
        telegram_id=read_int(data, "telegram_id"),
        short_names=read_strs(data, "short_names"),
    )


def _thread(data: Mapping[str, object]) -> ThreadTruth:
    return ThreadTruth(
        thread_id=read_str(data, "thread_id"),
        index=read_int(data, "index"),
        scenario=read_str(data, "scenario"),
        variant=read_str(data, "variant"),
        lang=read_str(data, "lang"),
        title=read_str(data, "title"),
        participants=read_strs(data, "participants"),
        telegram_conv_uid=read_str(data, "telegram_conv_uid"),
        mail_conv_uid=read_str(data, "mail_conv_uid"),
    )


def _part(data: Mapping[str, object]) -> PartTruth:
    return PartTruth(
        source=read_str(data, "source"),
        evidence_id=read_str(data, "evidence_id"),
        thread_id=read_str(data, "thread_id"),
        message_key=read_str(data, "message_key"),
        kind=read_str(data, "kind"),
        author=read_str(data, "author"),
        author_knowable=read_bool(data, "author_knowable"),
        author_handle=read_opt_str(data, "author_handle"),
        owner_class=read_str(data, "owner_class"),
        author_name=read_str(data, "author_name"),
        container_sender=read_str(data, "container_sender"),
        imported=read_bool(data, "imported"),
        sent_at=read_opt_int(data, "sent_at"),
        original_sent_at=read_opt_int(data, "original_sent_at"),
        text=read_str(data, "text"),
        tokens=read_strs(data, "tokens"),
        visible_tokens=read_strs(data, "visible_tokens"),
    )


def _fact(data: Mapping[str, object]) -> FactTruth:
    return FactTruth(
        token=read_str(data, "token"),
        thread_id=read_str(data, "thread_id"),
        speaker=read_str(data, "speaker"),
        kind=read_enum(data, "kind", FactKind),
        text=read_str(data, "text"),
        said_at=read_opt_int(data, "said_at"),
        handles=read_str_map(data, "handles"),
        in_parts=read_strs(data, "in_parts"),
        knowable=read_bool_map(data, "knowable"),
        visible=read_bool_map(data, "visible"),
    )


def _adversarial(data: Mapping[str, object]) -> AdversarialItem:
    return AdversarialItem(
        item_id=read_str(data, "item_id"),
        thread_id=read_str(data, "thread_id"),
        kind=read_str(data, "kind"),
        token=read_str(data, "token"),
        text=read_str(data, "text"),
        forbidden_tools=read_strs(data, "forbidden_tools"),
    )


def _question(data: Mapping[str, object]) -> Question:
    return Question(
        qid=read_str(data, "qid"),
        source=read_str(data, "source"),
        thread_id=read_str(data, "thread_id"),
        template=read_enum(data, "template", Template),
        lang=read_str(data, "lang"),
        text=read_str(data, "text"),
        expected=read_enum(data, "expected", Expected),
        expected_tokens=read_strs(data, "expected_tokens"),
        target_person=read_opt_str(data, "target_person"),
        target_handle=read_opt_str(data, "target_handle"),
        target_name=read_opt_str(data, "target_name"),
        expected_speaker=read_opt_str(data, "expected_speaker"),
        expected_date=read_opt_str(data, "expected_date"),
        subject_token=read_opt_str(data, "subject_token"),
        forbidden_tools=read_strs(data, "forbidden_tools"),
    )


def _truth(data: Mapping[str, object]) -> Truth:
    version = read_int(data, "version")
    if version != TRUTH_VERSION:
        raise TruthError("unsupported_truth_version")
    return Truth(
        version=version,
        seed=read_int(data, "seed"),
        n_threads=read_int(data, "n_threads"),
        account=read_str(data, "account"),
        own_addresses=read_strs(data, "own_addresses"),
        owner_id=read_str(data, "owner_id"),
        owner_telegram_id=read_int(data, "owner_telegram_id"),
        render_cap=read_int(data, "render_cap"),
        tz_offset_minutes=read_int(data, "tz_offset_minutes"),
        people=tuple(_person(read_obj(item)) for item in read_list(data, "people")),
        threads=tuple(_thread(read_obj(item)) for item in read_list(data, "threads")),
        parts=tuple(_part(read_obj(item)) for item in read_list(data, "parts")),
        facts=tuple(_fact(read_obj(item)) for item in read_list(data, "facts")),
        adversarial=tuple(_adversarial(read_obj(item)) for item in read_list(data, "adversarial")),
        questions=tuple(_question(read_obj(item)) for item in read_list(data, "questions")),
    )
