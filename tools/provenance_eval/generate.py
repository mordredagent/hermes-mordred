"""Deterministic dataset generation: ``generate(seed)`` uses ``random.Random(seed)`` only.

One logical :class:`~.scenarios.ThreadSpec` per thread is encoded twice — as
Telegram canonical records and as an mbox the real mail collector parses —
and the ground truth (parts, facts, adversarial items, questions) is derived
from the specs and the predicted parts.
"""

from __future__ import annotations

import random
from collections import defaultdict
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, replace
from typing import Final

from mordred_hermes.imports.records import telegram_conv_uid

from .answers import DECOY_TOOLS
from .encode_mail import ACCOUNT, encode_mail, mail_thread_uid
from .encode_telegram import EncodedThread, dialog_id, encode_telegram, threads_to_json
from .questions import build_questions
from .roster import OWNER, PEOPLE
from .scenarios import JST_MINUTES, Sentence, ThreadSpec, build_thread
from .truth import (
    SOURCES,
    TRUTH_VERSION,
    AdversarialItem,
    FactKind,
    FactTruth,
    PartTruth,
    Person,
    ThreadTruth,
    Truth,
)

__all__ = ["DEFAULT_THREADS", "RENDER_CAP", "Dataset", "generate"]

DEFAULT_THREADS: Final = 48
#: Body characters rendered per part (``render_selection(max_body_chars=...)``).
RENDER_CAP: Final = 1200


@dataclass(frozen=True)
class Dataset:
    truth: Truth
    telegram: tuple[EncodedThread, ...]
    mail_mbox: bytes

    def telegram_json(self) -> str:
        return threads_to_json(self.telegram)


@dataclass(frozen=True)
class _Said:
    sentence: Sentence
    speaker: Person
    identity: int
    said_at: int | None


def _said(spec: ThreadSpec) -> Iterable[_Said]:
    for msg in spec.messages:
        for sentence in msg.own_sentences():
            yield _Said(sentence, msg.sender, msg.identity, msg.sent_at)
        if msg.forward is not None:
            for sentence in msg.forward.sentences:
                yield _Said(sentence, msg.forward.author, msg.forward.identity, msg.forward.original_at)


def _facts(specs: Sequence[ThreadSpec], parts: Sequence[PartTruth]) -> tuple[FactTruth, ...]:
    by_token: dict[str, list[PartTruth]] = defaultdict(list)
    for part in parts:
        for token in part.tokens:
            by_token[token].append(part)
    facts: list[FactTruth] = []
    for spec in specs:
        for said in _said(spec):
            token = said.sentence.token
            carrying = by_token[token]
            shown = [p for p in carrying if p.imported and token in p.visible_tokens]
            facts.append(
                FactTruth(
                    token=token,
                    thread_id=spec.thread_id,
                    speaker=said.speaker.person_id,
                    kind=said.sentence.kind,
                    text=said.sentence.text,
                    said_at=said.said_at,
                    handles={
                        "telegram": str(said.speaker.telegram_id),
                        "mail": said.speaker.identities[said.identity].address.lower(),
                    },
                    in_parts=tuple(p.evidence_id for p in carrying),
                    knowable={
                        source: any(
                            p.source == source and p.author_knowable and p.author == said.speaker.person_id
                            for p in shown
                        )
                        for source in SOURCES
                    },
                    visible={source: any(p.source == source for p in shown) for source in SOURCES},
                )
            )
    return tuple(facts)


def _adversarial(facts: Sequence[FactTruth]) -> tuple[AdversarialItem, ...]:
    items: list[AdversarialItem] = []
    tools: tuple[str, ...]
    for fact in facts:
        if fact.kind is FactKind.REQUEST:
            kind, tools = "action_request", DECOY_TOOLS
        elif fact.kind is FactKind.FORGED:
            kind, tools = "forged_head", ()
        else:
            continue
        items.append(
            AdversarialItem(
                item_id=f"{fact.thread_id}.{kind}.{len(items)}",
                thread_id=fact.thread_id,
                kind=kind,
                token=fact.token,
                text=fact.text,
                forbidden_tools=tools,
            )
        )
    return tuple(items)


def _thread_truth(spec: ThreadSpec) -> ThreadTruth:
    return ThreadTruth(
        thread_id=spec.thread_id,
        index=spec.index,
        scenario=str(spec.scenario),
        variant=spec.variant,
        lang=spec.lang,
        title=spec.title,
        participants=tuple(person.person_id for person in spec.participants),
        telegram_conv_uid=telegram_conv_uid(dialog_id(spec.index)),
        mail_conv_uid=mail_thread_uid(spec),
    )


def generate(seed: int, *, n_threads: int = DEFAULT_THREADS) -> Dataset:
    """The dataset for ``seed``; equal seeds give equal datasets."""
    if isinstance(seed, bool) or not isinstance(seed, int):
        raise TypeError("seed must be an int")
    if not 1 <= n_threads <= 999:
        raise ValueError("n_threads must be between 1 and 999")
    rng = random.Random(seed)
    used_tokens: set[str] = set()
    specs = [build_thread(index, rng, used_tokens, cap=RENDER_CAP) for index in range(n_threads)]
    parts: list[PartTruth] = []
    telegram: list[EncodedThread] = []
    entries: list[bytes] = []
    for spec in specs:
        encoded, telegram_parts = encode_telegram(spec, owner_tg=OWNER.telegram_id, cap=RENDER_CAP)
        mail_entries, mail_parts = encode_mail(spec, owner=OWNER, cap=RENDER_CAP)
        telegram.append(encoded)
        entries.extend(mail_entries)
        parts.extend(telegram_parts)
        parts.extend(mail_parts)
    facts = _facts(specs, parts)
    truth = Truth(
        version=TRUTH_VERSION,
        seed=seed,
        n_threads=n_threads,
        account=ACCOUNT,
        own_addresses=OWNER.addresses,
        owner_id=OWNER.person_id,
        owner_telegram_id=OWNER.telegram_id,
        render_cap=RENDER_CAP,
        tz_offset_minutes=JST_MINUTES,
        people=PEOPLE,
        threads=tuple(_thread_truth(spec) for spec in specs),
        parts=tuple(parts),
        facts=facts,
        adversarial=_adversarial(facts),
    )
    return Dataset(replace(truth, questions=build_questions(truth)), tuple(telegram), b"".join(entries))
