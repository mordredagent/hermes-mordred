"""Threading: Gmail ids, reference union-find, guarded subject heuristic, partial threads."""

from __future__ import annotations

import random

import pytest

from mordred_hermes.imports.mail.threading import (
    HEURISTIC_WINDOW_SECONDS,
    ThreadInput,
    build_threads,
    default_thread_key,
    normalize_subject,
    subject_key,
)

DAY = 24 * 3600
PEOPLE = frozenset({"a@example.org", "b@example.net"})


def item(
    key: str,
    *,
    mid: str | None = None,
    irt: tuple[str, ...] = (),
    refs: tuple[str, ...] = (),
    thrid: str | None = None,
    subject: str = "topic",
    people: frozenset[str] = PEOPLE,
    at: int | None = 1_790_000_000,
    order: int = 0,
) -> ThreadInput:
    return ThreadInput(
        key=key,
        message_id=mid,
        in_reply_to=irt,
        references=refs,
        gm_thread_id=thrid,
        subject_key=subject_key(subject),
        participants=people,
        sent_at=at,
        order=order,
    )


@pytest.mark.parametrize(
    ("subject", "expected"),
    [
        ("Re: RE: Fwd: FW: AW: WG: Budget", "Budget"),
        ("Re[2]: Budget", "Budget"),
        ("RE(3): Budget", "Budget"),
        ("返信: 転送: 見積もり", "見積もり"),
        ("[dev-ml] Re: [tag] release", "release"),
        ("\uff32\uff45\uff1a\u3000テスト", "テスト"),  # full-width "Re:" and ideographic space
        ("  many   spaces\there ", "many spaces here"),
        ("Regarding the plan", "Regarding the plan"),
    ],
)
def test_subject_normalisation(subject: str, expected: str) -> None:
    assert normalize_subject(subject) == expected


def test_gmail_thread_ids_group_and_never_merge_with_each_other() -> None:
    items = [
        item("k1", mid="m1", thrid="11"),
        item("k2", mid="m2", irt=("m1",), refs=("m1",), thrid="11", order=1),
        item("k3", mid="m3", irt=("m2",), refs=("m1", "m2"), thrid="22", order=2),  # Gmail split it off
    ]
    threads = {thread.thread_key: thread for thread in build_threads(items)}
    assert set(threads) == {"g.11", "g.22"}
    assert threads["g.11"].members == ("k1", "k2")
    assert {thread.method for thread in threads.values()} == {"gmail_thrid"}


def test_message_without_gmail_id_joins_the_gmail_thread_it_replies_to() -> None:
    items = [item("k1", mid="m1", thrid="11"), item("k2", mid="m2", irt=("m1",), order=1)]
    (thread,) = build_threads(items)
    assert (thread.thread_key, thread.members) == ("g.11", ("k1", "k2"))


def test_reference_union_find_is_order_independent_and_key_is_stable() -> None:
    chain = [
        item("k1", mid="root", at=100),
        item("k2", mid="r1", irt=("root",), refs=("root",), at=200),
        item("k3", mid="r2", irt=("r1",), refs=("root", "r1"), at=300),
        item("k4", mid="r3", irt=("r1",), at=400),  # only In-Reply-To
    ]
    keys = set()
    for seed in range(5):
        shuffled = chain[:]
        random.Random(seed).shuffle(shuffled)
        (thread,) = build_threads(shuffled)
        assert thread.members == ("k1", "k2", "k3", "k4")
        assert thread.method == "references"
        assert not thread.partial
        keys.add(thread.thread_key)
    # The root alone has the same key, so a later import that adds replies keeps the conversation.
    assert keys == {default_thread_key(chain[0])}
    assert build_threads(chain[:1])[0].thread_key == default_thread_key(chain[0])


def test_missing_parent_marks_partial_thread() -> None:
    (thread,) = build_threads([item("k2", mid="r1", irt=("absent",), refs=("absent",))])
    assert thread.partial
    assert thread.method == "references"


def test_subject_heuristic_requires_same_participants_and_window() -> None:
    base = 1_790_000_000
    items = [
        item("k1", mid="m1", subject="Plan", at=base),
        item("k2", mid="m2", subject="Re: plan", at=base + 2 * DAY, order=1),
        item("k3", mid="m3", subject="Plan", people=frozenset({"c@example.org"}), at=base + DAY, order=2),
        item("k4", mid="m4", subject="Plan", at=base + 2 * DAY + HEURISTIC_WINDOW_SECONDS + 1, order=3),
        item("k5", mid="m5", subject="Plan", at=None, order=4),
    ]
    threads = build_threads(items)
    by_members = {thread.members: thread for thread in threads}
    assert by_members[("k1", "k2")].method == "heuristic"
    assert by_members[("k1", "k2")].thread_key == default_thread_key(items[0])
    for single in (("k3",), ("k4",), ("k5",)):
        assert by_members[single].method == "single"


def test_messages_with_reference_headers_never_use_the_subject_heuristic() -> None:
    items = [item("k1", mid="m1", subject="Plan"), item("k2", mid="m2", subject="Plan", irt=("elsewhere",))]
    methods = sorted(thread.method for thread in build_threads(items))
    assert methods == ["references", "single"]


def test_thread_keys_are_content_free() -> None:
    (thread,) = build_threads([item("k1", mid="secret-subject-id@example.org")])
    assert thread.thread_key.startswith("r.")
    assert "secret" not in thread.thread_key
