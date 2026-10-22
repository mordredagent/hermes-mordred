"""Threading: Gmail ids, reference union-find, guarded subject heuristic, partial threads."""

from __future__ import annotations

import random
from collections import Counter

import pytest

from mordred_hermes.imports.mail.merge_guard import followed_refs
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


# --- the merge guard in a batch (the same guard as the store's reconciliation) -------------------

ALICE, MALLORY, OWNER = "alice@example.org", "mallory@example.com", "owner@example.com"


def _five_threads_and_a_crafted_message(crafted_at: int) -> list[ThreadInput]:
    """Five two-message threads with Alice and one message from Mallory naming all five roots."""
    items: list[ThreadInput] = []
    for n in range(5):
        pair = frozenset({ALICE, OWNER})
        items.append(item(f"r{n}", mid=f"root{n}", people=pair, at=1_000 + n))
        items.append(item(f"p{n}", mid=f"reply{n}", irt=(f"root{n}",), refs=(f"root{n}",), people=pair, at=2_000 + n))
    roots = tuple(f"root{n}" for n in range(5))
    items.append(item("x", mid="crafted", refs=roots, people=frozenset({MALLORY, ALICE, OWNER}), at=crafted_at))
    return items


@pytest.mark.parametrize("crafted_at", [500, 1_500, 3_000])  # before, between and after the threads
def test_a_message_naming_five_threads_in_one_batch_joins_none_of_them(crafted_at: int) -> None:
    items = _five_threads_and_a_crafted_message(crafted_at)
    for seed in range(3):
        shuffled = items[:]
        random.Random(seed).shuffle(shuffled)
        stats: Counter[str] = Counter()
        threads = build_threads(shuffled, own={OWNER}, stats=stats)
        assert sorted(thread.members for thread in threads) == [
            ("r0", "p0"), ("r1", "p1"), ("r2", "p2"), ("r3", "p3"), ("r4", "p4"), ("x",)
        ]  # fmt: skip
        assert stats["merge_skipped"] == 1
        assert len({thread.thread_key for thread in threads}) == 6  # it names root0 first, yet keeps its own key
        keys = {thread.members: thread.thread_key for thread in threads}
        assert keys[("r0", "p0")] == default_thread_key(items[0])  # the thread holding the root keeps its key


def test_a_reply_chain_in_one_batch_still_groups_whatever_the_order() -> None:
    taro, hanako = "taro@example.net", "hanako@example.org"
    chain = [
        item("a", mid="A", people=frozenset({taro, OWNER}), at=100),
        item("b", mid="B", irt=("A",), refs=("A",), people=frozenset({hanako, taro, OWNER}), at=200),
        item("c", mid="C", irt=("B",), refs=("A", "B"), people=frozenset({OWNER, hanako}), at=300),
        item("d", mid="D", irt=("C",), refs=("A", "B", "C"), people=frozenset({taro, OWNER, hanako}), at=None),
    ]
    for seed in range(5):
        shuffled = chain[:]
        random.Random(seed).shuffle(shuffled)
        stats: Counter[str] = Counter()
        (thread,) = build_threads(shuffled, own={OWNER}, stats=stats)
        assert (thread.members, thread.method, stats["merge_skipped"]) == (("a", "b", "c", "d"), "references", 0)
        assert thread.thread_key == default_thread_key(chain[0])


def test_the_owner_is_never_the_shared_participant() -> None:
    root = item("a", mid="A", people=frozenset({ALICE, OWNER}))
    stray = item("b", mid="B", irt=("A",), refs=("A",), people=frozenset({MALLORY, OWNER}), order=1)
    stats: Counter[str] = Counter()
    assert len(build_threads([root, stray], own={OWNER}, stats=stats)) == 2 and stats["merge_skipped"] == 1
    assert len(build_threads([root, stray])) == 1  # without the owner's addresses it would count


def test_siblings_of_an_absent_parent_still_group() -> None:
    first = item("b", mid="B", irt=("A",), refs=("A",), at=200)
    second = item("c", mid="C", irt=("A",), refs=("A",), at=300, order=1)
    (thread,) = build_threads([first, second], own={OWNER})  # the absent parent's placeholder brings nobody
    assert thread.members == ("b", "c") and thread.partial


def test_excluded_copies_take_no_part_in_reference_grouping() -> None:
    forged = item("m1", mid="M1", irt=("M2",), refs=("M2",))  # a rejected copy of a stored message
    new = item("m2", mid="M2", order=1)
    reply = item("m3", mid="M3", irt=("M1",), refs=("M1",), order=2)  # names the excluded copy's id
    threads = build_threads([forged, new, reply], own={OWNER}, excluded={"m1"})
    assert sorted(thread.members for thread in threads) == [("m1",), ("m2",), ("m3",)]
    assert len(build_threads([forged, new, reply], own={OWNER})) == 1  # what it would have connected


def test_only_the_last_ten_references_are_followed_and_the_parent_is_kept() -> None:
    ancestors = tuple(f"anc{n}" for n in range(12))
    assert followed_refs(("parent",), (*ancestors, "parent")) == (*ancestors[-9:], "parent")
    far = item("far", mid="anc0")
    near = item("near", mid="parent", order=1)
    reply = item("reply", mid="R", irt=("parent",), refs=(*ancestors, "parent"), order=2)
    threads = {thread.members: thread for thread in build_threads([far, near, reply], own={OWNER})}
    assert set(threads) == {("far",), ("near", "reply")}  # anc0 is beyond the followed ids
    assert threads[("near", "reply")].partial  # but still marks the thread partial
