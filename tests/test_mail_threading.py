"""Threading: Gmail ids, reference union-find, guarded subject heuristic, partial threads."""

from __future__ import annotations

import itertools
import random
from collections import Counter

import pytest

from mordred_hermes.imports.mail.merge_guard import followed_refs
from mordred_hermes.imports.mail.threading import (
    HEURISTIC_WINDOW_SECONDS,
    Thread,
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


def _assert_kept_apart(threads: list[Thread], expected: list[set[str]], crafted: str) -> None:
    """Each ``expected`` group is one thread of its own: ``crafted`` sits alone or in one of them, bridging none."""
    found = sorted(sorted(set(thread.members) - {crafted}) for thread in threads)
    assert [members for members in found if members] == sorted(sorted(group) for group in expected)


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
def test_a_message_naming_five_threads_in_one_batch_bridges_none_of_them(crafted_at: int) -> None:
    items = _five_threads_and_a_crafted_message(crafted_at)
    for seed in range(3):
        shuffled = items[:]
        random.Random(seed).shuffle(shuffled)
        stats: Counter[str] = Counter()
        threads = build_threads(shuffled, own={OWNER}, stats=stats)
        _assert_kept_apart(threads, [{f"r{n}", f"p{n}"} for n in range(5)], "x")
        assert {"r4", "p4", "x"} in [set(thread.members) for thread in threads]  # through its direct parent only
        assert stats["merge_skipped"] == 1
        assert len({thread.thread_key for thread in threads}) == len(threads)  # distinct, though it names root0 first
        keys = {thread.members: thread.thread_key for thread in threads}
        assert keys[("r0", "p0")] == default_thread_key(items[0])  # the thread holding the root keeps its key


def _orders(items: list[ThreadInput]) -> list[list[ThreadInput]]:
    """The batch as built, reversed and shuffled with a fixed seed."""
    return [items, items[::-1], random.Random(20261022).sample(items, len(items))]


@pytest.mark.parametrize("shared_ancestors", [False, True])
@pytest.mark.parametrize("crafted_at", [500, 1_500, 3_000])  # before, between and after the threads
def test_replies_naming_absent_ancestors_form_their_threads_before_a_crafted_message_is_weighed(
    crafted_at: int, shared_ancestors: bool
) -> None:
    """The fifth-pass review: each reply names five older absent ancestors and its parent (six followed ids),
    the crafted message names only the five roots (five), so it used to be weighed first and joined them all."""
    pair = frozenset({ALICE, OWNER})
    items: list[ThreadInput] = []
    for n in range(5):
        ancestors = tuple(f"old{k}" if shared_ancestors else f"old{n}.{k}" for k in range(5))
        items.append(item(f"r{n}", mid=f"root{n}", people=pair, at=1_000 + n))
        items.append(
            item(f"p{n}", mid=f"reply{n}", irt=(f"root{n}",), refs=(*ancestors, f"root{n}"), people=pair, at=2_000 + n)
        )
    roots = tuple(f"root{n}" for n in range(5))
    items.append(item("x", mid="crafted", refs=roots, people=frozenset({MALLORY, ALICE, OWNER}), at=crafted_at))
    results = set()
    for order in _orders(items):
        stats: Counter[str] = Counter()
        threads = build_threads(order, own={OWNER}, stats=stats)
        _assert_kept_apart(threads, [{f"r{n}", f"p{n}"} for n in range(5)], "x")
        assert stats["merge_skipped"] > 0
        results.add(tuple((thread.thread_key, thread.members, thread.partial) for thread in threads))
    assert len(results) == 1  # the same threads and keys whatever the order of the batch


@pytest.mark.parametrize("stranger_at", [100, 900])  # dated before or after the children
def test_a_stranger_among_the_children_of_an_absent_parent_is_held_back_once(stranger_at: int) -> None:
    children = [item(f"c{n}", mid=f"C{n}", irt=("A",), refs=("A",), at=200 + n) for n in range(3)]
    stranger = item("s", mid="S", irt=("A",), refs=("A",), people=frozenset({MALLORY, OWNER}), at=stranger_at)
    for order in _orders([*children, stranger]):
        stats: Counter[str] = Counter()
        threads = build_threads(order, own={OWNER}, stats=stats)
        assert sorted(thread.members for thread in threads) == [("c0", "c1", "c2"), ("s",)]
        assert stats["merge_skipped"] == 1


def test_held_keys_never_name_a_thread_by_an_id_it_only_references() -> None:
    root = item("a", mid="A", at=100)
    reply = item("b", mid="B", irt=("A",), refs=("A",), at=200)
    (legacy,) = build_threads([reply])
    assert legacy.thread_key == default_thread_key(reply)  # the absent root's hash: file imports keep it
    (held,) = build_threads([reply], held_keys=True)
    assert held.thread_key == default_thread_key(item("b", mid="B"))  # its own id instead
    (whole,) = build_threads([reply, root], held_keys=True)
    assert whole.thread_key == default_thread_key(root)  # a thread holding its root keeps the root's key


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


# --- the sixth-pass review: References-only replies and siblings of an absent parent ---------------

BOB = "bob@example.net"


def test_references_only_replies_and_a_crafted_message_dated_earliest_bridge_no_threads() -> None:
    """Replies without ``In-Reply-To`` (one reference each) still join their parent before the crafted
    message naming the five roots is weighed, whatever the batch order, although it is dated first: it
    attaches to at most one thread (its direct parent's) and bridges none."""
    pair = frozenset({ALICE, OWNER})
    items: list[ThreadInput] = []
    for n in range(5):
        items.append(item(f"r{n}", mid=f"root{n}", people=pair, at=1_000 + n))
        items.append(item(f"p{n}", mid=f"reply{n}", refs=(f"root{n}",), people=pair, at=2_000 + n))
    roots = tuple(f"root{n}" for n in range(5))
    items.append(item("x", mid="crafted", refs=roots, people=frozenset({MALLORY, ALICE, OWNER}), at=500))
    results = set()
    for order in _orders(items):
        stats: Counter[str] = Counter()
        threads = build_threads(order, own={OWNER}, stats=stats)
        _assert_kept_apart(threads, [{f"r{n}", f"p{n}"} for n in range(5)], "x")
        assert stats["merge_skipped"] > 0
        results.add(tuple((thread.thread_key, thread.members) for thread in threads))
    assert len(results) == 1


def _two_branches_and_a_crafted_sibling(shape: str) -> list[ThreadInput]:
    """Two two-message branches under the absent parent A with disjoint correspondents (Alice, Bob), and
    Mallory's reply to A naming both, dated first. ``siblings``: all four reply to A; ``chain``: each
    branch is a reply to A and a reply to that."""
    items = [item("x", mid="X", irt=("A",), refs=("A",), people=frozenset({MALLORY, ALICE, BOB, OWNER}), at=50)]
    for branch, (who, at) in {"b": (ALICE, 100), "c": (BOB, 300)}.items():
        pair = frozenset({who, OWNER})
        items.append(item(f"{branch}1", mid=f"{branch}1", irt=("A",), refs=("A",), people=pair, at=at))
        parent = "A" if shape == "siblings" else f"{branch}1"
        refs = ("A",) if shape == "siblings" else ("A", f"{branch}1")
        items.append(item(f"{branch}2", mid=f"{branch}2", irt=(parent,), refs=refs, people=pair, at=at + 100))
    return items


@pytest.mark.parametrize("shape", ["siblings", "chain"])
def test_a_crafted_sibling_naming_both_correspondents_bridges_no_branches(shape: str) -> None:
    results = set()
    for order in _orders(_two_branches_and_a_crafted_sibling(shape)):
        stats: Counter[str] = Counter()
        threads = [set(thread.members) for thread in build_threads(order, own={OWNER}, stats=stats)]
        b_side = next(members for members in threads if "b1" in members)
        c_side = next(members for members in threads if "c1" in members)
        assert b_side != c_side and {"b1", "b2"} <= b_side and {"c1", "c2"} <= c_side
        assert (b_side | c_side) - {"x"} == {"b1", "b2", "c1", "c2"}  # the crafted message joins one or none
        assert stats["merge_skipped"] > 0
        results.add(tuple(sorted(tuple(sorted(members)) for members in threads)))
    assert len(results) == 1


def test_siblings_of_an_absent_parent_with_the_same_correspondents_and_their_replies_group() -> None:
    """Two replies to an absent root (same correspondents) each with a reply: one thread in any order."""
    pair = frozenset({ALICE, BOB, OWNER})
    items = [
        item("b1", mid="B1", irt=("A",), refs=("A",), people=pair, at=100),
        item("c1", mid="C1", irt=("A",), refs=("A",), people=pair, at=200),
        item("b2", mid="B2", irt=("B1",), refs=("A", "B1"), people=pair, at=300),
        item("c2", mid="C2", refs=("A", "C1"), people=pair, at=400),  # References only
    ]
    for order in _orders(items):
        stats: Counter[str] = Counter()
        (thread,) = build_threads(order, own={OWNER}, stats=stats)
        assert (thread.members, stats["merge_skipped"]) == (("b1", "c1", "b2", "c2"), 0)


def test_a_branching_tree_with_references_only_replies_groups_whatever_the_order() -> None:
    """Every union is guarded (two multi-message groups never join), yet a tree forms: ancestors join first."""
    pair = frozenset({ALICE, OWNER})
    tree = [
        item("a", mid="A", people=pair, at=100),
        item("b", mid="B", refs=("A",), people=pair, at=200),
        item("e", mid="E", irt=("A",), refs=("A",), people=pair, at=210),
        item("c", mid="C", refs=("A", "B"), people=pair, at=300),
        item("f", mid="F", irt=("E",), people=pair, at=310),
        item("d", mid="D", refs=("A", "B", "C"), people=pair, at=None),
    ]
    for seed in range(5):
        shuffled = random.Random(seed).sample(tree, len(tree))
        stats: Counter[str] = Counter()
        (thread,) = build_threads(shuffled, own={OWNER}, stats=stats)
        assert (thread.members, stats["merge_skipped"]) == (("a", "b", "e", "c", "f", "d"), 0)
        assert thread.thread_key == default_thread_key(tree[0]) and not thread.partial


# --- the seventh-pass review: a reply naming other groups still joins its direct parent first -------


def _two_triples_and_a_crafted_message(*, explicit_parent: bool, crafted: bool = True) -> list[ThreadInput]:
    """Two triples (Ai, Ri, Pi): Ai and Ri reference nothing, Pi references (Ai, Ri) (``explicit_parent``:
    with ``In-Reply-To: Ri`` too), all with Alice; Mallory's X, dated first, references (R0, R1)."""
    pair = frozenset({ALICE, OWNER})
    items: list[ThreadInput] = []
    if crafted:
        items.append(item("x", mid="X", refs=("R0", "R1"), people=frozenset({MALLORY, ALICE, OWNER}), at=500))
    for n in range(2):
        items.append(item(f"a{n}", mid=f"A{n}", people=pair, at=1_000 + n))
        items.append(item(f"r{n}", mid=f"R{n}", people=pair, at=1_100 + n))
        irt = (f"R{n}",) if explicit_parent else ()
        items.append(item(f"p{n}", mid=f"P{n}", irt=irt, refs=(f"A{n}", f"R{n}"), people=pair, at=1_200 + n))
    return items


def test_a_crafted_message_naming_two_triples_bridges_neither_with_or_without_in_reply_to() -> None:
    """The seventh-pass probe: each Pi joins Ri in phase 1 whatever else it names, so the date X forged
    decides nothing. X attaches through its direct parent (R1) alone; its other reference names a second
    established thread, so its weak edges merge nothing and it is counted."""
    triples = [{f"a{n}", f"r{n}", f"p{n}"} for n in range(2)]
    results = set()
    for explicit_parent in (False, True):
        legit = build_threads(_two_triples_and_a_crafted_message(explicit_parent=explicit_parent, crafted=False))
        _assert_kept_apart(legit, triples, "x")  # without X: two conversations
        for order in _orders(_two_triples_and_a_crafted_message(explicit_parent=explicit_parent)):
            stats: Counter[str] = Counter()
            threads = build_threads(order, own={OWNER}, stats=stats)
            _assert_kept_apart(threads, triples, "x")
            assert {"a1", "r1", "p1", "x"} in [set(thread.members) for thread in threads]
            assert stats["merge_skipped"] > 0
            results.add(tuple((thread.thread_key, thread.members) for thread in threads))
    assert len(results) == 1  # whatever the order, and with or without In-Reply-To


def test_replies_with_extra_references_still_form_one_conversation() -> None:
    """Replies naming, besides their direct parent, another branch of their thread or an earlier message
    that references nothing join their parents first, then pull those in: one conversation in any order."""
    pair = frozenset({ALICE, BOB, OWNER})
    tree = [
        item("z", mid="Z", people=pair, at=50),  # an earlier message the thread cites, with no references
        item("a", mid="A", people=pair, at=100),
        item("b", mid="B", irt=("A",), refs=("A",), people=pair, at=200),
        item("c", mid="C", irt=("A",), refs=("A",), people=pair, at=210),
        item("d", mid="D", irt=("C",), refs=("A", "B", "C"), people=pair, at=300),  # names the other branch
        item("y", mid="Y", refs=("Z", "D"), people=pair, at=400),  # References only, naming Z too
    ]
    for order in _orders(tree):
        stats: Counter[str] = Counter()
        (thread,) = build_threads(order, own={OWNER}, stats=stats)
        assert (thread.members, stats["merge_skipped"]) == (("z", "a", "b", "c", "d", "y"), 0)
        assert thread.thread_key == default_thread_key(tree[2]) and not thread.partial  # A, the root most name


# --- the eighth-pass review: pairs formed through one present ancestor, a crafted message dated first ---


def _two_pairs_under_absent_parents(crafted_at: int | None) -> list[ThreadInput]:
    """The eighth-pass probe, all with Alice, no ``In-Reply-To``: Ai references the absent Ui (dated
    100+i), Pi references (Ai, Vi) with Vi absent (dated 200+i), and X references (A0, A1)."""
    pair = frozenset({ALICE, OWNER})
    items: list[ThreadInput] = []
    for n in range(2):
        items.append(item(f"a{n}", mid=f"A{n}", refs=(f"U{n}",), people=pair, at=100 + n))
        items.append(item(f"p{n}", mid=f"P{n}", refs=(f"A{n}", f"V{n}"), people=pair, at=200 + n))
    if crafted_at is not None:
        items.append(item("x", mid="X", refs=("A0", "A1"), people=frozenset({MALLORY, ALICE, OWNER}), at=crafted_at))
    return items


@pytest.mark.parametrize("crafted_at", [0, 1_000])  # dated before or after both pairs
def test_pairs_formed_through_one_present_ancestor_settle_before_a_crafted_message_naming_both(
    crafted_at: int,
) -> None:
    """Each Pi's absent parent Vi leaves its pair to phase 2; absent ids never order it, so Pi (one present
    reference) joins Ai before X (two) is weighed, in every one of the 120 batch orders and whatever X's
    date: X attaches through its direct parent (A1) alone and is held back from the other pair."""
    pairs = [{f"a{n}", f"p{n}"} for n in range(2)]
    legit = build_threads(_two_pairs_under_absent_parents(None), own={OWNER})
    assert sorted(thread.members for thread in legit) == [("a0", "p0"), ("a1", "p1")]  # without X: two
    results = set()
    for order in itertools.permutations(_two_pairs_under_absent_parents(crafted_at)):
        stats: Counter[str] = Counter()
        threads = build_threads(list(order), own={OWNER}, stats=stats)
        _assert_kept_apart(threads, pairs, "x")
        assert {"a1", "p1", "x"} in [set(thread.members) for thread in threads]
        assert stats["merge_skipped"] > 0
        results.add(tuple((thread.thread_key, thread.members) for thread in threads))
    assert len(results) == 1  # the same threads and keys whatever the order of the batch
