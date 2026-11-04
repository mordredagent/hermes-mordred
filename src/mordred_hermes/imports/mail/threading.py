"""Mail threading: Gmail thread ids, then set-based guarded reference grouping, then a subject heuristic.

- ``X-GM-THRID`` groups first (method ``gmail_thrid``); its references are not
  followed. A message without one joins the Gmail thread of a message it
  references under the rules below.
- Otherwise messages are joined over ``Message-ID``, ``In-Reply-To`` and
  ``References`` (method ``references``, or ``single``). Those headers are typed
  by the sender, so the grouping is a pure function of the SET of messages, never
  of their order or the dates senders typed, under the rules of
  :mod:`.merge_guard` (``own`` holds the account owner's addresses, which never
  count as a shared participant). An id is *present* when a message of the
  import holds it; copies holding one id are one message only when their
  content digests are identical. An id held by differing copies is *contested*:
  it names no message (the copies count as ``untrusted_id``), and a message
  holding or following one is *untrusted*.

  1. Strong forest. Each message takes AT MOST ONE strong attachment: its Gmail
     thread; else its direct parent (its last ``In-Reply-To`` id, else, as RFC
     5322 says, its last ``References`` id) when present and sharing a
     participant; else, when that parent is absent, the other children of the
     absent parent with the same (non-empty) participant set. A contested
     parent gives none. Strong components are trees of single attachments, so
     no message bridges two of them. A component of several messages, or keyed
     by a Gmail thread id, is *established*; an untrusted message alone in its
     component is *pinned*: established for every guard, but never joined.
  2. Tier 1. A message's weak references are its followed ids (the last
     ``MAX_MERGE_REFS``) naming a present message of another strong component
     that shares a participant with it. A message with exactly ONE such
     component adds that edge. Edges between two messages alone in their strong
     components form weak clusters; a cluster of several messages is
     established. A message alone in its cluster joins the established
     component its edges touch (in either direction) when there is exactly one,
     and none when they touch several or a pinned one. Established components
     and clusters never join each other. A pinned message's references touch
     their targets without joining them.
  3. Tier 2. A message whose weak references reach two or more components is
     weighed against the tier-1 result only (so the decisions commute): its own
     group when established, the groups that touched it in tier 1 and the
     established (or pinned) groups it references; exactly one (not pinned) →
     it joins it, several → none; none at all → it forms a cluster with the
     messages it references that tier 1 left alone and untouched (never another
     tier-2 message).

  A message counts once as ``merge_skipped`` when one of its followed ids names
  a present message that ends in another conversation.
- ``excluded`` messages (copies the store will not write: duplicates and
  rejected copies of stored rows) take no part: their references are not
  followed and an id they carry is not a join point (another message naming it
  joins the stored conversation through the importer's resolver instead).
- Subject-only grouping joins single messages without any reference header
  only when the normalised subject AND the participant address set match and
  each message is within 30 days of the previous one (method ``heuristic``),
  ordered by date, then source uid. Excluded copies and copies of a contested
  id are never grouped by subject.
- A thread whose messages reference an id that is not in the import is
  *partial*.

Thread keys are content-free (Gmail ids are digits; everything else is a hash),
distinct per thread (a guard can keep apart two groups naming the same root: the
group holding the root message keeps its key, the other takes its own root's)
and stable when later imports add replies. With ``held_keys`` (the IMAP sync,
whose batches join stored conversations only through the store's guarded
reconciliation) a thread that does not hold its root message is keyed by its
oldest member's own id instead, so an id a message merely references never
names the conversation it is written to.
"""

from __future__ import annotations

import hashlib
import re
import unicodedata
from collections import Counter
from collections.abc import Collection, Container, Iterator, Mapping, Sequence
from dataclasses import dataclass, replace
from typing import Final

from .merge_guard import attach_target, counted_people, established, followed_refs, same_message, share_participant

__all__ = [
    "HEURISTIC_WINDOW_SECONDS",
    "Thread",
    "ThreadInput",
    "build_threads",
    "default_thread_key",
    "normalize_subject",
    "subject_key",
]

HEURISTIC_WINDOW_SECONDS: Final = 30 * 24 * 3600
_PREFIX_RE: Final = re.compile(
    r"^\s*(?:"
    r"(?:re|fwd?|fw|aw|wg|返信|転送)\s*(?:\[\d{1,4}\]|\(\d{1,4}\))?\s*[:\uff1a]"
    r"|\[[^\[\]]{0,64}\]"
    r")\s*",
    re.IGNORECASE,
)


@dataclass(frozen=True, kw_only=True)
class ThreadInput:
    key: str  # the message's source uid
    message_id: str | None
    in_reply_to: tuple[str, ...]
    references: tuple[str, ...]
    gm_thread_id: str | None
    subject_key: str
    participants: frozenset[str]
    sent_at: int | None
    order: int
    digest: str | None = None  # the copy's content digest; None (unknown) never proves two copies identical


@dataclass(frozen=True)
class Thread:
    thread_key: str
    method: str  # gmail_thrid | references | single | heuristic
    members: tuple[str, ...]  # source uids, oldest first (unknown dates last), then by source uid
    partial: bool


def normalize_subject(subject: str) -> str:
    """Strip reply/forward/tag prefixes (repeatedly), then NFKC and collapse whitespace."""
    value = unicodedata.normalize("NFKC", subject or "")
    while True:
        stripped = _PREFIX_RE.sub("", value, count=1)
        if stripped == value:
            break
        value = stripped
    return " ".join(unicodedata.normalize("NFKC", value).split())


def subject_key(subject: str) -> str:
    return normalize_subject(subject).casefold()


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:32]


def _root(item: ThreadInput) -> str:
    if item.references:
        return item.references[0]
    if item.in_reply_to:
        return item.in_reply_to[0]
    return item.message_id or item.key


def default_thread_key(item: ThreadInput) -> str:
    """The key a message gets on its own (Gmail id, else a hash of its thread root)."""
    if item.gm_thread_id:
        return f"g.{item.gm_thread_id}"
    return f"r.{_digest(_root(item))}"


class _UnionFind:
    """Union-find over message keys: the partition it ends with never depends on the order of the unions."""

    def __init__(self, parent: Mapping[str, str] | None = None) -> None:
        self.parent: dict[str, str] = dict(parent or {})

    def copy(self) -> _UnionFind:
        return _UnionFind(self.parent)

    def find(self, node: str) -> str:
        self.parent.setdefault(node, node)
        root = node
        while self.parent[root] != root:
            root = self.parent[root]
        while self.parent[node] != root:
            self.parent[node], node = root, self.parent[node]
        return root

    def union(self, left: str, right: str) -> None:
        a, b = self.find(left), self.find(right)
        if a != b:
            self.parent[max(a, b)] = min(a, b)


def _sort_key(item: ThreadInput) -> tuple[bool, int, str]:
    """Oldest first, unknown dates last, then the source uid: independent of the input order."""
    return (item.sent_at is None, item.sent_at or 0, item.key)


def _direct_parent(item: ThreadInput) -> str | None:
    """The id ``item`` replies to: its last ``In-Reply-To`` id, else its last ``References`` id (RFC 5322)."""
    if item.in_reply_to:
        return item.in_reply_to[-1]
    return item.references[-1] if item.references else None


def _named(item: ThreadInput) -> set[str]:
    """The ids a message's edges may follow: its followed references and its direct parent."""
    parent = _direct_parent(item)
    return {*followed_refs(item.in_reply_to, item.references), *((parent,) if parent else ())}


def _referenced(item: ThreadInput) -> tuple[str, ...]:
    return (*item.in_reply_to, *reversed(item.references))


@dataclass(frozen=True)
class _Batch:
    """The facts the grouping reads: the messages, their counted participants and who holds which id."""

    items: Sequence[ThreadInput]
    followers: Sequence[ThreadInput]  # the messages whose references are followed (not excluded, no Gmail id)
    people: Mapping[str, frozenset[str]]  # source uid → participants, the owner's addresses left out
    holders: Mapping[str, tuple[str, ...]]  # present Message-ID → its copies (one message: identical digests)
    contested: Mapping[str, tuple[str, ...]]  # Message-ID held by differing copies → those copies
    untrusted: frozenset[str]  # source uids holding or following a contested id


def _one_message(copies: Sequence[ThreadInput]) -> bool:
    """Copies sharing a Message-ID are one message: a single copy, or identical content (rule 5)."""
    return len(copies) == 1 or (
        same_message([copy.digest for copy in copies]) and len({copy.gm_thread_id for copy in copies}) == 1
    )


def _batch(items: Sequence[ThreadInput], own: Container[str], excluded: Collection[str]) -> _Batch:
    copies: dict[str, list[ThreadInput]] = {}
    for item in items:
        if item.message_id and item.key not in excluded:  # an excluded copy's id is no join point
            copies.setdefault(item.message_id, []).append(item)
    holders: dict[str, tuple[str, ...]] = {}
    contested: dict[str, tuple[str, ...]] = {}
    for message_id, group in copies.items():
        (holders if _one_message(group) else contested)[message_id] = tuple(copy.key for copy in group)
    followers = [item for item in items if item.key not in excluded and not item.gm_thread_id]
    untrusted = {key for keys in contested.values() for key in keys}
    untrusted.update(item.key for item in followers if not contested.keys().isdisjoint(_named(item)))
    return _Batch(
        items=items,
        followers=followers,
        people={item.key: counted_people(item.participants, own) for item in items},
        holders=holders,
        contested=contested,
        untrusted=frozenset(untrusted),
    )


def _attachment(batch: _Batch, item: ThreadInput) -> str | tuple[str, frozenset[str]] | None:
    """Step 1: a followed message's one strong attachment (a holder's uid, an absent parent's sibling node, none)."""
    parent, mine = _direct_parent(item), batch.people[item.key]
    if parent is None or parent in batch.contested:
        return None  # a contested id names no message: neither copy is the parent
    if parent in batch.holders:
        holder = batch.holders[parent][0]
        return holder if share_participant(mine, batch.people[holder]) else None
    return (parent, mine) if mine else None  # the children of one absent parent with the same correspondents


def _strong_components(batch: _Batch) -> _UnionFind:
    """Step 1 (module docstring): one Gmail thread, one message's copies, one attachment per message."""
    strong = _UnionFind()
    gmail: dict[str, str] = {}
    for item in batch.items:
        strong.find(item.key)
        if item.gm_thread_id:
            strong.union(item.key, gmail.setdefault(item.gm_thread_id, item.key))
    for keys in batch.holders.values():
        for key in keys[1:]:
            strong.union(keys[0], key)  # identical copies are one message
    siblings: dict[tuple[str, frozenset[str]], str] = {}
    for item in batch.followers:
        target = _attachment(batch, item)
        if isinstance(target, str):
            strong.union(item.key, target)
        elif target is not None:
            strong.union(item.key, siblings.setdefault(target, item.key))
    return strong


@dataclass(frozen=True)
class _Forest:
    """Step 1's result as the weak tiers read it."""

    strong: _UnionFind
    anchors: frozenset[str]  # roots of the established strong components (several messages, or a Gmail id)
    pinned: frozenset[str]  # untrusted messages alone in their component: established, never joined
    free: frozenset[str]  # the other messages alone in their component
    targets: Mapping[str, frozenset[str]]  # followed uid → the strong roots its weak references reach


def _targets(batch: _Batch, strong: _UnionFind, item: ThreadInput) -> frozenset[str]:
    """The other strong components ``item``'s followed ids name, sharing a participant (rule 2)."""
    own, mine = strong.find(item.key), batch.people[item.key]
    found: set[str] = set()
    for ref in followed_refs(item.in_reply_to, item.references):
        keys = batch.holders.get(ref)
        if keys and share_participant(mine, batch.people[keys[0]]) and strong.find(keys[0]) != own:
            found.add(strong.find(keys[0]))
    return frozenset(found)


def _forest(batch: _Batch) -> _Forest:
    strong = _strong_components(batch)
    sizes = Counter(strong.find(item.key) for item in batch.items)
    gmail = {strong.find(item.key) for item in batch.items if item.gm_thread_id}
    anchors = frozenset(root for root, size in sizes.items() if established(size, gmail=root in gmail))
    alone = sizes.keys() - anchors  # a message alone in its component is that component's root
    targets = {item.key: _targets(batch, strong, item) for item in batch.followers}
    return _Forest(
        strong=strong,
        anchors=anchors,
        pinned=frozenset(alone & batch.untrusted),
        free=frozenset(alone - batch.untrusted),
        targets={key: roots for key, roots in targets.items() if roots},
    )


@dataclass(frozen=True)
class _TierOne:
    """Step 2's result: the groups tier 2 weighs its messages against."""

    groups: _UnionFind  # strong components, weak clusters and the single messages joined to one
    established: frozenset[str]  # group roots holding an established component or a cluster of several
    touches: Mapping[str, frozenset[str]]  # single message → established or pinned roots its edges touch
    untouched: frozenset[str]  # single messages left alone that no tier-1 edge touches


def _tier_one_edges(forest: _Forest) -> list[tuple[str, str, bool]]:
    """(source root, target root, may form a cluster): one-reference messages' edges, then pinned claims."""
    edges: list[tuple[str, str, bool]] = []
    for key, roots in forest.targets.items():
        source = forest.strong.find(key)
        if source in forest.pinned:
            edges.extend((source, root, False) for root in roots)  # touches its targets, joins none
        elif len(roots) == 1:
            edges.extend((source, root, True) for root in roots)
    return edges


def _tier_one(forest: _Forest) -> _TierOne:
    """Step 2 (module docstring): weak clusters, then each message alone joins at most one established group."""
    clusters = _UnionFind()
    touches: dict[str, set[str]] = {}
    for source, target, joins in _tier_one_edges(forest):
        if joins and source in forest.free and target in forest.free:
            clusters.union(source, target)
            continue
        for single, other in ((source, target), (target, source)):
            if single in forest.free and other not in forest.free:
                touches.setdefault(single, set()).add(other)
    sizes = Counter(clusters.find(key) for key in forest.free)
    groups = forest.strong.copy()
    several = {root for root, size in sizes.items() if size > 1}
    untouched: set[str] = set()
    for key in forest.free:
        if clusters.find(key) in several:
            groups.union(key, clusters.find(key))
            continue
        joined, _held = attach_target(touches.get(key, set()), pinned=forest.pinned)
        if joined is not None:
            groups.union(key, joined)
        elif key not in touches:
            untouched.add(key)
    return _TierOne(
        groups=groups,
        established=frozenset(groups.find(root) for root in (*forest.anchors, *several)),
        touches={key: frozenset(found) for key, found in touches.items()},
        untouched=frozenset(untouched),
    )


def _tier_two(forest: _Forest, one: _TierOne) -> list[tuple[str, str]]:
    """Step 3: the joins of the messages reaching several components, each weighed against tier 1 only."""
    several = {key for key, roots in forest.targets.items() if len(roots) > 1 and key not in forest.pinned}
    loose = one.untouched - several
    joins: list[tuple[str, str]] = []
    for key in sorted(several):
        own = one.groups.find(key)
        reach = {own} if own in one.established else set()
        reach.update(one.groups.find(root) for root in one.touches.get(key, ()))
        named = {one.groups.find(root) for root in forest.targets[key]} - {own}
        reach.update(group for group in named if group in one.established or group in forest.pinned)
        target, _held = attach_target(reach, pinned=forest.pinned)
        if target is not None:
            joins.append((key, target))
        elif not reach:
            joins.extend((key, root) for root in forest.targets[key] if root in loose)
    return joins


def _skipped(batch: _Batch, groups: _UnionFind) -> int:
    """``merge_skipped``: the messages one of whose followed ids names a present message of another conversation."""
    count = 0
    for item in batch.followers:
        mine = groups.find(item.key)
        named = (keys for ref in followed_refs(item.in_reply_to, item.references) if (keys := batch.holders.get(ref)))
        count += any(groups.find(keys[0]) != mine for keys in named)
    return count


@dataclass(frozen=True)
class _Grouping:
    groups: list[list[ThreadInput]]
    counts: Counter[str]  # merge_skipped, untrusted_id (zero counts left out)
    contested: frozenset[str]  # source uids holding a contested Message-ID


def _components(items: Sequence[ThreadInput], own: Container[str], excluded: Collection[str]) -> _Grouping:
    """Group messages (strong forest, tier 1, tier 2) as the module docstring says."""
    batch = _batch(items, own, excluded)
    forest = _forest(batch)
    one = _tier_one(forest)
    final = one.groups
    for left, right in _tier_two(forest, one):  # every decision is taken before any is applied
        final.union(left, right)
    found: dict[str, list[ThreadInput]] = {}
    for item in items:
        found.setdefault(final.find(item.key), []).append(item)
    holding = frozenset(key for keys in batch.contested.values() for key in keys)
    counts = Counter(merge_skipped=_skipped(batch, final), untrusted_id=len(holding))
    return _Grouping(list(found.values()), +counts, holding)


def _heuristic_groups(singles: list[ThreadInput]) -> list[list[ThreadInput]]:
    buckets: dict[tuple[str, frozenset[str]], list[ThreadInput]] = {}
    for item in sorted(singles, key=_sort_key):
        buckets.setdefault((item.subject_key, item.participants), []).append(item)
    groups: list[list[ThreadInput]] = []
    for (subject, participants), items in buckets.items():
        if not subject or not participants:
            groups.extend([item] for item in items)
            continue
        current: list[ThreadInput] = []
        for item in items:
            previous = current[-1] if current else None
            joinable = (
                previous is not None
                and previous.sent_at is not None
                and item.sent_at is not None
                and item.sent_at - previous.sent_at <= HEURISTIC_WINDOW_SECONDS
            )
            if current and not joinable:
                groups.append(current)
                current = []
            current.append(item)
        groups.append(current)
    return groups


def _is_bare_single(members: list[ThreadInput]) -> bool:
    only = members[0]
    return len(members) == 1 and not (only.gm_thread_id or only.in_reply_to or only.references)


def _thread_root(members: Sequence[ThreadInput]) -> str:
    """The thread's root id, independent of input order and stable as replies arrive."""
    firsts = Counter(item.references[0] for item in members if item.references)
    if firsts:
        return min(firsts, key=lambda ref: (-firsts[ref], ref))
    parentless = [item for item in members if not item.in_reply_to]
    if parentless:
        earliest = min(parentless, key=lambda item: (item.sent_at is None, item.sent_at or 0, _root(item)))
        return _root(earliest)
    return min(item.in_reply_to[0] for item in members)


def _thread(members: list[ThreadInput], method: str, known_ids: set[str], *, held_keys: bool = False) -> Thread:
    ordered = sorted(members, key=_sort_key)
    if method == "gmail_thrid":
        key = default_thread_key(next(item for item in ordered if item.gm_thread_id))
    elif method == "references":
        root = _thread_root(ordered)
        if held_keys and all(item.message_id != root for item in ordered):
            oldest = ordered[0]  # a referenced id never names the conversation
            root = oldest.message_id or oldest.key
        key = f"r.{_digest(root)}"
    else:
        key = default_thread_key(ordered[0])
    partial = any(ref not in known_ids for item in ordered for ref in _referenced(item))
    return Thread(key, method, tuple(item.key for item in ordered), partial)


def _holds_root(thread: Thread, inputs: Mapping[str, ThreadInput]) -> bool:
    """True when the thread's key is the hash of one of its own members' Message-ID (it holds the root)."""
    return any(
        (mid := inputs[uid].message_id) is not None and f"r.{_digest(mid)}" == thread.thread_key
        for uid in thread.members
    )


def _earliest(thread: Thread, inputs: Mapping[str, ThreadInput]) -> tuple[bool, int, str]:
    return min(_sort_key(inputs[uid]) for uid in thread.members)


def _fallback_keys(thread: Thread, inputs: Mapping[str, ThreadInput]) -> Iterator[str]:
    """Keys for a thread whose own is taken: its members' own roots, oldest first, then hashes of its members."""
    for uid in sorted(thread.members, key=lambda uid: _sort_key(inputs[uid])):
        yield f"r.{_digest(inputs[uid].message_id or uid)}"
    members = "\n".join(sorted(thread.members))
    attempt = 0
    while True:
        attempt += 1
        yield "r." + _digest(str(attempt) + "\n" + members)


def _distinct_keys(threads: Sequence[Thread], inputs: Mapping[str, ThreadInput]) -> list[Thread]:
    """Threads with distinct keys: a contested key stays with the thread holding its root, else the earliest."""
    taken: set[str] = set()
    result: list[Thread] = []
    for thread in sorted(threads, key=lambda t: (not _holds_root(t, inputs), _earliest(t, inputs))):
        key = thread.thread_key
        if key in taken:
            key = next(candidate for candidate in _fallback_keys(thread, inputs) if candidate not in taken)
        taken.add(key)
        result.append(thread if key == thread.thread_key else replace(thread, thread_key=key))
    return result


def build_threads(
    items: Sequence[ThreadInput],
    *,
    own: Container[str] = frozenset(),
    excluded: Collection[str] = frozenset(),
    stats: Counter[str] | None = None,
    held_keys: bool = False,
) -> list[Thread]:
    """Group messages into threads (see the module docstring).

    ``own`` holds the account owner's addresses (never a shared participant),
    ``excluded`` the keys of messages that take no part in reference grouping,
    ``stats["merge_skipped"]`` gains the messages a merge guard held back and
    ``stats["untrusted_id"]`` the copies of contested Message-IDs, and
    ``held_keys`` keys a thread only by ids its own messages hold.
    """
    known_ids = {item.message_id for item in items if item.message_id}
    grouping = _components(items, own, excluded)
    if stats is not None:
        stats.update(grouping.counts)
    threads: list[Thread] = []
    singles: list[ThreadInput] = []
    for members in grouping.groups:
        if any(item.gm_thread_id for item in members):
            threads.append(_thread(members, "gmail_thrid", known_ids))
        elif _is_bare_single(members):
            if members[0].key in excluded or members[0].key in grouping.contested:
                threads.append(_thread(members, "single", known_ids))  # never grouped by subject either
            else:
                singles.append(members[0])
        else:
            threads.append(_thread(members, "references", known_ids, held_keys=held_keys))
    for group in _heuristic_groups(singles):
        threads.append(_thread(group, "heuristic" if len(group) > 1 else "single", known_ids))
    inputs = {item.key: item for item in items}
    return sorted(_distinct_keys(threads, inputs), key=lambda thread: thread.thread_key)
