"""Mail threading: Gmail thread ids, then a two-phase guarded reference union-find, then a subject heuristic.

- ``X-GM-THRID`` groups first (method ``gmail_thrid``); its references are not
  followed. A message without one joins the Gmail thread of a message it
  references.
- Otherwise messages are joined by union-find over ``Message-ID``,
  ``In-Reply-To`` and ``References`` (method ``references``, or ``single``).
  Those headers are typed by the sender, so the grouping runs in two phases
  whose result does not depend on the order of the input:

  A message's direct parent is its last ``In-Reply-To`` id, else (RFC 5322)
  its last ``References`` id. No union, in either phase, joins two groups that
  both already hold several messages (rule 3 of :mod:`.merge_guard`).

  1. Strong edges, decided by the structure of the batch alone (never its
     order or the dates senders typed). Children of the same absent parent
     whose non-owner participant sets are equal join first (``own`` holds the
     account owner's addresses, which never count). Then, top-down along the
     parents that are in the import (ancestors first, then source uid), a
     message joins its direct parent when the two messages share a
     participant and every other followed id it names that is in the import
     is already in its parent's group; a message naming other groups is left
     to phase 2. Each message so joins its parent's group while it is still on
     its own, so reply chains form whatever their order, and the direct
     parents form a forest, so no message joins two groups here. An absent
     parent then belongs to the largest group of its children.
  2. Weak edges, fewest followed ids first (then date, then source uid), so
     single-reference replies settle before any message naming several groups
     is weighed: the groups of a message's followed ids (the last
     ``MAX_MERGE_REFS``, parent kept) that name a message of the import, and
     the group holding its absent parent, are decided together by
     :func:`.merge_guard.fold_plan`, the guard the store applies across
     batches, against the groups as they stand: a group joins only when it
     shares a participant other than the owner, at most one group that
     already holds several messages takes part in a merge, and a Gmail thread
     is never folded into another. A message following more than
     ``_MANY_REFS`` ids that names more than one group already holding several
     messages merges nothing. Older absent ancestors are not followed.

  A message a guard held back counts once as ``merge_skipped`` in ``stats``.
- ``excluded`` messages (copies the store will not write: duplicates and
  rejected copies of stored rows) take no part: their references are not
  followed and an id they carry is not a join point (another message naming it
  joins the stored conversation through the importer's resolver instead).
- Subject-only grouping joins single messages without any reference header
  only when the normalised subject AND the participant address set match and
  each message is within 30 days of the previous one (method ``heuristic``).
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

from .merge_guard import GroupFacts, fold_plan, followed_refs

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
#: Phase 2: a message following more ids than this merges nothing when it names several multi-message groups.
_MANY_REFS: Final = 3
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


@dataclass(frozen=True)
class Thread:
    thread_key: str
    method: str  # gmail_thrid | references | single | heuristic
    members: tuple[str, ...]  # source uids, oldest first (unknown dates last)
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
    def __init__(self) -> None:
        self.parent: dict[str, str] = {}

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


def _sort_key(item: ThreadInput) -> tuple[int, int, int]:
    return (item.sent_at is None, item.sent_at or 0, item.order)


def _direct_parent(item: ThreadInput) -> str | None:
    """The id ``item`` replies to: its last ``In-Reply-To`` id, else its last ``References`` id (RFC 5322)."""
    if item.in_reply_to:
        return item.in_reply_to[-1]
    return item.references[-1] if item.references else None


def _targets(item: ThreadInput, present: Container[str]) -> list[str]:
    """The ids phase 2 weighs for ``item``: its followed ids naming messages of the import, then its absent parent."""
    refs = [ref for ref in followed_refs(item.in_reply_to, item.references) if ref in present]
    parent = _direct_parent(item)
    if parent is not None and parent not in present:
        refs.append(parent)
    return refs


def _referenced(item: ThreadInput) -> tuple[str, ...]:
    return (*item.in_reply_to, *reversed(item.references))


def _dated_order(item: ThreadInput) -> tuple[bool, int, str]:
    """Oldest first, unknown dates last, then the source uid: independent of the input order."""
    return (item.sent_at is None, item.sent_at or 0, item.key)


#: The facts of a node no message has reached yet (the placeholder of an absent id).
_PLACEHOLDER: Final = GroupFacts(age=(True, 0, ""), gmail=False, messages=0, people=frozenset())


class _Groups:
    """Union-find over message keys, Message-ID and Gmail thread nodes, with each group's merge facts."""

    def __init__(self) -> None:
        self._uf = _UnionFind()
        self._facts: dict[str, GroupFacts] = {}
        self.held: set[str] = set()  # source uids of the messages a guard held back (each counts once)

    def root(self, node: str) -> str:
        return self._uf.find(node)

    def facts(self, root: str) -> GroupFacts:
        return self._facts.get(root, _PLACEHOLDER)

    def add(self, item: ThreadInput, people: frozenset[str], *, linked: bool) -> None:
        node = f"k:{item.key}"
        self._facts[self.root(node)] = GroupFacts(
            age=(item.sent_at is None, item.sent_at or 0, node),
            gmail=bool(item.gm_thread_id),
            messages=1,
            people=people,
        )
        if item.gm_thread_id:
            self.union(node, f"g:{item.gm_thread_id}")  # the server's thread id: authoritative, never guarded
        if linked and item.message_id:
            self.union(node, f"m:{item.message_id}")

    def join(self, item_key: str, node: str) -> bool:
        """Strong edge: join the message ``item_key`` with ``node``'s group unless both already hold several messages.

        A refused edge counts ``item_key`` as held back (rule 3 of :mod:`.merge_guard`).
        """
        a, b = self.root(f"k:{item_key}"), self.root(node)
        if a != b and self.facts(a).messages > 1 and self.facts(b).messages > 1:
            self.held.add(item_key)
            return False
        self.union(a, b)
        return True

    def follow(self, item: ThreadInput, targets: Sequence[str]) -> None:
        """Weak edges: join ``item``'s group with the groups of ``targets`` (:func:`_targets`) as the guard allows.

        The absent parent's group is the one phase 1 gave it (the largest group of
        that parent's children).
        """
        home = self.root(f"k:{item.key}")
        involved = {home, *(self.root(f"m:{ref}") for ref in targets)}
        if len(involved) < 2:
            return
        facts = {root: self.facts(root) for root in involved}
        if len(targets) > _MANY_REFS and sum(facts[root].messages > 1 for root in involved - {home}) > 1:
            self.held.add(item.key)  # it names several established threads: it joins none of them
            return
        survivor, others, guarded = fold_plan(home, facts)
        for other in others:
            self.union(survivor, other)
        if guarded:
            self.held.add(item.key)

    def union(self, left: str, right: str) -> None:
        """Join the groups of the nodes ``left`` and ``right`` (``k:`` source uid, ``m:`` Message-ID, ``g:`` Gmail)."""
        a, b = self.root(left), self.root(right)
        if a == b:
            return
        root, child = min(a, b), max(a, b)
        self._uf.parent[child] = root
        merged = self.facts(root).joined([self.facts(child)])
        self._facts[root] = replace(merged, age=(*merged.age[:2], root))
        self._facts.pop(child, None)


def _depths(parents: Mapping[str, str]) -> dict[str, int]:
    """Each key's depth along its parents in the import (a key absent from ``parents`` is a root, depth 0).

    Keys on, or leading into, a cycle of crafted ids get none (they have no strong edge).
    """
    depth: dict[str, int] = {}
    cyclic: set[str] = set()
    for start in parents:
        path: list[str] = []
        seen: set[str] = set()
        node = start
        while node in parents and node not in depth and node not in cyclic and node not in seen:
            path.append(node)
            seen.add(node)
            node = parents[node]
        if node in cyclic or node in seen:
            cyclic.update(path)
            continue
        base = depth.get(node, 0)
        for offset, key in enumerate(reversed(path), start=1):
            depth[key] = base + offset
    return depth


def _sibling_classes(
    groups: _Groups, children: Mapping[str, list[ThreadInput]], people: Mapping[str, frozenset[str]]
) -> None:
    """Children of the same absent parent with the same (non-empty) participant set join: equivalence classes."""
    for kids in children.values():
        first: dict[frozenset[str], str] = {}
        for kid in sorted(kids, key=lambda kid: kid.key):
            if people[kid.key]:
                groups.join(kid.key, f"k:{first.setdefault(people[kid.key], kid.key)}")


def _parent_edges(
    groups: _Groups,
    items: Sequence[ThreadInput],
    parents: Mapping[str, str],
    present: Container[str],
    people: Mapping[str, frozenset[str]],
) -> None:
    """Each message with its direct parent, ancestors first, so it joins while still on its own (module doc)."""
    depth = _depths(parents)
    for item in sorted((item for item in items if item.key in depth), key=lambda item: (depth[item.key], item.key)):
        parent = parents[item.key]
        if not people[item.key] & people[parent]:
            continue  # weighed (and counted) in phase 2
        home = groups.root(f"k:{parent}")
        named = (ref for ref in followed_refs(item.in_reply_to, item.references) if ref in present)
        if all(groups.root(f"m:{ref}") == home for ref in named):
            groups.join(item.key, f"k:{parent}")


def _strong_edges(
    groups: _Groups,
    items: Sequence[ThreadInput],
    present: Mapping[str, str],
    people: Mapping[str, frozenset[str]],
) -> None:
    """Phase 1: sibling classes under absent parents, then direct parents top-down (module docstring).

    Each absent parent's node then joins the largest group of its children (then
    the smallest root), so in phase 2 only the children outside that group are
    weighed against it.
    """
    children: dict[str, list[ThreadInput]] = {}
    parents: dict[str, str] = {}
    for item in items:
        parent = _direct_parent(item)
        if parent is None:
            continue
        found = present.get(parent)
        if found is None:
            children.setdefault(parent, []).append(item)
        else:
            parents[item.key] = found
    _sibling_classes(groups, children, people)
    _parent_edges(groups, items, parents, present, people)
    for parent, kids in children.items():
        sizes = Counter(groups.root(f"k:{kid.key}") for kid in kids)
        groups.union(f"m:{parent}", min(sizes, key=lambda root: (-sizes[root], root)))  # a placeholder: brings nobody


def _components(
    items: Sequence[ThreadInput], own: Container[str], excluded: Collection[str]
) -> tuple[dict[str, list[ThreadInput]], int]:
    """Group messages (Gmail thread ids, strong then weak reference edges); (groups, messages a guard held back)."""
    groups = _Groups()
    people = {item.key: frozenset(address for address in item.participants if address not in own) for item in items}
    for item in items:
        groups.add(item, people[item.key], linked=item.key not in excluded)
    present: dict[str, str] = {}  # Message-ID → its earliest-dated linked holder, whatever the input order
    for item in sorted(items, key=_dated_order):
        if item.message_id and item.key not in excluded:
            present.setdefault(item.message_id, item.key)
    followers = [item for item in items if item.key not in excluded and not item.gm_thread_id]
    _strong_edges(groups, followers, present, people)
    targets = {item.key: _targets(item, present) for item in followers}
    for item in sorted(followers, key=lambda item: (len(targets[item.key]), *_dated_order(item))):
        groups.follow(item, targets[item.key])
    found: dict[str, list[ThreadInput]] = {}
    for item in items:
        found.setdefault(groups.root(f"k:{item.key}"), []).append(item)
    return found, len(groups.held)


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
            oldest = min(ordered, key=_dated_order)  # a referenced id never names the conversation
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


def _dated(inputs: Mapping[str, ThreadInput], uid: str) -> tuple[bool, int, str]:
    """Oldest first, unknown dates last, then the source uid: independent of the input order."""
    return (inputs[uid].sent_at is None, inputs[uid].sent_at or 0, uid)


def _earliest(thread: Thread, inputs: Mapping[str, ThreadInput]) -> tuple[bool, int, str]:
    return min(_dated(inputs, uid) for uid in thread.members)


def _fallback_keys(thread: Thread, inputs: Mapping[str, ThreadInput]) -> Iterator[str]:
    """Keys for a thread whose own is taken: its members' own roots, oldest first, then hashes of its members."""
    for uid in sorted(thread.members, key=lambda uid: _dated(inputs, uid)):
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
    ``stats["merge_skipped"]`` gains the messages a merge guard held back, and
    ``held_keys`` keys a thread only by ids its own messages hold.
    """
    known_ids = {item.message_id for item in items if item.message_id}
    components, skipped = _components(items, own, excluded)
    if stats is not None and skipped:
        stats["merge_skipped"] += skipped
    threads: list[Thread] = []
    singles: list[ThreadInput] = []
    for members in components.values():
        if any(item.gm_thread_id for item in members):
            threads.append(_thread(members, "gmail_thrid", known_ids))
        elif _is_bare_single(members):
            if members[0].key in excluded:
                threads.append(_thread(members, "single", known_ids))  # never grouped by subject either
            else:
                singles.append(members[0])
        else:
            threads.append(_thread(members, "references", known_ids, held_keys=held_keys))
    for group in _heuristic_groups(singles):
        threads.append(_thread(group, "heuristic" if len(group) > 1 else "single", known_ids))
    inputs = {item.key: item for item in items}
    return sorted(_distinct_keys(threads, inputs), key=lambda thread: thread.thread_key)
