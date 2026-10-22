"""Mail threading: Gmail thread ids, then set-based guarded reference grouping, then a subject heuristic.

- ``X-GM-THRID`` groups first (method ``gmail_thrid``); its references are not
  followed. A message without one joins the Gmail thread of a message it
  references.
- Otherwise messages are joined over ``Message-ID``, ``In-Reply-To`` and
  ``References`` (method ``references``, or ``single``). Those headers are typed
  by the sender, so the grouping is a pure function of the SET of messages, never
  of their order or the dates senders typed, under the rules of
  :mod:`.merge_guard` (``own`` holds the account owner's addresses, which never
  count as a shared participant):

  1. Strong components, by union-find over strong edges only: one Gmail thread
     id; one Message-ID; a message and its direct parent (its last
     ``In-Reply-To`` id, else, as RFC 5322 says, its last ``References`` id)
     when the parent is in the import and the two share a participant; and the
     children of one absent parent whose (non-empty) participant sets are equal.
     A strong edge attaches a message to its one parent, so no message bridges
     two components through strong edges. A component of several messages, or
     keyed by a Gmail thread id, is *established*.
  2. Weak clusters: the messages left alone in their component join by
     union-find over their weak edges with each other. A weak edge is a
     followed id (the last ``MAX_MERGE_REFS``) naming a message of the import,
     the two messages sharing a participant; ids no message of the import holds
     are ignored.
  3. Attachment: each cluster (a lone message too) joins the established
     component that its members' weak edges reach, or whose members' weak edges
     reach it, when there is exactly one; when there are several it joins none
     and counts once as ``merge_skipped``; when there is none it stays a
     conversation of its own. Established components are never joined with
     each other by weak edges, whatever the references say.

  A message also counts once as ``merge_skipped`` when one of its followed ids
  names a message that ends in another conversation because the two share no
  participant, or because both are in established components.
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

from .merge_guard import attach_target, counted_people, established, followed_refs, share_participant

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
    """Union-find over message keys: the partition it ends with never depends on the order of the unions."""

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


def _referenced(item: ThreadInput) -> tuple[str, ...]:
    return (*item.in_reply_to, *reversed(item.references))


def _dated_order(item: ThreadInput) -> tuple[bool, int, str]:
    """Oldest first, unknown dates last, then the source uid: independent of the input order."""
    return (item.sent_at is None, item.sent_at or 0, item.key)


@dataclass(frozen=True)
class _Edge:
    """A weak edge: ``source`` follows an id that ``target`` (in another strong component) holds."""

    source: str
    target: str
    shared: bool  # the two messages share a participant (rule 2 of :mod:`.merge_guard`)


@dataclass(frozen=True)
class _Batch:
    """The facts the grouping reads: the messages, their counted participants and the ids' holders."""

    items: Sequence[ThreadInput]
    followers: Sequence[ThreadInput]  # the messages whose references are followed (not excluded, no Gmail id)
    people: Mapping[str, frozenset[str]]  # source uid → participants, the owner's addresses left out
    holders: Mapping[str, Sequence[str]]  # Message-ID → the source uids of the linked messages holding it


def _batch(items: Sequence[ThreadInput], own: Container[str], excluded: Collection[str]) -> _Batch:
    holders: dict[str, list[str]] = {}
    for item in items:
        if item.message_id and item.key not in excluded:  # an excluded copy's id is no join point
            holders.setdefault(item.message_id, []).append(item.key)
    return _Batch(
        items=items,
        followers=[item for item in items if item.key not in excluded and not item.gm_thread_id],
        people={item.key: counted_people(item.participants, own) for item in items},
        holders=holders,
    )


def _strong_components(batch: _Batch) -> _UnionFind:
    """Step 1 (module docstring): Gmail ids, Message-IDs, direct parents in the import, equal siblings."""
    strong = _UnionFind()
    gmail: dict[str, str] = {}
    for item in batch.items:
        strong.find(item.key)
        if item.gm_thread_id:
            strong.union(item.key, gmail.setdefault(item.gm_thread_id, item.key))
    for keys in batch.holders.values():
        for key in keys[1:]:
            strong.union(keys[0], key)
    _parent_edges(batch, strong)
    return strong


def _parent_edges(batch: _Batch, strong: _UnionFind) -> None:
    """Each followed message with its direct parent (sharing a participant), or its equal siblings when it is absent."""
    siblings: dict[tuple[str, frozenset[str]], str] = {}
    for item in batch.followers:
        parent, mine = _direct_parent(item), batch.people[item.key]
        if parent is None:
            continue
        if parent in batch.holders:
            for holder in batch.holders[parent]:
                if share_participant(mine, batch.people[holder]):
                    strong.union(item.key, holder)
        elif mine:  # children of one absent parent with the same correspondents
            strong.union(item.key, siblings.setdefault((parent, mine), item.key))


def _established(batch: _Batch, strong: _UnionFind) -> set[str]:
    """The roots of the established strong components (several messages, or a Gmail thread id)."""
    sizes = Counter(strong.find(item.key) for item in batch.items)
    gmail = {strong.find(item.key) for item in batch.items if item.gm_thread_id}
    return {root for root, size in sizes.items() if established(size, gmail=root in gmail)}


def _weak_edges(batch: _Batch, strong: _UnionFind) -> list[_Edge]:
    """Each followed id held by a message of another strong component (absent ids are ignored)."""
    edges: list[_Edge] = []
    for item in batch.followers:
        for ref in followed_refs(item.in_reply_to, item.references):
            for holder in batch.holders.get(ref, ()):
                if strong.find(holder) != strong.find(item.key):
                    shared = share_participant(batch.people[item.key], batch.people[holder])
                    edges.append(_Edge(item.key, holder, shared))
    return edges


def _clusters(batch: _Batch, strong: _UnionFind, anchors: Container[str], edges: Sequence[_Edge]) -> _UnionFind:
    """Step 2: the messages alone in their strong component, joined by their weak edges with each other."""
    clusters = _UnionFind()
    for item in batch.items:
        if strong.find(item.key) not in anchors:
            clusters.find(item.key)
    for edge in edges:
        if edge.shared and strong.find(edge.source) not in anchors and strong.find(edge.target) not in anchors:
            clusters.union(edge.source, edge.target)
    return clusters


def _reached(
    strong: _UnionFind, anchors: Container[str], clusters: _UnionFind, edges: Sequence[_Edge]
) -> dict[str, set[str]]:
    """Cluster root → the established components its weak edges reach, in either direction."""
    reached: dict[str, set[str]] = {}
    for edge in edges:
        if not edge.shared:
            continue
        source, target = strong.find(edge.source), strong.find(edge.target)
        if source in anchors and target not in anchors:
            reached.setdefault(clusters.find(edge.target), set()).add(source)
        elif target in anchors and source not in anchors:
            reached.setdefault(clusters.find(edge.source), set()).add(target)
    return reached


def _components(
    items: Sequence[ThreadInput], own: Container[str], excluded: Collection[str]
) -> tuple[dict[str, list[ThreadInput]], int]:
    """Group messages (strong components, weak clusters, attachment); (groups, ``merge_skipped``)."""
    batch = _batch(items, own, excluded)
    strong = _strong_components(batch)
    anchors = _established(batch, strong)
    edges = _weak_edges(batch, strong)
    clusters = _clusters(batch, strong, anchors, edges)
    reached = _reached(strong, anchors, clusters, edges)
    final = _UnionFind()
    by_cluster: dict[str, set[str]] = {}  # cluster root → its messages (step 3 weighs each cluster once)
    for item in items:
        root = strong.find(item.key)
        final.union(item.key, root)
        if root not in anchors:
            by_cluster.setdefault(clusters.find(item.key), set()).add(item.key)
    held_clusters: list[set[str]] = []
    for root, cluster in by_cluster.items():
        for key in cluster:
            final.union(key, root)
        target, held = attach_target(reached.get(root, set()))
        if target is not None:
            final.union(root, target)
        elif held:
            held_clusters.append(cluster)
    return _final_groups(items, final), _skipped(edges, strong, anchors, final, held_clusters)


def _final_groups(items: Sequence[ThreadInput], final: _UnionFind) -> dict[str, list[ThreadInput]]:
    found: dict[str, list[ThreadInput]] = {}
    for item in items:
        found.setdefault(final.find(item.key), []).append(item)
    return found


def _skipped(
    edges: Sequence[_Edge],
    strong: _UnionFind,
    anchors: Container[str],
    final: _UnionFind,
    held_clusters: Sequence[set[str]],
) -> int:
    """``merge_skipped``: messages whose edge a guard refused, then held clusters none of whose members counted."""
    held: set[str] = set()
    for edge in edges:
        if final.find(edge.source) == final.find(edge.target):
            continue
        if not edge.shared or (strong.find(edge.source) in anchors and strong.find(edge.target) in anchors):
            held.add(edge.source)  # rule 2, or two established components (rule 3)
    return len(held) + sum(not cluster & held for cluster in held_clusters)


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
