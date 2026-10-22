"""Mail threading: Gmail thread ids, then reference union-find, then a guarded subject heuristic.

- ``X-GM-THRID`` groups first (method ``gmail_thrid``). A message without one
  joins the Gmail thread of a message it references.
- Otherwise messages are joined by union-find over ``Message-ID``,
  ``In-Reply-To`` and ``References`` (method ``references``, or ``single``).
- Subject-only grouping joins single messages without any reference header
  only when the normalised subject AND the participant address set match and
  each message is within 30 days of the previous one (method ``heuristic``).
- A thread whose messages reference an id that is not in the import is
  *partial*.

Thread keys are content-free (Gmail ids are digits; everything else is a hash)
and stable when later imports add replies.
"""

from __future__ import annotations

import hashlib
import re
import unicodedata
from collections import Counter
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from typing import Final

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


def _referenced(item: ThreadInput) -> tuple[str, ...]:
    return (*item.in_reply_to, *reversed(item.references))


def _components(items: Sequence[ThreadInput]) -> dict[str, list[ThreadInput]]:
    """Group messages: Gmail thread ids first, reference union-find for the rest."""
    by_id = {item.message_id: item for item in items if item.message_id}
    uf = _UnionFind()
    for item in items:
        uf.find(f"k:{item.key}")
        if item.gm_thread_id:
            uf.union(f"k:{item.key}", f"g:{item.gm_thread_id}")
            continue
        if item.message_id:
            uf.union(f"k:{item.key}", f"m:{item.message_id}")
        for ref in _referenced(item):
            target = by_id.get(ref)
            if target is not None and target.gm_thread_id:
                continue  # attached to that Gmail thread below
            uf.union(f"k:{item.key}", f"m:{ref}")
    groups: dict[str, list[ThreadInput]] = {}
    for item in items:
        groups.setdefault(uf.find(f"k:{item.key}"), []).append(item)
    return _attach_to_gmail(groups, by_id)


def _attach_to_gmail(
    groups: dict[str, list[ThreadInput]], by_id: dict[str, ThreadInput]
) -> dict[str, list[ThreadInput]]:
    gmail_root = {item.gm_thread_id: root for root, members in groups.items() for item in members if item.gm_thread_id}
    for root in sorted(groups):
        members = groups[root]
        if any(item.gm_thread_id for item in members):
            continue
        target = _gmail_target(members, by_id)
        if target is not None and gmail_root.get(target) in groups:
            groups[gmail_root[target]].extend(groups.pop(root))
    return groups


def _gmail_target(members: Iterable[ThreadInput], by_id: dict[str, ThreadInput]) -> str | None:
    for item in sorted(members, key=_sort_key):
        for ref in _referenced(item):
            target = by_id.get(ref)
            if target is not None and target.gm_thread_id:
                return target.gm_thread_id
    return None


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


def _thread(members: list[ThreadInput], method: str, known_ids: set[str]) -> Thread:
    ordered = sorted(members, key=_sort_key)
    if method == "gmail_thrid":
        key = default_thread_key(next(item for item in ordered if item.gm_thread_id))
    elif method == "references":
        key = f"r.{_digest(_thread_root(ordered))}"
    else:
        key = default_thread_key(ordered[0])
    partial = any(ref not in known_ids for item in ordered for ref in _referenced(item))
    return Thread(key, method, tuple(item.key for item in ordered), partial)


def build_threads(items: Sequence[ThreadInput]) -> list[Thread]:
    """Group messages into threads (see the module docstring)."""
    known_ids = {item.message_id for item in items if item.message_id}
    threads: list[Thread] = []
    singles: list[ThreadInput] = []
    for members in _components(items).values():
        if any(item.gm_thread_id for item in members):
            threads.append(_thread(members, "gmail_thrid", known_ids))
        elif _is_bare_single(members):
            singles.append(members[0])
        else:
            threads.append(_thread(members, "references", known_ids))
    for group in _heuristic_groups(singles):
        threads.append(_thread(group, "heuristic" if len(group) > 1 else "single", known_ids))
    threads.sort(key=lambda thread: thread.thread_key)
    return threads
