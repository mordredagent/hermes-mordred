"""Merge guards: when sender-typed reference headers may join two mail threads.

``In-Reply-To`` and ``References`` are typed by whoever sent the message, so
following them blindly lets one crafted message pull unrelated threads into one
conversation. ONE module holds the rules for both places mail threads are joined:

- the grouping of one batch (:func:`.threading.build_threads`), a pure function of
  the batch's SET of messages (never their order or the dates senders typed):
  a strong forest first, where each message takes AT MOST ONE strong attachment
  (its Gmail thread; else its present direct parent when the two share a
  participant; else, its direct parent absent, the siblings of that absent parent
  with an equal participant set), so no message bridges two strong components;
  then tier 1, the messages with exactly one weak reference: clusters of messages
  alone in their strong components, and each message left alone joins the one
  :func:`established` group its edges touch (:func:`attach_target`); then tier 2,
  the messages with several weak references, each weighed against the tier-1
  result only: it joins the one established group it reaches (its own counts),
  none when they are several, and clusters with the untouched single messages
  it names when it reaches none;
- the store's reconciliation across batches (``ImportStore.write_batch(..., refs=...)``,
  one message at a time, by :func:`fold_plan`).

The rules:

1. Only the last :data:`MAX_MERGE_REFS` referenced ids of a message are followed
   (:func:`followed_refs`): ``References`` in header order, then ``In-Reply-To`` (so
   the parent is always kept). In a batch, an id no message of the batch holds is
   never followed by a weak edge.
2. Two messages (or groups) are joined by a reference edge only when they share a
   participant (:func:`share_participant`; sender and recipient addresses, the
   account owner's never count: :func:`counted_people`). In the store, a group that
   holds no message joins freely: it brings nobody in.
3. At most one *established* group takes part in a merge (:func:`established`): in
   the store, a conversation holding several messages (:func:`holds_thread`) or
   keyed by a Gmail thread id, otherwise nothing is merged for that message; in a
   batch, a strong component of several messages or keyed by a Gmail thread id, or
   a tier-1 cluster of several messages, and weak edges never join two of them (a
   group whose edges reach several joins none: :func:`attach_target`).
4. A group keyed by a Gmail thread id is authoritative: it is never folded into
   another. In the store it is the survivor when one is involved (else the
   earliest-dated group).
5. Copies holding one Message-ID are one message only when their content digests
   are known and identical (:func:`same_message`). An id held by differing copies
   names no message in a batch: references to it are not followed, the copies
   count as ``untrusted_id``, and a message holding or following such an id is
   untrusted: alone in its strong component it is *pinned*, established for every
   guard but never joined (:func:`attach_target`).

A message whose followed ids name a present message that ends in another
conversation (a guard held the edge back) counts once as ``merge_skipped``.
Pure functions: no store, no I/O, nothing logged.
"""

from __future__ import annotations

from collections.abc import Collection, Container, Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Final

__all__ = [
    "MAX_MERGE_REFS",
    "GroupFacts",
    "attach_target",
    "counted_people",
    "established",
    "fold_plan",
    "followed_refs",
    "holds_thread",
    "nearest_refs",
    "same_message",
    "share_participant",
]

#: Referenced ids kept and followed per message: the nearest ancestors (``In-Reply-To`` last).
MAX_MERGE_REFS: Final = 10


def nearest_refs(ids: Sequence[str]) -> tuple[str, ...]:
    """The last :data:`MAX_MERGE_REFS` of ``ids`` (ordered nearest last)."""
    return tuple(ids)[-MAX_MERGE_REFS:]


def followed_refs(in_reply_to: Sequence[str], references: Sequence[str]) -> tuple[str, ...]:
    """The ids a message's edges follow, nearest last: ``References`` (its parents left out), then ``In-Reply-To``."""
    parents = set(in_reply_to)
    ordered = dict.fromkeys((*(ref for ref in references if ref not in parents), *in_reply_to))
    return nearest_refs(tuple(ordered))


def counted_people(addresses: Iterable[str], own: Container[str]) -> frozenset[str]:
    """The addresses that can be a shared participant (rule 2): the account owner's ``own`` never count."""
    return frozenset(address for address in addresses if address not in own)


def share_participant(left: frozenset[str], right: frozenset[str]) -> bool:
    """Rule 2: the two participant sets (owner already left out) have an address in common."""
    return not left.isdisjoint(right)


def holds_thread(messages: int) -> bool:
    """Rule 3: a group of ``messages`` messages already holds a thread."""
    return messages > 1


def established(messages: int, *, gmail: bool) -> bool:
    """Rule 3: a group no weak edge folds into another: it holds a thread or a Gmail thread id (rule 4)."""
    return holds_thread(messages) or gmail


def same_message(digests: Collection[str | None]) -> bool:
    """Rule 5: copies sharing one Message-ID are one message only when their content digests are known and equal."""
    return None not in digests and len(set(digests)) == 1


def attach_target(reached: Collection[str], *, pinned: Container[str] = frozenset()) -> tuple[str | None, bool]:
    """Rule 3 in a batch: (the established group a message or cluster joins, or None; whether a guard held it back).

    ``reached`` holds the established (or pinned, rule 5) groups its weak edges
    reach: it joins the only one unless that one is pinned, none when they are
    several (held back), and none when there is none.
    """
    if len(reached) == 1:
        (only,) = reached
        return (None, True) if only in pinned else (only, False)
    return None, len(reached) > 1


@dataclass(frozen=True)
class GroupFacts:
    """What a merge decision needs to know about one group (a planned thread or a stored conversation)."""

    age: tuple[bool, int, str]  # unknown dates last, then the earliest date, then a stable id
    gmail: bool  # keyed by a Gmail thread id: never folded into another
    messages: int  # messages it already holds (0: a placeholder)
    people: frozenset[str]  # sender and recipient addresses, the account owner's excluded

    def joined(self, others: Sequence[GroupFacts]) -> GroupFacts:
        """The facts of this group after ``others`` were folded into it (it keeps its id)."""
        earliest = min((self.age[:2], *(other.age[:2] for other in others)))
        return GroupFacts(
            age=(*earliest, self.age[2]),
            gmail=self.gmail or any(other.gmail for other in others),
            messages=self.messages + sum(other.messages for other in others),
            people=self.people.union(*(other.people for other in others)),
        )


def fold_plan(home: str, involved: Mapping[str, GroupFacts]) -> tuple[str, list[str], bool]:
    """The store's rule for one message: (the survivor, the groups folded into it, whether a guard held a merge back).

    ``home`` is the group of the message whose edges connect ``involved`` (it is
    one of them). See the module docstring for the rules.
    """
    mine = involved[home].people
    joined = {
        key
        for key, facts in involved.items()
        if key == home or not facts.messages or share_participant(facts.people, mine)
    }
    gmail = {key for key in joined if involved[key].gmail}
    survivor = min(gmail or joined, key=lambda key: involved[key].age)
    others = sorted(key for key in joined if key != survivor and key not in gmail)
    guarded = len(joined) < len(involved)
    if sum(established(involved[key].messages, gmail=involved[key].gmail) for key in (survivor, *others)) > 1:
        return survivor, [], True  # a fold may take at most one established group (rule 3)
    return survivor, others, guarded
