"""Merge guards: when sender-typed reference headers may join two mail threads.

``In-Reply-To`` and ``References`` are typed by whoever sent the message, so
following them blindly lets one crafted message pull unrelated threads into one
conversation. ONE implementation decides it for both places mail threads are
joined:

- the grouping of one batch (:func:`.threading.build_threads`: a message and its direct
  parent, or its siblings with the same participants under an absent parent, by rules 2
  and 3 between the two, ancestors first; every other reference edge by :func:`fold_plan`,
  fewest followed ids first, after those reply chains formed);
- the store's reconciliation across batches (``ImportStore.write_batch(..., refs=...)``).

The rules (:func:`followed_refs`, :func:`fold_plan`):

1. Only the last :data:`MAX_MERGE_REFS` referenced ids of a message are followed:
   ``References`` in header order, then ``In-Reply-To`` (so the parent is always kept).
2. A group joins the group of the message whose edges connect them only when the two
   share a participant (sender and recipient addresses; the account owner's never
   count). A group that holds no message joins freely: it brings nobody in.
3. At most one of the groups merged may already hold several messages; otherwise
   nothing is merged for that message.
4. A group keyed by a Gmail thread id is authoritative: it is never folded into
   another, and when one is involved it is the survivor (else the earliest-dated
   group).

A message whose edges a guard held back (rule 2 or 3) counts once as ``merge_skipped``.
Pure functions: no store, no I/O, nothing logged.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Final

__all__ = ["MAX_MERGE_REFS", "GroupFacts", "fold_plan", "followed_refs", "nearest_refs"]

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
    """(the survivor, the groups folded into it, whether a guard held a merge back).

    ``home`` is the group of the message whose edges connect ``involved`` (it is
    one of them). See the module docstring for the rules.
    """
    mine = involved[home].people
    joined = {key for key, facts in involved.items() if key == home or not facts.messages or facts.people & mine}
    gmail = {key for key in joined if involved[key].gmail}
    survivor = min(gmail or joined, key=lambda key: involved[key].age)
    others = sorted(key for key in joined if key != survivor and key not in gmail)
    guarded = len(joined) < len(involved)
    if sum(involved[key].messages > 1 for key in (survivor, *others)) > 1:
        return survivor, [], True  # a fold may take at most one group that already holds a thread
    return survivor, others, guarded
