"""Mail reference reconciliation on a caller-owned import-store transaction.

The caller supplies participant decoding and conversation merging. This module
never opens connections, decides copy acceptance, persists references, or commits.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Callable, Mapping, Sequence
from typing import TYPE_CHECKING, Final

from .records import ImportMessage, OwnerClass, Participant

if TYPE_CHECKING:
    from .mail.merge_guard import GroupFacts

ParticipantDecoder = Callable[[str], tuple[Participant, ...]]
ConversationMerge = Callable[[sqlite3.Connection, str, str, Sequence[str]], int]

#: A mail conversation keyed by a Gmail thread id (``mail.threading.default_thread_key``) is never folded away.
_GMAIL_THREAD_PREFIX: Final = "g."
#: Joins of message ``m`` onto its run ``r`` and conversation ``c``, and the scopes a reconciliation looks in:
#: parents among rows of committed runs or of the run being written, replies among committed rows (a reply
#: of the batch itself is weighed from its own side), of one source and account.
_RUN_AND_CONV: Final = (
    "JOIN import_runs r ON r.run_id = m.run_id JOIN import_conversations c ON c.conv_uid = m.conv_uid"
)
_IN_SCOPE: Final = "(r.state = 'committed' OR m.run_id = ?) AND c.source = ? AND c.source_account = ?"
_COMMITTED_SCOPE: Final = "r.state = 'committed' AND c.source = ? AND c.source_account = ?"


def reconcile(
    conn: sqlite3.Connection,
    run_id: str,
    messages: Sequence[ImportMessage],
    links: Mapping[str, Sequence[str]],
    *,
    decode_participants: ParticipantDecoder,
    merge_into: ConversationMerge,
) -> tuple[set[str], set[str], int]:
    """Merge the conversations the batch's reference edges connect; (survivors, dropped conv uids, skipped)."""
    from .mail.merge_guard import fold_plan

    survivors: set[str] = set()
    dropped: set[str] = set()
    skipped = 0
    facts: dict[str, GroupFacts] = {}  # per batch: a conversation changes here only by a merge
    owners: dict[tuple[str, str], frozenset[str]] = {}
    for msg in messages:
        linked = _linked_conversations(conn, run_id, msg.source_uid, links.get(msg.source_uid, ()))
        if linked is None or len(linked[1]) < 2:
            continue
        home, involved, scope = linked
        if scope not in owners:
            owners[scope] = _own_addresses(conn, *scope)
        for conv_uid in involved - facts.keys():
            facts[conv_uid] = _conv_facts(conn, run_id, conv_uid, owners[scope], decode_participants)
        survivor, others, guarded = fold_plan(home, {uid: facts[uid] for uid in involved})
        skipped += guarded
        if others:
            merge_into(conn, run_id, survivor, others)
            facts[survivor] = facts[survivor].joined([facts.pop(uid) for uid in others])
            dropped.update(others)
            survivors.difference_update(others)
            survivors.add(survivor)
    return survivors, dropped, skipped


def _own_addresses(conn: sqlite3.Connection, source: str, account: str) -> frozenset[str]:
    """The account's recorded own addresses (``import_accounts``), case-folded; empty when unreadable."""
    row = conn.execute(
        "SELECT own_addresses_json FROM import_accounts WHERE source = ? AND account = ?", (source, account)
    ).fetchone()
    try:
        value = json.loads(str(row[0])) if row is not None else []
    except ValueError:
        return frozenset()
    if not isinstance(value, list):
        return frozenset()
    return frozenset(item.casefold() for item in value if isinstance(item, str))


def _conv_facts(
    conn: sqlite3.Connection, run_id: str, conv_uid: str, own: frozenset[str], decode_participants: ParticipantDecoder
) -> GroupFacts:
    """Age, Gmail key, message count and non-owner participants of ``conv_uid`` (committed rows and the run's)."""
    from .mail.merge_guard import GroupFacts

    key = conn.execute("SELECT conversation_id FROM import_conversations WHERE conv_uid = ?", (conv_uid,))
    gmail = str(key.fetchone()[0]).startswith(_GMAIL_THREAD_PREFIX)
    rows = conn.execute(
        "SELECT m.sent_at, m.sender_id, m.owner_class, m.recipients_json FROM import_messages m "
        "JOIN import_runs r ON r.run_id = m.run_id "
        "WHERE m.conv_uid = ? AND (r.state = 'committed' OR m.run_id = ?)",
        (conv_uid, run_id),
    ).fetchall()
    dates = [int(row[0]) for row in rows if row[0] is not None]
    people: set[str] = set()
    owner = OwnerClass.ACCOUNT_OWNER.value
    for _sent_at, sender_id, owner_class, recipients in rows:
        if sender_id and owner_class != owner:
            people.add(str(sender_id).casefold())
        people.update(
            item.stable_id.casefold()
            for item in decode_participants(str(recipients))
            if item.stable_id and item.owner_class is not OwnerClass.ACCOUNT_OWNER
        )
    return GroupFacts(
        age=(not dates, min(dates) if dates else 0, conv_uid),
        gmail=gmail,
        messages=len(rows),
        people=frozenset(people - own),
    )


def _linked_conversations(
    conn: sqlite3.Connection, run_id: str, source_uid: str, parents: Sequence[str]
) -> tuple[str, set[str], tuple[str, str]] | None:
    """(``source_uid``'s conversation, it with its parents' and the committed replies', (source, account))."""
    row = conn.execute(
        "SELECT m.conv_uid, m.message_id, c.source, c.source_account FROM import_messages m "
        "JOIN import_conversations c ON c.conv_uid = m.conv_uid WHERE m.source_uid = ?",
        (source_uid,),
    ).fetchone()
    if row is None:
        return None
    conv_uid, message_id, source, account = (str(value) for value in row)
    scope = (run_id, source, account)
    involved = {conv_uid}
    if parents:
        involved.update(
            str(found[0])
            for found in conn.execute(
                f"SELECT DISTINCT m.conv_uid FROM import_messages m {_RUN_AND_CONV} "
                f"WHERE {_IN_SCOPE} AND m.message_id IN ({', '.join('?' for _ in parents)})",
                (*scope, *parents),
            )
        )
    involved.update(
        str(found[0])
        for found in conn.execute(
            f"SELECT DISTINCT m.conv_uid FROM import_mail_refs f "
            f"JOIN import_messages m ON m.source_uid = f.source_uid {_RUN_AND_CONV} "
            f"WHERE f.ref_message_id = ? AND {_COMMITTED_SCOPE}",
            (message_id, source, account),
        )
    )
    return conv_uid, involved, (source, account)
