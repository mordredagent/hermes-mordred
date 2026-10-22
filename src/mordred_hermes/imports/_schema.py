"""Schema v2 of the ``import_*`` tables in ``mordred.db`` (the activity store's encrypted file).

The import tables share the file with the activity tables but never their
metadata: :data:`STATEMENTS` create everything below, including the separate
``import_meta`` key/value table, and nothing here reads or writes
``activity_*``.

Two columns go beyond the record contract's field list, both storage-only:

- ``import_messages.run_id`` names the :class:`~.store.ImportStore` run that
  last wrote the row; readers expose a row only while that run is
  ``committed``.
- ``import_parts.id`` is an ``INTEGER PRIMARY KEY`` (a stable rowid alias) for
  the external-content FTS index; ``part_uid`` stays unique. An implicit rowid
  could be renumbered by ``VACUUM`` and silently desynchronise the index.

``import_parts_fts`` uses the ``trigram`` tokenizer: Japanese text has no
word separators, so the default ``unicode61`` tokenizer would index a whole
sentence as one token and a name inside it would never match. FTS5
``secure-delete`` is enabled so deleted parts leave no tokens behind in the
index. Both are available in the stdlib SQLite and in the bundled SQLCipher.

``import_mail_refs`` (v2) keeps, per stored mail message, the normalised
Message-IDs it references (``In-Reply-To`` and ``References``), indexed by the
referenced id, so a batch that brings in a missing parent finds the replies
fetched before it and merges their conversations (``ImportStore.write_batch``);
v2 also indexes ``import_messages.message_id`` for that lookup.

:data:`MIGRATIONS` has the shape of the activity schema's: ``MIGRATIONS[n]``
upgrades ``n`` to ``n + 1`` inside the transaction that opens the store.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Final

SCHEMA_VERSION: Final = 2

TABLES: Final = (
    "import_meta",
    "import_conversations",
    "import_messages",
    "import_parts",
    "import_runs",
    "import_accounts",
    "import_mail_refs",
)

#: Run states. ``open`` is a run in progress; ``dry_run`` rows never persist message data.
RUN_STATES: Final = ("open", "dry_run", "committed", "failed")

_V1_STATEMENTS: Final = (
    """
    CREATE TABLE import_meta (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE import_conversations (
        conv_uid TEXT PRIMARY KEY,
        source TEXT NOT NULL,
        source_account TEXT NOT NULL,
        conversation_id TEXT NOT NULL,
        kind TEXT NOT NULL,
        title TEXT NOT NULL,
        participants_json TEXT NOT NULL,
        last_message_at INTEGER,
        message_count INTEGER NOT NULL,
        archived INTEGER NOT NULL,
        sync_cursor TEXT,
        record_version INTEGER NOT NULL
    )
    """,
    "CREATE INDEX import_conversations_source ON import_conversations (source, source_account)",
    """
    CREATE TABLE import_messages (
        source_uid TEXT PRIMARY KEY,
        conv_uid TEXT NOT NULL,
        message_id TEXT NOT NULL,
        sent_at INTEGER,
        imported_at INTEGER NOT NULL,
        sender_kind TEXT NOT NULL,
        sender_id TEXT,
        sender_name TEXT NOT NULL,
        owner_class TEXT NOT NULL,
        owner_evidence TEXT NOT NULL,
        recipients_json TEXT NOT NULL,
        reply_to_uid TEXT,
        media TEXT,
        provenance_quality TEXT NOT NULL,
        source_revision TEXT,
        record_version INTEGER NOT NULL,
        content_digest TEXT NOT NULL,
        run_id TEXT NOT NULL
    )
    """,
    "CREATE INDEX import_messages_conv ON import_messages (conv_uid)",
    "CREATE INDEX import_messages_sent_at ON import_messages (sent_at)",
    """
    CREATE TABLE import_parts (
        id INTEGER PRIMARY KEY,
        part_uid TEXT NOT NULL UNIQUE,
        source_uid TEXT NOT NULL,
        ordinal INTEGER NOT NULL,
        part_kind TEXT NOT NULL,
        author_kind TEXT NOT NULL,
        author_id TEXT,
        author_name TEXT NOT NULL,
        author_owner_class TEXT NOT NULL,
        author_evidence TEXT NOT NULL,
        original_sent_at INTEGER,
        original_ref TEXT,
        text TEXT NOT NULL,
        provenance_quality TEXT NOT NULL
    )
    """,
    "CREATE UNIQUE INDEX import_parts_message ON import_parts (source_uid, ordinal)",
    """
    CREATE VIRTUAL TABLE import_parts_fts USING fts5(
        text, content = 'import_parts', content_rowid = 'id', tokenize = 'trigram'
    )
    """,
    "INSERT INTO import_parts_fts (import_parts_fts, rank) VALUES ('secure-delete', 1)",
    """
    CREATE TRIGGER import_parts_fts_insert AFTER INSERT ON import_parts BEGIN
        INSERT INTO import_parts_fts (rowid, text) VALUES (new.id, new.text);
    END
    """,
    """
    CREATE TRIGGER import_parts_fts_delete AFTER DELETE ON import_parts BEGIN
        INSERT INTO import_parts_fts (import_parts_fts, rowid, text) VALUES ('delete', old.id, old.text);
    END
    """,
    """
    CREATE TRIGGER import_parts_fts_update AFTER UPDATE ON import_parts BEGIN
        INSERT INTO import_parts_fts (import_parts_fts, rowid, text) VALUES ('delete', old.id, old.text);
        INSERT INTO import_parts_fts (rowid, text) VALUES (new.id, new.text);
    END
    """,
    """
    CREATE TABLE import_runs (
        run_id TEXT PRIMARY KEY,
        source TEXT NOT NULL,
        started_at REAL NOT NULL,
        finished_at REAL,
        state TEXT NOT NULL CHECK (state IN ('open', 'dry_run', 'committed', 'failed')),
        counts_json TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE import_accounts (
        source TEXT NOT NULL,
        account TEXT NOT NULL,
        own_addresses_json TEXT NOT NULL,
        PRIMARY KEY (source, account)
    )
    """,
)

#: v2: the referenced ids of mail messages (cross-batch thread reconciliation).
_MAIL_REFS: Final = (
    """
    CREATE TABLE import_mail_refs (
        source_uid TEXT NOT NULL,
        ref_message_id TEXT NOT NULL,
        PRIMARY KEY (source_uid, ref_message_id)
    )
    """,
    "CREATE INDEX import_mail_refs_ref ON import_mail_refs (ref_message_id)",
    # The reconciliation looks referenced ids up among stored messages.
    "CREATE INDEX import_messages_message_id ON import_messages (message_id)",
)

STATEMENTS: Final = (*_V1_STATEMENTS, *_MAIL_REFS)

#: ``MIGRATIONS[n]`` upgrades a store from schema ``n`` to ``n + 1``.
MIGRATIONS: Final[Mapping[int, tuple[str, ...]]] = {1: _MAIL_REFS}
