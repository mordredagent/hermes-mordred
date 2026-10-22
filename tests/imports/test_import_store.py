"""Behaviour contract of ``ImportStore`` (plain SQLite through the opener seam) and its protection gate."""

from __future__ import annotations

import dataclasses
import sqlite3
import sys
from pathlib import Path
from typing import Any

import pytest

from mordred_hermes import dbcrypt
from mordred_hermes.activity import _gate
from mordred_hermes.activity._gate import ActivityRefused, refusal
from mordred_hermes.activity._paths import store_path
from mordred_hermes.activity.store import ActivityStore
from mordred_hermes.dbcrypt import _monitor, _shim
from mordred_hermes.imports import _schema
from mordred_hermes.imports import store as store_module
from mordred_hermes.imports.records import (
    ImportConversation,
    ImportMessage,
    OwnerClass,
    PartKind,
    ProvenanceQuality,
    RecordError,
    content_digest,
)
from mordred_hermes.imports.store import ImportRefused, ImportStore, WriteResult, open_import_store

from ._factories import (
    MAIL_CONV_UID,
    OWNER,
    OWNER_ID,
    SUZUKI,
    TANAKA,
    TG_CONV_UID,
    authored,
    mail_conv,
    mail_uid,
    message,
    part,
    tg_conv,
    tg_uid,
    ts,
)

DAY1, DAY2, DAY3 = ts(2026, 10, 1, 12), ts(2026, 10, 2, 12), ts(2026, 10, 3, 12)


def plain_opener(path: Path) -> sqlite3.Connection:
    return sqlite3.connect(path)


def make_store(home: Path) -> ImportStore:
    store = ImportStore(home / "mordred.db", plain_opener)
    store.initialize(home)
    return store


def commit(store: ImportStore, conv: ImportConversation, messages: list[ImportMessage]) -> WriteResult:
    run = store.run_begin(conv.source)
    result = store.write_thread(run, messages, conversation=conv)
    store.run_commit(run, {"inserted": result.inserted})
    return result


def rows(store: ImportStore, sql: str, *params: Any) -> list[tuple[Any, ...]]:
    with store.connection() as conn:
        return [tuple(row) for row in conn.execute(sql, params)]


def edited(msg: ImportMessage, text: str, *, revision: str | None) -> ImportMessage:
    parts = tuple(dataclasses.replace(p, text=text) if p.part_kind is PartKind.AUTHORED else p for p in msg.parts)
    digest = content_digest("".join(p.text for p in parts))
    return dataclasses.replace(msg, parts=parts, source_revision=revision, content_digest=digest)


def mail_message(message_id: str, text: str, *, sent_at: int | None = DAY2) -> ImportMessage:
    uid = mail_uid(message_id)
    authored_part = part(uid, author=OWNER, text=text)
    quoted = part(
        uid, PartKind.QUOTED, 1, ordinal=1, author=TANAKA, text="earlier words", quality=ProvenanceQuality.HEURISTIC
    )
    return message(uid, (authored_part, quoted), conv_uid=MAIL_CONV_UID, sent_at=sent_at, recipients=(TANAKA, SUZUKI))


# --- schema and binding ----------------------------------------------------------------------------


def test_initialize_creates_only_import_tables_bound_to_the_profile(tmp_path: Path) -> None:
    store = ImportStore(tmp_path / "mordred.db", plain_opener)

    meta = store.initialize(tmp_path)

    assert (meta.schema_version, meta.profile_home) == (2, str(tmp_path.resolve()))
    names = {name for (name,) in rows(store, "SELECT name FROM sqlite_master WHERE type IN ('table', 'trigger')")}
    assert set(_schema.TABLES) | {"import_parts_fts"} <= names and "import_mail_refs" in names
    assert {"import_parts_fts_insert", "import_parts_fts_delete", "import_parts_fts_update"} <= names
    assert not any(name.startswith("activity_") for name in names)
    assert store.initialize(tmp_path) == meta == store.meta()


def test_import_and_activity_tables_coexist_in_one_file(tmp_path: Path) -> None:
    activity = ActivityStore(tmp_path / "mordred.db", plain_opener)
    activity.initialize(tmp_path)
    store = make_store(tmp_path)
    commit(store, tg_conv(), [authored(1)])

    assert activity.initialize(tmp_path).schema_version >= 2
    assert "import_messages" not in activity.status().counts
    assert rows(store, "SELECT key FROM activity_meta WHERE key = 'schema_version'") == [("schema_version",)]
    assert store.contains([tg_uid(1)]) == {tg_uid(1)}


def test_a_store_bound_to_another_home_is_refused(tmp_path: Path) -> None:
    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()
    ImportStore(tmp_path / "mordred.db", plain_opener).initialize(tmp_path / "a")

    with pytest.raises(ImportRefused) as caught:
        ImportStore(tmp_path / "mordred.db", plain_opener).initialize(tmp_path / "b")
    assert caught.value.code == "profile_mismatch"
    assert str(tmp_path) not in caught.value.refusal.detail


def test_a_newer_schema_is_refused_not_recreated(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    with store.connection() as conn:
        conn.execute("UPDATE import_meta SET value = '3' WHERE key = 'schema_version'")

    for call in (lambda: store.initialize(tmp_path), store.meta, store.status):
        with pytest.raises(ImportRefused) as caught:
            call()
        assert caught.value.code == "schema_newer"
    assert rows(store, "SELECT value FROM import_meta WHERE key = 'schema_version'") == [("3",)]


def test_a_store_without_a_schema_version_is_unavailable(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    with store.connection() as conn:
        conn.execute("DELETE FROM import_meta WHERE key = 'schema_version'")

    with pytest.raises(ImportRefused) as caught:
        store.initialize(tmp_path)
    assert caught.value.code == "store_unavailable"


def test_an_older_schema_is_upgraded_through_migrations(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = make_store(tmp_path)
    monkeypatch.setattr(store_module, "SUPPORTED_SCHEMA_VERSION", 3)
    monkeypatch.setattr(
        _schema, "MIGRATIONS", {**_schema.MIGRATIONS, 2: ("ALTER TABLE import_runs ADD COLUMN note TEXT",)}
    )

    assert store.initialize(tmp_path).schema_version == 3
    assert rows(store, "SELECT value FROM import_meta WHERE key = 'schema_version'") == [("3",)]
    assert "note" in {row[1] for row in rows(store, "PRAGMA table_info(import_runs)")}


def _as_v1(store: ImportStore) -> None:
    """Turn a fresh store back into a schema-v1 one (no ``import_mail_refs``, no message-id index)."""
    with store.connection() as conn:
        conn.execute("DROP TABLE import_mail_refs")
        conn.execute("DROP INDEX import_messages_message_id")
        conn.execute("UPDATE import_meta SET value = '1' WHERE key = 'schema_version'")


def test_a_v1_store_is_upgraded_in_place_to_v2(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    commit(store, mail_conv(), [mail_message("m1@example.com", "kept across the upgrade")])
    _as_v1(store)

    assert ImportStore(tmp_path / "mordred.db", plain_opener).initialize(tmp_path).schema_version == 2

    assert rows(store, "SELECT value FROM import_meta WHERE key = 'schema_version'") == [("2",)]
    names = {name for (name,) in rows(store, "SELECT name FROM sqlite_master WHERE type IN ('table', 'index')")}
    assert {"import_mail_refs", "import_mail_refs_ref", "import_messages_message_id"} <= names
    assert rows(store, "SELECT count(*) FROM import_mail_refs") == [(0,)]
    assert store.contains([mail_uid("m1@example.com")]) == {mail_uid("m1@example.com")}  # rows untouched


def test_a_missing_migration_step_is_refused(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = make_store(tmp_path)
    monkeypatch.setattr(store_module, "SUPPORTED_SCHEMA_VERSION", 3)

    with pytest.raises(ImportRefused) as caught:
        store.initialize(tmp_path)
    assert caught.value.code == "store_unavailable"
    assert rows(store, "SELECT value FROM import_meta WHERE key = 'schema_version'") == [("2",)]


# --- write_thread: idempotency and revisions --------------------------------------------------------


def test_write_thread_is_idempotent_on_source_uid(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    thread = [authored(1, text="first"), authored(2, text="second")]

    assert commit(store, tg_conv(), thread) == WriteResult(2, 0, 0, 0)
    assert commit(store, tg_conv(), thread) == WriteResult(0, 2, 0, 0)
    assert rows(store, "SELECT count(*) FROM import_messages") == [(2,)]
    assert rows(store, "SELECT count(*) FROM import_parts") == [(2,)]


@pytest.mark.parametrize(
    ("stored", "incoming", "outcome", "text_after"),
    [
        ((None, "v1"), (None, "v1"), "duplicates", "v1"),
        ((None, "v1"), (None, "v2"), "conflicts", "v1"),
        ((None, "v1"), ("edit-1", "v2"), "revised", "v2"),
        (("edit-1", "v1"), ("edit-2", "v1"), "revised", "v1"),
        (("edit-1", "v1"), ("edit-1", "v1"), "duplicates", "v1"),
        (("edit-1", "v1"), ("edit-1", "v2"), "conflicts", "v1"),
    ],
)
def test_revision_matrix(
    tmp_path: Path, stored: tuple[str | None, str], incoming: tuple[str | None, str], outcome: str, text_after: str
) -> None:
    store = make_store(tmp_path)
    base = authored(1)
    commit(store, tg_conv(), [edited(base, stored[1], revision=stored[0])])

    result = commit(store, tg_conv(), [edited(base, incoming[1], revision=incoming[0])])

    assert dataclasses.asdict(result) == {"inserted": 0, "duplicates": 0, "revised": 0, "conflicts": 0} | {outcome: 1}
    assert rows(store, "SELECT text FROM import_parts") == [(text_after,)]
    expected_revision = incoming[0] if outcome == "revised" else stored[0]
    assert rows(store, "SELECT source_revision FROM import_messages") == [(expected_revision,)]


def test_a_revision_replaces_every_part_and_the_index(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    uid = tg_uid(1)
    original = message(
        uid, (part(uid, text="original words"), part(uid, PartKind.QUOTED, 1, ordinal=1, text="quoted line"))
    )
    commit(store, tg_conv(), [original])

    revision = message(uid, (part(uid, text="replacement words"),))
    result = commit(store, tg_conv(), [dataclasses.replace(revision, source_revision="edit-1")])

    assert result.revised == 1
    assert rows(store, "SELECT part_uid, text FROM import_parts") == [(f"{uid}#a", "replacement words")]
    assert store.search("quoted") == store.search("original") == []
    assert [hit.part_uid for hit in store.search("replacement")] == [f"{uid}#a"]


def test_legacy_never_replaces_an_api_record_and_is_upgraded_by_one(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    api = authored(1, text="api text")
    legacy = edited(authored(1, quality=ProvenanceQuality.LEGACY), "legacy text", revision="whatever")
    commit(store, tg_conv(), [api])

    assert commit(store, tg_conv(), [legacy]) == WriteResult(0, 1, 0, 0)
    assert rows(store, "SELECT text, provenance_quality FROM import_parts") == [("api text", "api_identity")]

    other = tmp_path / "other"
    other.mkdir()
    fresh = make_store(other)
    commit(fresh, tg_conv(), [legacy])
    assert commit(fresh, tg_conv(), [api]) == WriteResult(0, 0, 1, 0)
    assert rows(fresh, "SELECT provenance_quality FROM import_messages") == [("api_identity",)]


def test_an_invalid_record_is_refused_before_anything_is_written(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    run = store.run_begin("telegram")
    broken = dataclasses.replace(authored(2), content_digest="not-a-digest")

    with pytest.raises(RecordError) as caught:
        store.write_thread(run, [authored(1), broken], conversation=tg_conv())
    assert caught.value.code == "bad_content_digest"
    assert rows(store, "SELECT count(*) FROM import_conversations") == [(0,)]
    assert rows(store, "SELECT count(*) FROM import_messages") == [(0,)]


def test_a_misfit_record_rolls_the_whole_thread_back(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    run = store.run_begin("telegram")
    elsewhere = dataclasses.replace(authored(2), conv_uid="tg:-100999", source_uid="tg:-100999:2")
    elsewhere = dataclasses.replace(elsewhere, parts=(part("tg:-100999:2"),))

    with pytest.raises(RecordError) as caught:
        store.write_thread(run, [authored(1), elsewhere], conversation=tg_conv())
    assert caught.value.code == "unknown_conversation"
    assert rows(store, "SELECT count(*) FROM import_messages") == [(0,)]
    assert rows(store, "SELECT count(*) FROM import_parts_fts") == [(0,)]
    assert rows(store, "SELECT count(*) FROM import_conversations") == [(0,)]


def test_records_of_another_source_are_refused_by_the_run(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    run = store.run_begin("telegram")
    store.upsert_conversation(mail_conv())

    with pytest.raises(RecordError) as caught:
        store.write_thread(run, [mail_message("m1@example.com", "hello")])
    assert caught.value.code == "source_mismatch"
    with pytest.raises(RecordError) as caught:
        store.write_thread(run, [], conversation=mail_conv())
    assert caught.value.code == "source_mismatch"


def test_a_conversation_of_another_account_is_a_conflict(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    store.upsert_conversation(tg_conv())
    store.upsert_conversation(dataclasses.replace(tg_conv(), title="Renamed"))

    with pytest.raises(ImportRefused) as caught:
        store.upsert_conversation(dataclasses.replace(tg_conv(), source_account="42"))
    assert caught.value.code == "conflict"
    assert rows(store, "SELECT title, source_account FROM import_conversations") == [("Renamed", OWNER_ID)]


# --- runs ---------------------------------------------------------------------------------------


def test_uncommitted_rows_are_invisible_then_reclaimed_by_the_next_run(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    run = store.run_begin("telegram")
    store.write_thread(run, [authored(1, text="pending words")], conversation=tg_conv())

    assert store.search("pending") == []
    assert store.search(None) == []
    assert store.contains([tg_uid(1)]) == set()
    assert store.parts_for([f"{tg_uid(1)}#a"]) == {}
    assert store.neighbors(f"{tg_uid(1)}#a", 3) == []

    store.run_fail(run, {"inserted": 1})
    assert commit(store, tg_conv(), [authored(1, text="pending words")]) == WriteResult(1, 0, 0, 0)
    assert [hit.source_uid for hit in store.search("pending")] == [tg_uid(1)]


def test_a_thread_written_twice_in_one_run_is_a_duplicate(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    run = store.run_begin("telegram")
    store.write_thread(run, [authored(1)], conversation=tg_conv())

    assert store.write_thread(run, [authored(1), authored(1)]) == WriteResult(0, 2, 0, 0)


def test_a_dry_run_reports_the_real_counts_and_keeps_nothing(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    commit(store, tg_conv(), [authored(1)])
    run = store.run_begin("telegram", dry_run=True)

    result = store.write_thread(
        run, [authored(1), authored(2), edited(authored(3), "x", revision=None)], conversation=tg_conv()
    )
    store.run_commit(run, {"inserted": result.inserted, "duplicates": result.duplicates})

    assert result == WriteResult(2, 1, 0, 0)
    assert rows(store, "SELECT count(*) FROM import_messages") == [(1,)]
    assert rows(store, "SELECT state, counts_json FROM import_runs WHERE run_id = ?", run) == [
        ("dry_run", '{"duplicates":1,"inserted":2}')
    ]


def test_closed_unknown_and_malformed_runs_are_refused(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    run = store.run_begin("telegram")
    store.run_commit(run, {})

    for call in (
        lambda: store.write_thread(run, [authored(1)], conversation=tg_conv()),
        lambda: store.run_commit(run, {}),
        lambda: store.run_fail("no-such-run", {}),
    ):
        with pytest.raises(ImportRefused) as caught:
            call()
        assert caught.value.code == "run_not_open"
    for counts in ({"Inserted": 1}, {"inserted": -1}, {"inserted": True}, {"text with spaces": 1}):
        with pytest.raises(RecordError, match="bad_counts"):
            store.run_fail(store.run_begin("mail"), counts)
    with pytest.raises(RecordError, match="unknown_enum"):
        store.run_begin("fax")


# --- reads ----------------------------------------------------------------------------------------


@pytest.fixture
def archive(tmp_path: Path) -> ImportStore:
    store = make_store(tmp_path)
    commit(
        store,
        tg_conv(),
        [
            authored(1, text="田中太郎の見積もりの件 please", sent_at=DAY1),
            authored(2, text="Lunch tomorrow?", sent_at=DAY2),
            authored(3, text="見積もり revised 50% off", sent_at=DAY3),
            authored(4, text="undated 見積もり note", sent_at=None),
        ],
    )
    commit(store, mail_conv(), [mail_message("m1@example.com", "見積もり from mail")])
    return store


def uids(hits: list[Any]) -> list[str]:
    return [hit.source_uid for hit in hits]


def test_search_matches_japanese_substrings_through_the_index(archive: ImportStore) -> None:
    hits = archive.search("見積もり")

    assert set(uids(hits)) == {tg_uid(1), tg_uid(3), tg_uid(4), mail_uid("m1@example.com")}
    assert all(hit.rank != 0.0 for hit in hits)
    assert uids(archive.search("見積もり revised")) == [tg_uid(3)]
    assert uids(archive.search("LUNCH")) == [tg_uid(2)]


def test_short_terms_match_by_like_and_wildcards_stay_literal(archive: ImportStore) -> None:
    assert [(hit.source_uid, hit.rank) for hit in archive.search("田中")] == [(tg_uid(1), 0.0)]
    assert uids(archive.search("見積もり 件")) == [tg_uid(1)]
    assert uids(archive.search("%")) == [tg_uid(3)]
    assert archive.search("_") == []


@pytest.mark.parametrize("query", ['"見積もり" OR lunch', "NEAR(lunch tomorrow)", "text:lunch", "lun*", '"', "a\x00b'"])
def test_query_syntax_is_never_interpreted(archive: ImportStore, query: str) -> None:
    assert archive.search(query) == []


def test_search_filters_apply_in_sql(archive: ImportStore) -> None:
    assert uids(archive.search("見積もり", source="mail")) == [mail_uid("m1@example.com")]
    assert set(uids(archive.search("見積もり", conv_uids=[TG_CONV_UID]))) == {tg_uid(1), tg_uid(3), tg_uid(4)}
    assert set(uids(archive.search("見積もり", since=DAY2, until=DAY3 + 1))) == {tg_uid(3), mail_uid("m1@example.com")}
    assert archive.search("見積もり", conv_uids=[]) == []
    assert archive.search("見積もり", limit=0) == []
    assert len(archive.search("見積もり", limit=1)) == 1


def test_search_without_text_lists_the_newest_parts_first(archive: ImportStore) -> None:
    hits = archive.search(None, conv_uids=[TG_CONV_UID])

    assert uids(hits) == [tg_uid(3), tg_uid(2), tg_uid(1), tg_uid(4)]
    assert archive.search("   ", conv_uids=[TG_CONV_UID]) == hits
    assert uids(archive.search(None, since=DAY3)) == [tg_uid(3)]


def test_parts_for_round_trips_the_stored_records(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    original = mail_message("m1@example.com", "見積もり from mail")
    commit(store, mail_conv(), [original])
    quoted, own = f"{original.source_uid}#q1", f"{original.source_uid}#a"

    found = store.parts_for([quoted, own, "tg:-1:1#a", quoted])

    assert list(found) == [quoted, own]
    assert found[quoted].conversation == mail_conv()
    assert found[quoted].message == original
    assert found[quoted].part.author_owner_class is OwnerClass.OTHER
    assert found[own].part == original.parts[0]


def test_neighbors_follow_reading_order(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    nine = message(
        tg_uid(9), (part(tg_uid(9), text="nine"), part(tg_uid(9), PartKind.QUOTED, 1, ordinal=1)), sent_at=200
    )
    commit(
        store,
        tg_conv(),
        [
            authored(11, sent_at=None),
            authored(10, sent_at=200),
            nine,
            authored(8, sent_at=100),
            authored(7, sent_at=50),
        ],
    )

    around_nine = [item.part.part_uid for item in store.neighbors(f"{tg_uid(9)}#a", 1)]
    around_ten = [item.message.message_id for item in store.neighbors(f"{tg_uid(10)}#a", 1)]

    assert around_nine == [f"{tg_uid(8)}#a", f"{tg_uid(9)}#a", f"{tg_uid(9)}#q1", f"{tg_uid(10)}#a"]
    assert around_ten == ["9", "9", "10", "11"]
    assert [item.message.message_id for item in store.neighbors(f"{tg_uid(9)}#q1", 0)] == ["9", "9"]
    assert store.neighbors(f"{tg_uid(9)}#a", -5) == store.neighbors(f"{tg_uid(9)}#a", 0)
    assert store.neighbors("tg:-100123:404#a", 2) == []


def test_delete_source_removes_one_account_and_its_text(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    commit(store, tg_conv(), [authored(1, text="zebrafinchmarker secret"), authored(2)])
    commit(store, mail_conv(), [mail_message("m1@example.com", "mail stays")])
    with store.connection() as conn:
        conn.execute("INSERT INTO import_accounts VALUES ('telegram', ?, '[]')", (OWNER_ID,))
    assert b"zebrafinchmarker" in (tmp_path / "mordred.db").read_bytes()

    assert store.delete_source("telegram", OWNER_ID) == 2

    assert store.search("zebrafinch") == []
    assert rows(store, "SELECT count(*) FROM import_conversations WHERE source = 'telegram'") == [(0,)]
    assert rows(store, "SELECT count(*) FROM import_accounts") == [(0,)]
    assert rows(store, "SELECT DISTINCT source_uid FROM import_parts") == [(mail_uid("m1@example.com"),)]
    assert b"zebrafinchmarker" not in (tmp_path / "mordred.db").read_bytes()
    assert store.delete_source("telegram", OWNER_ID) == 0


def test_status_reports_counts_and_the_latest_run_only(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    commit(store, tg_conv(), [authored(1, text="SECRET one"), authored(2, text="SECRET two")])
    run = store.run_begin("mail")
    store.write_thread(run, [mail_message("m1@example.com", "SECRET mail")], conversation=mail_conv())

    status = store.status()

    assert status["schema_version"] == 2
    assert status["sources"] == {
        "telegram": {"conversations": 1, "messages": 2, "parts": 2, "uncommitted_messages": 0},
        "mail": {"conversations": 1, "messages": 0, "parts": 0, "uncommitted_messages": 1},
    }
    assert status["runs"] == {"committed": 1, "open": 1}
    assert (status["last_run"]["run_id"], status["last_run"]["state"], status["last_run"]["counts"]) == (
        run,
        "open",
        {},
    )
    assert "SECRET" not in repr(status)


def test_an_empty_store_has_no_runs(tmp_path: Path) -> None:
    assert make_store(tmp_path).status() == {"schema_version": 2, "sources": {}, "runs": {}, "last_run": None}


def test_sources_count_committed_messages_only(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    assert store.sources() == {}
    commit(store, tg_conv(), [authored(1), authored(2)])
    run = store.run_begin("mail")
    store.write_thread(run, [mail_message("m1@example.com", "draft")], conversation=mail_conv())
    assert store.sources() == {"telegram": 2}  # the open mail run is invisible
    store.run_commit(run, {})
    assert store.sources() == {"mail": 1, "telegram": 2}


# --- import_meta markers --------------------------------------------------------------------------


def test_meta_markers_round_trip(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    key = store_module.TELEGRAM_RETIRED_ACCOUNT
    assert key == "telegram.retired_account" and store.get_meta(key) is None
    store.set_meta(key, OWNER_ID)
    assert store.get_meta(key) == OWNER_ID
    store.set_meta(key, "100")  # replaced, never duplicated
    assert store.get_meta(key) == "100"
    assert rows(store, "SELECT count(*) FROM import_meta WHERE key = ?", key) == [(1,)]
    store.delete_meta(key)
    store.delete_meta(key)  # absent is fine
    assert store.get_meta(key) is None
    assert store.get_meta("schema_version") == "2"  # reserved keys stay readable
    assert store.meta() == store_module.ImportMeta(2, str(tmp_path.resolve()))


@pytest.mark.parametrize("key", sorted(store_module.RESERVED_META_KEYS))
def test_reserved_meta_keys_are_never_settable(tmp_path: Path, key: str) -> None:
    store = make_store(tmp_path)
    before = rows(store, "SELECT key, value FROM import_meta ORDER BY key")
    for change in (lambda: store.set_meta(key, "x"), lambda: store.delete_meta(key)):
        with pytest.raises(RecordError) as raised:
            change()
        assert raised.value.code == "reserved_meta_key"
    assert rows(store, "SELECT key, value FROM import_meta ORDER BY key") == before
    assert store.meta().schema_version == 2


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("", "1"),
        ("Telegram.account", "1"),
        ("telegram..account", "1"),
        ("telegram.account; DROP TABLE import_meta", "1"),
        ("telegram.retired_account", "1\n2"),
        ("telegram.retired_account", "x" * 257),
        ("telegram.retired_account", 7),
    ],
)
def test_malformed_meta_is_refused(tmp_path: Path, key: str, value: Any) -> None:
    store = make_store(tmp_path)
    with pytest.raises(RecordError) as raised:
        store.set_meta(key, value)
    assert raised.value.code == "bad_meta"
    assert store.get_meta("telegram.retired_account") is None


# --- failures -------------------------------------------------------------------------------------


def test_a_busy_store_is_refused_without_retrying(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = make_store(tmp_path)
    monkeypatch.setattr(store_module, "BUSY_TIMEOUT_S", 0.05)
    holder = sqlite3.connect(tmp_path / "mordred.db", isolation_level=None)
    holder.execute("BEGIN IMMEDIATE")
    try:
        with pytest.raises(ImportRefused) as caught:
            store.run_begin("telegram")
    finally:
        holder.rollback()
        holder.close()
    assert caught.value.code == "busy"


@pytest.mark.parametrize(
    ("error", "expected"),
    [
        (sqlite3.OperationalError("database or disk is full"), "disk_full"),
        (sqlite3.DatabaseError("database disk image is malformed"), "store_unavailable"),
        (ActivityRefused(refusal("unkeyed_connection")), "unkeyed_connection"),
    ],
)
def test_opener_failures_become_content_free_refusals(tmp_path: Path, error: BaseException, expected: str) -> None:
    def failing(_path: Path) -> sqlite3.Connection:
        raise error

    with pytest.raises(ImportRefused) as caught:
        ImportStore(tmp_path / "mordred.db", failing).status()
    assert caught.value.code == expected
    assert str(caught.value) == expected
    assert "import store" in caught.value.refusal.detail


# --- the protection gate --------------------------------------------------------------------------


@pytest.fixture
def protected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A home that passes every process/home-level check (armed, shim loaded, key resolves)."""
    monkeypatch.setattr(sys, "platform", "darwin")
    monkeypatch.setattr(_shim, "is_installed", lambda: True)
    monkeypatch.setattr(dbcrypt, "_PROVIDER", lambda: object())
    dbcrypt.arm(tmp_path)
    return tmp_path


class _ClaimsKey(sqlite3.Connection):
    """Plain SQLite pretending to be keyed (the shim's connection carries ``mordred_key``)."""

    mordred_key: Any = "pretend"


class _ClaimsKeyModule:
    @staticmethod
    def connect(database: str, **kwargs: Any) -> sqlite3.Connection:
        return sqlite3.connect(database, factory=_ClaimsKey, **kwargs)


def test_open_refuses_a_plain_home_before_creating_anything(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "platform", "darwin")

    with pytest.raises(ImportRefused) as caught:
        open_import_store(tmp_path)
    assert caught.value.code == "not_armed"
    assert not (tmp_path / "plugin-data").exists()


def test_open_refuses_other_platforms(protected: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "platform", "linux")
    with pytest.raises(ImportRefused) as caught:
        open_import_store(protected)
    assert caught.value.code == "unsupported_platform"
    assert caught.value.refusal.detail == "the import store requires macOS database encryption"


def test_open_refuses_an_unkeyed_process_connection(protected: Path) -> None:
    with pytest.raises(ImportRefused) as caught:
        open_import_store(protected)
    assert caught.value.code == "unkeyed_connection"
    path = store_path(protected)
    assert not path.exists() or path.stat().st_size == 0


def test_open_refuses_a_planted_plaintext_store(protected: Path) -> None:
    path = store_path(protected)
    with sqlite3.connect(path) as planted:
        planted.execute("CREATE TABLE planted (x INTEGER)")
    planted.close()

    with pytest.raises(ImportRefused) as caught:
        open_import_store(protected)
    assert caught.value.code == "plaintext_store"


def test_open_refuses_a_store_that_reads_without_the_key(protected: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(_gate, "_process_sqlite", lambda: _ClaimsKeyModule)
    with pytest.raises(ImportRefused) as caught:
        open_import_store(protected)
    assert caught.value.code == "plaintext_store"


def test_open_binds_only_the_import_tables(protected: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(_gate, "_process_sqlite", lambda: _ClaimsKeyModule)
    monkeypatch.setattr(_monitor, "is_plaintext", lambda _path: False)

    store = open_import_store(protected)

    assert store.path == store_path(protected)
    assert store.meta().profile_home == str(protected.resolve())
    tables = {name for (name,) in rows(store, "SELECT name FROM sqlite_master WHERE type = 'table'")}
    assert "import_meta" in tables and "activity_meta" not in tables


def test_open_refuses_a_store_bound_to_another_profile(protected: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(_gate, "_process_sqlite", lambda: _ClaimsKeyModule)
    monkeypatch.setattr(_monitor, "is_plaintext", lambda _path: False)
    other = protected / "elsewhere"
    other.mkdir()
    ImportStore(store_path(protected), sqlite3.connect).initialize(other)

    with pytest.raises(ImportRefused) as caught:
        open_import_store(protected)
    assert caught.value.code == "profile_mismatch"


def test_open_refuses_an_unusable_data_directory(protected: Path) -> None:
    (protected / "plugin-data").mkdir()
    (protected / "plugin-data" / "mordred").write_text("not a directory", encoding="utf-8")

    with pytest.raises(ImportRefused) as caught:
        open_import_store(protected)
    assert caught.value.code == "store_unavailable"
