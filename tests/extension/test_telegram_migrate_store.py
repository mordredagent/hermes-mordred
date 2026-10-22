"""``hermes-mordred telegram migrate-store``: legacy ``.enc`` archive into ``mordred.db``, content-free.

Library half (:mod:`mordred_hermes.extension.telegram.migrate`) on a synthetic
``ArchiveStore`` with a random key and a plain-SQLite ``ImportStore``; CLI half
through ``cli.main`` with ``open_import_store`` and the credential store
replaced. Fixture names, titles and text are canaries that must never reach
stdout, stderr, logs or the audit log.
"""

from __future__ import annotations

import json
import logging
import os
import sqlite3
import sys
from pathlib import Path
from typing import Any

import pytest

from mordred_hermes.extension.telegram import hardening, migrate, secrets, store
from mordred_hermes.imports import store as store_module
from mordred_hermes.imports.records import OwnerClass
from mordred_hermes.imports.store import ImportRefused, ImportStore
from mordred_hermes.wizard import cli, telegram_cli

pytestmark = pytest.mark.skipif(
    sys.platform == "win32", reason="mordred.db (and so migrate-store) is macOS-only; Windows keeps the .enc archive"
)

OWNER = 7
DIRECT = 11
GROUP = -(1_000_000_000_000 + 44)
DAY = 1_790_000_000
CANARIES = (
    "CANARY-OWNER-LABEL",
    "CANARY-TITLE-DIRECT",
    "CANARY-TITLE-GROUP",
    "CANARY-ALICE",
    "CANARY-BOB",
    "CANARY-TEXT",
)


def _rows() -> dict[int, list[store.StoredMessage]]:
    return {
        DIRECT: [
            store.StoredMessage(id=1, date=DAY, sender="", text="CANARY-TEXT-1 from me", out=True),
            store.StoredMessage(id=2, date=DAY + 60, sender="CANARY-ALICE", text="CANARY-TEXT-2", reply_to=1),
            store.StoredMessage(id=3, date=DAY + 120, sender="", text="CANARY-TEXT-3 \x1b[31mred", media="photo"),
        ],
        GROUP: [
            store.StoredMessage(id=5, date=DAY, sender="CANARY-BOB", text="CANARY-TEXT-5"),
            store.StoredMessage(id=6, date=DAY + 30, sender="CANARY-OWNER-LABEL", text="CANARY-TEXT-6", out=True),
            store.StoredMessage(id=7, date=0, sender="", text="CANARY-TEXT-7"),
        ],
    }


def _info(dialog_id: int, kind: str, title: str, rows: list[store.StoredMessage]) -> store.DialogInfo:
    return store.DialogInfo(
        dialog_id=dialog_id,
        kind=kind,
        title=title,
        last_message_id=rows[-1].id,
        message_count=len(rows),
        last_date=max(row.date for row in rows),
    )


@pytest.fixture
def key() -> bytes:
    return os.urandom(32)


@pytest.fixture
def archive(tmp_path: Path, key: bytes) -> store.ArchiveStore:
    """Two dialogs (owner, other and empty-sender rows) under ``$HERMES_HOME/mordred/telegram``."""
    seeded = store.ArchiveStore(key, tmp_path / "mordred" / "telegram")
    rows = _rows()
    for dialog_id, messages in rows.items():
        seeded.append_messages(dialog_id, messages)
    seeded.save_index(
        store.ArchiveIndex(
            account_label="CANARY-OWNER-LABEL",
            account_id=OWNER,
            last_sync=DAY + 500,
            dialogs={
                DIRECT: _info(DIRECT, "user", "CANARY-TITLE-DIRECT", rows[DIRECT]),
                GROUP: _info(GROUP, "group", "CANARY-TITLE-GROUP", rows[GROUP]),
            },
        )
    )
    return seeded


@pytest.fixture
def imports(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> ImportStore:
    db = ImportStore(tmp_path / "mordred.db", sqlite3.connect)
    db.initialize(tmp_path)
    monkeypatch.setattr(store_module, "open_import_store", lambda _home: db)
    return db


@pytest.fixture
def audits(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []

    def record(decision: str, counts: Any, *, mode: str, error: str | None = None) -> None:
        entries.append({"decision": decision, "mode": mode, "error": error, **counts})

    monkeypatch.setattr(migrate, "audit_event", record)
    return entries


class _Secrets:
    """The sealed credential store, counting unseals."""

    def __init__(self, store_key: bytes | None, *, session: str | None = None) -> None:
        self.value = (
            None
            if store_key is None
            else secrets.TelegramSecrets(api_id=1, api_hash="ab" * 16, store_key=store_key, session=session)
        )
        self.loads = 0

    def load(self, *, fresh: bool = False) -> secrets.TelegramSecrets | None:
        self.loads += 1
        return self.value

    def update(self, mutate: Any) -> Any:
        self.value = mutate(self.value)
        return self.value


@pytest.fixture
def sealed(key: bytes, monkeypatch: pytest.MonkeyPatch) -> _Secrets:
    held = _Secrets(key)
    monkeypatch.setattr(telegram_cli, "_secret_store", lambda: held)
    monkeypatch.setattr(hardening, "harden_process", lambda: None)
    return held


def _segment_files(archive: store.ArchiveStore) -> list[Path]:
    dialogs = archive._root / "dialogs"
    return sorted(dialogs.glob("*.enc")) if dialogs.is_dir() else []


def _index_version(archive: store.ArchiveStore) -> int:
    return int(archive._read("index.enc", "index")["version"])


def _no_canaries(*texts: str) -> None:
    joined = "\n".join(texts)
    assert [canary for canary in CANARIES if canary in joined] == []


def _run(argv: list[str], capsys: pytest.CaptureFixture[str]) -> tuple[int, str, str]:
    code = cli.main(argv)
    out, err = capsys.readouterr()
    return code, out, err


# -- plan / dry run ----------------------------------------------------------------------------


def test_plan_counts_per_dialog_and_writes_nothing(archive: store.ArchiveStore, imports: ImportStore) -> None:
    plan = migrate.plan_migration(archive, imports)
    direct, group = sorted(plan.dialogs, key=lambda d: d.kind != "user")
    assert (direct.kind, direct.messages, direct.owner, direct.other, direct.unknown) == ("user", 3, 1, 1, 1)
    assert (group.kind, group.messages, group.owner, group.other, group.unknown) == ("group", 3, 1, 1, 1)
    assert plan.totals() == {
        "dialogs": 2,
        "invalid_dialogs": 0,
        "messages": 6,
        "owner": 2,
        "other": 2,
        "unknown": 2,
        "empty_sender": 3,
        "unreadable_segments": 0,
        "invalid": 0,
        "would_insert": 6,
        "present": 0,
    }
    assert plan.retired is False
    assert imports.status()["runs"] == {} and imports.status()["sources"] == {}  # not even a run row
    assert archive.load_index().retired_to is None and _index_version(archive) == 1


def test_store_dry_run_reports_inserts_and_keeps_nothing(archive: store.ArchiveStore, imports: ImportStore) -> None:
    result = migrate.run_migration(archive, imports, commit=False)
    assert (result.committed, result.retired) == (False, False)
    assert (result.counts["inserted"], result.counts["duplicates"], result.counts["dialogs"]) == (6, 0, 2)
    status = imports.status()
    assert status["runs"] == {"dry_run": 1} and status["sources"] == {}
    assert archive.load_index().retired_to is None


# -- commit ------------------------------------------------------------------------------------


def test_commit_writes_attributed_rows_retires_the_index_and_reruns_only_duplicate(
    archive: store.ArchiveStore, imports: ImportStore
) -> None:
    before = archive.load_index()
    result = migrate.run_migration(archive, imports, commit=True)
    assert (result.committed, result.retired) == (True, True)
    assert (result.counts["inserted"], result.counts["duplicates"], result.counts["invalid"]) == (6, 0, 0)
    status = imports.status()
    assert status["runs"] == {"committed": 1} and status["sources"]["telegram"]["messages"] == 6

    after = archive.load_index()
    assert _index_version(archive) == 2 and after.retired_to == store.RETIRED_TO_IMPORT_STORE
    assert (after.account_id, after.account_label, after.last_sync) == (OWNER, before.account_label, before.last_sync)
    assert after.dialogs == before.dialogs  # cursors and counts kept; nothing else cleared

    parts = imports.parts_for([f"tg:{DIRECT}:1#a", f"tg:{DIRECT}:2#a", f"tg:{DIRECT}:3#a", f"tg:{GROUP}:6#a"])
    classes = {uid: part.part.author_owner_class for uid, part in parts.items()}
    assert classes == {
        f"tg:{DIRECT}:1#a": OwnerClass.ACCOUNT_OWNER,
        f"tg:{DIRECT}:2#a": OwnerClass.OTHER,
        f"tg:{DIRECT}:3#a": OwnerClass.UNKNOWN,
        f"tg:{GROUP}:6#a": OwnerClass.ACCOUNT_OWNER,  # the out flag decides, never the name
    }
    assert "\x1b" not in parts[f"tg:{DIRECT}:3#a"].part.text and "�" in parts[f"tg:{DIRECT}:3#a"].part.text
    conv = parts[f"tg:{DIRECT}:1#a"].conversation
    assert (conv.sync_cursor, conv.message_count, conv.source_account) == ("3", 3, str(OWNER))

    again = migrate.run_migration(archive, imports, commit=True)
    assert (again.counts["inserted"], again.counts["duplicates"]) == (0, 6)
    assert imports.status()["runs"] == {"committed": 2}
    replan = migrate.plan_migration(archive, imports)
    assert replan.retired is True and (replan.totals()["would_insert"], replan.totals()["present"]) == (0, 6)


def test_commit_rerun_never_overwrites_a_conversation_a_later_sync_advanced(
    archive: store.ArchiveStore, imports: ImportStore
) -> None:
    from dataclasses import replace

    migrate.run_migration(archive, imports, commit=True)
    conv = imports.parts_for([f"tg:{DIRECT}:1#a"])[f"tg:{DIRECT}:1#a"].conversation
    imports.upsert_conversation(replace(conv, sync_cursor="99", message_count=42))
    migrate.run_migration(archive, imports, commit=True)
    conv = imports.parts_for([f"tg:{DIRECT}:1#a"])[f"tg:{DIRECT}:1#a"].conversation
    assert (conv.sync_cursor, conv.message_count) == ("99", 42)


def test_unreadable_segments_and_invalid_rows_are_counted_and_skipped(
    archive: store.ArchiveStore, imports: ImportStore
) -> None:
    (archive._root / "dialogs" / f"{archive.segment_name(GROUP, 0)}.enc").write_bytes(b"MTG1" + b"\0" * 64)
    archive.append_messages(DIRECT, [store.StoredMessage(id=4, date=10**13, sender="CANARY-ALICE", text="x")])
    plan = migrate.plan_migration(archive, imports)
    totals = plan.totals()
    assert (totals["messages"], totals["unreadable_segments"], totals["invalid"], totals["would_insert"]) == (
        4,
        1,
        1,
        3,
    )
    result = migrate.run_migration(archive, imports, commit=True)
    assert (result.counts["inserted"], result.counts["invalid"], result.counts["unreadable_segments"]) == (3, 1, 1)
    conv = imports.parts_for([f"tg:{DIRECT}:1#a"])[f"tg:{DIRECT}:1#a"].conversation
    assert conv.message_count == 3  # the committed count, not the archive's 4


@pytest.mark.parametrize(
    ("account_id", "with_dialogs", "code"), [(0, True, "account_unknown"), (0, False, "archive_empty")]
)
def test_an_archive_without_an_account_is_refused_before_any_run(
    tmp_path: Path, key: bytes, imports: ImportStore, account_id: int, with_dialogs: bool, code: str
) -> None:
    archive = store.ArchiveStore(key, tmp_path / "tg")
    if with_dialogs:
        archive.save_index(store.ArchiveIndex(account_id=account_id, dialogs={1: store.DialogInfo(1, "user", "t")}))
    with pytest.raises(migrate.MigrationError) as raised:
        migrate.run_migration(archive, imports, commit=True)
    assert raised.value.code == code
    assert imports.status()["runs"] == {}


def test_commit_refuses_while_a_sync_holds_the_lock(archive: store.ArchiveStore, imports: ImportStore) -> None:
    with archive.locked(), pytest.raises(store.StoreError, match="sync_in_progress"):
        migrate.run_migration(archive, imports, commit=True)
    assert imports.status()["runs"] == {} and archive.load_index().retired_to is None


# -- finalize ----------------------------------------------------------------------------------


def test_finalize_refuses_before_commit(archive: store.ArchiveStore, imports: ImportStore) -> None:
    with pytest.raises(migrate.MigrationError) as raised:
        migrate.finalize(archive, imports)
    assert raised.value.code == "not_migrated"
    assert len(_segment_files(archive)) == 2


def test_finalize_refuses_a_count_mismatch_and_deletes_nothing(
    archive: store.ArchiveStore, imports: ImportStore
) -> None:
    migrate.run_migration(archive, imports, commit=True)
    archive.append_messages(DIRECT, [store.StoredMessage(id=9, date=DAY + 900, sender="CANARY-ALICE", text="late")])
    files = {path: path.read_bytes() for path in _segment_files(archive)}
    with pytest.raises(migrate.MigrationError) as raised:
        migrate.finalize(archive, imports)
    assert raised.value.code == "finalize_mismatch"
    assert raised.value.counts == {
        "dialogs": 2,
        "messages": 7,
        "missing": 1,
        "mismatched_dialogs": 1,
        "unreadable_segments": 0,
    }
    assert {path: path.read_bytes() for path in _segment_files(archive)} == files

    migrate.run_migration(archive, imports, commit=True)  # migrates the late row; now the counts match
    assert migrate.finalize(archive, imports).messages == 7


def test_finalize_refuses_an_unreadable_segment(archive: store.ArchiveStore, imports: ImportStore) -> None:
    migrate.run_migration(archive, imports, commit=True)
    (archive._root / "dialogs" / f"{archive.segment_name(GROUP, 0)}.enc").write_bytes(b"MTG1" + b"\0" * 64)
    with pytest.raises(migrate.MigrationError) as raised:
        migrate.finalize(archive, imports)
    assert raised.value.code == "finalize_mismatch" and raised.value.counts["unreadable_segments"] == 1
    assert len(_segment_files(archive)) == 2


def test_finalize_wipes_segments_only_and_keeps_the_retired_index(
    archive: store.ArchiveStore, imports: ImportStore
) -> None:
    migrate.run_migration(archive, imports, commit=True)
    (archive._root / "dialogs" / "stale.tmp").write_bytes(b"partial")
    result = migrate.finalize(archive, imports)
    assert (result.dialogs, result.messages, result.segments_deleted) == (2, 6, 2)
    assert sorted(p.name for p in (archive._root / "dialogs").iterdir()) == [".gitignore"]  # no .enc or .tmp left
    assert (archive._root / "index.enc").is_file() and _index_version(archive) == 2
    assert archive.load_index().retired_to == store.RETIRED_TO_IMPORT_STORE
    assert imports.status()["sources"]["telegram"]["messages"] == 6  # the store is untouched
    assert migrate.finalize(archive, imports).segments_deleted == 0  # idempotent


def test_finalize_is_refused_on_windows(
    archive: store.ArchiveStore, imports: ImportStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(migrate, "_platform", lambda: "win32")
    with pytest.raises(migrate.MigrationError, match="unsupported_platform"):
        migrate.finalize(archive, imports)


# -- CLI ---------------------------------------------------------------------------------------


def test_cli_dry_run_prints_counts_only_and_audits_once(
    archive: store.ArchiveStore,
    imports: ImportStore,
    sealed: _Secrets,
    audits: list[dict[str, Any]],
    capsys: pytest.CaptureFixture[str],
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.DEBUG)
    code, out, err = _run(["telegram", "migrate-store"], capsys)
    assert code == 0, err
    assert "dry run: nothing was written" in out and "  messages: 6" in out and "would_insert=3" in out
    assert "dialog 1 (" in out and "--commit" in out
    assert sealed.loads == 1 and imports.status()["runs"] == {}
    assert audits == [
        {"decision": "dry_run", "mode": "dry_run", "error": None, **migrate.plan_migration(archive, imports).totals()}
    ]
    _no_canaries(out, err, caplog.text, json.dumps(audits))


def test_cli_commit_then_finalize_json(
    archive: store.ArchiveStore,
    imports: ImportStore,
    sealed: _Secrets,
    audits: list[dict[str, Any]],
    capsys: pytest.CaptureFixture[str],
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.DEBUG)
    code, out, err = _run(["telegram", "migrate-store", "--commit", "--json"], capsys)
    assert code == 0, err
    payload = json.loads(out)
    assert (payload["mode"], payload["decision"], payload["retired"]) == ("commit", "committed", True)
    assert payload["counts"]["inserted"] == 6 and archive.load_index().retired_to == "mordred.db"

    code, out2, err2 = _run(["telegram", "migrate-store", "--finalize", "--yes", "--json"], capsys)
    assert code == 0, err2
    payload = json.loads(out2)
    assert payload["decision"] == "finalized"
    assert payload["counts"] == {"dialogs": 2, "messages": 6, "segments_deleted": 2}
    assert _segment_files(archive) == [] and (archive._root / "index.enc").is_file()
    assert [entry["decision"] for entry in audits] == ["committed", "finalized"]
    assert sealed.loads == 2  # one unseal per command
    _no_canaries(out, err, out2, err2, caplog.text, json.dumps(audits))


def test_cli_text_commit_names_the_next_step(
    archive: store.ArchiveStore, imports: ImportStore, sealed: _Secrets, capsys: pytest.CaptureFixture[str]
) -> None:
    code, out, err = _run(["telegram", "migrate-store", "--commit"], capsys)
    assert code == 0, err
    assert "under one import run" in out and "  inserted: 6" in out and "--finalize --yes" in out
    _no_canaries(out, err)


def test_cli_finalize_without_yes_is_a_usage_error_before_anything_opens(
    archive: store.ArchiveStore,
    sealed: _Secrets,
    audits: list[dict[str, Any]],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def never(_home: Path) -> ImportStore:
        raise AssertionError("the store must not be opened")

    monkeypatch.setattr(store_module, "open_import_store", never)
    code, out, err = _run(["telegram", "migrate-store", "--finalize"], capsys)
    assert code == 2 and out == "" and "--yes" in err
    assert sealed.loads == 0 and audits == [] and len(_segment_files(archive)) == 2


def test_cli_commit_and_finalize_are_mutually_exclusive(sealed: _Secrets, capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as raised:
        cli.main(["telegram", "migrate-store", "--commit", "--finalize", "--yes"])
    assert raised.value.code == 2 and sealed.loads == 0
    capsys.readouterr()
    assert telegram_cli.telegram_migrate_store(commit=True, finalize=True, yes=True) == 2


def test_cli_finalize_before_commit_is_not_migrated(
    archive: store.ArchiveStore,
    imports: ImportStore,
    sealed: _Secrets,
    audits: list[dict[str, Any]],
    capsys: pytest.CaptureFixture[str],
) -> None:
    code, out, err = _run(["telegram", "migrate-store", "--finalize", "--yes"], capsys)
    assert code == 1 and "not_migrated" in err and out == ""
    code, out, err = _run(["telegram", "migrate-store", "--finalize", "--yes", "--json"], capsys)
    assert code == 1 and json.loads(out)["error"] == "not_migrated"
    assert [(entry["decision"], entry["error"]) for entry in audits] == [("failed", "not_migrated")] * 2
    assert len(_segment_files(archive)) == 2


def test_cli_finalize_mismatch_prints_counts_and_exits_1(
    archive: store.ArchiveStore, imports: ImportStore, sealed: _Secrets, capsys: pytest.CaptureFixture[str]
) -> None:
    assert _run(["telegram", "migrate-store", "--commit"], capsys)[0] == 0
    archive.append_messages(GROUP, [store.StoredMessage(id=8, date=DAY + 800, sender="CANARY-BOB", text="late")])
    code, out, err = _run(["telegram", "migrate-store", "--finalize", "--yes"], capsys)
    assert code == 1 and "finalize_mismatch" in err
    assert "nothing was deleted" in out and "  missing: 1" in out
    assert len(_segment_files(archive)) == 2
    _no_canaries(out, err)


@pytest.mark.parametrize("gate", ["not_armed", "unsupported_platform"])
@pytest.mark.parametrize("argv", [[], ["--commit"], ["--finalize", "--yes"]])
def test_cli_gate_refusal_exits_1_before_any_unseal(
    archive: store.ArchiveStore,
    sealed: _Secrets,
    audits: list[dict[str, Any]],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    gate: str,
    argv: list[str],
) -> None:
    def refused(_home: Path) -> ImportStore:
        raise ImportRefused(gate)

    monkeypatch.setattr(store_module, "open_import_store", refused)
    code, out, err = _run(["telegram", "migrate-store", *argv], capsys)
    assert code == 1 and out == "" and f"({gate})" in err
    assert sealed.loads == 0 and audits == []
    assert archive.load_index().retired_to is None and len(_segment_files(archive)) == 2


def test_cli_without_credentials_is_not_configured(
    imports: ImportStore, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(telegram_cli, "_secret_store", lambda: _Secrets(None))
    monkeypatch.setattr(hardening, "harden_process", lambda: None)
    code, out, err = _run(["telegram", "migrate-store", "--commit"], capsys)
    assert code == 1 and out == "" and "telegram login" in err
    assert imports.status()["runs"] == {}


def test_cli_default_audit_writes_one_counts_only_entry(
    archive: store.ArchiveStore,
    imports: ImportStore,
    sealed: _Secrets,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert _run(["telegram", "migrate-store", "--commit"], capsys)[0] == 0
    lines = (tmp_path / "mordred" / "audit.log").read_text(encoding="utf-8").splitlines()
    entries = [json.loads(line) for line in lines]
    [entry] = [item for item in entries if item.get("event") == migrate.AUDIT_EVENT]
    assert (entry["decision"], entry["mode"], entry["reason"], entry["inserted"]) == ("committed", "commit", None, 6)
    assert all(
        isinstance(value, int)
        for key, value in entry.items()
        if key not in {"event", "decision", "reason", "mode", "ts"}
    )
    _no_canaries("\n".join(lines))


# -- logout --forget ---------------------------------------------------------------------------


class _Revocable:
    """A Telethon client stand-in for the session revoke."""

    def __init__(self) -> None:
        self.logged_out = False

    async def connect(self) -> None:
        return None

    async def is_user_authorized(self) -> bool:
        return True

    async def log_out(self) -> None:
        self.logged_out = True

    async def disconnect(self) -> None:
        return None


def _logout(held: _Secrets, client: _Revocable) -> int:
    return telegram_cli.telegram_logout(forget=True, store=held, client_factory=lambda *_a, **_k: client)


def test_logout_forget_deletes_the_accounts_import_rows_before_the_key(
    archive: store.ArchiveStore, imports: ImportStore, key: bytes, capsys: pytest.CaptureFixture[str]
) -> None:
    migrate.run_migration(archive, imports, commit=True)
    assert imports.status()["sources"]["telegram"]["messages"] == 6
    held, client = _Secrets(key, session="S"), _Revocable()
    assert _logout(held, client) == 0
    out, err = capsys.readouterr()
    assert imports.status()["sources"] == {}
    assert held.value is None and client.logged_out and held.loads == 1
    assert not list(archive._root.rglob("*.enc"))
    assert "Telegram rows in mordred.db" in out and "NOT deleted" not in err
    _no_canaries(out, err)


def test_logout_forget_reports_rows_it_could_not_delete_and_exits_1(
    archive: store.ArchiveStore,
    imports: ImportStore,
    key: bytes,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    migrate.run_migration(archive, imports, commit=True)

    def refused(_home: Path) -> ImportStore:
        raise ImportRefused("not_armed")

    monkeypatch.setattr(store_module, "open_import_store", refused)
    held, client = _Secrets(key, session="S"), _Revocable()
    assert _logout(held, client) == 1
    out, err = capsys.readouterr()
    assert "import_rows_not_deleted:import_store_unavailable" in err
    assert "Deleted the API credentials, the archive key, the hardware key, and the local archive." in out
    assert "mordred.db" not in out  # never claims the rows went
    assert imports.status()["sources"]["telegram"]["messages"] == 6
    assert held.value is None and client.logged_out  # the rest of --forget still ran
    assert not list(archive._root.rglob("*.enc"))
    _no_canaries(out, err)


def test_logout_forget_of_an_unmigrated_archive_never_opens_the_store(
    archive: store.ArchiveStore, key: bytes, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def never(_home: Path) -> ImportStore:
        raise AssertionError("an unretired index names no import rows")

    monkeypatch.setattr(store_module, "open_import_store", never)
    held = _Secrets(key, session="S")
    assert _logout(held, _Revocable()) == 0
    assert held.value is None and not list(archive._root.rglob("*.enc"))
    capsys.readouterr()
