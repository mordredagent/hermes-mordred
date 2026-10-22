"""Telegram sync sinks: ``.enc`` archive vs ``mordred.db`` (``ImportStore``), selection and service reads."""

from __future__ import annotations

import asyncio
import datetime as dt
import sqlite3
from dataclasses import dataclass, field, replace
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from mordred_hermes.extension.telegram import client, history, secrets, service, store
from mordred_hermes.imports.records import OwnerClass, Participant, SenderKind
from mordred_hermes.imports.store import ImportRefused, ImportStore

OWNER = 7
KEY = b"\x01" * 32
_BASE = dt.datetime(2026, 10, 1, 9, tzinfo=dt.UTC)
_GROUP_ID = -(1_000_000_000_000 + 44)
EVERYTHING = client.SyncOptions(include_archived=True, since_days=None, max_group_size=None)


@dataclass
class _Msg:
    id: int
    message: str = "text"
    date: dt.datetime | None = None
    out: bool = False
    sender_id: int | None = None
    from_id: Any = None
    sender: Any = None
    fwd_from: Any = None
    forward: Any = None
    reply_to: Any = None
    media: Any = None

    def __post_init__(self) -> None:
        if self.date is None:
            self.date = _BASE + dt.timedelta(minutes=self.id)


_Msg.__name__ = "Message"


@dataclass
class _Dialog:
    id: int
    name: str
    entity: Any
    is_user: bool = False
    is_group: bool = False


@dataclass
class _Client:
    history: dict[str, list[Any]]
    dialogs: list[_Dialog] = field(default_factory=list)
    calls: list[tuple[str, int]] = field(default_factory=list)
    me: int = OWNER
    connected: int = 0
    fail_at: int | None = None

    async def get_me(self) -> Any:
        return SimpleNamespace(id=self.me, first_name="Me", last_name=None)

    async def iter_dialogs(self, archived: bool = False):
        if not archived:
            for dialog in self.dialogs:
                yield dialog

    async def iter_messages(self, entity: str, *, min_id: int = 0, reverse: bool = False, **_: Any):
        self.calls.append((entity, min_id))
        for m in sorted(self.history[entity], key=lambda m: m.id, reverse=not reverse):
            if m.id <= min_id:
                continue
            if self.fail_at is not None and m.id == self.fail_at:
                raise ConnectionError("dropped")
            yield m

    async def connect(self) -> None:
        self.connected += 1

    async def is_user_authorized(self) -> bool:
        return True

    async def disconnect(self) -> None:
        return None


def _bob(first_name: str = "Bob") -> SimpleNamespace:
    return SimpleNamespace(first_name=first_name, bot=False)


def _fake_client() -> _Client:
    bob, team = _Dialog(11, "Bob", "bob", is_user=True), _Dialog(_GROUP_ID, "Team", "team", is_group=True)
    history_ = {
        "bob": [
            _Msg(1, "hi", sender_id=11, sender=_bob()),
            _Msg(2, "see you at 5", out=True),
            _Msg(3, "ok", sender_id=11, sender=_bob(), reply_to=SimpleNamespace(reply_to_msg_id=2, quote_text="at 5")),
            _Msg(
                4,
                "Carol's note",
                sender_id=11,
                sender=_bob(),
                fwd_from=SimpleNamespace(from_id=SimpleNamespace(user_id=12), date=_BASE),
                forward=SimpleNamespace(sender=SimpleNamespace(first_name="Carol")),
            ),
            SimpleNamespace(id=5, date=_BASE),  # a service message: seen, never stored
        ],
        "team": [
            _Msg(1, "agenda", sender_id=OWNER, from_id=SimpleNamespace(user_id=OWNER)),
            _Msg(2, "rules", from_id=SimpleNamespace(channel_id=44)),
        ],
    }
    return _Client(history=history_, dialogs=[bob, team])


def _import_store(tmp_path: Path) -> ImportStore:
    imports = ImportStore(tmp_path / "mordred.db", sqlite3.connect)
    imports.initialize(tmp_path)
    return imports


def _archive(tmp_path: Path) -> store.ArchiveStore:
    return store.ArchiveStore(KEY, tmp_path / "tg")


def _rows(imports: ImportStore, sql: str, *params: Any) -> list[tuple[Any, ...]]:
    with imports.connection() as conn:
        return [tuple(row) for row in conn.execute(sql, params)]


def _conversations(imports: ImportStore) -> dict[str, tuple[Any, ...]]:
    rows = _rows(imports, "SELECT conv_uid, sync_cursor, message_count, last_message_at FROM import_conversations")
    return {row[0]: row[1:] for row in rows}


@pytest.fixture
def darwin(monkeypatch):
    monkeypatch.setattr(history, "_platform", lambda: "darwin")


def _refusing(code: str = "not_armed"):
    calls: list[Path] = []

    def opener(home: Path) -> ImportStore:
        calls.append(home)
        raise ImportRefused(code)

    return opener, calls


def _counting(imports: ImportStore):
    calls: list[Path] = []

    def opener(home: Path) -> ImportStore:
        calls.append(home)
        return imports

    return opener, calls


# -- index versions -----------------------------------------------------------------------


def test_index_v1_round_trip_is_unchanged(tmp_path):
    archive = _archive(tmp_path)
    index = store.ArchiveIndex(account_label="Me", account_id=OWNER, last_sync=5)
    index.dialogs[11] = store.DialogInfo(dialog_id=11, kind="user", title="Bob", last_message_id=3)
    archive.save_index(index)
    raw = archive._read("index.enc", "index")
    assert raw["version"] == 1 and "retired_to" not in raw
    assert list(raw) == ["version", "account_label", "account_id", "last_sync", "dialogs"]
    assert archive.load_index() == index and archive.load_index().retired_to is None


def test_index_v2_round_trip_with_empty_dialogs(tmp_path):
    archive = _archive(tmp_path)
    index = store.ArchiveIndex(account_label="Me", account_id=OWNER, last_sync=9, retired_to="mordred.db")
    archive.save_index(index)
    raw = archive._read("index.enc", "index")
    assert (raw["version"], raw["retired_to"], raw["dialogs"]) == (2, "mordred.db", [])
    assert archive.load_index() == index


@pytest.mark.parametrize(
    "payload",
    [
        {"version": 2, "retired_to": "elsewhere.db", "dialogs": []},
        {"version": 2, "dialogs": []},
        {"version": 3, "retired_to": "mordred.db", "dialogs": []},
    ],
)
def test_index_versions_other_than_1_and_retired_2_are_refused(tmp_path, payload):
    archive = _archive(tmp_path)
    archive._write("index.enc", "index", payload)
    with pytest.raises(store.StoreError, match="store_undecryptable"):
        archive.load_index()


def test_index_refuses_to_write_an_unknown_retirement_target(tmp_path):
    with pytest.raises(store.StoreError, match="store_index_invalid"):
        _archive(tmp_path).save_index(store.ArchiveIndex(retired_to="state.db"))


# -- sink selection -------------------------------------------------------------------------


def test_archive_with_dialogs_stays_on_enc(tmp_path, darwin):
    archive = _archive(tmp_path)
    index = store.ArchiveIndex(dialogs={11: store.DialogInfo(dialog_id=11, kind="user", title="Bob")})
    opener, calls = _counting(_import_store(tmp_path))
    sink = history.select_sink(archive, index, home=tmp_path, opener=opener)
    assert isinstance(sink, history.ArchiveSink) and calls == []


def test_retired_index_uses_the_import_store(tmp_path):
    imports = _import_store(tmp_path)
    opener, calls = _counting(imports)
    index = store.ArchiveIndex(retired_to="mordred.db")
    sink = history.select_sink(_archive(tmp_path), index, home=tmp_path, opener=opener)
    assert isinstance(sink, history.ImportSink) and sink.store is imports and calls == [tmp_path]


def test_retired_index_never_falls_back_to_enc(tmp_path):
    opener, _ = _refusing()
    index = store.ArchiveIndex(retired_to="mordred.db", dialogs={1: store.DialogInfo(1, "user", "x")})
    with pytest.raises(store.StoreError, match="import_store_unavailable"):
        history.select_sink(_archive(tmp_path), index, home=tmp_path, opener=opener)


def test_fresh_account_on_macos_goes_straight_to_mordred_db(tmp_path, darwin):
    archive = _archive(tmp_path)
    opener, _ = _counting(_import_store(tmp_path))
    index = archive.load_index()
    sink = history.select_sink(archive, index, home=tmp_path, opener=opener)
    assert isinstance(sink, history.ImportSink)
    assert index.retired_to == "mordred.db"
    assert archive._read("index.enc", "index")["version"] == 2  # rewritten before the first write
    assert archive.load_index().retired_to == "mordred.db"


def test_fresh_account_elsewhere_or_with_the_gate_closed_stays_on_enc(tmp_path, monkeypatch):
    archive = _archive(tmp_path)
    monkeypatch.setattr(history, "_platform", lambda: "linux")
    opener, calls = _counting(_import_store(tmp_path))
    assert isinstance(
        history.select_sink(archive, store.ArchiveIndex(), home=tmp_path, opener=opener), history.ArchiveSink
    )
    assert calls == []
    monkeypatch.setattr(history, "_platform", lambda: "darwin")
    refusing, refused = _refusing("unprotected_process")
    index = store.ArchiveIndex()
    assert isinstance(history.select_sink(archive, index, home=tmp_path, opener=refusing), history.ArchiveSink)
    assert refused == [tmp_path] and index.retired_to is None and not (tmp_path / "tg" / "index.enc").exists()


def test_archive_sync_refuses_a_retired_index(tmp_path):
    archive = _archive(tmp_path)
    archive.save_index(store.ArchiveIndex(account_id=OWNER, retired_to="mordred.db"))
    fake = _fake_client()
    with pytest.raises(store.StoreError, match="import_store_unavailable"):
        asyncio.run(client.sync_archive(fake, archive, options=EVERYTHING))
    assert fake.calls == [] and archive.load_messages(11) == []


# -- syncing into mordred.db ----------------------------------------------------------------


def _sync(fake: _Client, archive: store.ArchiveStore, imports: ImportStore) -> client.SyncProgress:
    sink = history.select_sink(archive, archive.load_index(), home=archive._root.parent, opener=lambda _h: imports)
    assert isinstance(sink, history.ImportSink)
    return asyncio.run(client.sync_archive(fake, archive, options=EVERYTHING, sink=sink))


def test_end_to_end_sync_writes_attributed_rows_and_cursors(tmp_path, darwin):
    archive, imports, fake = _archive(tmp_path), _import_store(tmp_path), _fake_client()
    result = _sync(fake, archive, imports)
    assert (result.dialogs_done, result.messages_imported) == (2, 6)
    status = imports.status()
    assert status["runs"] == {"committed": 1} and status["sources"]["telegram"]["messages"] == 6
    assert status["last_run"]["counts"]["inserted"] == 6 and status["last_run"]["counts"]["skipped"] == 1

    parts = imports.parts_for(["tg:11:2#a", "tg:11:3#a", "tg:11:3#q1", "tg:11:4#f1", f"tg:{_GROUP_ID}:2#a"])
    assert parts["tg:11:2#a"].part.author_owner_class is OwnerClass.ACCOUNT_OWNER
    assert parts["tg:11:3#a"].part.author_id == "11"
    quote = parts["tg:11:3#q1"].part  # resolved within the same run, before anything was committed
    assert (quote.author_owner_class, quote.author_evidence, quote.text) == (
        OwnerClass.ACCOUNT_OWNER,
        "reply_quote_resolved",
        "at 5",
    )
    forwarded = parts["tg:11:4#f1"]
    assert (forwarded.part.author_id, forwarded.part.author_name, forwarded.message.owner_class) == (
        "12",
        "Carol",
        OwnerClass.OTHER,
    )
    assert imports.contains(["tg:11:4"]) == {"tg:11:4"} and not imports.parts_for(["tg:11:4#a"])
    admin = parts[f"tg:{_GROUP_ID}:2#a"].part
    assert (admin.author_kind, admin.author_owner_class) == (SenderKind.CHANNEL, OwnerClass.UNKNOWN)

    convs = _conversations(imports)
    assert convs["tg:11"][:2] == ("5", 4)  # the service message advanced the cursor
    assert convs[f"tg:{_GROUP_ID}"][:2] == ("2", 2)
    conv = parts["tg:11:2#a"].conversation
    assert {(p.owner_class, p.stable_id) for p in conv.participants} == {
        (OwnerClass.OTHER, "11"),
        (OwnerClass.ACCOUNT_OWNER, "7"),
    }
    index = archive.load_index()
    assert (index.retired_to, index.account_id, index.dialogs) == ("mordred.db", OWNER, {})
    assert index.last_sync > 0 and archive.load_messages(11) == []  # nothing went to .enc


def test_second_sync_fetches_only_new_messages_and_resolves_quotes_from_the_store(tmp_path, darwin):
    archive, imports, fake = _archive(tmp_path), _import_store(tmp_path), _fake_client()
    _sync(fake, archive, imports)
    fake.calls.clear()
    reply = SimpleNamespace(reply_to_msg_id=1, quote_text="hi")
    fake.history["bob"].append(_Msg(6, "hi to you", out=True, reply_to=reply))
    result = _sync(fake, archive, imports)
    assert result.messages_imported == 1
    assert sorted(fake.calls) == [("bob", 5), ("team", 2)]
    quote = imports.parts_for(["tg:11:6#q1"])["tg:11:6#q1"].part
    assert (quote.author_id, quote.author_owner_class) == ("11", OwnerClass.OTHER)  # Bob's committed row
    assert _conversations(imports)["tg:11"][:2] == ("6", 5)
    assert imports.status()["runs"] == {"committed": 2}


def test_failed_sync_publishes_nothing_and_does_not_advance_cursors(tmp_path, darwin):
    archive, imports, fake = _archive(tmp_path), _import_store(tmp_path), _fake_client()
    _sync(fake, archive, imports)
    fake.history["bob"].extend([_Msg(6, "six", sender_id=11), _Msg(7, "seven", sender_id=11)])
    fake.fail_at = 7
    with pytest.raises(ConnectionError):
        _sync(fake, archive, imports)
    assert imports.status()["runs"] == {"committed": 1, "failed": 1}
    assert imports.contains(["tg:11:6"]) == set()
    assert _conversations(imports)["tg:11"][:2] == ("5", 4)
    fake.fail_at = None
    fake.calls.clear()
    result = _sync(fake, archive, imports)
    assert ("bob", 5) in fake.calls and result.messages_imported == 2
    assert imports.contains(["tg:11:6", "tg:11:7"]) == {"tg:11:6", "tg:11:7"}
    assert _conversations(imports)["tg:11"][:2] == ("7", 6)


def test_conversation_of_another_account_is_an_account_mismatch(tmp_path, darwin):
    archive, imports = _archive(tmp_path), _import_store(tmp_path)
    foreign = client.convert_dialog(_Dialog(11, "Bob", "bob", is_user=True), account="99")
    imports.upsert_conversation(foreign)
    with pytest.raises(store.StoreError, match="account_mismatch"):
        _sync(_fake_client(), archive, imports)
    assert imports.status()["runs"] == {"failed": 1}


# -- the service ----------------------------------------------------------------------------


def _value() -> secrets.TelegramSecrets:
    return secrets.TelegramSecrets(api_id=1, api_hash="ab" * 16, store_key=KEY, session="s")


def _service(tmp_path: Path, fake: _Client, opener: Any) -> service.TelegramService:
    value = _value()
    return service.TelegramService(
        secret_store=SimpleNamespace(load=lambda fresh=False: value, flags=lambda: {"logged_in": True}),
        archive_root=tmp_path / "tg",
        client_factory=lambda *a, **k: fake,
        installed=lambda: True,
        memory_guard=lambda: None,
        import_store_opener=opener,
        home=tmp_path,
    )


def _run_sync(svc: service.TelegramService) -> None:
    async def run() -> None:
        await svc.start_sync(EVERYTHING)
        await svc.wait_for_sync()

    asyncio.run(run())


def test_service_sync_status_and_dialogs_on_mordred_db(tmp_path, darwin, monkeypatch):
    monkeypatch.setattr(service, "_audit", lambda *a, **k: None)
    imports = _import_store(tmp_path)
    svc = _service(tmp_path, _fake_client(), lambda _home: imports)
    _run_sync(svc)
    assert svc._last_error is None
    status = asyncio.run(svc.status())
    assert (status["dialog_count"], status["message_count"]) == (2, 6)
    rows = asyncio.run(svc.dialogs())
    assert [(r["id"], r["conv_uid"], r["kind"], r["message_count"]) for r in rows] == [
        ("11", "tg:11", "user", 4),
        (str(_GROUP_ID), f"tg:{_GROUP_ID}", "group", 2),
    ]
    assert rows[0]["last_date"] == rows[0]["last_message_at"] == int((_BASE + dt.timedelta(minutes=4)).timestamp())
    assert _archive(tmp_path).load_index().retired_to == "mordred.db"


def test_service_dialogs_and_status_on_the_archive(tmp_path, monkeypatch):
    monkeypatch.setattr(history, "_platform", lambda: "linux")
    monkeypatch.setattr(service, "_audit", lambda *a, **k: None)
    opener, calls = _refusing()
    svc = _service(tmp_path, _fake_client(), opener)
    _run_sync(svc)
    assert svc._last_error is None and calls == []
    status = asyncio.run(svc.status())
    assert (status["dialog_count"], status["message_count"]) == (2, 6)
    rows = asyncio.run(svc.dialogs())
    assert {(r["id"], r["kind"], r["message_count"]) for r in rows} == {("11", "user", 4), (str(_GROUP_ID), "group", 2)}
    assert "conv_uid" not in rows[0] and _archive(tmp_path).load_index().retired_to is None


def test_service_refuses_a_retired_index_when_the_gate_refuses(tmp_path, monkeypatch):
    monkeypatch.setattr(service, "_audit", lambda *a, **k: None)
    _archive(tmp_path).save_index(store.ArchiveIndex(account_id=OWNER, retired_to="mordred.db"))
    fake = _fake_client()
    opener, _ = _refusing("no_key")
    svc = _service(tmp_path, fake, opener)
    _run_sync(svc)
    assert svc._last_error == "import_store_unavailable"
    assert fake.connected == 0 and _archive(tmp_path).load_messages(11) == []  # never reached Telegram
    with pytest.raises(store.StoreError, match="import_store_unavailable") as raised:
        asyncio.run(svc.dialogs())
    assert service.error_code(raised.value, "x") == "import_store_unavailable"


# -- logout --forget ------------------------------------------------------------------------


def test_forget_deletes_the_accounts_import_rows(tmp_path, darwin):
    archive, imports = _archive(tmp_path), _import_store(tmp_path)
    _sync(_fake_client(), archive, imports)
    assert history.forget_imported_history(archive, home=tmp_path, opener=lambda _h: imports) is None
    assert imports.status()["sources"] == {}


def test_forget_reports_an_unavailable_store_and_skips_unretired_archives(tmp_path):
    archive = _archive(tmp_path)
    opener, calls = _refusing()
    assert history.forget_imported_history(archive, home=tmp_path, opener=opener) is None  # no index at all
    archive.save_index(store.ArchiveIndex(account_id=OWNER))
    assert history.forget_imported_history(archive, home=tmp_path, opener=opener) is None and calls == []
    archive.save_index(store.ArchiveIndex(account_id=OWNER, retired_to="mordred.db"))
    assert history.forget_imported_history(archive, home=tmp_path, opener=opener) == "import_store_unavailable"


def test_dialog_rows_name_bots_and_keep_the_wire_keys(tmp_path):
    conv = client.convert_dialog(_Dialog(12, "Helper", SimpleNamespace(bot=True), is_user=True), account="7")
    bot = Participant(kind=SenderKind.BOT, stable_id="12", display_name="Helper", owner_class=OwnerClass.OTHER)
    (row,) = history.dialog_rows([replace(conv, participants=(bot,))])
    assert row["kind"] == "bot" and set(row) >= {"id", "title", "kind", "message_count", "last_date", "archived"}
