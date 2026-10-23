"""``mordred_history_search``: head-lined parts from mordred.db or the legacy archive, in reader mode only.

Fixtures are synthetic (no real names, RFC 2606 domains only). The import
store is a plain-SQLite :class:`ImportStore` injected through the service's
``import_store_opener`` / ``home`` seams, like the ask-rendering tests.
"""

from __future__ import annotations

import asyncio
import builtins
import datetime as dt
import json
import re
import sqlite3
import uuid
from collections.abc import Iterator
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from mordred_hermes.activity import _gate
from mordred_hermes.extension.telegram import hermes_tools, search, secrets, service, store
from mordred_hermes.imports.records import (
    ConversationKind,
    ImportConversation,
    ImportMessage,
    PartKind,
    Source,
    telegram_conv_uid,
    telegram_source_uid,
)
from mordred_hermes.imports.render import TRUNCATION_MARKER
from mordred_hermes.imports.store import TELEGRAM_RETIRED_ACCOUNT, ImportRefused, ImportStore
from mordred_hermes.privacy_check import egress
from tests.imports._factories import (
    DIALOG,
    MAIL_CONV_UID,
    ORIGINAL_AT,
    OWNER,
    OWNER_ID,
    SENT_AT,
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
)

_KEY = b"\x07" * 32
_LOCAL = SimpleNamespace(model="m", base_url="http://127.0.0.1:11434/v1")
_HEAD = re.compile(r"^\[(?:Telegram|Mail) (\S+)\] speaker: ")
_OTHER_DIALOG = -200
_OTHER_CONV_UID = telegram_conv_uid(_OTHER_DIALOG)
_OTHER_SENT_AT = SENT_AT - 10 * 86400


# -- fixtures ------------------------------------------------------------------------------------


def _plain_opener(path: Path) -> sqlite3.Connection:
    return sqlite3.connect(path)


def _commit(imports: ImportStore, conv: ImportConversation, messages: list[ImportMessage]) -> None:
    run = imports.run_begin(Source.TELEGRAM)
    result = imports.write_thread(run, messages, conversation=conv)
    imports.run_commit(run, {"inserted": result.inserted})


def _team_messages() -> list[ImportMessage]:
    forwarded_uid = tg_uid(4569)
    forwarded = part(
        forwarded_uid,
        PartKind.FORWARDED,
        1,
        author=TANAKA,
        text="明日の会議は10時に始まります、資料を忘れずに",
        original_sent_at=ORIGINAL_AT,
    )
    quoting_uid = tg_uid(4571)
    own = part(quoting_uid, ordinal=0, author=SUZUKI, text="了解です")
    quoted = part(quoting_uid, PartKind.QUOTED, 1, ordinal=1, author=OWNER, text="10時に集合でお願いします")
    return [
        authored(4567, OWNER, text="予算は金曜までに送ります"),
        message(forwarded_uid, (forwarded,), sender=OWNER, sent_at=SENT_AT + 60),
        message(quoting_uid, (own, quoted), sender=SUZUKI, sent_at=SENT_AT + 120),
        authored(4573, TANAKA, text="The Budget review moved to Monday", sent_at=SENT_AT + 180),
        authored(4575, TANAKA, text="later one", sent_at=SENT_AT + 240),
        authored(4577, TANAKA, text="later two", sent_at=SENT_AT + 300),
    ]


def _other_conv() -> ImportConversation:
    return ImportConversation(
        conv_uid=_OTHER_CONV_UID,
        source=Source.TELEGRAM,
        source_account=OWNER_ID,
        conversation_id=str(_OTHER_DIALOG),
        kind=ConversationKind.DIRECT,
        title="Family",
        participants=(SUZUKI, OWNER),
        last_message_at=_OTHER_SENT_AT,
        message_count=1,
        archived=False,
        sync_cursor=None,
    )


def _other_message(msg_id: int, text: str, sent_at: int = _OTHER_SENT_AT) -> ImportMessage:
    uid = telegram_source_uid(_OTHER_DIALOG, msg_id)
    return message(
        uid, (part(uid, author=SUZUKI, text=text),), conv_uid=_OTHER_CONV_UID, sender=SUZUKI, sent_at=sent_at
    )


class _Opener:
    """``open_import_store``-shaped seam that counts opens (one per call: the store is never cached)."""

    def __init__(self, imports: ImportStore | None, refusal: str | None = None) -> None:
        self.imports = imports
        self.refusal = refusal
        self.opened = 0

    def __call__(self, _home: Path) -> ImportStore:
        self.opened += 1
        if self.refusal is not None or self.imports is None:
            raise ImportRefused(self.refusal or "not_armed")
        return self.imports


class _Secrets:
    """The sealed Telegram credentials; ``load`` is the unseal (Touch ID). ``value=None``: not configured."""

    def __init__(self, *, configured: bool = True, forbidden: bool = False) -> None:
        self.value = (
            secrets.TelegramSecrets(
                api_id=1,
                api_hash="ab" * 16,
                store_key=_KEY,
                session="s",
                backend="local",
                local_endpoint="http://127.0.0.1:1/v1",
                local_model="m",
            )
            if configured
            else None
        )
        self.forbidden = forbidden
        self.unseals = 0

    def load(self, fresh: bool = True) -> secrets.TelegramSecrets | None:
        self.unseals += 1
        if self.forbidden:
            raise AssertionError("the Telegram credentials must not be unsealed")
        return self.value

    def flags(self) -> dict[str, Any] | None:
        return {} if self.value is not None else None


def _service(tmp_path: Path, opener: _Opener | None = None, sealed: _Secrets | None = None) -> Any:
    return service.TelegramService(
        secret_store=sealed if sealed is not None else _Secrets(),
        archive_root=tmp_path / "tg",
        policy_check=lambda _b, _u: None,
        import_store_opener=opener,
        home=tmp_path,
        memory_guard=lambda: None,
    )


@pytest.fixture
def session() -> Iterator[str]:
    """A session the privacy_check hook put into reader mode in this process."""
    sid = f"search-{uuid.uuid4().hex}"
    egress.mark_reader(sid)
    yield sid
    with egress._SESSIONS.lock:
        egress._SESSIONS.reader.discard(sid)
        egress._SESSIONS.tainted.discard(sid)


@pytest.fixture
def retired(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> _Opener:
    """An account whose index is retired to mordred.db, holding the Team and Family chats."""
    imports = ImportStore(tmp_path / "mordred.db", _plain_opener)
    imports.initialize(tmp_path)
    _commit(imports, tg_conv(), _team_messages())
    _commit(imports, _other_conv(), [_other_message(7, "budget for the trip")])
    archive = store.ArchiveStore(_KEY, tmp_path / "tg")
    archive.save_index(store.ArchiveIndex(account_label="Owner", account_id=int(OWNER_ID), retired_to="mordred.db"))
    opener = _Opener(imports)
    monkeypatch.setattr(hermes_tools, "_service", lambda: _service(tmp_path, opener))
    return opener


@pytest.fixture
def legacy(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> _Opener:
    """An account still on the .enc archive (index version 1)."""
    archive = store.ArchiveStore(_KEY, tmp_path / "tg")
    archive.append_messages(
        -5,
        [
            store.StoredMessage(id=1, date=1_790_000_000, sender="Carol", text="Budget review moved to Monday"),
            store.StoredMessage(id=2, date=1_790_000_100, sender="Me", text="thanks", out=True),
            store.StoredMessage(id=3, date=1_790_000_200, sender="Carol", text="see you on monday"),
        ],
    )
    archive.save_index(
        store.ArchiveIndex(
            account_label="Me",
            last_sync=1_790_000_300,
            dialogs={-5: store.DialogInfo(-5, "group", "Finance team", message_count=3, last_date=1_790_000_200)},
        )
    )
    opener = _Opener(None)
    monkeypatch.setattr(hermes_tools, "_service", lambda: _service(tmp_path, opener))
    return opener


def _search(args: dict[str, Any], session: str | None, agent: Any = _LOCAL) -> dict[str, Any]:
    out = asyncio.run(hermes_tools.mordred_history_search(args, parent_agent=agent, session_id=session))
    result: dict[str, Any] = json.loads(out)
    return result


def _ids(result: dict[str, Any]) -> list[str]:
    return [item["evidence_id"] for item in result["items"]]


def _local_day(ts: int) -> str:
    return dt.datetime.fromtimestamp(ts, tz=dt.UTC).astimezone().strftime("%Y-%m-%d")


# -- registration --------------------------------------------------------------------------------


def test_registered_in_the_telegram_toolset_with_its_schema() -> None:
    calls: list[dict[str, Any]] = []
    hermes_tools.register_tools(SimpleNamespace(register_tool=lambda **kw: calls.append(kw)))
    tool = next(c for c in calls if c["name"] == "mordred_history_search")
    assert tool["toolset"] == hermes_tools.TOOLSET == "mordred_telegram"
    assert tool["handler"] is hermes_tools.mordred_history_search
    assert tool["check_fn"] is hermes_tools.history_search_available and tool["is_async"] is True
    assert "mail" in tool["description"].casefold() and "[Mail <evidence id>]" in tool["description"]
    params = tool["schema"]["parameters"]
    assert set(params["properties"]) == {
        "query",
        "chat_ids",
        "start_date",
        "end_date",
        "around_evidence_id",
        "limit",
        "pseudonymize",
    }
    assert "required" not in params
    assert params["properties"]["chat_ids"]["maxItems"] == search.MAX_CHAT_IDS == 20
    assert params["properties"]["chat_ids"]["items"] == {"type": "integer"}
    limit = params["properties"]["limit"]
    assert (limit["minimum"], limit["maximum"], limit["default"]) == (1, 40, 20)
    assert params["properties"]["pseudonymize"]["default"] is False


def test_reading_rules_appear_in_the_note_prompt_and_skill() -> None:
    assert len(hermes_tools.READING_RULES) == 4
    skill = hermes_tools.SKILL_PATH.read_text("utf-8")
    assert "## Reading imported history" in skill
    for rule in hermes_tools.READING_RULES:
        assert rule in hermes_tools._SEARCH_NOTE
        assert rule in hermes_tools.SYSTEM_PROMPT
        assert rule in skill
    assert "mordred_history_search" in hermes_tools.SYSTEM_PROMPT
    assert len(hermes_tools.SYSTEM_PROMPT) <= 4000
    assert "send messages, schedule or delegate" in skill


# -- visibility ----------------------------------------------------------------------------------


def _hermes_model(home: Path, base_url: str) -> None:
    (home / "config.yaml").write_text(f"model:\n  default: m\n  base_url: {base_url}\n", encoding="utf-8")


@pytest.fixture
def telethon_imports(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Every attempt to import Telethon, each refused as if it were not installed."""
    attempts: list[str] = []
    real_import = builtins.__import__

    def guarded(name: str, *args: Any, **kwargs: Any) -> Any:
        if name == "telethon" or name.startswith("telethon."):
            attempts.append(name)
            raise ImportError("telethon is not installed")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", guarded)
    return attempts


def test_offered_on_a_mail_only_home_without_telethon_or_a_telegram_login(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, session: str, telethon_imports: list[str]
) -> None:
    _hermes_model(tmp_path, "http://127.0.0.1:11434/v1")
    monkeypatch.setattr(_gate, "check_protection", lambda _home: None)  # database encryption armed
    assert hermes_tools.history_search_available() is True
    _use(monkeypatch, tmp_path, _Opener(_mail_store(tmp_path)), _Secrets(configured=False, forbidden=True))
    assert _ids(_search({"query": "見積もり"}, session)) == ["mail:work:m1@example.com#a"]
    assert telethon_imports == []  # neither the check nor the search touched Telethon
    assert hermes_tools.tools_available() is False  # telegram_ask / telegram_chats stay hidden


def test_not_offered_when_the_gate_refuses_and_telegram_is_unconfigured(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _hermes_model(tmp_path, "http://127.0.0.1:11434/v1")
    monkeypatch.setattr(_gate, "check_protection", lambda _home: _gate.refusal("not_armed"))
    assert hermes_tools.history_search_available() is False  # no credentials in this home
    monkeypatch.setattr(hermes_tools, "tools_available", lambda: True)  # Telegram logged in after all
    assert hermes_tools.history_search_available() is True
    monkeypatch.setattr(_gate, "check_protection", lambda _home: None)
    _hermes_model(tmp_path, "https://api.openai.com/v1")  # never offered to a model that may not read it
    assert hermes_tools.history_search_available() is False


# -- mordred.db (index retired) ------------------------------------------------------------------


@pytest.mark.parametrize("query", ["会議", "明日の会議"])  # LIKE fallback (2 chars) and trigram FTS
def test_japanese_query_returns_the_forwarded_part_with_its_head_line(
    retired: _Opener, session: str, query: str
) -> None:
    out = _search({"query": query}, session)
    assert _ids(out) == ["tg:-100123:4569#f1"]
    item = out["items"][0]
    assert item == {
        "evidence_id": "tg:-100123:4569#f1",
        "speaker_class": "other",
        "part_kind": "forwarded",
        "provenance_quality": "api_identity",
        "text": item["text"],
    }
    head, body = item["text"].split("\n", 1)
    assert head.startswith("[Telegram tg:-100123:4569#f1] speaker: 田中 太郎 (forwarded text; ")
    assert "forwarded by account owner" in head and "→ chat: Team / " in head
    assert body == "  明日の会議は10時に始まります、資料を忘れずに"
    assert out["search"] == {"mode": "fts", "candidates": 1, "returned": 1, "truncated": False, "complete": True}
    assert out["conversations"] == [{"conv_uid": TG_CONV_UID, "label": out["conversations"][0]["label"]}]
    assert out["conversations"][0]["label"].startswith("✈ Team · seen in archive: ")
    assert out["reading_rules"] == list(hermes_tools.READING_RULES)
    assert set(out) == {"note", "reading_rules", "coverage", "search", "conversations", "items"}
    assert set(out["coverage"]) == {"archive_updated", "sync_running", "hint"}


def test_quoted_text_keeps_its_own_speaker(retired: _Opener, session: str) -> None:
    out = _search({"query": "集合"}, session)
    assert _ids(out) == ["tg:-100123:4571#q1"]
    head = out["items"][0]["text"].split("\n", 1)[0]
    assert "speaker: account owner (quoted text; quoted by 鈴木 花子)" in head
    assert out["items"][0]["speaker_class"] == "account_owner" and out["items"][0]["part_kind"] == "quoted"


def test_english_query_is_case_insensitive_across_chats(retired: _Opener, session: str) -> None:
    out = _search({"query": "BUDGET"}, session)
    assert sorted(_ids(out)) == ["tg:-100123:4573#a", "tg:-200:7#a"]
    labels = {c["conv_uid"]: c["label"] for c in out["conversations"]}
    assert set(labels) == {TG_CONV_UID, _OTHER_CONV_UID}
    assert labels[_OTHER_CONV_UID] == "✈ Family · 鈴木 花子 ⇄ account owner"


def test_chat_ids_restrict_the_search(retired: _Opener, session: str) -> None:
    assert _ids(_search({"query": "budget", "chat_ids": [_OTHER_DIALOG]}, session)) == ["tg:-200:7#a"]
    # telegram_chats lists ids as strings; both forms are accepted.
    assert _ids(_search({"query": "budget", "chat_ids": [str(DIALOG)]}, session)) == ["tg:-100123:4573#a"]


def test_dates_restrict_the_search(retired: _Opener, session: str) -> None:
    day = _local_day(_OTHER_SENT_AT)
    out = _search({"query": "budget", "start_date": day, "end_date": day}, session)
    assert _ids(out) == ["tg:-200:7#a"]
    later = _local_day(SENT_AT)
    assert _ids(_search({"query": "budget", "start_date": later}, session)) == ["tg:-100123:4573#a"]


def test_around_evidence_id_returns_neighbouring_parts_in_reading_order(retired: _Opener, session: str) -> None:
    out = _search({"around_evidence_id": "tg:-100123:4567#a", "query": "ignored"}, session)
    assert _ids(out) == ["tg:-100123:4567#a", "tg:-100123:4569#f1", "tg:-100123:4571#a", "tg:-100123:4571#q1"]
    middle = _search({"around_evidence_id": "tg:-100123:4571#q1"}, session)
    assert _ids(middle) == [
        "tg:-100123:4567#a",
        "tg:-100123:4569#f1",
        "tg:-100123:4571#a",
        "tg:-100123:4571#q1",
        "tg:-100123:4573#a",
        "tg:-100123:4575#a",
    ]
    assert middle["search"]["complete"] is True
    narrow = _search({"around_evidence_id": "tg:-100123:4571#q1", "limit": 2}, session)
    assert "tg:-100123:4571#q1" in _ids(narrow) and len(narrow["items"]) == 2
    assert _search({"around_evidence_id": "tg:-100123:9999#a"}, session)["items"] == []


def test_every_item_starts_with_a_head_line_naming_its_evidence_id(retired: _Opener, session: str) -> None:
    out = _search({"limit": 40}, session)
    assert len(out["items"]) == 8
    for item in out["items"]:
        lines = item["text"].split("\n")
        found = _HEAD.match(lines[0])
        assert found is not None and found.group(1) == item["evidence_id"]
        assert all(line.startswith("  ") for line in lines[1:])


def test_pseudonymize_replaces_names_and_titles(retired: _Opener, session: str) -> None:
    plain = json.dumps(_search({"query": "会議"}, session), ensure_ascii=False)
    assert "田中 太郎" in plain and "⟦" not in plain
    out = _search({"query": "会議", "pseudonymize": True}, session)
    text = json.dumps(out, ensure_ascii=False)
    assert "田中" not in text and "Team" not in text
    head = out["items"][0]["text"].split("\n", 1)[0]
    assert re.search(r"speaker: ⟦P\d+⟧ \(forwarded text; ", head) and "→ chat: ⟦C1⟧ / " in head
    assert "forwarded by account owner" in head  # the owner is a role, never an alias
    assert out["conversations"][0]["label"].startswith("✈ ⟦C1⟧ · ")


def test_limit_and_the_result_size_cap(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, session: str) -> None:
    imports = ImportStore(tmp_path / "mordred.db", _plain_opener)
    imports.initialize(tmp_path)
    long_text = "週次レポート " + "あいうえお" * 500  # 2507 characters
    _commit(imports, _other_conv(), [_other_message(n, f"{long_text} {n}", _OTHER_SENT_AT + n) for n in range(1, 61)])
    archive = store.ArchiveStore(_KEY, tmp_path / "tg")
    archive.save_index(store.ArchiveIndex(account_id=int(OWNER_ID), retired_to="mordred.db"))
    monkeypatch.setattr(hermes_tools, "_service", lambda: _service(tmp_path, _Opener(imports)))

    few = _search({"query": "週次レポート", "limit": 3}, session)
    assert few["search"] == {"mode": "fts", "candidates": 60, "returned": 3, "truncated": False, "complete": False}
    for item in few["items"]:
        body = item["text"].split("\n", 1)[1]
        assert body.endswith(TRUNCATION_MARKER) and len(body) <= search.MAX_BODY_CHARS + len(TRUNCATION_MARKER)

    capped = _search({"query": "週次レポート", "limit": 40}, session)
    assert capped["search"]["truncated"] is True and capped["search"]["complete"] is False
    assert 0 < capped["search"]["returned"] < 40
    assert len(json.dumps(capped, ensure_ascii=False)) <= search.MAX_RESULT_CHARS
    assert _search({"query": "週次レポート", "limit": 400}, session)["search"]["returned"] <= search.MAX_LIMIT


def test_each_call_opens_the_store_afresh(retired: _Opener, session: str) -> None:
    _search({"query": "budget"}, session)
    _search({"query": "budget"}, session)
    assert retired.opened == 2


def test_store_refusal_is_content_free(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, session: str) -> None:
    archive = store.ArchiveStore(_KEY, tmp_path / "tg")
    archive.save_index(store.ArchiveIndex(account_id=int(OWNER_ID), retired_to="mordred.db"))
    opener = _Opener(None, refusal="not_armed")
    monkeypatch.setattr(hermes_tools, "_service", lambda: _service(tmp_path, opener))
    assert _search({"query": "budget"}, session) == {"error": "import_store_unavailable"}
    assert opener.opened == 1  # never a fallback to .enc


# -- the legacy .enc archive ---------------------------------------------------------------------


def test_legacy_archive_is_searched_with_the_same_item_shape(legacy: _Opener, session: str) -> None:
    out = _search({"query": "MONDAY"}, session)
    assert _ids(out) == ["tg:-5:3#a", "tg:-5:1#a"]  # newest first
    assert out["search"] == {"mode": "legacy", "candidates": 2, "returned": 2, "truncated": False, "complete": True}
    item = out["items"][1]
    assert set(item) == {"evidence_id", "speaker_class", "part_kind", "provenance_quality", "text"}
    assert (item["speaker_class"], item["part_kind"], item["provenance_quality"]) == ("other", "authored", "legacy")
    head, body = item["text"].split("\n", 1)
    assert head.startswith("[Telegram tg:-5:1#a] speaker: Carol (legacy: forwards not distinguished) → chat: ")
    assert body == "  Budget review moved to Monday"
    assert out["conversations"][0]["conv_uid"] == "tg:-5"
    assert legacy.opened == 1  # mordred.db is probed first; its refusal leaves the unretired .enc archive


def test_legacy_archive_filters_and_neighbours(legacy: _Opener, session: str) -> None:
    owner = _search({"query": "thanks", "pseudonymize": True}, session)
    assert _ids(owner) == ["tg:-5:2#a"]
    assert "speaker: account owner (legacy" in owner["items"][0]["text"]
    assert _search({"query": "monday", "chat_ids": [-6]}, session)["items"] == []
    near = _search({"around_evidence_id": "tg:-5:1#a"}, session)
    assert _ids(near) == ["tg:-5:1#a", "tg:-5:2#a", "tg:-5:3#a"]
    # Without words, chats or dates the archive is read for its last week only: never "complete".
    assert _search({}, session)["search"]["complete"] is False


# -- choosing the source without unsealing the Telegram credentials -------------------------------


def _mail_message(message_id: str, text: str, sent_at: int) -> ImportMessage:
    uid = mail_uid(message_id)
    own = part(uid, author=TANAKA, text=text)
    quoted = part(uid, PartKind.QUOTED, 1, ordinal=1, author=OWNER, text="前回の件、承知しました")
    return message(uid, (own, quoted), conv_uid=MAIL_CONV_UID, sender=TANAKA, sent_at=sent_at, recipients=(OWNER,))


def _mail_store(tmp_path: Path) -> ImportStore:
    """Imported mail only: two messages of one thread, no Telegram rows and no retirement marker."""
    imports = ImportStore(tmp_path / "mordred.db", _plain_opener)
    imports.initialize(tmp_path)
    run = imports.run_begin(Source.MAIL)
    imports.write_thread(
        run,
        [
            _mail_message("m1@example.com", "見積もりは来週お送りします", SENT_AT),
            _mail_message("m2@example.com", "The budget draft is attached", SENT_AT + 60),
        ],
        conversation=mail_conv(),
    )
    imports.run_commit(run, {"inserted": 2})
    return imports


def _use(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, opener: _Opener, sealed: _Secrets) -> None:
    monkeypatch.setattr(hermes_tools, "_service", lambda: _service(tmp_path, opener, sealed))


def test_mail_only_home_is_searched_without_any_telegram_configuration(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, session: str
) -> None:
    opener, sealed = _Opener(_mail_store(tmp_path)), _Secrets(configured=False, forbidden=True)
    _use(monkeypatch, tmp_path, opener, sealed)
    assert not (tmp_path / "tg").exists()  # no Telegram archive, no index.enc, no credentials

    out = _search({"query": "見積もり"}, session)
    first = "mail:work:m1@example.com#a"
    assert _ids(out) == [first]
    head, body = out["items"][0]["text"].split("\n", 1)
    assert head.startswith(f"[Mail {first}] speaker: 田中 太郎") and body == "  見積もりは来週お送りします"
    assert out["search"] == {"mode": "fts", "candidates": 1, "returned": 1, "truncated": False, "complete": True}
    assert out["conversations"] == [{"conv_uid": MAIL_CONV_UID, "label": "✉ 見積もりの件 · 田中 太郎 ⇄ account owner"}]

    newest = _search({}, session)
    assert _ids(newest)[:2] == ["mail:work:m2@example.com#a", "mail:work:m2@example.com#q1"]
    quoted = newest["items"][1]
    assert (quoted["speaker_class"], quoted["part_kind"]) == ("account_owner", "quoted")
    near = _search({"around_evidence_id": first}, session)
    assert set(_ids(near)) == {first, "mail:work:m1@example.com#q1", *_ids(newest)[:2]}
    pseudonymized = _search({"query": "budget", "pseudonymize": True}, session)
    assert pseudonymized["conversations"][0]["label"].startswith("✉ ⟦C1⟧ · ⟦P")

    assert sealed.unseals == 0 and opener.opened == 4  # opened afresh per call, never unsealed


def test_a_retired_store_with_the_marker_is_searched_without_the_unseal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, retired: _Opener, session: str
) -> None:
    assert retired.imports is not None
    retired.imports.set_meta(TELEGRAM_RETIRED_ACCOUNT, OWNER_ID)
    sealed = _Secrets(forbidden=True)
    _use(monkeypatch, tmp_path, retired, sealed)
    out = _search({"query": "BUDGET"}, session)
    assert sorted(_ids(out)) == ["tg:-100123:4573#a", "tg:-200:7#a"] and out["search"]["mode"] == "fts"
    assert sealed.unseals == 0


def test_a_retired_index_without_the_marker_costs_one_unseal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, retired: _Opener, session: str
) -> None:
    sealed = _Secrets()  # retired by a Mordred that wrote no marker: index.enc is read once
    _use(monkeypatch, tmp_path, retired, sealed)
    assert sorted(_ids(_search({"query": "BUDGET"}, session))) == ["tg:-100123:4573#a", "tg:-200:7#a"]
    assert sealed.unseals == 1


def test_an_unmigrated_archive_is_searched_beside_the_store(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, legacy: _Opener, session: str
) -> None:
    opener, sealed = _Opener(_mail_store(tmp_path)), _Secrets()
    _use(monkeypatch, tmp_path, opener, sealed)
    out = _search({"query": "budget"}, session)
    assert _ids(out) == ["mail:work:m2@example.com#a", "tg:-5:1#a"]  # newest first across both
    assert out["search"] == {
        "mode": "fts+legacy",
        "candidates": 2,
        "returned": 2,
        "truncated": False,
        "complete": True,
    }
    assert [c["conv_uid"] for c in out["conversations"]] == [MAIL_CONV_UID, "tg:-5"]
    assert _ids(_search({"around_evidence_id": "mail:work:m1@example.com#a"}, session))[0].startswith("mail:")
    assert _ids(_search({"around_evidence_id": "tg:-5:1#a"}, session)) == ["tg:-5:1#a", "tg:-5:2#a", "tg:-5:3#a"]
    assert sealed.unseals == 3  # the .enc archive is the only reason to unseal
    empty = ImportStore(tmp_path / "empty.db", _plain_opener)
    empty.initialize(tmp_path)
    _use(monkeypatch, tmp_path, _Opener(empty), sealed)
    assert _search({"query": "budget"}, session)["search"]["mode"] == "legacy"  # nothing imported beside it


def test_a_marked_store_that_refuses_never_falls_back_to_enc(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, retired: _Opener, session: str
) -> None:
    assert retired.imports is not None
    retired.imports.set_meta(TELEGRAM_RETIRED_ACCOUNT, OWNER_ID)
    archive = store.ArchiveStore(_KEY, tmp_path / "tg")
    archive.append_messages(-5, [store.StoredMessage(id=1, date=SENT_AT, sender="Carol", text="stale budget row")])
    opener, sealed = _Opener(retired.imports, refusal="no_key"), _Secrets()
    _use(monkeypatch, tmp_path, opener, sealed)
    assert _search({"query": "budget"}, session) == {"error": "import_store_unavailable"}
    assert opener.opened == 1 and sealed.unseals == 1  # the marker is unreachable; index.enc names the store


@pytest.mark.parametrize(
    ("refusal", "code"),
    [("not_armed", "no_history"), ("unsupported_platform", "no_history"), ("no_key", "import_store_unavailable")],
)
def test_no_store_and_no_telegram_archive(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, session: str, refusal: str, code: str
) -> None:
    opener, sealed = _Opener(None, refusal=refusal), _Secrets(configured=False, forbidden=True)
    _use(monkeypatch, tmp_path, opener, sealed)
    assert _search({"query": "budget"}, session) == {"error": code}
    assert sealed.unseals == 0


def test_an_empty_store_and_no_telegram_archive_is_no_history(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, session: str
) -> None:
    imports = ImportStore(tmp_path / "mordred.db", _plain_opener)
    imports.initialize(tmp_path)
    sealed = _Secrets(forbidden=True)  # logged in, never synced: no index.enc
    _use(monkeypatch, tmp_path, _Opener(imports), sealed)
    assert _search({}, session) == {"error": "no_history"}
    assert sealed.unseals == 0
    (tmp_path / "other").mkdir()
    mail = _mail_store(tmp_path / "other")
    _use(monkeypatch, tmp_path, _Opener(mail), sealed)
    assert _search({"query": "absent words"}, session)["items"] == []  # history exists: an honest empty result


# -- arguments and gates -------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("args", "code"),
    [
        ({"query": 5}, "invalid_request"),
        ({"query": "x" * 1001}, "invalid_request"),
        ({"chat_ids": "-5"}, "invalid_request"),
        ({"chat_ids": list(range(1, 22))}, "invalid_request"),
        ({"chat_ids": ["abc"]}, "invalid_request"),
        ({"chat_ids": [0]}, "invalid_request"),
        ({"chat_ids": [True]}, "invalid_request"),
        ({"limit": "10"}, "invalid_request"),
        ({"pseudonymize": "yes"}, "invalid_request"),
        ({"start_date": "9/8"}, "invalid_date"),
        ({"start_date": "2026-10-15", "end_date": "2026-10-01"}, "invalid_date"),
        ({"end_date": 20261001}, "invalid_date"),
        ({"around_evidence_id": "tg:-5:1"}, "invalid_evidence_id"),
        ({"around_evidence_id": 7}, "invalid_evidence_id"),
    ],
)
def test_invalid_arguments_are_refused_before_anything_opens(
    retired: _Opener, session: str, args: dict[str, Any], code: str
) -> None:
    assert _search(args, session) == {"error": code}
    assert retired.opened == 0


@pytest.mark.parametrize("sid", [None, "", "never-entered-reader-mode"])
def test_refused_unless_the_hook_put_the_session_into_reader_mode(
    retired: _Opener, monkeypatch: pytest.MonkeyPatch, sid: str | None
) -> None:
    monkeypatch.setattr(hermes_tools, "_service", lambda: pytest.fail("the archive must not be opened"))
    out = _search({"query": "budget"}, sid)
    assert out["error"] == "reader_mode_unavailable" and set(out) == {"error", "note"}
    assert retired.opened == 0


def test_succeeds_once_the_session_is_in_reader_mode(retired: _Opener) -> None:
    sid = f"search-{uuid.uuid4().hex}"
    assert _search({"query": "budget"}, sid)["error"] == "reader_mode_unavailable"
    egress.mark_reader(sid)
    try:
        assert _ids(_search({"query": "budget", "chat_ids": [_OTHER_DIALOG]}, sid)) == ["tg:-200:7#a"]
    finally:
        with egress._SESSIONS.lock:
            egress._SESSIONS.reader.discard(sid)
            egress._SESSIONS.tainted.discard(sid)


def test_endpoint_gate_refusal_is_unchanged(retired: _Opener, session: str) -> None:
    agent = SimpleNamespace(model="m", base_url="https://api.openai.com/v1")
    assert _search({"query": "budget"}, session, agent) == {"error": "hermes_model_not_allowed"}
    assert retired.opened == 0


def test_search_history_reads_records_directly() -> None:
    conv = tg_conv()
    records = [(conv, _team_messages())]
    result = search.search_history(records, search.SearchRequest(query="later", limit=1))
    assert result.mode == "legacy" and [i.evidence_id for i in result.items] == ["tg:-100123:4577#a"]
    assert (result.candidates, result.complete, result.truncated) == (2, False, False)
    tight = search.search_history(records, search.SearchRequest(query="later"), budget=10)
    assert tight.items == () and tight.truncated is True and tight.conversations == ()
