"""Store-backed quote linking (``StoreLinker``), ``ImportStore.find_messages`` and own-address rows."""

from __future__ import annotations

import json
import sqlite3
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Any

import pytest

from mordred_hermes.imports.mail import (
    EmlBytes,
    ImportPlan,
    MboxSource,
    QuoteClaim,
    StoreLinker,
    mail_store_status,
    plan_import,
    remember_own_addresses,
    stored_own_addresses,
)
from mordred_hermes.imports.mail._text import link_key
from mordred_hermes.imports.mail.link import text_digest
from mordred_hermes.imports.records import OwnerClass, PartKind, RecordError
from mordred_hermes.imports.store import ImportRefused, ImportStore

FIXTURES = Path(__file__).parent / "fixtures" / "mail"
OWN = ["owner@example.com"]
IMPORTED_AT = 1_800_000_000
ORIGINAL_UID = "mail:work:orig1@mail.example.com"
ORIGINAL_TEXT = "来週の打ち合わせは木曜でお願いします。CANARY-STORE-ORIGINAL"
ORIGINAL_AT = int(parsedate_to_datetime("Tue, 06 Oct 2026 09:30:20 +0900").timestamp())


def _eml(*headers: str, body: str) -> bytes:
    head = "\n".join(
        (*headers, "Subject: Meeting", "Content-Type: text/plain; charset=UTF-8", "Content-Transfer-Encoding: 8bit")
    )
    return f"{head}\n\n{body}".encode()


def original(*, sent: bool = True) -> bytes:
    """The owner's message; only a Sent-labelled copy may anchor a quote link."""
    labels = ("X-Gmail-Labels: Sent",) if sent else ()
    return _eml(
        *labels,
        "Message-ID: <orig1@mail.example.com>",
        "Date: Tue, 06 Oct 2026 09:30:20 +0900",
        "From: owner@example.com",
        "To: jiro@example.org",
        body=f"田中さん\n\n{ORIGINAL_TEXT}\n",
    )


ATTRIBUTION = "2026年10月6日(火) 9:30 佐々木 葵 <owner@example.com>:"


def reply(*, in_reply_to: bool = True, attributed: bool = True, quote: str = ORIGINAL_TEXT) -> bytes:
    headers = ["Message-ID: <r1@example.net>", "From: jiro@example.org", "Date: Tue, 06 Oct 2026 11:00:00 +0900"]
    if in_reply_to:
        headers.append("In-Reply-To: <orig1@mail.example.com>")
    lead = f"{ATTRIBUTION}\n" if attributed else ""
    return _eml(*headers, body=f"了解です。\n\n{lead}> {quote}\n")


def unattributed_full_quote() -> bytes:
    """The whole original re-wrapped, with no attribution and no reference header."""
    headers = ("Message-ID: <r2@example.net>", "From: jiro@example.org", "Date: Tue, 06 Oct 2026 12:00:00 +0900")
    return _eml(
        *headers, body="ok\n\n> 田中さん\n>\n> 来週の打ち合わせは木曜で\n> お願いします。CANARY-STORE-ORIGINAL\n"
    )


@pytest.fixture
def store(tmp_path: Path) -> ImportStore:
    db = ImportStore(tmp_path / "mordred.db", sqlite3.connect)
    db.initialize(tmp_path)
    return db


def plan(*messages: bytes, account: str = "work", linker: Any = None) -> ImportPlan:
    return plan_import(
        [EmlBytes(list(messages))], account=account, own_addresses=OWN, linker=linker, imported_at=IMPORTED_AT
    )


def commit(store: ImportStore, result: ImportPlan, *, fail: bool = False) -> None:
    run = store.run_begin("mail")
    for thread in result.threads:
        store.write_thread(run, thread.messages, conversation=thread.conversation)
    (store.run_fail if fail else store.run_commit)(run, {"parsed": result.report.parsed})


def quote_author(result: ImportPlan, source_uid: str) -> tuple[str, str, str | None]:
    msg = next(m for m in result.messages() if m.source_uid == source_uid)
    part = next(p for p in msg.parts if p.part_kind is PartKind.QUOTED)
    return part.author_owner_class.value, part.author_evidence, part.original_ref


def claim(text: str = ORIGINAL_TEXT, **overrides: Any) -> QuoteClaim:
    key = link_key(text)
    fields: dict[str, Any] = {
        "container_uid": "mail:work:r1@example.net",
        "kind": PartKind.QUOTED,
        "claimed_address": None,
        "claimed_name": "",
        "claimed_at": None,
        "claimed_message_id": None,
        "reply_message_ids": (),
        "text": text,
        "text_key": key,
        "text_digest": text_digest(key),
    }
    fields.update(overrides)
    return QuoteClaim(**fields)


# --- the three link paths through plan_import ------------------------------------------------------


def test_without_the_store_a_quote_of_an_earlier_import_stays_unlinked(store: ImportStore) -> None:
    commit(store, plan(original()))
    assert quote_author(plan(reply()), "mail:work:r1@example.net")[:2] == ("unknown", "claimed_own_unlinked")


def test_store_links_by_message_id(store: ImportStore) -> None:
    commit(store, plan(original()))
    linker = StoreLinker(store, "work")
    result = plan(reply(), linker=linker)
    assert quote_author(result, "mail:work:r1@example.net") == ("account_owner", "linked_message_id", ORIGINAL_UID)
    assert linker.records == 1
    assert linker.error is None


def test_store_links_by_address_and_date(store: ImportStore) -> None:
    commit(store, plan(original()))
    result = plan(reply(in_reply_to=False), linker=StoreLinker(store, "work"))
    assert quote_author(result, "mail:work:r1@example.net") == ("account_owner", "linked_address_date", ORIGINAL_UID)


def test_store_links_an_unattributed_whole_quote_by_text_hash(store: ImportStore) -> None:
    commit(store, plan(original()))
    result = plan(unattributed_full_quote(), linker=StoreLinker(store, "work"))
    assert quote_author(result, "mail:work:r2@example.net") == ("account_owner", "linked_text_hash", ORIGINAL_UID)


def test_altered_quote_never_links_even_with_every_reference(store: ImportStore) -> None:
    commit(store, plan(original()))
    forged = reply(quote="打ち合わせは中止です。全額返金します。CANARY-STORE-FORGED")
    result = plan(forged, linker=StoreLinker(store, "work"))
    assert quote_author(result, "mail:work:r1@example.net")[:2] == ("unknown", "claimed_own_unlinked")


# --- the linker directly ---------------------------------------------------------------------------


def test_every_path_requires_containment(store: ImportStore) -> None:
    commit(store, plan(original()))
    linker = StoreLinker(store, "work")
    by_id = {"reply_message_ids": ("orig1@mail.example.com",)}
    by_date = {"claimed_address": "owner@example.com", "claimed_at": ORIGINAL_AT + 30}
    for refs in (by_id, by_date):
        found = linker(claim(**refs))
        assert found is not None and found.original_ref == ORIGINAL_UID
        assert found.owner_class is OwnerClass.ACCOUNT_OWNER
        assert linker(claim("これは元のメールに無い文章です。CANARY-STORE-NOT-CONTAINED", **refs)) is None
    assert linker(claim(**{**by_date, "claimed_at": ORIGINAL_AT + 601})) is None  # outside ±10 min
    assert linker(claim(**{**by_date, "claimed_address": "other@example.com"})) is None
    # A short quote ("ok") is contained in almost anything: it links only as the whole text.
    assert linker(claim("木曜", **by_id)) is None


def test_container_itself_is_never_its_own_anchor(store: ImportStore) -> None:
    commit(store, plan(original()))
    linker = StoreLinker(store, "work")
    assert linker(claim(container_uid=ORIGINAL_UID, reply_message_ids=("orig1@mail.example.com",))) is None


def test_account_scoping(store: ImportStore) -> None:
    commit(store, plan(original()))
    refs = {"reply_message_ids": ("orig1@mail.example.com",)}
    assert StoreLinker(store, "work")(claim(**refs)) is not None
    assert StoreLinker(store, "home")(claim(**refs)) is None
    other = plan(reply(), account="home", linker=StoreLinker(store, "home"))
    assert quote_author(other, "mail:home:r1@example.net")[:2] == ("unknown", "claimed_own_unlinked")
    with pytest.raises(RecordError):
        StoreLinker(store, "owner@example.com")


def test_only_committed_sent_copies_anchor_links(store: ImportStore, tmp_path: Path) -> None:
    # An own-address record (no Sent label) is the owner for display, but its From is typed by anyone.
    commit(store, plan(original(sent=False)))
    refs = {"reply_message_ids": ("orig1@mail.example.com",)}
    assert StoreLinker(store, "work")(claim(**refs)) is None
    # A Sent copy written by a run that failed is invisible.
    failed = ImportStore(tmp_path / "failed.db", sqlite3.connect)
    failed.initialize(tmp_path)
    commit(failed, plan(original()), fail=True)
    assert StoreLinker(failed, "work")(claim(**refs)) is None
    commit(failed, plan(original()))
    assert StoreLinker(failed, "work")(claim(**refs)) is not None


def test_store_failure_disables_linking_with_a_code_and_queries_once(
    store: ImportStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[str] = []

    def refuse(*args: Any, **kwargs: Any) -> list[Any]:
        calls.append("find")
        raise ImportRefused("busy")

    monkeypatch.setattr(store, "find_messages", refuse)
    linker = StoreLinker(store, "work")
    assert linker(claim(reply_message_ids=("orig1@mail.example.com",))) is None
    assert linker(claim()) is None
    assert (linker.error, calls) == ("busy", ["find"])
    assert "busy" in repr(linker) and "CANARY" not in repr(linker)


def test_linker_loads_lazily_and_once(store: ImportStore, monkeypatch: pytest.MonkeyPatch) -> None:
    commit(store, plan(original()))
    calls: list[dict[str, Any]] = []
    real = store.find_messages

    def counting(*args: Any, **kwargs: Any) -> Any:
        calls.append(kwargs)
        return real(*args, **kwargs)

    monkeypatch.setattr(store, "find_messages", counting)
    linker = StoreLinker(store, "work")
    assert calls == [] and "unloaded" in repr(linker)
    linker(claim())
    linker(claim(reply_message_ids=("orig1@mail.example.com",)))
    assert calls == [{"owner_class": OwnerClass.ACCOUNT_OWNER}]


# --- ImportStore.find_messages ---------------------------------------------------------------------


@pytest.fixture
def takeout(store: ImportStore) -> ImportStore:
    commit(store, plan_import([MboxSource(FIXTURES / "takeout_small.mbox")], account="work", own_addresses=OWN))
    return store


def _uids(found: list[Any]) -> list[tuple[str, str]]:
    return [(item.message.source_uid.rsplit(":", 1)[-1], item.part.part_kind.value) for item in found]


def test_find_messages_returns_every_part_in_reading_order(takeout: ImportStore) -> None:
    everything = takeout.find_messages("mail", "work")
    assert [uid for uid, _ in _uids(everything)] == [
        "a1@mail.example.net",
        "a2@mail.example.com",
        "a2@mail.example.com",
        "a3@mail.example.net",
        "a3@mail.example.net",
        "a3@mail.example.net",
        "b1@mail.example.org",
        "b2@mail.example.org",
        "b2@mail.example.org",
    ]
    assert all(item.conversation.source_account == "work" for item in everything)
    assert [item.part.ordinal for item in everything[3:6]] == [0, 1, 2]


def test_find_messages_filters(takeout: ImportStore) -> None:
    by_id = takeout.find_messages("mail", "work", message_ids=["a2@mail.example.com", "nope@example.com"])
    assert _uids(by_id) == [("a2@mail.example.com", "authored"), ("a2@mail.example.com", "quoted")]
    many = [f"x{n}@example.com" for n in range(600)] + ["b1@mail.example.org"]  # more than one IN chunk
    assert _uids(takeout.find_messages("mail", "work", message_ids=many)) == [("b1@mail.example.org", "authored")]
    assert takeout.find_messages("mail", "work", message_ids=[]) == []
    by_sender = takeout.find_messages("mail", "work", sender_address="TARO@Example.NET")
    assert sorted({uid for uid, _ in _uids(by_sender)}) == ["a1@mail.example.net", "a3@mail.example.net"]
    a2_at = 1_791_165_600
    window = takeout.find_messages("mail", "work", sent_between=(a2_at, a2_at))
    assert {uid for uid, _ in _uids(window)} == {"a2@mail.example.com"}
    owners = takeout.find_messages("mail", "work", owner_class=OwnerClass.ACCOUNT_OWNER)
    assert sorted({uid for uid, _ in _uids(owners)}) == ["a2@mail.example.com", "b1@mail.example.org"]
    combined = takeout.find_messages(
        "mail", "work", owner_class="account_owner", sender_address="owner.old@example.org"
    )
    assert _uids(combined) == [("b1@mail.example.org", "authored")]
    assert takeout.find_messages("mail", "home") == []
    assert takeout.find_messages("telegram", "work") == []
    with pytest.raises(RecordError) as bad:
        takeout.find_messages("mail", "work", owner_class="nobody")
    assert bad.value.code == "unknown_enum"


def test_find_messages_hides_uncommitted_rows(store: ImportStore) -> None:
    run = store.run_begin("mail")
    result = plan(original())
    for thread in result.threads:
        store.write_thread(run, thread.messages, conversation=thread.conversation)
    assert store.find_messages("mail", "work") == []
    store.run_commit(run, {})
    assert [item.message.source_uid for item in store.find_messages("mail", "work")] == [ORIGINAL_UID]


# --- own addresses and status ----------------------------------------------------------------------


def test_own_addresses_merge_per_account_and_status_counts_only(takeout: ImportStore) -> None:
    assert stored_own_addresses(takeout, "work") == frozenset()
    assert remember_own_addresses(takeout, "work", ["owner@example.com"]) == 1
    assert remember_own_addresses(takeout, "work", ["owner.old@example.org", "owner@example.com"]) == 2
    assert remember_own_addresses(takeout, "home", ["me@example.net"]) == 1
    assert stored_own_addresses(takeout, "work") == {"owner@example.com", "owner.old@example.org"}
    status = mail_store_status(takeout)
    assert status["accounts"] == {"home": {"own_addresses": 1}, "work": {"own_addresses": 2}}
    assert status["mail"]["messages"] == 5
    assert status["runs"] == {"committed": 1}
    assert status["last_run"]["state"] == "committed"
    assert "@" not in json.dumps(status["accounts"])
    assert takeout.delete_source("mail", "work") == 5
    assert stored_own_addresses(takeout, "work") == frozenset()


def test_corrupt_own_address_row_fails_closed(store: ImportStore) -> None:
    with store.connection() as conn:
        conn.execute("INSERT INTO import_accounts VALUES ('mail', 'work', '{\"not\": \"a list\"}')")
    with pytest.raises(ImportRefused) as refused:
        stored_own_addresses(store, "work")
    assert refused.value.code == "store_unavailable"
    with pytest.raises(ImportRefused):
        remember_own_addresses(store, "work", ["owner@example.com"])
