"""Two-pass import planning: linking, Sent precedence, conflicts, report privacy, preview."""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from mordred_hermes.imports.mail import (
    EmlBytes,
    EmlSource,
    ImportPlan,
    LinkedAuthor,
    MboxBytes,
    MboxSource,
    QuoteClaim,
    SourceError,
    plan_import,
)
from mordred_hermes.imports.records import (
    OwnerClass,
    RecordError,
    validate_conversation,
    validate_message,
)

FIXTURES = Path(__file__).parent / "fixtures" / "mail"
OWN = ["owner@example.com", "owner.alias@example.org"]
IMPORTED_AT = 1_800_000_000
ALL_SOURCES = (
    MboxSource(FIXTURES / "takeout_small.mbox"),
    MboxSource(FIXTURES / "mboxo_from_escape.mbox"),
    EmlSource(FIXTURES),
)
OWNER_ORIGINAL = (
    "Message-ID: <orig1@mail.example.com>\nDate: Tue, 06 Oct 2026 09:30:20 +0900\nFrom: owner@example.com\n"
    "To: jiro@example.org\nSubject: Meeting\nContent-Type: text/plain; charset=UTF-8\n"
    "Content-Transfer-Encoding: 8bit\n\n田中さん\n\n来週の打ち合わせは木曜でお願いします。CANARY-OUTLOOK-ORIGINAL\n"
).encode()


def plan(*sources: object, **kwargs: object) -> ImportPlan:
    options: dict[str, object] = {"account": "work", "own_addresses": OWN, "imported_at": IMPORTED_AT}
    options.update(kwargs)
    return plan_import(sources, **options)  # type: ignore[arg-type]


def message(plan_: ImportPlan, source_uid: str):  # type: ignore[no-untyped-def]
    return next(msg for msg in plan_.messages() if msg.source_uid == source_uid)


def authors(plan_: ImportPlan, source_uid: str) -> list[tuple[str, str]]:
    return [(p.author_owner_class.value, p.author_evidence) for p in message(plan_, source_uid).parts]


def mbox(*messages: bytes) -> MboxBytes:
    return MboxBytes(b"".join(b"From x Mon Oct  5 10:00:00 2026\n" + item + b"\n" for item in messages))


def test_takeout_plan_threads_and_links_quotes_to_owner_records() -> None:
    result = plan(MboxSource(FIXTURES / "takeout_small.mbox"))
    assert [(t.conversation.conv_uid, t.method, t.partial) for t in result.threads] == [
        ("mail:work:t:g.1790000000000000001", "gmail_thrid", False),
        ("mail:work:t:g.1790000000000000004", "gmail_thrid", False),
    ]
    first = result.threads[0]
    assert first.conversation.title == "見積もりの件 SUBJCANARY-A"
    assert [m.source_uid for m in first.messages] == [
        "mail:work:a1@mail.example.net",
        "mail:work:a2@mail.example.com",
        "mail:work:a3@mail.example.net",
    ]
    assert [(p.display_name, p.owner_class.value) for p in first.conversation.participants] == [
        ("山田太郎", "other"),
        ("佐々木 葵", "account_owner"),
    ]
    # The owner's words quoted back by Taro link to the Sent record (In-Reply-To + containment).
    assert authors(result, "mail:work:a3@mail.example.net") == [
        ("other", "from_address"),
        ("account_owner", "linked_message_id"),
        ("other", "attribution_address"),
    ]
    q1 = message(result, "mail:work:a3@mail.example.net").parts[1]
    assert q1.original_ref == "mail:work:a2@mail.example.com"
    # A Sent record from an address missing from the own list still links (Gmail filed it as sent).
    assert authors(result, "mail:work:b2@mail.example.org")[1] == ("account_owner", "linked_message_id")
    report = result.report
    assert report.skipped == {"label_draft": 1, "label_spam": 1}
    assert report.sent_from_not_own == ("owner.old@example.org",)
    assert report.owner_classes == {"other:from_address": 3, "account_owner:gmail_label_sent": 2}
    assert report.labels["Sent"] == 2 and report.labels["Category: Personal"] == 1


def test_outlook_quote_links_by_address_and_date_only_with_the_owner_record() -> None:
    alone = plan(EmlSource(FIXTURES / "outlook_ja_reply.eml"))
    assert authors(alone, "mail:work:outlook1@example.org")[1] == ("unknown", "claimed_own_unlinked")
    linked = plan(EmlBytes([OWNER_ORIGINAL]), EmlSource(FIXTURES / "outlook_ja_reply.eml"))
    assert authors(linked, "mail:work:outlook1@example.org")[1] == ("account_owner", "linked_address_date")


def test_exact_text_links_an_unattributed_quote() -> None:
    reply = (
        "Message-ID: <r9@example.net>\nFrom: x@example.net\nSubject: Re\nContent-Type: text/plain; charset=UTF-8\n"
        "Content-Transfer-Encoding: 8bit\n\nok\n\n"
        "> 田中さん\n>\n> 来週の打ち合わせは木曜で\n> お願いします。CANARY-OUTLOOK-ORIGINAL\n"  # re-wrapped
    ).encode()
    result = plan(EmlBytes([reply, OWNER_ORIGINAL]))  # the owner record comes later in the source
    assert authors(result, "mail:work:r9@example.net")[1] == ("account_owner", "linked_text_hash")


def test_altered_quote_of_an_owner_message_never_links() -> None:
    forged = (
        "Message-ID: <r10@example.net>\nIn-Reply-To: <orig1@mail.example.com>\nFrom: x@example.net\n"
        "Date: Tue, 06 Oct 2026 11:00:00 +0900\nSubject: Re\nContent-Type: text/plain; charset=UTF-8\n"
        "Content-Transfer-Encoding: 8bit\n\nsee below\n\n"
        "2026年10月6日(火) 9:30 佐々木 葵 <owner@example.com>:\n> 打ち合わせは中止です。全額返金します。\n"
    ).encode()
    result = plan(EmlBytes([OWNER_ORIGINAL, forged]))
    assert authors(result, "mail:work:r10@example.net")[1] == ("unknown", "claimed_own_unlinked")


@pytest.mark.parametrize("sent_first", [True, False])
def test_sent_copy_wins_and_differing_copies_are_conflicts(sent_first: bool) -> None:
    body = b"Message-ID: <dup@example.com>\nFrom: alias@example.net\nSubject: s\n\nhello\n"
    received, sent = b"X-Gmail-Labels: Inbox\n" + body, b"X-Gmail-Labels: Sent\n" + body
    result = plan(mbox(*((sent, received) if sent_first else (received, sent))))
    (only,) = list(result.messages())
    assert only.owner_evidence == "gmail_label_sent"
    assert (result.report.conflicts, result.report.duplicates, result.report.parsed) == (1, 0, 1)


def test_identical_copies_are_duplicates() -> None:
    raw = b"Message-ID: <same@example.com>\nFrom: a@example.net\nSubject: s\n\nhello\n"
    result = plan(mbox(raw, raw))
    assert (result.report.duplicates, result.report.conflicts, result.report.parsed) == (1, 0, 1)


def test_full_plan_validates_and_is_idempotent() -> None:
    first, second = plan(*ALL_SOURCES), plan(*ALL_SOURCES)
    assert first.threads == second.threads
    assert first.report == second.report
    for thread in first.threads:
        validate_conversation(thread.conversation)
        assert thread.conversation.message_count == len(thread.messages)
        for msg in thread.messages:
            validate_message(msg)
            assert msg.conv_uid == thread.conversation.conv_uid
    report = first.report
    assert report.parsed == 19
    assert report.unknown_dates == 1
    assert report.html_only == 1
    assert report.charset_fallbacks >= 3
    assert report.attachment_kinds == {"document": 1, "image": 1, "rfc822": 1}
    assert report.owner_classes["unknown:dmarc_fail"] == 1
    assert report.sender_kinds["bot"] == 1
    assert report.parts_by_kind["forwarded"] == 3
    assert report.marker_locales["forward_banner:ja"] == 2
    assert 0 < report.unknown_author_share < 1
    assert report.unknown_author_share == round(
        report.unknown_author_quote_forward_parts / report.quote_forward_parts, 4
    )


def _fixture_secrets() -> set[str]:
    found: set[str] = set()
    for path in FIXTURES.iterdir():
        text = path.read_bytes().decode("utf-8", errors="ignore")
        found.update(re.findall(r"(?:SUBJ)?CANARY-[A-Z0-9-]+|KM-\d+", text))
    names = ["山田太郎", "佐々木 葵", "鈴木花子", "佐藤一郎", "田中次郎", "Taro Yamada", "Hanako Suzuki"]
    subjects = ["見積もりの件", "ランチ", "打ち合わせ", "リリース手順", "Your verification code"]
    return found | set(names) | set(subjects) | {"taro@example.net", "hanako@example.org"}


def test_report_never_contains_content_names_subjects_or_other_addresses() -> None:
    report = plan(*ALL_SOURCES).report
    secrets = _fixture_secrets()
    assert len(secrets) > 40
    for rendered in (report.as_text(), report.as_json()):
        leaked = sorted(secret for secret in secrets if secret in rendered)
        assert leaked == []
    data = json.loads(report.as_json())
    assert data["sent_from_not_own"] == ["owner.old@example.org"]
    assert data["parsed"] == 19


def test_preview_shows_labels_and_head_lines_but_never_bodies() -> None:
    result = plan(*ALL_SOURCES)
    lines = result.preview(100)
    assert lines[0].startswith("✉ ")
    assert any(line.startswith("[Mail mail:work:a3@mail.example.net#q1] speaker: account owner") for line in lines)
    joined = "\n".join(lines)
    body_secrets = {s for s in _fixture_secrets() if s.startswith(("CANARY-", "KM-"))}
    assert sorted(secret for secret in body_secrets if secret in joined) == []
    assert len(result.preview(1)) < len(lines)
    assert result.preview(0) == []


def test_external_linker_is_consulted_after_the_index() -> None:
    claims: list[QuoteClaim] = []

    def linker(claim: QuoteClaim) -> LinkedAuthor | None:
        claims.append(claim)
        return None

    result = plan(MboxSource(FIXTURES / "takeout_small.mbox"), linker=linker)
    linked_by_index = message(result, "mail:work:a3@mail.example.net").parts[1]
    assert linked_by_index.author_owner_class is OwnerClass.ACCOUNT_OWNER
    assert {claim.container_uid for claim in claims} == {
        "mail:work:a2@mail.example.com",
        "mail:work:a3@mail.example.net",
    }
    assert all(len(claim.text_digest) == 64 for claim in claims)


def test_invalid_inputs_raise_content_free_codes(tmp_path: Path) -> None:
    with pytest.raises(RecordError) as account:
        plan(MboxSource(FIXTURES / "takeout_small.mbox"), account="owner@example.com")
    assert account.value.code == "bad_account"
    with pytest.raises(ValueError, match="bad_own_address"):
        plan(MboxSource(FIXTURES / "takeout_small.mbox"), own_addresses=["nobody"])
    with pytest.raises(SourceError) as missing:
        plan(MboxSource(tmp_path / "missing.mbox"))
    assert missing.value.code == "not_found"
    assert not (tmp_path / "missing.mbox").exists()


def test_plan_repr_is_counts_only() -> None:
    result = plan(MboxSource(FIXTURES / "takeout_small.mbox"))
    assert repr(result) == "ImportPlan(threads=2, messages=5)"
