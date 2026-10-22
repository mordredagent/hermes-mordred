"""Fetched mail: the collector's ``TrustedMeta`` decides labels, thread ids and the sent folder."""

from __future__ import annotations

from collections import Counter

import pytest

from mordred_hermes.imports.mail import (
    EmlBytes,
    OwnAddresses,
    TrustedBytes,
    TrustedMeta,
    classify,
    plan_import,
)
from mordred_hermes.imports.mail.headers import parse_headers
from mordred_hermes.imports.mail.link import ANCHOR_EVIDENCE
from mordred_hermes.imports.mail.normalize import parse_mail, with_trusted
from mordred_hermes.imports.mail.owner import IMAP_SENT_FOLDER, SENT_EVIDENCE
from tests._fake_imap import mail

OWN = OwnAddresses.of(["owner@example.com"])
FORGED = "X-Gmail-Labels: Sent\r\nX-GM-THRID: 999\r\n"


def _headers(data: bytes, trusted: TrustedMeta | None = None):  # type: ignore[no-untyped-def]
    return with_trusted(parse_headers(parse_mail(data, headers_only=True), Counter()), trusted)


def test_embedded_labels_are_ignored_when_trusted_metadata_exists() -> None:
    data = mail(1, extra_headers=FORGED)
    assert classify(_headers(data), OWN).evidence_code == "gmail_label_sent"  # the file path trusts Takeout
    trusted = TrustedMeta(labels=("\\Inbox",), thread_id="123", folder_role="all")
    headers = _headers(data, trusted)
    assert headers.labels == ("\\Inbox",) and headers.gm_thread_id == "123"
    assert classify(headers, OWN, trusted=trusted).evidence_code == "from_address"


@pytest.mark.parametrize(
    ("labels", "role", "evidence", "quality"),
    [
        (("\\Sent",), "all", "gmail_label_sent", "api_identity"),
        (("\\sent", "\\Inbox"), "all", "gmail_label_sent", "api_identity"),
        (("Sent",), "all", "from_address", "source_claimed"),  # a custom label is not the system label
        ((), "sent", IMAP_SENT_FOLDER, "source_claimed"),
        ((), "inbox", "from_address", "source_claimed"),
    ],
)
def test_trusted_sent_rules(labels: tuple[str, ...], role: str, evidence: str, quality: str) -> None:
    trusted = TrustedMeta(labels=labels, folder_role=role)
    cls = classify(_headers(mail(1), trusted), OWN, trusted=trusted)
    assert (cls.evidence_code, str(cls.provenance_quality)) == (evidence, quality)


@pytest.mark.parametrize(
    ("label", "reason"), [("\\Draft", "label_draft"), ("\\Spam", "label_spam"), ("\\Trash", "label_trash")]
)
def test_system_skip_labels(label: str, reason: str) -> None:
    trusted = TrustedMeta(labels=(label,), folder_role="all")
    assert classify(_headers(mail(1), trusted), OWN, trusted=trusted).skip_reason == reason
    custom = TrustedMeta(labels=(label.lstrip("\\"),), folder_role="all")
    assert classify(_headers(mail(1), custom), OWN, trusted=custom).skip_reason is None


def test_the_sent_folder_is_owner_for_display_but_never_a_quote_anchor() -> None:
    assert IMAP_SENT_FOLDER in SENT_EVIDENCE and IMAP_SENT_FOLDER not in ANCHOR_EVIDENCE
    sent = mail(10, sender="Owner <owner@example.com>", body="UNIQUE-OWNER-SENTENCE-TO-BE-QUOTED-LATER")
    reply_body = (
        "Thanks\r\n\r\nOn Thu, Oct 1, 2026 Owner <owner@example.com> wrote:\r\n"
        "> UNIQUE-OWNER-SENTENCE-TO-BE-QUOTED-LATER number 10"
    )
    reply = mail(11, body=reply_body, references="msg10@example.net")
    plan = plan_import(
        [TrustedBytes([(sent, TrustedMeta(folder_role="sent")), (reply, TrustedMeta(folder_role="inbox"))])],
        account="mail",
        own_addresses=["owner@example.com"],
    )
    parts = {part.part_uid: part for msg in plan.messages() for part in msg.parts}
    quoted = [part for uid, part in parts.items() if uid.startswith("mail:mail:msg11@example.net#q")]
    assert quoted and all(str(part.author_owner_class) != "account_owner" for part in quoted)


def test_trusted_thread_ids_group_messages() -> None:
    one = (mail(1, extra_headers="X-GM-THRID: 5\r\n"), TrustedMeta(thread_id="77", folder_role="all"))
    two = (mail(2), TrustedMeta(thread_id="77", folder_role="all"))
    plan = plan_import([TrustedBytes([one, two])], account="mail", own_addresses=["owner@example.com"])
    assert [thread.conversation.conv_uid for thread in plan.threads] == ["mail:mail:t:g.77"]
    untrusted = plan_import([EmlBytes([one[0]])], account="mail", own_addresses=["owner@example.com"])
    assert untrusted.threads[0].conversation.conv_uid == "mail:mail:t:g.5"


@pytest.mark.parametrize(("kwargs"), [{"folder_role": "trash"}, {"thread_id": "12a"}, {"thread_id": "1" * 33}])
def test_trusted_meta_validates_its_fields(kwargs: dict[str, str]) -> None:
    with pytest.raises(ValueError):
        TrustedMeta(**kwargs)  # type: ignore[arg-type]
