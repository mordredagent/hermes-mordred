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
from mordred_hermes.imports.mail._imap_codec import SystemLabel, fetch_records, gmail_labels, system_label
from mordred_hermes.imports.mail.headers import parse_headers
from mordred_hermes.imports.mail.link import ANCHOR_EVIDENCE
from mordred_hermes.imports.mail.normalize import parse_mail, with_trusted
from mordred_hermes.imports.mail.owner import IMAP_SENT_FOLDER, SENT_EVIDENCE
from tests._fake_imap import mail

OWN = OwnAddresses.of(["owner@example.com"])
FORGED = "X-Gmail-Labels: Sent\r\nX-GM-THRID: 999\r\n"


def _headers(data: bytes, trusted: TrustedMeta | None = None):  # type: ignore[no-untyped-def]
    return with_trusted(parse_headers(parse_mail(data, headers_only=True), Counter()), trusted)


def _system(*labels: str) -> tuple[str, ...]:
    """Labels as the collector hands them over: wire-recognised system labels, else plain custom labels."""
    return tuple(system_label(label) or label for label in labels)


def test_embedded_labels_are_ignored_when_trusted_metadata_exists() -> None:
    data = mail(1, extra_headers=FORGED)
    assert classify(_headers(data), OWN).evidence_code == "gmail_label_sent"  # the file path trusts Takeout
    trusted = TrustedMeta(labels=_system("\\Inbox"), thread_id="123", folder_role="all")
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
    trusted = TrustedMeta(labels=_system(*labels), folder_role=role)
    cls = classify(_headers(mail(1), trusted), OWN, trusted=trusted)
    assert (cls.evidence_code, str(cls.provenance_quality)) == (evidence, quality)


@pytest.mark.parametrize(
    ("label", "reason"), [("\\Draft", "label_draft"), ("\\Spam", "label_spam"), ("\\Trash", "label_trash")]
)
def test_system_skip_labels(label: str, reason: str) -> None:
    trusted = TrustedMeta(labels=_system(label), folder_role="all")
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


@pytest.mark.parametrize(
    "wire",
    [
        b'" \\\\Sent "',  # a custom label " \Sent ": no trimming turns it into the system label
        b"&AFw-Sent",  # modified UTF-7 for "\Sent": decoded AFTER the system-label check
        b'"&AFw-sent"',
        b'"\\\\Sent\\\\"',
    ],
)
def test_custom_labels_that_decode_to_a_system_name_never_classify(wire: bytes) -> None:
    [record] = fetch_records([b"1 (UID 1 X-GM-LABELS (" + wire + b"))"])
    labels = gmail_labels(record["X-GM-LABELS"])
    assert labels and not any(isinstance(label, SystemLabel) for label in labels)
    trusted = TrustedMeta(labels=labels, folder_role="all")
    cls = classify(_headers(mail(1), trusted), OWN, trusted=trusted)
    assert cls.evidence_code == "from_address" and cls.skip_reason is None
    # A plain string spelled exactly like the system label is still not one: only the collector makes those.
    plain = TrustedMeta(labels=("\\Sent", "\\Draft"), folder_role="all")
    assert classify(_headers(mail(1), plain), OWN, trusted=plain).evidence_code == "from_address"


@pytest.mark.parametrize(
    ("late", "outcome"),
    [(b"\\Draft", ("label_draft", "label_draft")), (b'"\\\\Sent"', (None, "gmail_label_sent"))],
)
def test_system_labels_are_found_at_any_position(late: bytes, outcome: tuple[str | None, str]) -> None:
    custom = b" ".join(b'"label %d"' % n for n in range(150))
    [record] = fetch_records([b"1 (UID 1 X-GM-LABELS (" + custom + b" " + late + b"))"])
    labels = gmail_labels(record["X-GM-LABELS"])
    system = [label for label in labels if isinstance(label, SystemLabel)]
    assert len(system) == 1 and len(labels) == 1 + 64  # every system label, at most 64 custom ones
    trusted = TrustedMeta(labels=labels, folder_role="all")
    cls = classify(_headers(mail(1, sender="Owner <owner@example.com>"), trusted), OWN, trusted=trusted)
    assert (cls.skip_reason, cls.evidence_code) == outcome


def test_a_custom_label_listed_first_never_hides_the_system_label() -> None:
    [record] = fetch_records([b'1 (UID 1 X-GM-LABELS (&AFw-Sent "\\\\Sent"))'])
    labels = gmail_labels(record["X-GM-LABELS"])
    assert [type(label).__name__ for label in labels] == ["SystemLabel", "str"]
    trusted = TrustedMeta(labels=labels, folder_role="all")
    assert classify(_headers(mail(1), trusted), OWN, trusted=trusted).evidence_code == "gmail_label_sent"
