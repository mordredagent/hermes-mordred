"""Owner classification: rule order, evidence codes, DMARC, list rewrite, bots; names never decide."""

from __future__ import annotations

from collections import Counter
from pathlib import Path

import pytest

from mordred_hermes.imports.mail.headers import MailHeaders, parse_headers
from mordred_hermes.imports.mail.normalize import parse_mail
from mordred_hermes.imports.mail.owner import OwnAddresses, canonical_address, classify, dmarc_failed
from mordred_hermes.imports.records import OwnerClass, ProvenanceQuality, SenderKind

FIXTURES = Path(__file__).parent / "fixtures" / "mail"
OWN = OwnAddresses.of(["owner@example.com", "owner.alias@example.org"])
FAIL_TOP = "Authentication-Results: mx.google.com; spf=softfail; dmarc=fail (p=NONE) header.from=example.com\n"
PASS_TOP = "Authentication-Results: mx.google.com; dkim=pass; dmarc=pass (p=NONE) header.from=example.com\n"


def headers(text: str) -> MailHeaders:
    return parse_headers(parse_mail(text.encode(), headers_only=True), Counter())


def fixture_headers(name: str) -> MailHeaders:
    return parse_headers(parse_mail((FIXTURES / name).read_bytes(), headers_only=True), Counter())


def summary(h: MailHeaders, *, sent_label: str = "Sent") -> tuple[str, str, str, str]:
    result = classify(h, OWN, sent_label=sent_label)
    return result.owner_class.value, result.sender_kind.value, result.provenance_quality.value, result.evidence_code


@pytest.mark.parametrize("label", ["Draft", "Chat", "Spam", "Trash", "drafts"])
def test_skip_labels_win_over_everything(label: str) -> None:
    result = classify(headers(f"X-Gmail-Labels: Sent,{label}\nFrom: owner@example.com\n\n"), OWN)
    assert result.skip_reason is not None
    assert result.skip_reason.startswith("label_")


def test_sent_label_is_api_identity_even_for_an_unlisted_address() -> None:
    h = headers("X-Gmail-Labels: Inbox,Sent\nFrom: Someone <someone@example.net>\n\n")
    assert summary(h) == ("account_owner", "user", "api_identity", "gmail_label_sent")


def test_custom_sent_label() -> None:
    h = headers("X-Gmail-Labels: =?UTF-8?Q?=E9=80=81=E4=BF=A1=E6=B8=88=E3=81=BF?=\nFrom: x@example.net\n\n")
    assert summary(h, sent_label="送信済み")[3] == "gmail_label_sent"
    assert summary(h)[3] == "from_address"


def test_own_from_is_source_claimed() -> None:
    assert summary(headers("From: Anyone <Owner@Example.com>\n\n")) == (
        "account_owner",
        "user",
        "source_claimed",
        "own_address",
    )


def test_topmost_google_dmarc_fail_downgrades_own_from_to_unknown() -> None:
    assert summary(fixture_headers("spoof_own_dmarc_fail.eml")) == ("unknown", "unknown", "unknown", "dmarc_fail")
    # A forged pass below Google's fail does not help; a fail below Google's pass does not hurt.
    assert summary(headers(FAIL_TOP + PASS_TOP + "From: owner@example.com\n\n"))[3] == "dmarc_fail"
    assert summary(headers(PASS_TOP + FAIL_TOP + "From: owner@example.com\n\n"))[3] == "own_address"
    other_authserv = "Authentication-Results: mx.example.net; dmarc=fail\n"
    assert summary(headers(other_authserv + "From: owner@example.com\n\n"))[3] == "own_address"
    assert not dmarc_failed([])


def test_sent_label_wins_over_dmarc_fail() -> None:
    h = headers(FAIL_TOP + "X-Gmail-Labels: Sent\nFrom: owner@example.com\n\n")
    assert summary(h)[3] == "gmail_label_sent"


def test_list_rewrite_via_original_from() -> None:
    assert summary(fixture_headers("list_rewrite.eml")) == ("account_owner", "user", "source_claimed", "list_rewrite")
    rewritten = (
        "From: Owner via ML <ml@lists.example.org>\nX-Original-From: owner@example.com\nList-Id: <ml.example.org>\n"
    )
    assert summary(headers(PASS_TOP + rewritten + "\n")) == ("account_owner", "user", "source_claimed", "list_rewrite")


def test_original_from_without_list_id_is_not_a_list_rewrite() -> None:
    h = headers("From: phish@example.net\nX-Original-From: Owner <owner@example.com>\n\n")
    assert summary(h) == ("other", "user", "source_claimed", "from_address")


def test_list_rewrite_needs_a_from_that_was_actually_rewritten() -> None:
    # X-Original-From equal to From: nothing was rewritten, so an own Reply-To proves nothing.
    h = headers(
        "From: phish@example.net\nX-Original-From: phish@example.net\nList-Id: <l.example.org>\n"
        "Reply-To: owner@example.com\n\n"
    )
    assert summary(h) == ("other", "channel", "source_claimed", "mailing_list")
    # Gmail dot/plus forms of the same address are the same address.
    same = headers(
        "From: Fixture.Phish+x@gmail.com\nX-Original-From: fixturephish@googlemail.com\nList-Id: <l.example.org>\n"
        "Reply-To: owner@example.com\n\n"
    )
    assert summary(same)[3] == "mailing_list"


def test_list_rewrite_with_google_dmarc_fail_is_unknown() -> None:
    rewritten = "From: ml@lists.example.org\nX-Original-From: owner@example.com\nList-Id: <ml.example.org>\n"
    assert summary(headers(FAIL_TOP + rewritten + "\n")) == ("unknown", "unknown", "unknown", "dmarc_fail")
    reply_to = "From: ml@lists.example.org\nReply-To: owner@example.com\nList-Id: <ml.example.org>\n"
    assert summary(headers(FAIL_TOP + reply_to + "\n"))[3] == "dmarc_fail"
    # A DMARC fail on a message that claims no own author changes nothing.
    assert summary(headers(FAIL_TOP + "From: a@example.net\n\n"))[3] == "from_address"


def test_reply_to_own_counts_only_on_list_mail() -> None:
    listed = headers("From: list@lists.example.org\nList-Id: <l.example.org>\nReply-To: owner@example.com\n\n")
    assert summary(listed)[3] == "list_rewrite"
    plain = headers("From: phish@example.net\nReply-To: owner@example.com\n\n")
    assert summary(plain) == ("other", "user", "source_claimed", "from_address")


@pytest.mark.parametrize(
    ("extra", "kind", "code"),
    [
        ("Auto-Submitted: auto-replied\n", "bot", "auto_submitted"),
        ("List-Id: <news.example.org>\n", "channel", "mailing_list"),
        ("Precedence: bulk\n", "channel", "precedence_bulk"),
        ("Precedence: junk\n", "channel", "precedence_bulk"),
    ],
)
def test_automated_senders(extra: str, kind: str, code: str) -> None:
    assert summary(headers(f"From: news@example.net\n{extra}\n")) == ("other", kind, "source_claimed", code)


def test_auto_submitted_no_is_a_person() -> None:
    assert summary(headers("From: a@example.net\nAuto-Submitted: no\n\n"))[3] == "from_address"


@pytest.mark.parametrize("local", ["no-reply", "noreply", "do-not-reply", "donotreply", "MAILER-DAEMON", "bounces+x"])
def test_noreply_local_parts_are_bots(local: str) -> None:
    assert summary(headers(f"From: Service <{local}@example.com>\n\n"))[1:] == (
        "bot",
        "source_claimed",
        "noreply_sender",
    )


def test_bot_fixture() -> None:
    result = classify(fixture_headers("bot_noreply.eml"), OWN)
    assert (result.owner_class, result.sender_kind, result.evidence_code) == (
        OwnerClass.OTHER,
        SenderKind.BOT,
        "auto_submitted",
    )


def test_missing_from_is_unknown() -> None:
    assert summary(headers("Subject: x\n\n")) == ("unknown", "unknown", "unknown", "no_from")
    assert summary(headers("From: Only A Name\n\n"))[3] == "no_from"


@pytest.mark.parametrize("name", ["佐々木 葵", "account owner", "me", "owner@example.com"])
def test_display_name_never_decides_identity(name: str) -> None:
    h = headers(f'From: "{name}" <stranger@example.net>\n\n')
    assert summary(h) == ("other", "user", "source_claimed", "from_address")


def test_gmail_dot_and_plus_normalisation_only_for_gmail_domains() -> None:
    own = OwnAddresses.of(["fixture.owner@gmail.com", "owner@example.com"])
    assert "Fixture.Owner+news@googlemail.com" in own
    assert "fixtureowner@gmail.com" in own
    assert "owner+tag@example.com" not in own
    assert "o.wner@example.com" not in own
    assert canonical_address("A.B+c@GMAIL.com") == "ab@gmail.com"
    assert canonical_address("A.B+c@example.com") == "a.b+c@example.com"


def test_own_addresses_validate_and_hide_values() -> None:
    with pytest.raises(ValueError, match="bad_own_address"):
        OwnAddresses.of(["not-an-address"])
    assert repr(OWN) == "OwnAddresses(count=2)"


def test_quality_values_are_canonical_enums() -> None:
    result = classify(headers("From: owner@example.com\n\n"), OWN)
    assert result.provenance_quality is ProvenanceQuality.SOURCE_CLAIMED
