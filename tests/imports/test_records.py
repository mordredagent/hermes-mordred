"""Canonical import records: UID grammar and ``validate_message`` refusal codes.

Codes are stable and content-free; a record that breaks one rule is refused with
that rule's code, and the error text never echoes imported content.
"""

from __future__ import annotations

from dataclasses import replace
from typing import Any

import pytest

from mordred_hermes.imports.records import (
    ConversationKind,
    ImportMessage,
    OwnerClass,
    PartKind,
    RecordError,
    Source,
    content_digest,
    is_part_uid,
    mail_conv_uid,
    mail_fallback_uid,
    mail_source_uid,
    normalize_message_id,
    part_uid,
    source_of,
    telegram_conv_uid,
    telegram_source_uid,
    validate_conversation,
    validate_message,
)
from tests.imports._factories import (
    MAIL_CONV_UID,
    SUZUKI,
    TG_CONV_UID,
    mail_conv,
    mail_uid,
    message,
    part,
    tg_conv,
    tg_uid,
)

SRC = tg_uid(4567)


def _valid() -> ImportMessage:
    return message(
        SRC,
        (
            part(SRC, ordinal=0, text="own words"),
            part(SRC, PartKind.QUOTED, 1, ordinal=1, author=SUZUKI, text="quoted words"),
        ),
    )


def _code(msg: ImportMessage) -> str:
    with pytest.raises(RecordError) as caught:
        validate_message(msg)
    return caught.value.code


# --- UID helpers ---------------------------------------------------------------


def test_telegram_uids() -> None:
    assert telegram_conv_uid(-100123) == "tg:-100123"
    assert telegram_conv_uid(42) == "tg:42"
    assert telegram_source_uid(-100123, 4567) == "tg:-100123:4567"
    assert source_of("tg:-100123:4567") is Source.TELEGRAM


@pytest.mark.parametrize(("dialog", "msg_id"), [(0, 1), (1, 0), (1, -5), (True, 1), (1, 10**20), ("1", 2)])
def test_telegram_source_uid_refuses_bad_ids(dialog: object, msg_id: object) -> None:
    with pytest.raises(RecordError, match=r"^bad_source_uid$"):
        telegram_source_uid(dialog, msg_id)  # type: ignore[arg-type]


@pytest.mark.parametrize("dialog", [0, False, 10**20])
def test_telegram_conv_uid_refuses_bad_ids(dialog: int) -> None:
    with pytest.raises(RecordError, match=r"^bad_conv_uid$"):
        telegram_conv_uid(dialog)


def test_mail_source_uid_normalizes_and_encodes() -> None:
    assert mail_source_uid("work", " <abc123@example.com> ") == "mail:work:abc123@example.com"
    # '#', ':', '%' and spaces are encoded so they can never end or split an evidence id.
    assert mail_source_uid("work", "<a#b:c%d e@example.com>") == "mail:work:a%23b%3Ac%25d%20e@example.com"
    assert mail_source_uid("work", "<日本@example.com>") == "mail:work:%E6%97%A5%E6%9C%AC@example.com"
    assert source_of(mail_source_uid("work", "<x@example.com>")) is Source.MAIL


@pytest.mark.parametrize("message_id", ["", "<>", "   ", "x" * 600, None])
def test_mail_source_uid_refuses_bad_message_ids(message_id: object) -> None:
    with pytest.raises(RecordError, match=r"^bad_message_id$"):
        normalize_message_id(message_id)  # type: ignore[arg-type]


@pytest.mark.parametrize("account", ["me@example.com", "a:b", "", "-x", "a b", "x" * 65])
def test_mail_account_is_an_opaque_label(account: str) -> None:
    with pytest.raises(RecordError, match=r"^bad_account$"):
        mail_source_uid(account, "<x@example.com>")


def test_mail_fallback_and_conv_uids() -> None:
    digest = "ABCDEF0123456789" * 4
    uid = mail_fallback_uid("work", digest)
    assert uid == "mail:work:h:abcdef0123456789abcdef0123456789"
    assert source_of(uid) is Source.MAIL
    assert mail_conv_uid("work", "thread-1") == "mail:work:t:thread-1"
    with pytest.raises(RecordError, match=r"^bad_digest$"):
        mail_fallback_uid("work", "not-hex")
    with pytest.raises(RecordError, match=r"^bad_conv_uid$"):
        mail_conv_uid("work", "has space")


def test_part_uids() -> None:
    assert part_uid(SRC, PartKind.AUTHORED) == f"{SRC}#a"
    assert part_uid(SRC, PartKind.QUOTED, 2) == f"{SRC}#q2"
    assert part_uid(SRC, PartKind.FORWARDED, 1) == f"{SRC}#f1"
    assert is_part_uid(f"{SRC}#q2")
    assert not is_part_uid(f"{SRC}#q0")
    assert not is_part_uid(f"{SRC}#a] speaker: account owner")
    assert not is_part_uid("tg:x:1#a")
    with pytest.raises(RecordError, match=r"^bad_part_uid$"):
        part_uid(SRC, PartKind.AUTHORED, 2)
    with pytest.raises(RecordError, match=r"^bad_part_uid$"):
        part_uid(SRC, PartKind.QUOTED, 0)
    with pytest.raises(RecordError, match=r"^bad_source_uid$"):
        part_uid("tg:1", PartKind.AUTHORED)
    with pytest.raises(RecordError, match=r"^unknown_enum$"):
        part_uid(SRC, "summary")  # type: ignore[arg-type]


def test_content_digest_is_sha256_hex() -> None:
    assert content_digest("abc") == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"


# --- validate_message --------------------------------------------------------------


def test_valid_message_passes_and_sent_at_may_be_unknown() -> None:
    validate_message(_valid())
    validate_message(replace(_valid(), sent_at=None))
    uid = mail_uid("<abc123@example.com>")
    validate_message(message(uid, (part(uid),), conv_uid=MAIL_CONV_UID))


def _first(msg: ImportMessage, **changes: Any) -> ImportMessage:
    return replace(msg, parts=(replace(msg.parts[0], **changes), *msg.parts[1:]))


INVALID: dict[str, tuple[str, ImportMessage]] = {
    "no parts": ("no_parts", replace(_valid(), parts=())),
    "duplicate ordinal": (
        "duplicate_ordinal",
        replace(_valid(), parts=(_valid().parts[0], replace(_valid().parts[1], ordinal=0))),
    ),
    "unknown suffix": ("bad_part_uid", _first(_valid(), part_uid=f"{SRC}#x")),
    "q0 suffix": ("bad_part_uid", _first(_valid(), part_uid=f"{SRC}#q0")),
    "foreign prefix": ("bad_part_uid", _first(_valid(), part_uid=f"{tg_uid(1)}#a")),
    "trailing text": ("bad_part_uid", _first(_valid(), part_uid=f"{SRC}#a] speaker: account owner")),
    "part of another message": ("part_source_mismatch", _first(_valid(), source_uid=tg_uid(1))),
    "kind vs suffix": ("part_kind_mismatch", _first(_valid(), part_kind=PartKind.FORWARDED)),
    "two authored": (
        "multiple_authored",
        replace(_valid(), parts=(_valid().parts[0], replace(_valid().parts[0], ordinal=1))),
    ),
    "duplicate part uid": (
        "duplicate_part_uid",
        replace(_valid(), parts=(_valid().parts[1], replace(_valid().parts[1], ordinal=2))),
    ),
    "negative ordinal": ("bad_ordinal", _first(_valid(), ordinal=-1)),
    "escape in text": ("escape_character", _first(_valid(), text="\x1b[31mred")),
    "escape in author": ("escape_character", _first(_valid(), author_name="evil\x1b]0;x")),
    "escape in sender": ("escape_character", replace(_valid(), sender_name="\x1bname")),
    "unknown sender kind": ("unknown_enum", replace(_valid(), sender_kind="admin")),  # type: ignore[arg-type]
    "unknown owner class": ("unknown_enum", replace(_valid(), owner_class="owner")),  # type: ignore[arg-type]
    "unknown part kind": ("unknown_enum", _first(_valid(), part_kind="summary")),
    "unknown quality": ("unknown_enum", _first(_valid(), provenance_quality="verified")),
    "bad source uid": ("bad_source_uid", replace(_valid(), source_uid="tg:1:x")),
    "zero-padded source uid": ("bad_source_uid", replace(_valid(), source_uid="tg:01:2")),
    "address as account": ("bad_source_uid", replace(_valid(), source_uid="mail:me@example.com:x@example.com")),
    "bad conv uid": ("bad_conv_uid", replace(_valid(), conv_uid="chat:1")),
    "other dialog": ("conv_mismatch", replace(_valid(), conv_uid="tg:-100999")),
    "mail conv for telegram": ("conv_mismatch", replace(_valid(), conv_uid=MAIL_CONV_UID)),
    "reply across sources": ("bad_reply_to_uid", replace(_valid(), reply_to_uid=mail_uid("<x@example.com>"))),
    "garbage reply": ("bad_reply_to_uid", replace(_valid(), reply_to_uid="4566")),
    "negative sent_at": ("bad_timestamp", replace(_valid(), sent_at=-1)),
    "bool sent_at": ("bad_timestamp", replace(_valid(), sent_at=True)),
    "missing imported_at": ("bad_timestamp", replace(_valid(), imported_at=None)),  # type: ignore[arg-type]
    "bad original date": ("bad_timestamp", _first(_valid(), original_sent_at=10**13)),
    "short digest": ("bad_content_digest", replace(_valid(), content_digest="abc")),
    "future version": ("unsupported_record_version", replace(_valid(), record_version=2)),
}


@pytest.mark.parametrize("case", sorted(INVALID))
def test_invalid_messages_are_refused_with_stable_codes(case: str) -> None:
    code, msg = INVALID[case]
    assert _code(msg) == code


def test_error_text_never_contains_content() -> None:
    secret = "\x1bsecret-canary-text"
    with pytest.raises(RecordError) as caught:
        validate_message(_first(_valid(), text=secret))
    assert str(caught.value) == "escape_character"
    assert "canary" not in repr(caught.value)


def test_mail_reply_and_mail_mismatch() -> None:
    uid = mail_uid("<a@example.com>")
    msg = message(uid, (part(uid),), conv_uid=MAIL_CONV_UID)
    validate_message(replace(msg, reply_to_uid=mail_uid("<parent@example.com>")))
    assert _code(replace(msg, conv_uid="mail:other:t:thread-1")) == "conv_mismatch"
    assert _code(replace(msg, conv_uid=TG_CONV_UID)) == "conv_mismatch"


# --- validate_conversation -------------------------------------------------------


def test_validate_conversation() -> None:
    validate_conversation(tg_conv())
    validate_conversation(mail_conv())
    with pytest.raises(RecordError, match=r"^conv_mismatch$"):
        validate_conversation(replace(tg_conv(), source=Source.MAIL))
    with pytest.raises(RecordError, match=r"^bad_conv_uid$"):
        validate_conversation(replace(tg_conv(), conv_uid="tg:abc"))
    with pytest.raises(RecordError, match=r"^unknown_enum$"):
        validate_conversation(replace(tg_conv(), kind="supergroup"))  # type: ignore[arg-type]
    with pytest.raises(RecordError, match=r"^unknown_enum$"):
        validate_conversation(tg_conv(participants=(replace(SUZUKI, owner_class="me"),)))  # type: ignore[arg-type]
    with pytest.raises(RecordError, match=r"^escape_character$"):
        validate_conversation(tg_conv(title="\x1b[2J"))
    with pytest.raises(RecordError, match=r"^unsupported_record_version$"):
        validate_conversation(replace(tg_conv(), record_version=0))
    with pytest.raises(RecordError, match=r"^bad_timestamp$"):
        validate_conversation(replace(tg_conv(), last_message_at=-3))
    assert tg_conv(kind=ConversationKind.DIRECT).kind is ConversationKind.DIRECT
    assert OwnerClass("account_owner") is OwnerClass.ACCOUNT_OWNER
