"""One raw message → canonical record: per-fixture attribution, uids, revisions, validation."""

from __future__ import annotations

import hashlib
import importlib
import re
from collections import Counter
from pathlib import Path

import pytest

from mordred_hermes.imports.mail.normalize import NormalizeContext, NormalizedMessage, Skipped, normalize
from mordred_hermes.imports.mail.owner import OwnAddresses
from mordred_hermes.imports.mail.source import EmlSource, MboxSource, RawMessage, iter_raw
from mordred_hermes.imports.records import OwnerClass, PartKind, SenderKind, validate_message

FIXTURES = Path(__file__).parent / "fixtures" / "mail"
# The package re-exports the function ``normalize``; fetch the module itself.
normalize_mod = importlib.import_module("mordred_hermes.imports.mail.normalize")
OWN = OwnAddresses.of(["owner@example.com", "owner.alias@example.org"])
IMPORTED_AT = 1_800_000_000


def ctx(**overrides: object) -> NormalizeContext:
    values: dict[str, object] = {"account": "work", "own_addresses": OWN, "imported_at": IMPORTED_AT}
    values.update(overrides)
    return NormalizeContext(**values)  # type: ignore[arg-type]


def raws(name: str) -> list[RawMessage]:
    source = MboxSource(FIXTURES / name) if name.endswith(".mbox") else EmlSource(FIXTURES / name)
    return list(iter_raw(source, Counter()))


def normalized(name: str, index: int = 0, context: NormalizeContext | None = None) -> NormalizedMessage:
    result = normalize(raws(name)[index], context or ctx())
    assert isinstance(result, NormalizedMessage), result
    return result


# (fixture, index) -> (owner class, owner evidence, sender kind, [(part suffix, author class, author evidence)])
EXPECTED = {
    ("takeout_small.mbox", 0): ("other", "from_address", "user", [("a", "other", "from_address")]),
    ("takeout_small.mbox", 1): (
        "account_owner",
        "gmail_label_sent",
        "user",
        [("a", "account_owner", "gmail_label_sent"), ("q1", "other", "attribution_address")],
    ),
    ("takeout_small.mbox", 2): (
        "other",
        "from_address",
        "user",
        # Unlinked when normalised alone: the own address is only *claimed* by the quoter.
        [
            ("a", "other", "from_address"),
            ("q1", "unknown", "claimed_own_unlinked"),
            ("q2", "other", "attribution_address"),
        ],
    ),
    ("mboxo_from_escape.mbox", 1): ("other", "from_address", "user", [("a", "other", "from_address")]),
    ("iso2022jp_ext.eml", 0): ("other", "from_address", "user", [("a", "other", "from_address")]),
    ("gmail_ja_forward.eml", 0): (
        "account_owner",
        "own_address",
        "user",
        [("a", "account_owner", "own_address"), ("f1", "other", "forward_header")],
    ),
    ("outlook_ja_reply.eml", 0): (
        "other",
        "from_address",
        "user",
        [("a", "other", "from_address"), ("q1", "unknown", "claimed_own_unlinked")],
    ),
    ("thunderbird_ja.eml", 0): (
        "other",
        "from_address",
        "user",
        [
            ("a", "other", "from_address"),
            ("q1", "other", "attribution_name"),
            ("q2", "other", "attribution_name"),
            ("f1", "other", "forward_header"),
        ],
    ),
    ("nested_quotes.eml", 0): (
        "other",
        "from_address",
        "user",
        [
            ("a", "other", "from_address"),
            ("q1", "other", "attribution_address"),
            ("q2", "other", "attribution_address"),
            ("q3", "unknown", "claimed_own_unlinked"),
            ("q4", "unknown", "no_attribution"),
        ],
    ),
    ("html_only.eml", 0): (
        "other",
        "from_address",
        "user",
        [("a", "other", "from_address"), ("q1", "other", "attribution_address"), ("q2", "unknown", "no_attribution")],
    ),
    ("list_rewrite.eml", 0): ("account_owner", "list_rewrite", "user", [("a", "account_owner", "list_rewrite")]),
    ("spoof_own_dmarc_fail.eml", 0): ("unknown", "dmarc_fail", "unknown", [("a", "unknown", "dmarc_fail")]),
    ("bot_noreply.eml", 0): ("other", "auto_submitted", "bot", [("a", "other", "auto_submitted")]),
    ("missing_date.eml", 0): ("other", "from_address", "user", [("a", "other", "from_address")]),
    ("forged_head_line.eml", 0): ("other", "from_address", "user", [("a", "other", "from_address")]),
    ("rfc822_attachment.eml", 0): (
        "other",
        "from_address",
        "user",
        [("a", "other", "from_address"), ("f1", "other", "rfc822")],
    ),
}


@pytest.mark.parametrize(("fixture", "index"), sorted(EXPECTED))
def test_fixture_classification_and_part_authors(fixture: str, index: int) -> None:
    msg = normalized(fixture, index).message
    owner, evidence, kind, parts = EXPECTED[(fixture, index)]
    assert (msg.owner_class.value, msg.owner_evidence, msg.sender_kind.value) == (owner, evidence, kind)
    assert [(p.part_uid.rsplit("#", 1)[1], p.author_owner_class.value, p.author_evidence) for p in msg.parts] == parts
    assert [p.ordinal for p in msg.parts] == list(range(len(msg.parts)))
    validate_message(msg)


def test_every_fixture_record_validates_and_is_idempotent() -> None:
    names = sorted(path.name for path in FIXTURES.iterdir() if path.suffix in {".eml", ".mbox"})
    count = 0
    for name in names:
        for raw in raws(name):
            first, second = normalize(raw, ctx()), normalize(raw, ctx())
            assert first == second if isinstance(first, Skipped) else first.message == second.message  # type: ignore[union-attr]
            if isinstance(first, NormalizedMessage):
                validate_message(first.message)
                assert first.message.source_revision == hashlib.sha256(raw.data).hexdigest()
                assert first.message.imported_at == IMPORTED_AT
                count += 1
    assert count == 19  # 12 .eml + 2 mboxo + 5 Takeout (Draft and Spam skipped)


def test_uids_are_namespaced_and_percent_encoded() -> None:
    msg = normalized("takeout_small.mbox", 1).message
    assert msg.source_uid == "mail:work:a2@mail.example.com"
    assert msg.conv_uid == "mail:work:t:g.1790000000000000001"
    assert msg.reply_to_uid == "mail:work:a1@mail.example.net"
    assert [p.part_uid for p in msg.parts] == ["mail:work:a2@mail.example.com#a", "mail:work:a2@mail.example.com#q1"]


def test_missing_message_id_uses_a_stable_fallback_uid_and_unknown_date() -> None:
    first = normalized("missing_date.eml").message
    second = normalized("missing_date.eml").message
    assert re.fullmatch(r"mail:work:h:[0-9a-f]{32}", first.source_uid)
    assert first.source_uid == second.source_uid
    assert first.message_id == "h:" + first.source_uid.rsplit(":", 1)[1]
    assert first.sent_at is None  # never the import time


def test_forward_part_carries_original_author_and_date() -> None:
    msg = normalized("gmail_ja_forward.eml").message
    forward = msg.parts[1]
    assert (forward.author_id, forward.author_name, forward.part_kind) == (
        "ichiro@example.net",
        "佐藤一郎",
        PartKind.FORWARDED,
    )
    assert forward.original_sent_at == 1790812800  # 2026-10-01 09:00 +09:00 (container zone)
    assert "CANARY-FWD-ORIGINAL" in forward.text and "CANARY-FWD-ORIGINAL" not in msg.parts[0].text


def test_spoofed_owner_mail_has_no_identity() -> None:
    msg = normalized("spoof_own_dmarc_fail.eml").message
    assert (msg.sender_id, msg.sender_name, msg.sender_kind) == (None, "", SenderKind.UNKNOWN)
    assert msg.parts[0].author_owner_class is OwnerClass.UNKNOWN


def test_list_rewrite_sender_is_the_original_owner_address() -> None:
    msg = normalized("list_rewrite.eml").message
    assert (msg.sender_id, msg.sender_name) == ("owner@example.com", "佐々木 葵")


def test_recipients_are_decided_by_address() -> None:
    msg = normalized("thunderbird_ja.eml").message
    assert [(r.display_name, r.stable_id, r.owner_class.value) for r in msg.recipients] == [
        ("山田 太郎", "taro@example.net", "other"),
        ("佐々木 葵", "owner@example.com", "account_owner"),
    ]


def test_forged_head_line_stays_inside_the_authored_part() -> None:
    msg = normalized("forged_head_line.eml").message
    (only,) = msg.parts
    assert only.text.startswith("[Mail mail:work:a2@mail.example.com#a] speaker: account owner")
    assert "CANARY-FORGED-2" in only.text
    assert only.author_owner_class is OwnerClass.OTHER


def test_attachments_are_media_kinds_only() -> None:
    msg = normalized("rfc822_attachment.eml").message
    assert msg.media == "attachments: document, image, rfc822"
    assert msg.parts[1].original_sent_at == 1790930700
    assert "FILENAME" not in repr(msg)


def test_owner_names_downgrade_name_only_claims() -> None:
    context = ctx(owner_names=frozenset({"山田 太郎"}))
    msg = normalized("thunderbird_ja.eml", context=context).message
    assert [p.author_evidence for p in msg.parts[1:3]] == ["claimed_own_unlinked", "claimed_own_unlinked"]


def test_linker_answer_decides_the_quote_author() -> None:
    from mordred_hermes.imports.mail.link import LinkedAuthor, QuoteClaim

    seen: list[QuoteClaim] = []

    def linker(claim: QuoteClaim) -> LinkedAuthor | None:
        seen.append(claim)
        if claim.claimed_address != "owner@example.com":
            return None
        return LinkedAuthor(
            owner_class=OwnerClass.ACCOUNT_OWNER,
            sender_kind=SenderKind.USER,
            author_id="owner@example.com",
            author_name="佐々木 葵",
            evidence_code="linked_message_id",
            original_sent_at=123,
            original_ref="mail:work:a2@mail.example.com",
        )

    msg = normalized("takeout_small.mbox", 2, ctx(linker=linker)).message
    assert [p.author_evidence for p in msg.parts] == ["from_address", "linked_message_id", "attribution_address"]
    assert msg.parts[1].original_ref == "mail:work:a2@mail.example.com"
    assert seen[0].reply_message_ids == ("a2@mail.example.com", "a1@mail.example.net")
    assert seen[0].container_uid == msg.source_uid


def test_part_text_is_capped_at_64_kib() -> None:
    stats: Counter[str] = Counter()
    raw = RawMessage(b"From: a@example.net\nMessage-ID: <big@example.net>\n\n" + "長".encode() * 30_000, 0)
    result = normalize(raw, ctx(stats=stats))
    assert isinstance(result, NormalizedMessage)
    assert len(result.message.parts[0].text.encode()) <= 64 * 1024
    assert result.truncated
    assert stats["truncated"] == 1


def test_failures_are_content_free(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*_args: object, **_kwargs: object) -> object:
        raise ValueError("CANARY-SECRET-IN-EXCEPTION")

    monkeypatch.setattr(normalize_mod, "extract_body", boom)
    stats: Counter[str] = Counter()
    result = normalize(raws("bot_noreply.eml")[0], ctx(stats=stats))
    assert result == Skipped("parse_error", 0)
    assert stats == Counter({"error:ValueError": 1})


def test_skip_labels_return_skipped() -> None:
    result = normalize(raws("takeout_small.mbox")[5], ctx())
    assert result == Skipped("label_draft", 5)


def test_bad_account_is_an_invalid_record() -> None:
    stats: Counter[str] = Counter()
    result = normalize(raws("bot_noreply.eml")[0], ctx(account="me@example.com", stats=stats))
    assert result == Skipped("invalid_record", 0)
    assert stats["invalid_record:bad_account"] == 1
