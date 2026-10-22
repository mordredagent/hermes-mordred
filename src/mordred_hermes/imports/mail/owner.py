"""Owner classification of a mail message from its headers.

:func:`classify` applies the SPEC rules in order; the first match wins and its
evidence code is stored as ``owner_evidence``:

1. Labels ``Draft``/``Chat``/``Spam``/``Trash`` → skipped.
2. The Sent label (``sent_label``) → ``account_owner`` (``gmail_label_sent``,
   quality ``api_identity``: Gmail itself filed the message as sent).
3. No ``From`` address → ``unknown`` (``no_from``).
4. ``From`` is an own address → ``account_owner`` (``own_address``,
   ``source_claimed``), unless the topmost ``Authentication-Results`` whose
   authserv-id is ``mx.google.com`` says ``dmarc=fail`` → ``unknown``
   (``dmarc_fail``).
5. A list-rewritten ``From`` whose ``X-Original-From`` (or ``Reply-To``) is
   own → ``account_owner`` (``list_rewrite``, ``source_claimed``) only with
   real list evidence: ``List-Id`` is present and the ``From`` address differs
   from every ``X-Original-From`` address (the list really rewrote it). The
   same DMARC check as rule 4 applies → ``unknown`` (``dmarc_fail``). Both
   headers are typed by the sender, so a ``list_rewrite`` (like an
   ``own_address``) record is the owner for display only and never anchors a
   quote link (:mod:`.importer` indexes Sent copies only).
6. ``Auto-Submitted`` (not ``no``), a no-reply style local part, ``List-Id`` or
   ``Precedence: bulk|list|junk`` → sender kind ``bot``/``channel``, owner
   class ``other``.
7. Otherwise ``other`` (``from_address``).

A display name never decides identity: only addresses are compared. Gmail dot
and plus normalisation applies to ``gmail.com``/``googlemail.com`` only.

Fetched mail (``trusted`` is the IMAP collector's :class:`~.source.TrustedMeta`)
replaces rules 1 and 2, and the embedded ``X-Gmail-Labels`` header is ignored.
Only labels the collector marked as system labels (:class:`._imap_codec.SystemLabel`,
recognised on the wire before decoding) count; a custom label never classifies,
even when its decoded text is ``\\Sent`` or `` \\Sent `` (no trimming, no folding
of custom labels), and every label is inspected whatever its position:

1. The Gmail system labels ``\\Draft``, ``\\Spam``, ``\\Trash`` → skipped
   (custom labels never skip).
2. The Gmail system label ``\\Sent`` → ``gmail_label_sent`` (``api_identity``);
   a custom label named "Sent" (or "\\Sent") is not the system label.
2b. The generic server's sent folder chosen at ``mail setup`` (folder role
    ``sent``) → ``account_owner`` (``imap_sent_folder``, ``source_claimed``):
    the folder names its purpose, it does not verify authorship, so such a
    record is the owner for display only and never anchors a quote link.

Rules 3 to 7 then apply unchanged.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Final

from ..records import OwnerClass, ProvenanceQuality, SenderKind
from ._imap_codec import SystemLabel
from .headers import Address, MailHeaders
from .source import TrustedMeta

__all__ = [
    "IMAP_SENT_FOLDER",
    "SENT_EVIDENCE",
    "SKIP_LABELS",
    "SYSTEM_SKIP_LABELS",
    "Classification",
    "OwnAddresses",
    "canonical_address",
    "classify",
    "dmarc_failed",
    "is_noreply",
]

#: Labels whose messages are never imported (folded label → skip reason).
SKIP_LABELS: Final = {
    "draft": "label_draft",
    "drafts": "label_draft",
    "chat": "label_chat",
    "chats": "label_chat",
    "spam": "label_spam",
    "trash": "label_trash",
}
#: Gmail system labels (``X-GM-LABELS``, case-folded) whose messages are never imported.
SYSTEM_SKIP_LABELS: Final = {"\\draft": "label_draft", "\\spam": "label_spam", "\\trash": "label_trash"}
_SYSTEM_SENT: Final = "\\sent"
#: Evidence code of a generic server's sent folder (owner for display; never a quote anchor).
IMAP_SENT_FOLDER: Final = "imap_sent_folder"
#: Evidence codes of a sent copy: it wins over a received copy of the same Message-ID.
SENT_EVIDENCE: Final = frozenset({"gmail_label_sent", IMAP_SENT_FOLDER})
_GMAIL_DOMAINS: Final = frozenset({"gmail.com", "googlemail.com"})
_GOOGLE_AUTHSERV: Final = "mx.google.com"
_DMARC_FAIL_RE: Final = re.compile(r"(?:^|[\s;])dmarc\s*=\s*fail\b", re.IGNORECASE)
_NOREPLY_RE: Final = re.compile(
    r"(?:no[-_.]?reply|do[-_.]?not[-_.]?reply|mailer[-_.]?daemon|postmaster|bounces?)(?:[-_.+].*)?",
    re.IGNORECASE,
)
_BULK_PRECEDENCE: Final = frozenset({"bulk", "list", "junk"})


def canonical_address(address: str) -> str:
    """Lowercase; for Gmail domains also drop dots and ``+tag`` in the local part."""
    value = "".join(address.split()).lower()
    local, sep, domain = value.rpartition("@")
    if not sep or not local:
        return value
    if domain in _GMAIL_DOMAINS:
        return f"{local.split('+', 1)[0].replace('.', '')}@gmail.com"
    return value


@dataclass(frozen=True)
class OwnAddresses:
    """The account's own addresses in canonical form."""

    canonical: frozenset[str]

    @classmethod
    def of(cls, addresses: Iterable[str]) -> OwnAddresses:
        values: set[str] = set()
        for address in addresses:
            value = canonical_address(address)
            local, sep, domain = value.rpartition("@")
            if not sep or not local or "." not in domain:
                raise ValueError("bad_own_address")
            values.add(value)
        return cls(frozenset(values))

    def __contains__(self, address: object) -> bool:
        return isinstance(address, str) and bool(address) and canonical_address(address) in self.canonical

    def __repr__(self) -> str:
        return f"OwnAddresses(count={len(self.canonical)})"


@dataclass(frozen=True, kw_only=True)
class Classification:
    owner_class: OwnerClass
    sender_kind: SenderKind
    provenance_quality: ProvenanceQuality
    evidence_code: str
    skip_reason: str | None = None


def is_noreply(address: str) -> bool:
    local = address.rpartition("@")[0]
    return bool(local) and _NOREPLY_RE.fullmatch(local) is not None


def dmarc_failed(authentication_results: Iterable[str]) -> bool:
    """True when the topmost ``mx.google.com`` Authentication-Results says ``dmarc=fail``."""
    for value in authentication_results:
        authserv = value.split(";", 1)[0].strip().split()
        if authserv and authserv[0].lower() == _GOOGLE_AUTHSERV:
            return _DMARC_FAIL_RE.search(value) is not None
    return False


def _has_label(labels: Iterable[str], wanted: str) -> bool:
    folded = wanted.strip().casefold()
    return any(label.strip().casefold() == folded for label in labels)


def _skip(labels: Iterable[str]) -> str | None:
    for label in labels:
        reason = SKIP_LABELS.get(label.strip().casefold())
        if reason is not None:
            return reason
    return None


def _any_own(addresses: Iterable[Address], own: OwnAddresses) -> bool:
    return any(item.address in own for item in addresses)


def _list_rewrite(headers: MailHeaders, sender: Address, own: OwnAddresses) -> bool:
    """An own author behind a list-rewritten ``From`` (rule 5), with real list evidence only."""
    if not headers.list_id:
        return False
    originals = {canonical_address(item.address) for item in headers.x_original_from if item.address}
    if canonical_address(sender.address) in originals:
        return False  # From was not rewritten: no list rewrite happened
    return _any_own(headers.x_original_from, own) or _any_own(headers.reply_to, own)


def _own_claim(headers: MailHeaders, sender: Address, own: OwnAddresses) -> str | None:
    """``own_address`` (rule 4), ``list_rewrite`` (rule 5) or ``None``."""
    if sender.address in own:
        return "own_address"
    if _list_rewrite(headers, sender, own):
        return "list_rewrite"
    return None


def _automated(headers: MailHeaders, sender: Address) -> tuple[SenderKind, str] | None:
    if headers.auto_submitted is not None and headers.auto_submitted.split(";", 1)[0].strip() != "no":
        return SenderKind.BOT, "auto_submitted"
    if is_noreply(sender.address):
        return SenderKind.BOT, "noreply_sender"
    if headers.list_id:
        return SenderKind.CHANNEL, "mailing_list"
    if headers.precedence in _BULK_PRECEDENCE:
        return SenderKind.CHANNEL, "precedence_bulk"
    return None


def _result(owner: OwnerClass, kind: SenderKind, quality: ProvenanceQuality, code: str) -> Classification:
    return Classification(owner_class=owner, sender_kind=kind, provenance_quality=quality, evidence_code=code)


def _skipped(reason: str) -> Classification:
    return Classification(
        owner_class=OwnerClass.UNKNOWN,
        sender_kind=SenderKind.UNKNOWN,
        provenance_quality=ProvenanceQuality.UNKNOWN,
        evidence_code=reason,
        skip_reason=reason,
    )


def _trusted_rules(trusted: TrustedMeta) -> Classification | None:
    """Rules 1, 2 and 2b for fetched mail: the server's system labels and folder role only."""
    system = {label.casefold() for label in trusted.labels if isinstance(label, SystemLabel)}
    for label, reason in SYSTEM_SKIP_LABELS.items():
        if label in system:
            return _skipped(reason)
    if _SYSTEM_SENT in system:
        return _result(OwnerClass.ACCOUNT_OWNER, SenderKind.USER, ProvenanceQuality.API_IDENTITY, "gmail_label_sent")
    if trusted.folder_role == "sent":
        return _result(OwnerClass.ACCOUNT_OWNER, SenderKind.USER, ProvenanceQuality.SOURCE_CLAIMED, IMAP_SENT_FOLDER)
    return None


def _label_rules(headers: MailHeaders, sent_label: str) -> Classification | None:
    """Rules 1 and 2 for file imports: the ``X-Gmail-Labels`` header Takeout writes."""
    skip = _skip(headers.labels)
    if skip is not None:
        return _skipped(skip)
    if _has_label(headers.labels, sent_label):
        return _result(OwnerClass.ACCOUNT_OWNER, SenderKind.USER, ProvenanceQuality.API_IDENTITY, "gmail_label_sent")
    return None


def classify(
    headers: MailHeaders,
    own_addresses: OwnAddresses,
    *,
    sent_label: str = "Sent",
    trusted: TrustedMeta | None = None,
) -> Classification:
    """Classify the sender of one message (see the module docstring for the rule order).

    With ``trusted`` (fetched mail) the embedded labels are ignored and ``sent_label`` is unused.
    """
    early = _label_rules(headers, sent_label) if trusted is None else _trusted_rules(trusted)
    if early is not None:
        return early
    sender = headers.sender
    if sender is None:
        return _result(OwnerClass.UNKNOWN, SenderKind.UNKNOWN, ProvenanceQuality.UNKNOWN, "no_from")
    own_claim = _own_claim(headers, sender, own_addresses)
    if own_claim is not None:
        if dmarc_failed(headers.authentication_results):
            return _result(OwnerClass.UNKNOWN, SenderKind.UNKNOWN, ProvenanceQuality.UNKNOWN, "dmarc_fail")
        return _result(OwnerClass.ACCOUNT_OWNER, SenderKind.USER, ProvenanceQuality.SOURCE_CLAIMED, own_claim)
    automated = _automated(headers, sender)
    if automated is not None:
        return _result(OwnerClass.OTHER, automated[0], ProvenanceQuality.SOURCE_CLAIMED, automated[1])
    return _result(OwnerClass.OTHER, SenderKind.USER, ProvenanceQuality.SOURCE_CLAIMED, "from_address")
