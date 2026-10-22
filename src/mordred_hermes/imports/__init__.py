"""Canonical imported-message records, rendering and evidence (library only).

Shared by the Telegram extension, the mail collector and the Hermes read tool.
This package registers no plugin component and has no optional dependencies:

- :mod:`.records` — canonical conversation/message/part records, UID grammar
  and :func:`validate_message`.
- :mod:`.aliases` — identity-keyed aliases, :func:`safe_display`, scrubbing.
- :mod:`.render` — deterministic head line + indented body per part.
- :mod:`.evidence` — citation and quote validation, source cards from stored data.
- :mod:`.store` — :class:`ImportStore`, the ``import_*`` tables of the encrypted
  ``mordred.db``, opened only through the activity protection gate.
- :mod:`.legacy_enc` — the legacy ``.enc`` Telegram archive as canonical records.

Imported text is reference data: nothing here lets it choose a speaker label,
an evidence id or a card field. Nothing here logs message content.
"""

from __future__ import annotations

from .aliases import IdentityAliases, clean_display, neutralize, safe_display
from .evidence import EVIDENCE_ID_RE, EvidenceCard, EvidenceReport, validate
from .legacy_enc import iter_legacy_archive, legacy_conversation, legacy_message
from .records import (
    ConversationKind,
    ImportConversation,
    ImportMessage,
    ImportPart,
    OwnerClass,
    Participant,
    PartKind,
    ProvenanceQuality,
    RecordError,
    SenderKind,
    Source,
    content_digest,
    mail_conv_uid,
    mail_fallback_uid,
    mail_source_uid,
    part_uid,
    telegram_conv_uid,
    telegram_source_uid,
    validate_conversation,
    validate_message,
)
from .render import (
    LABELS,
    HeadStyle,
    RenderedPart,
    RenderedPartRef,
    conversation_label,
    format_date,
    part_ref,
    render_part,
    render_selection,
    truncate_part,
)
from .store import (
    ImportMeta,
    ImportRefused,
    ImportStore,
    SearchHit,
    StoredPart,
    WriteResult,
    open_import_store,
)

__all__ = [
    "EVIDENCE_ID_RE",
    "LABELS",
    "ConversationKind",
    "EvidenceCard",
    "EvidenceReport",
    "HeadStyle",
    "IdentityAliases",
    "ImportConversation",
    "ImportMessage",
    "ImportMeta",
    "ImportPart",
    "ImportRefused",
    "ImportStore",
    "OwnerClass",
    "PartKind",
    "Participant",
    "ProvenanceQuality",
    "RecordError",
    "RenderedPart",
    "RenderedPartRef",
    "SearchHit",
    "SenderKind",
    "Source",
    "StoredPart",
    "WriteResult",
    "clean_display",
    "content_digest",
    "conversation_label",
    "format_date",
    "iter_legacy_archive",
    "legacy_conversation",
    "legacy_message",
    "mail_conv_uid",
    "mail_fallback_uid",
    "mail_source_uid",
    "neutralize",
    "open_import_store",
    "part_ref",
    "part_uid",
    "render_part",
    "render_selection",
    "safe_display",
    "telegram_conv_uid",
    "telegram_source_uid",
    "truncate_part",
    "validate",
    "validate_conversation",
    "validate_message",
]
