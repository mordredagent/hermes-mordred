"""Fixed label vocabulary for rendered imported history.

Every word the renderer puts around imported text comes from this table, never
from the imported data or from a model. ``account owner`` (``アカウント所有者``)
is the ONLY way the account owner is named; a contact whose display name
collides with a reserved label is rendered as ``<name> (contact)`` by
:func:`mordred_hermes.imports.aliases.safe_display`.
"""

from __future__ import annotations

from typing import Final

LABELS: Final[dict[str, dict[str, str]]] = {
    "en": {
        "owner": "account owner",
        "unknown_sender": "unknown sender",
        "forwarded": "forwarded text",
        "quoted": "quoted text",
        "original_date": "original date",
        "forwarded_by": "forwarded by",
        "quoted_by": "quoted by",
        "speaker": "speaker",
        "chat": "chat",
        "to": "to",
        "legacy_qualifier": "legacy: forwards not distinguished",
        "seen_in_archive": "seen in archive",
        "date_unknown": "date unknown",
        "unknown": "unknown",
        "contact": "contact",
        "channel": "channel",
        "bot": "bot",
    },
    "ja": {
        "owner": "アカウント所有者",
        "unknown_sender": "不明な送信者",
        "forwarded": "転送されたテキスト",
        "quoted": "引用されたテキスト",
        "original_date": "元の日時",
        "forwarded_by": "転送者",
        "quoted_by": "引用者",
        "speaker": "発言者",
        "chat": "チャット",
        "to": "宛先",
        "legacy_qualifier": "旧形式: 転送は区別されていません",
        "seen_in_archive": "アーカイブ内の参加者",
        "date_unknown": "日時不明",
        "unknown": "不明",
        "contact": "連絡先",
        "channel": "チャンネル",
        "bot": "ボット",
    },
}

#: Display names that would read as a trusted role. Compared after NFKC,
#: case folding and whitespace collapsing.
RESERVED_LABELS: Final[frozenset[str]] = frozenset(
    {"account owner", "アカウント所有者", "me", "self", "user", "assistant", "unknown sender"}
    | {table[key] for table in LABELS.values() for key in ("owner", "unknown_sender")}
)


def labels_for(lang: str) -> dict[str, str]:
    """Return the label table for ``lang``; unsupported languages raise ``ValueError``."""
    table = LABELS.get(lang)
    if table is None:
        raise ValueError("unsupported_language")
    return table
