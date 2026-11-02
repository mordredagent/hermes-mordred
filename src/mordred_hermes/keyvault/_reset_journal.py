"""Durable reset journal for ``keyvault reset`` (schema, encoder, strict reader).

The journal is the exact validated owner set committed to the stable parent
directory before any native wrapping key is destroyed, so an interrupted reset
resumes against the same targets.  The strict reader is shared by the wizard
(``keyvault reset`` resumes from it) and by checked custody
(:func:`mordred_hermes.keyvault._native_key_id._checked_keyvault_role`), so it
lives in the keyvault package rather than in the CLI layer.  The encoder lives
beside it so the schema version and field set cannot drift between writer and
reader.  ``_storage`` remains the only module that touches the journal file.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from . import _native_key_id, _storage

_RESET_JOURNAL_VERSION = 2
# v1 could contain inferred known-name targets; it cannot authorize deletion.


@dataclass(frozen=True)
class _ResetJournal:
    """Validated state needed to finish an interrupted reset."""

    key_ids: dict[str, str]
    retained_legacy: list[str]
    metadata_incomplete: bool
    root_identity: tuple[int, int]


def _encode_reset_journal(
    root: Path,
    key_ids: dict[str, str],
    retained_legacy: list[str],
    metadata_incomplete: bool,
) -> tuple[_ResetJournal, bytes]:
    """Build the durable recovery record committed before native deletion."""
    root_meta = root.lstat()
    journal = _ResetJournal(
        key_ids=dict(sorted(key_ids.items())),
        retained_legacy=sorted(set(retained_legacy)),
        metadata_incomplete=metadata_incomplete,
        root_identity=(root_meta.st_dev, root_meta.st_ino),
    )
    payload = {
        "version": _RESET_JOURNAL_VERSION,
        "root_identity": {
            "device": journal.root_identity[0],
            "inode": journal.root_identity[1],
        },
        "targets": [
            {
                "key_id": key_id,
                _native_key_id.NATIVE_KEY_ID_FIELD: native_key_id,
            }
            for key_id, native_key_id in journal.key_ids.items()
        ],
        "retained_legacy": journal.retained_legacy,
        "metadata_incomplete": journal.metadata_incomplete,
    }
    return journal, json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _load_reset_journal(  # noqa: C901, PLR0912 - strict schema validation is intentionally explicit
    root: Path,
) -> _ResetJournal:
    """Read and strictly validate a pending stable-parent reset journal."""
    try:
        payload = json.loads(
            _storage.safe_read(_storage.reset_journal_path(root)),
            object_pairs_hook=_native_key_id._unique_ownership_object,
        )
    except (json.JSONDecodeError, UnicodeDecodeError, _native_key_id.NativeKeyIdMismatch) as exc:
        raise _storage.KeyvaultCorruptError("reset journal is not valid JSON") from exc
    required_fields = {
        "version",
        "root_identity",
        "targets",
        "retained_legacy",
        "metadata_incomplete",
    }
    if not isinstance(payload, dict) or set(payload) != required_fields:
        raise _storage.KeyvaultCorruptError("reset journal has an invalid schema")
    if type(payload["version"]) is not int or payload["version"] != _RESET_JOURNAL_VERSION:
        raise _storage.KeyvaultCorruptError("reset journal has an unsupported version")

    identity = payload["root_identity"]
    if not isinstance(identity, dict) or set(identity) != {"device", "inode"}:
        raise _storage.KeyvaultCorruptError("reset journal has an invalid root identity")
    device = identity["device"]
    inode = identity["inode"]
    if type(device) is not int or type(inode) is not int or device < 0 or inode < 0:
        raise _storage.KeyvaultCorruptError("reset journal has an invalid root identity")

    rows = payload["targets"]
    if not isinstance(rows, list):
        raise _storage.KeyvaultCorruptError("reset journal targets must be a list")
    key_ids: dict[str, str] = {}
    for row in rows:
        if not isinstance(row, dict) or set(row) != {"key_id", _native_key_id.NATIVE_KEY_ID_FIELD}:
            raise _storage.KeyvaultCorruptError("reset journal has an invalid target")
        key_id = row["key_id"]
        native_key_id = row[_native_key_id.NATIVE_KEY_ID_FIELD]
        if not isinstance(key_id, str) or not key_id or not isinstance(native_key_id, str):
            raise _storage.KeyvaultCorruptError("reset journal has an invalid target")
        if key_id in key_ids:
            raise _storage.KeyvaultCorruptError("reset journal contains a duplicate logical key id")
        try:
            from .log_encryption import AUDIT_LOG_KEY_ID

            if key_id != AUDIT_LOG_KEY_ID:
                _native_key_id._checked_main_logical(key_id)
            validated_native_key_id = _native_key_id.persisted_native_key_id(root, key_id, native_key_id)
        except (_native_key_id.NativeKeyIdMismatch, _native_key_id.InvalidMainKeyId) as exc:
            raise _storage.KeyvaultCorruptError("reset journal target does not belong to this profile") from exc
        key_ids[key_id] = validated_native_key_id

    retained = payload["retained_legacy"]
    if (
        not isinstance(retained, list)
        or any(not isinstance(key_id, str) or not key_id for key_id in retained)
        or len(set(retained)) != len(retained)
    ):
        raise _storage.KeyvaultCorruptError("reset journal has an invalid retained-legacy list")
    metadata_incomplete = payload["metadata_incomplete"]
    if not isinstance(metadata_incomplete, bool):
        raise _storage.KeyvaultCorruptError("reset journal has an invalid metadata-incomplete flag")

    if retained or metadata_incomplete:
        raise _storage.KeyvaultCorruptError("reset journal ownership is ambiguous; retained for explicit recovery")

    return _ResetJournal(
        key_ids=dict(sorted(key_ids.items())),
        retained_legacy=sorted(retained),
        metadata_incomplete=metadata_incomplete,
        root_identity=(device, inode),
    )
