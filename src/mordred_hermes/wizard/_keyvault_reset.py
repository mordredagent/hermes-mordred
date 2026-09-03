"""``hermes-mordred keyvault reset`` — destroy all key material (irreversible).

Extracted verbatim from :mod:`mordred_hermes.wizard.keyvault_cli`, which keeps
the read/recover commands plus the ``cli_*`` argparse handlers and re-exports
:func:`reset_keyvault` so ``cli_reset`` (and the tests that patch it) still
resolve the name there.

The ``keyvault_cli`` helpers ``_resolve_root`` / ``_terminal_safe`` are imported
lazily inside the functions that need them: ``keyvault_cli`` imports this module
at import time, so a top-level import back would be circular.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import sys
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

from ..keyvault import _native_key_id, _storage
from . import _term
from ._defaults import resolve_backend, resolve_prompt_io

if TYPE_CHECKING:
    from ..keyvault.wrap import NativeBackend
    from .configure import PromptIO


#: Phrase the operator must type to confirm an interactive reset.
_RESET_CONFIRM_PHRASE = "reset"
_RESET_JOURNAL_VERSION = 1


@dataclass(frozen=True)
class _ResetJournal:
    """Validated state needed to finish an interrupted reset."""

    key_ids: dict[str, str]
    retained_legacy: list[str]
    metadata_incomplete: bool
    root_identity: tuple[int, int]


def _classify_reset_row(
    root: Path,
    metadata_key_hash: object,
    row: object,
) -> tuple[str, str | None, bool] | None:
    """Return ``(logical, physical-or-legacy-None, metadata_incomplete)``.

    A malformed persisted physical selector is never returned. When the row
    still has a valid logical main-key id, its deterministic current-profile
    selector is safe to clean up and the row is marked incomplete.
    """

    if not isinstance(row, dict):
        return None
    key_id = row.get("key_id")
    try:
        key_id = _native_key_id.validate_main_key_id(key_id)
    except _native_key_id.InvalidMainKeyId:
        return None
    try:
        expected_key_hash = hashlib.sha256(key_id.encode("utf-8")).digest()[:16].hex()
    except UnicodeEncodeError:
        return None
    row_incomplete = metadata_key_hash != expected_key_hash
    if _native_key_id.NATIVE_KEY_ID_FIELD not in row:
        return key_id, None, row_incomplete
    try:
        return key_id, _native_key_id.native_key_id_from_row(root, key_id, row), row_incomplete
    except _native_key_id.NativeKeyIdMismatch:
        return key_id, _native_key_id.scoped_native_key_id(root, key_id), True


def _pending_reset_target(root: Path, meta: dict[str, Any]) -> tuple[tuple[str, str] | None, bool]:
    """Return a safe pending-main target and whether its metadata is corrupt."""

    if _native_key_id.PENDING_NATIVE_KEY_FIELD not in meta:
        return None, False
    try:
        pending = _native_key_id.pending_native_key_from_meta(root, meta)
        if pending is None:  # pragma: no cover - field presence guarantees a result
            raise _native_key_id.NativeKeyIdMismatch("pending native-key ownership journal is malformed")
        pending_logical = _native_key_id.validate_main_key_id(pending[0])
    except (_native_key_id.InvalidMainKeyId, _native_key_id.NativeKeyIdMismatch):
        # Recover only the logical id from a malformed journal. Its physical
        # selector is untrusted; derive the profile-owned target.
        raw_pending = meta[_native_key_id.PENDING_NATIVE_KEY_FIELD]
        raw_logical = raw_pending.get("key_id") if isinstance(raw_pending, Mapping) else None
        try:
            pending_logical = _native_key_id.validate_main_key_id(raw_logical)
        except _native_key_id.InvalidMainKeyId:
            return None, True
        return (pending_logical, _native_key_id.scoped_native_key_id(root, pending_logical)), True
    return (pending_logical, pending[1]), False


def _audit_reset_target(root: Path, meta: dict[str, Any], logical_key_id: str) -> tuple[str | None, bool]:
    """Validate audit ownership records without trusting malformed selectors."""

    valid_targets: set[str] = set()
    incomplete = False
    for field, reader in (
        (_native_key_id.AUDIT_KEY_FIELD, _native_key_id.committed_audit_key_from_meta),
        (_native_key_id.PENDING_AUDIT_KEY_FIELD, _native_key_id.pending_audit_key_from_meta),
    ):
        if field not in meta:
            continue
        try:
            physical = reader(root, meta, logical_key_id)
        except _native_key_id.NativeKeyIdMismatch:
            incomplete = True
            continue
        if physical is not None:
            valid_targets.add(physical)
    if len(valid_targets) == 1:
        return valid_targets.pop(), incomplete
    # Disagreeing records are corrupt. The caller retains its canonical known
    # target and warns that manual cleanup may be necessary.
    return None, incomplete or len(valid_targets) > 1


def _collect_reset_key_ids(root: Path) -> tuple[dict[str, str], list[str], bool]:
    """Return ``(owned_targets, retained_legacy, metadata_incomplete)``.

    ``owned_targets`` maps operator-facing logical ids to deterministic
    profile-scoped physical ids.  A legacy metadata row has no
    ``native_key_id`` and cannot prove exclusive ownership of its machine-global
    Keychain tag, so reset retains that tag rather than risking deletion of a
    different ``HERMES_HOME`` profile's key.

    Corrupt/missing metadata cannot safely name custom keys.  The two
    well-known *scoped* ids are still safe to attempt because their physical ids
    are derived from this root, but no legacy logical id is ever inferred.
    """
    from ..keyvault.api import _DEFAULT_KEY_ID
    from ..keyvault.log_encryption import AUDIT_LOG_KEY_ID

    targets: dict[str, str] = {
        _DEFAULT_KEY_ID: _native_key_id.scoped_native_key_id(root, _DEFAULT_KEY_ID),
        AUDIT_LOG_KEY_ID: _native_key_id.scoped_native_key_id(root, AUDIT_LOG_KEY_ID),
    }
    retained_legacy: list[str] = []
    metadata_incomplete = False
    try:
        meta = _storage.load_meta(root)
    except _storage.KeyvaultCorruptError:
        metadata_incomplete = True
        meta = {"keys": {}}
    if not (root / "meta.json").exists():
        metadata_incomplete = True

    for metadata_key_hash, row in meta.get("keys", {}).items():
        classified = _classify_reset_row(root, metadata_key_hash, row)
        if classified is None:
            metadata_incomplete = True
            continue
        key_id, physical, row_incomplete = classified
        metadata_incomplete = metadata_incomplete or row_incomplete
        if physical is None:
            retained_legacy.append(key_id)
            continue
        targets[key_id] = physical

    pending_target, pending_incomplete = _pending_reset_target(root, meta)
    metadata_incomplete = metadata_incomplete or pending_incomplete
    if pending_target is not None:
        targets[pending_target[0]] = pending_target[1]

    # Audit ownership records are auxiliary but still part of the reset
    # schema. Validate them so malformed selectors produce the incomplete
    # cleanup warning. Never use an invalid persisted selector; the canonical
    # scoped audit target seeded above remains safe and sufficient.
    audit_target, audit_incomplete = _audit_reset_target(root, meta, AUDIT_LOG_KEY_ID)
    metadata_incomplete = metadata_incomplete or audit_incomplete
    if audit_target is not None:
        targets[AUDIT_LOG_KEY_ID] = audit_target

    # The global legacy audit tag is retained whenever any legacy main row
    # exists. The scoped known ids above are always safe/idempotent cleanup
    # targets, including after a failed first generation with no committed row.
    if retained_legacy:
        retained_legacy.append(AUDIT_LOG_KEY_ID)

    return dict(sorted(targets.items())), sorted(set(retained_legacy)), metadata_incomplete


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
        payload = json.loads(_storage.safe_read(_storage.reset_journal_path(root)))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
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
            validated_native_key_id = _native_key_id.persisted_native_key_id(root, key_id, native_key_id)
        except _native_key_id.NativeKeyIdMismatch as exc:
            raise _storage.KeyvaultCorruptError("reset journal target does not belong to this profile") from exc
        key_ids[key_id] = validated_native_key_id

    from ..keyvault.api import _DEFAULT_KEY_ID
    from ..keyvault.log_encryption import AUDIT_LOG_KEY_ID

    if not {_DEFAULT_KEY_ID, AUDIT_LOG_KEY_ID} <= key_ids.keys():
        raise _storage.KeyvaultCorruptError("reset journal is missing a required profile-owned target")

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

    return _ResetJournal(
        key_ids=dict(sorted(key_ids.items())),
        retained_legacy=sorted(retained),
        metadata_incomplete=metadata_incomplete,
        root_identity=(device, inode),
    )


def _confirm_reset(
    prompt_io: PromptIO,
    key_ids: list[str],
    retained_legacy: list[str] | None = None,
) -> bool:
    """Show the irreversible-destruction warning and require the operator to type
    the confirmation phrase. Returns True only on an exact (stripped) match.
    """
    from .keyvault_cli import _terminal_safe

    retained_note = ""
    if retained_legacy:
        displayed_retained = ", ".join(_terminal_safe(key_id) for key_id in retained_legacy)
        retained_note = f"  Legacy global keys retained (exclusive ownership is unproven): {displayed_retained}\n"
    displayed_key_ids = ", ".join(_terminal_safe(key_id) for key_id in key_ids)
    print(
        "\n"
        "WARNING: keyvault reset DESTROYS the listed profile-owned key material — "
        "this cannot be undone.\n"
        "  The only way back is `keyvault recover` with your 24-word Seed Phrase,\n"
        "  Passphrase and backup blob. Without them, any wallet or secret derived\n"
        "  from this keyvault is lost permanently.\n"
        f"  Keys to destroy: {displayed_key_ids}\n"
        f"{retained_note}",
        file=sys.stderr,
    )
    answer = prompt_io.ask_text(f"Type {_RESET_CONFIRM_PHRASE!r} to confirm")
    return answer.strip() == _RESET_CONFIRM_PHRASE


def _delete_wrapping_keys(
    key_ids: dict[str, str],
    *,
    root: Path,
    backend: NativeBackend | None,
) -> list[str]:
    """Delete native wrapping keys and return the ids that could not be removed.

    Every id is attempted so one backend failure does not strand later keys.
    The caller keeps the on-disk metadata when this returns failures, allowing
    a later reset retry to discover custom key ids rather than orphaning them.
    """
    from ..keyvault import _native_key_id, wrap

    try:
        backend = resolve_backend(backend)
    except Exception as exc:
        _term.emit_error(
            f"could not initialize the native wrapping-key backend ({exc}); "
            "the on-disk keyvault was retained so cleanup can be retried."
        )
        return list(key_ids)
    backend = _native_key_id.bind_backend_to_root(backend, root)

    failures: list[str] = []
    for key_id, native_key_id in key_ids.items():
        try:
            wrap.delete_wrapping_key(key_id, backend=backend, native_key_id=native_key_id)
        except Exception as exc:
            failures.append(key_id)
            _term.emit_error(
                f"could not delete native wrapping key {key_id!r} ({exc}); "
                "the on-disk keyvault was retained so cleanup can be retried."
            )
    return failures


def reset_keyvault(  # noqa: C901, PLR0912, PLR0915 - destructive state machine is intentionally explicit
    *,
    home: Path | None = None,
    backend: NativeBackend | None = None,
    prompt_io: PromptIO | None = None,
    assume_yes: bool = False,
) -> int:
    """Destroy the keyvault: delete every provably profile-owned native
    wrapping key and remove the on-disk keyvault directory. Irreversible.

    Legacy machine-global keys are retained when exclusive ownership cannot be
    proven; the completion message reports those ids explicitly.

    Returns 0 once the keyvault is gone (or was already absent), 1 if the operator
    declines the confirmation. ``assume_yes`` skips the interactive prompt for
    scripted use; tests inject ``prompt_io`` / ``backend``.
    """
    from .keyvault_cli import _resolve_root, _terminal_safe

    root = _resolve_root(home)
    journal_path = _storage.reset_journal_path(root)
    try:
        root.lstat()
    except FileNotFoundError:
        root_seen = False
    except OSError as exc:
        _term.emit_error(f"cannot inspect keyvault root before reset: {exc}")
        return 1
    else:
        # ``lstat`` is intentional: a dangling root symlink is an unsafe
        # existing object, not an absent keyvault.
        root_seen = True
    try:
        journal_path.lstat()
    except FileNotFoundError:
        journal_seen = False
    except OSError as exc:
        _term.emit_error(f"cannot inspect keyvault reset journal: {exc}")
        return 1
    else:
        journal_seen = True
    if not root_seen and not journal_seen:
        # Do not create ~/.hermes/mordred merely to report a no-op.
        print("No keyvault found — nothing to reset.")
        return 0

    try:
        with _storage.keyvault_lifecycle_lock(root):
            try:
                journal = _load_reset_journal(root)
            except FileNotFoundError:
                journal = None
            except (OSError, _storage.KeyvaultCorruptError) as exc:
                _term.emit_error(f"cannot inspect pending keyvault reset journal: {exc}")
                return 1

            if journal is not None:
                # Resume from the durable exact target set even when a prior
                # rmtree removed meta.json or the whole root. The journal is
                # recovery state, not proof of operator consent: every
                # interactive invocation confirms again before native deletion.
                try:
                    root_meta = root.lstat()
                except FileNotFoundError:
                    root_meta = None
                if root_meta is not None:
                    try:
                        _storage._check_dir_mode(root)
                    except OSError as exc:
                        _term.emit_error(f"refusing to resume reset against unsafe keyvault root {root}: {exc}")
                        return 1
                    if (root_meta.st_dev, root_meta.st_ino) != journal.root_identity:
                        _term.emit_error(
                            "cannot resume keyvault reset: the keyvault root was replaced "
                            "after the reset journal was committed"
                        )
                        return 1
                if not assume_yes:
                    prompt_io = resolve_prompt_io(prompt_io)
                    if not _confirm_reset(prompt_io, list(journal.key_ids), journal.retained_legacy):
                        print("Reset aborted — nothing was deleted.")
                        return 1
            else:
                try:
                    _storage._check_dir_mode(root)
                except FileNotFoundError:
                    # A concurrent reset completed between the unlocked
                    # preflight and this lifecycle acquisition.
                    print("No keyvault found — nothing to reset.")
                    return 0
                except OSError as exc:
                    _term.emit_error(f"refusing to reset unsafe keyvault root {root}: {exc}")
                    return 1

                try:
                    key_ids, retained_legacy, metadata_incomplete = _collect_reset_key_ids(root)
                except (OSError, _storage.KeyvaultCorruptError) as exc:
                    _term.emit_error(f"cannot inspect keyvault metadata before reset: {exc}")
                    return 1

                # Keep the stable lifecycle lock across confirmation. This
                # makes the displayed key list authoritative: no concurrent
                # generation can add a key after the operator approves
                # destruction.
                if not assume_yes:
                    prompt_io = resolve_prompt_io(prompt_io)
                    if not _confirm_reset(prompt_io, list(key_ids), retained_legacy):
                        print("Reset aborted — nothing was deleted.")
                        return 1

                journal, encoded_journal = _encode_reset_journal(
                    root,
                    key_ids,
                    retained_legacy,
                    metadata_incomplete,
                )
                try:
                    _storage.write_reset_journal(root, encoded_journal)
                except Exception as exc:
                    _term.emit_error(f"could not durably journal keyvault reset ({exc}); no native keys were deleted.")
                    return 1

            # Rotate the independent generation lease after the stable journal
            # is durable and before native deletion. This invalidates cached
            # writers even if a later re-init happens to reuse root dev/inode.
            try:
                _storage.ensure_generation_epoch(root, force_new=True)
            except Exception as exc:
                _term.emit_error(
                    f"could not rotate the keyvault generation lease ({exc}); "
                    "the reset journal was retained and no native keys were deleted."
                )
                return 1

            failures = _delete_wrapping_keys(journal.key_ids, root=root, backend=backend)
            if failures:
                _term.emit_error(
                    "Keyvault reset is incomplete; the on-disk key list and reset "
                    "journal were retained. Retry after resolving native backend access."
                )
                return 1

            try:
                current_root = root.lstat()
            except FileNotFoundError:
                current_root = None
            if current_root is not None:
                if (current_root.st_dev, current_root.st_ino) != journal.root_identity:
                    _term.emit_error(
                        "Native wrapping keys were deleted, but the keyvault root "
                        "was replaced before directory removal; reset journal retained."
                    )
                    return 1
                try:
                    shutil.rmtree(root)
                except OSError as exc:
                    # The stable parent journal survives even if rmtree removed
                    # in-root metadata before failing, keeping cached writers
                    # fail-closed and preserving exact retry targets.
                    _term.emit_error(
                        f"Native wrapping keys deleted, but the keyvault directory could "
                        f"not be removed ({exc}); retry reset to finish cleanup."
                    )
                    return 1
            try:
                root.lstat()
            except FileNotFoundError:
                pass
            else:
                _term.emit_error(
                    "Native wrapping keys were deleted, but the keyvault directory "
                    "still exists; reset journal retained."
                )
                return 1

            try:
                # Commit the root-directory removal before clearing the
                # recovery journal. A crash between these two flushes can only
                # leave an absent root with a retained journal, never resurrect
                # an old root whose native keys have already been destroyed.
                _storage.fsync_keyvault_parent(root)
            except OSError as exc:
                _term.emit_error(
                    f"Native wrapping keys and keyvault files were removed, but "
                    f"directory removal could not be made durable ({exc}); retry reset."
                )
                return 1

            try:
                _storage.clear_reset_journal(root)
            except _storage.KeyvaultResetJournalRestoreError as exc:
                _term.emit_error(
                    "CRITICAL: keyvault reset removed all profile-owned material, but "
                    f"its fail-closed reset journal could not be restored after a storage "
                    f"flush failure ({exc}). Do not recreate or use this profile until "
                    "the filesystem is healthy and reset has been retried."
                )
                return 1
            except OSError as exc:
                _term.emit_error(
                    f"Keyvault files and native keys were removed, but the completed "
                    f"reset journal could not be durably cleared ({exc}); retry reset."
                )
                return 1
    except OSError as exc:
        _term.emit_error(f"cannot lock keyvault lifecycle for reset: {exc}")
        return 1

    if journal.retained_legacy or journal.metadata_incomplete:
        print("Keyvault files reset — all provably profile-owned key material was destroyed.")
        if journal.retained_legacy:
            displayed_retained = ", ".join(_terminal_safe(key_id) for key_id in journal.retained_legacy)
            print(
                "Legacy global native key(s) were retained because exclusive profile ownership "
                f"cannot be proven: {displayed_retained}."
            )
        if journal.metadata_incomplete:
            print("Metadata was incomplete; unknown legacy/custom native keys may require manual cleanup.")
    else:
        print("Keyvault reset — all profile-owned key material destroyed.")
    print("Run `hermes-mordred keyvault init` to create a new key.")
    return 0
