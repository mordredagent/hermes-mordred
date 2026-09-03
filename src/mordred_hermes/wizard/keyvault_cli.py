"""``hermes-mordred keyvault {list,verify-digest,recover,init}`` — keyvault CLI.

Phase 4 PR8 (``list`` / ``verify-digest``) + PR10 (``recover`` / ``init``).
SPEC.md §4.2 / TODO.md §4.2.

``list`` / ``verify-digest`` only *read* the on-disk keyvault layout
(``meta.json`` + ``digests/<key_id_hash>.commit``); they need neither a
Secure-Enclave ``NativeBackend`` nor the ``cryptography`` stack, so the
read helpers import on any platform.

- ``list`` — print each key's cleartext id, on-disk hash and creation
  timestamp. The verification digest (key material) is never printed.
- ``verify-digest`` — print the full 32-byte verification digest of
  every key, hex-encoded, so the operator can cross-check it against the
  value recorded on a second device at generation time.
- ``recover`` — restore a keyvault from an :func:`export_backup` blob.
  Backend-coupled: it builds a production ``_SecKeyBackend`` and calls
  :func:`mordred_hermes.keyvault.api.import_backup` (PR9 landed the
  backend). The heavy imports stay function-local so this module still
  imports on any platform.
- ``init`` — the air-gap-gated generation ceremony, which lives in
  :mod:`mordred_hermes.wizard._keyvault_init` and is re-exported here as
  :func:`init_keyvault` / :class:`TerminalSeedSurface`.
- ``reset`` — the irreversible destruction ceremony, which lives in
  :mod:`mordred_hermes.wizard._keyvault_reset` and is re-exported here as
  :func:`reset_keyvault`.

The wizard owns reads over ``~/.hermes/mordred/keyvault/``; ``keyvault``
itself remains the sole writer (PATHS.md).
"""

from __future__ import annotations

import argparse
import hashlib
import importlib
from pathlib import Path
from typing import TYPE_CHECKING, Any

from .._home import hermes_home as _hermes_home
from ..keyvault import _native_key_id, _storage
from . import _term
from ._defaults import resolve_backend, resolve_prompt_io
from ._keyvault_init import (
    TerminalSeedSurface,
    _provision_audit_log_key,
    _stderr_audit_sink,
    init_keyvault,
)
from ._keyvault_init import (
    _blackout_guidance as _blackout_guidance,  # re-exported for tests
)
from ._keyvault_reset import reset_keyvault

if TYPE_CHECKING:
    from ..keyvault.wrap import AuditSink, NativeBackend
    from .configure import PromptIO

__all__ = [
    "TerminalSeedSurface",
    "cli_init",
    "cli_list",
    "cli_recover",
    "cli_reset",
    "cli_verify_digest",
    "init_keyvault",
    "list_keys",
    "recover",
    "reset_keyvault",
    "verify_digest",
]


def _resolve_root(home: Path | None) -> Path:
    """Resolve the keyvault root, defaulting the Hermes home via :func:`_hermes_home`.

    The home is resolved here (not deferred to ``resolve_keyvault_dir``'s
    own default) so tests can monkeypatch this module's :func:`_hermes_home`
    to point at a ``tmp_path``.
    """
    return _storage.resolve_keyvault_dir(home if home is not None else _hermes_home())


def _terminal_safe(value: object) -> str:
    """Render persisted values without emitting terminal control characters."""

    text = value if isinstance(value, str) else str(value)
    return text if text.isprintable() else text.encode("unicode_escape").decode("ascii")


def _load_meta_or_report(root: Path) -> dict[str, Any] | None:
    """``load_meta`` with the read commands' shared corrupt/unreadable reporting.

    Returns ``None`` after printing the error (callers return 1) so the two
    read-only commands can't drift apart on wording or remediation hints.
    """
    try:
        with _storage.keyvault_read_lock(root) as profile_present:
            if not profile_present:
                return {"version": 1, "keys": {}}
            _storage.assert_keyvault_active(root)
            return _storage.load_meta(root)
    except _storage.KeyvaultCorruptError as exc:
        _term.emit_error(
            f"keyvault metadata is corrupt ({root / 'meta.json'}): {exc}. "
            "Run `hermes-mordred keyvault recover` from a backup blob, or "
            "`hermes-mordred keyvault reset` to discard this keyvault and start over."
        )
        return None
    except OSError as exc:
        _term.emit_error(f"cannot read keyvault metadata ({root / 'meta.json'}): {exc}")
        return None


def _validated_metadata_key_row(key_id_hash: str, row: object) -> tuple[str, dict[str, Any]] | None:
    """Validate a CLI-visible metadata row and its canonical object key."""

    if not isinstance(row, dict):
        return None
    try:
        key_id = _native_key_id.validate_main_key_id(row.get("key_id"))
        expected_key_id_hash = hashlib.sha256(key_id.encode("utf-8")).digest()[:16].hex()
    except (_native_key_id.InvalidMainKeyId, UnicodeEncodeError):
        return None
    if key_id_hash != expected_key_id_hash:
        return None
    return key_id, row


def _validated_digest_dir_or_report(root: Path) -> Path | None:
    """Return the safe digest directory, reporting an unsafe parent cleanly."""

    digests_dir = root / "digests"
    try:
        # ``safe_read`` validates only the final file component. The parent
        # must be a real mode-0700 directory before any metadata-derived
        # commit path is constructed.
        _storage._check_dir_mode(digests_dir)
    except OSError as exc:
        _term.emit_error(f"cannot inspect keyvault digest directory: {exc}")
        return None
    return digests_dir


def _display_verification_digest(digests_dir: Path, key_id_hash: str, row: object) -> bool:
    """Validate and print one digest; return whether the row was usable."""

    validated = _validated_metadata_key_row(key_id_hash, row)
    if validated is None:
        # The object key is metadata-controlled. Reject it before constructing
        # a path so traversal-shaped hashes can never escape ``digests/``.
        _term.emit_error("  keyvault metadata contains an invalid key row or hash")
        return False
    display_key_id = _terminal_safe(validated[0])
    commit = digests_dir / f"{key_id_hash}.commit"
    try:
        digest = _storage.safe_read(commit)
    except OSError as exc:
        _term.emit_error(f"  {display_key_id}  (hash {key_id_hash}): digest unavailable — {exc}")
        return False
    if len(digest) != 32:
        _term.emit_error(f"  {display_key_id}  (hash {key_id_hash}): digest must be exactly 32 bytes")
        return False
    print(f"  {display_key_id}  (hash {key_id_hash}): {digest.hex()}")
    return True


def list_keys(*, home: Path | None = None, as_json: bool = False) -> int:
    """Print the keyvault's key ids. Returns 0 always (an empty vault is not an error).

    Returns 1 when the on-disk keyvault state cannot be read at all (corrupt
    ``meta.json`` / unreadable file) — the read fails before there is
    anything to list, so this is a genuine error, not an empty vault.
    """
    import json

    root = _resolve_root(home)
    meta = _load_meta_or_report(root)
    if meta is None:
        return 1
    if _native_key_id.PENDING_NATIVE_KEY_FIELD in meta:
        _term.emit_error("Keyvault native-key provisioning is incomplete; run `hermes-mordred keyvault reset`.")
        return 1
    keys = meta["keys"]
    validated_rows: list[tuple[str, str, dict[str, Any]]] = []
    for key_id_hash in sorted(keys):
        validated = _validated_metadata_key_row(key_id_hash, keys[key_id_hash])
        if validated is None:
            _term.emit_error("keyvault metadata contains an invalid key row")
            return 1
        validated_rows.append((key_id_hash, validated[0], validated[1]))
    if as_json:
        rows = [
            {
                "key_id": key_id,
                "key_id_hash": key_id_hash,
                "created_at": row.get("created_at", "<unknown>"),
            }
            for key_id_hash, key_id, row in validated_rows
        ]
        print(json.dumps(rows, indent=2))
        return 0
    if not keys:
        print("No keys in keyvault.")
        return 0
    print(f"{len(keys)} key(s) in keyvault:")
    for key_id_hash, key_id, row in validated_rows:
        created = row.get("created_at", "<unknown>")
        print(f"  {_terminal_safe(key_id)}  (hash {key_id_hash}, created {_terminal_safe(created)})")
    return 0


def verify_digest(*, home: Path | None = None) -> int:
    """Print every key's full verification digest for offline cross-checking.

    Returns 0 when every digest was read, 1 when the vault is empty, any
    ``digests/<hash>.commit`` file could not be read, or ``meta.json`` itself
    is corrupt/unreadable.
    """
    root = _resolve_root(home)
    try:
        # Keep the metadata row set and every corresponding commit read in one
        # lifecycle snapshot. Otherwise reset can publish its journal/remove
        # the tree after meta.json is read but before the digest files are read.
        with _storage.keyvault_read_lock(root) as profile_present:
            if not profile_present:
                _term.emit_error("No keys to verify in keyvault.")
                return 1
            meta = _load_meta_or_report(root)
            if meta is None:
                return 1
            if _native_key_id.PENDING_NATIVE_KEY_FIELD in meta:
                _term.emit_error("Keyvault native-key provisioning is incomplete; run `hermes-mordred keyvault reset`.")
                return 1
            keys = meta["keys"]
            if not keys:
                _term.emit_error("No keys to verify in keyvault.")
                return 1
            digests_dir = _validated_digest_dir_or_report(root)
            if digests_dir is None:
                return 1

            rc = 0
            print("Verification digests (compare against the value recorded at generation time):")
            for key_id_hash in sorted(keys):
                if not _display_verification_digest(digests_dir, key_id_hash, keys[key_id_hash]):
                    rc = 1
            return rc
    except OSError as exc:
        _term.emit_error(f"cannot read keyvault metadata ({root / 'meta.json'}): {exc}")
        return 1


def _preflight_recovery_imports() -> None:
    """Resolve the recovery stack before any secret is prompted for.

    Before the split into helpers, ``recover`` imported the crypto-backed modules
    right after reading the blob — so a broken install failed *before* the
    operator typed the Seed Phrase. The helpers below import lazily; this keeps
    that ordering by importing the same modules up front.
    """
    for name in (
        "cryptography.exceptions",
        "mordred_hermes.keyvault._bip39",
        "mordred_hermes.keyvault.api",
        "mordred_hermes.keyvault.pow",
        "mordred_hermes.keyvault.backup",
        "mordred_hermes.keyvault.recovery",
    ):
        importlib.import_module(name)


def _read_backup_blob(blob_path: Path) -> bytes | None:
    """Read the backup blob, reporting (and returning ``None`` on) an OSError.

    Split out of :func:`recover` for cyclomatic headroom only — same message,
    same exit behaviour (the caller returns 1 on ``None``).
    """
    try:
        return blob_path.read_bytes()
    except OSError as exc:
        _term.emit_error(f"cannot read backup blob {blob_path}: {exc}")
        return None


def _validated_seed_and_pow(seed_phrase: str) -> tuple[str, bytes] | None:
    """Normalize the Seed Phrase, validate its BIP39 checksum, and compute the PoW.

    Returns ``(normalized_seed, pow_bytes)`` on success or ``None`` (already
    reported) when the checksum fails. Split out of :func:`recover` for
    cyclomatic headroom only — the checksum validation and its error message,
    and the PoW computation, are unchanged and in the same order.
    """
    from ..keyvault import _bip39, api
    from ..keyvault import pow as kvpow

    # Validate the BIP39 checksum up front for a legible error. import_backup
    # would also reject a mistyped seed, but later and via a digest mismatch.
    normalized_seed = api._normalize_seed_phrase(seed_phrase)
    try:
        _bip39.mnemonic_to_entropy(normalized_seed)
    except ValueError as exc:
        _term.emit_error(f"Seed Phrase rejected: {exc}")
        return None

    # PoW is a deterministic function of the normalized seed (SPEC
    # §"Proof-of-Work (PoW) algorithm"), so recovery recomputes it rather
    # than asking the operator to transcribe 32 more bytes.
    pow_bytes = kvpow.compute_pow(normalized_seed, difficulty_bits=kvpow.POW_DIFFICULTY_BITS)
    return normalized_seed, pow_bytes


def _import_backup_or_report(
    *,
    blob: bytes,
    passphrase: str,
    seed_phrase: str,
    pow_bytes: bytes,
    backend: NativeBackend,
    sink: AuditSink,
    home: Path | None,
    prompt_io: PromptIO,
) -> str | None:
    """Import the backup, retrying once with a legacy backup passphrase on ``InvalidTag``.

    Returns the imported ``key_id`` on success, or ``None`` after reporting the
    failure. Split out of :func:`recover` for cyclomatic headroom only: every
    exception type, message, and the InvalidTag -> legacy-prompt -> retry
    sequence are unchanged, in the same order. The legacy backup passphrase
    (prompted for only on that retry) never leaves this frame — its reference
    is dropped when the function returns.
    """
    from cryptography.exceptions import InvalidTag

    from ..keyvault import api
    from ..keyvault._exceptions import WrapError
    from ..keyvault.backup import BackupCorrupt, BackupImportConflict
    from ..keyvault.recovery import RecoveryDigestMismatch

    legacy_backup_passphrase: str | None = None

    try:
        try:
            key_id = api.import_backup(
                blob,
                passphrase,
                seed_phrase=seed_phrase,
                pow_bytes=pow_bytes,
                backend=backend,
                audit_sink=sink,
                home=home,
            )
        except InvalidTag:
            # Older export_backup accepted an arbitrary KDF passphrase while
            # embedding a digest committed under the recovery passphrase. Such
            # a blob needs both values. Ask only after the normal, consistent
            # path fails authentication; current backups still use two prompts.
            legacy_backup_passphrase = prompt_io.ask_password(
                "Legacy backup encryption passphrase (leave blank to cancel)"
            )
            if not legacy_backup_passphrase:
                _term.emit_error(
                    "Recovery rejected: backup ciphertext authentication failed "
                    "(wrong legacy encryption passphrase or a tampered blob)."
                )
                return None
            key_id = api.import_backup(
                blob,
                passphrase,
                seed_phrase=seed_phrase,
                pow_bytes=pow_bytes,
                backend=backend,
                audit_sink=sink,
                home=home,
                backup_passphrase=legacy_backup_passphrase,
            )
    except RecoveryDigestMismatch:
        _term.emit_error(
            "Recovery rejected: the verification digest does not match — the Seed "
            "Phrase or Passphrase was mis-transcribed."
        )
        return None
    except BackupCorrupt as exc:
        _term.emit_error(f"Recovery rejected: backup blob is corrupt — {exc}")
        return None
    except BackupImportConflict as exc:
        _term.emit_error(
            f"Recovery rejected: destination keyvault is not fresh — {exc}. "
            "Use a new Hermes home, or verify a backup and reset the existing keyvault first."
        )
        return None
    except InvalidTag:
        _term.emit_error(
            "Recovery rejected: backup ciphertext authentication failed "
            "(wrong legacy encryption passphrase or a tampered blob)."
        )
        return None
    except WrapError as exc:
        _term.emit_error(f"Recovery failed: Secure Enclave error — {exc}")
        return None
    return key_id


def recover(
    *,
    blob_path: Path,
    home: Path | None = None,
    backend: NativeBackend | None = None,
    prompt_io: PromptIO | None = None,
    audit_sink: AuditSink | None = None,
) -> int:
    """Restore a keyvault from an ``export_backup`` blob on this device.

    Reads the blob at ``blob_path``, prompts for the 24-word Seed Phrase
    and the Passphrase, recomputes the seed-bound PoW, and restores the
    keyvault via :func:`mordred_hermes.keyvault.api.import_backup`.

    ``backend=None`` builds the production Secure-Enclave backend;
    ``prompt_io=None`` uses the prompt_toolkit-backed prompts. Both are
    injected by tests.

    Returns 0 on success; 1 on an unreadable/corrupt blob, a Seed Phrase
    that fails the BIP39 checksum, a verification-digest mismatch
    (mis-transcribed seed/passphrase), or a Secure Enclave failure.
    """
    blob = _read_backup_blob(blob_path)
    if blob is None:
        return 1
    _preflight_recovery_imports()

    prompt_io = resolve_prompt_io(prompt_io)
    # Security review H5: the Seed Phrase is the keyvault's root secret —
    # collect it masked (ask_password), never with terminal echo
    # (ask_text), so it does not land in scrollback or a shared TTY.
    seed_phrase = prompt_io.ask_password("24-word Seed Phrase")
    passphrase = prompt_io.ask_password("Passphrase")

    validated = _validated_seed_and_pow(seed_phrase)
    if validated is None:
        return 1
    normalized_seed, pow_bytes = validated
    del validated  # the tuple would otherwise keep the normalized seed alive past the final del

    backend = resolve_backend(backend)
    sink = audit_sink if audit_sink is not None else _stderr_audit_sink

    key_id = _import_backup_or_report(
        blob=blob,
        passphrase=passphrase,
        seed_phrase=seed_phrase,
        pow_bytes=pow_bytes,
        backend=backend,
        sink=sink,
        home=home,
        prompt_io=prompt_io,
    )
    if key_id is None:
        return 1

    _provision_audit_log_key(backend, home=home)
    # L2 (PR #39 review): import_backup has consumed the seed/passphrase;
    # drop the str references (CPython cannot zero an immutable str in
    # place — this shortens the exposure window rather than scrubbing it).
    # The legacy backup passphrase, if prompted for, was local to
    # _import_backup_or_report and is already gone with that frame.
    del seed_phrase, passphrase, normalized_seed
    print(f"Keyvault recovered. Imported key: {_terminal_safe(key_id)}")
    return 0


# -----------------------------------------------------------------------------
# CLI adapters wired in cli.py.
# -----------------------------------------------------------------------------


def cli_list(args: argparse.Namespace) -> int:
    """argparse handler for ``keyvault list [--json]``."""
    return list_keys(as_json=bool(getattr(args, "json", False)))


def cli_verify_digest(args: argparse.Namespace) -> int:
    """argparse handler for ``keyvault verify-digest`` (takes no options)."""
    del args
    return verify_digest()


def cli_recover(args: argparse.Namespace) -> int:
    """argparse handler for ``keyvault recover --blob <path>``."""
    return recover(blob_path=Path(args.blob))


def cli_init(args: argparse.Namespace) -> int:
    """argparse handler for ``keyvault init`` (encrypted seed storage by default)."""
    return init_keyvault(store_seed_for_hd=getattr(args, "store_seed_for_hd", True))


def cli_reset(args: argparse.Namespace) -> int:
    """argparse handler for ``keyvault reset [--yes]``."""
    return reset_keyvault(assume_yes=bool(getattr(args, "assume_yes", False)))
