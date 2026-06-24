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

The wizard owns reads over ``~/.hermes/mordred/keyvault/``; ``keyvault``
itself remains the sole writer (PATHS.md).
"""

from __future__ import annotations

import argparse
import shutil
import sys
from pathlib import Path
from typing import TYPE_CHECKING

from .._home import hermes_home as _hermes_home
from ..keyvault import _storage
from ._keyvault_init import (
    TerminalSeedSurface,
    _stderr_audit_sink,
    init_keyvault,
)
from ._keyvault_init import (
    _blackout_guidance as _blackout_guidance,  # re-exported for tests
)

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


def list_keys(*, home: Path | None = None, as_json: bool = False) -> int:
    """Print the keyvault's key ids. Returns 0 always (an empty vault is not an error)."""
    import json

    meta = _storage.load_meta(_resolve_root(home))
    keys = meta["keys"]
    if as_json:
        rows = [
            {
                "key_id": keys[key_id_hash].get("key_id", "<unknown>"),
                "key_id_hash": key_id_hash,
                "created_at": keys[key_id_hash].get("created_at", "<unknown>"),
            }
            for key_id_hash in sorted(keys)
        ]
        print(json.dumps(rows, indent=2))
        return 0
    if not keys:
        print("No keys in keyvault.")
        return 0
    print(f"{len(keys)} key(s) in keyvault:")
    for key_id_hash in sorted(keys):
        row = keys[key_id_hash]
        key_id = row.get("key_id", "<unknown>")
        created = row.get("created_at", "<unknown>")
        print(f"  {key_id}  (hash {key_id_hash}, created {created})")
    return 0


def verify_digest(*, home: Path | None = None) -> int:
    """Print every key's full verification digest for offline cross-checking.

    Returns 0 when every digest was read, 1 when the vault is empty or any
    ``digests/<hash>.commit`` file could not be read.
    """
    root = _resolve_root(home)
    meta = _storage.load_meta(root)
    keys = meta["keys"]
    if not keys:
        print("No keys to verify in keyvault.", file=sys.stderr)
        return 1

    rc = 0
    print("Verification digests (compare against the value recorded at generation time):")
    for key_id_hash in sorted(keys):
        key_id = keys[key_id_hash].get("key_id", "<unknown>")
        commit = root / "digests" / f"{key_id_hash}.commit"
        try:
            digest = _storage.safe_read(commit)
        except OSError as exc:
            print(f"  {key_id}  (hash {key_id_hash}): digest unavailable — {exc}", file=sys.stderr)
            rc = 1
            continue
        print(f"  {key_id}  (hash {key_id_hash}): {digest.hex()}")
    return rc


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
    try:
        blob = blob_path.read_bytes()
    except OSError as exc:
        print(f"cannot read backup blob {blob_path}: {exc}", file=sys.stderr)
        return 1

    from ..keyvault import _bip39, api
    from ..keyvault import pow as kvpow

    if prompt_io is None:
        from .configure import PromptToolkitIO

        prompt_io = PromptToolkitIO()
    # Security review H5: the Seed Phrase is the keyvault's root secret —
    # collect it masked (ask_password), never with terminal echo
    # (ask_text), so it does not land in scrollback or a shared TTY.
    seed_phrase = prompt_io.ask_password("24-word Seed Phrase")
    passphrase = prompt_io.ask_password("Passphrase")

    # Validate the BIP39 checksum up front for a legible error. import_backup
    # would also reject a mistyped seed, but later and via a digest mismatch.
    normalized_seed = api._normalize_seed_phrase(seed_phrase)
    try:
        _bip39.mnemonic_to_entropy(normalized_seed)
    except ValueError as exc:
        print(f"Seed Phrase rejected: {exc}", file=sys.stderr)
        return 1

    # PoW is a deterministic function of the normalized seed (SPEC
    # §"Proof-of-Work (PoW) algorithm"), so recovery recomputes it rather
    # than asking the operator to transcribe 32 more bytes.
    pow_bytes = kvpow.compute_pow(normalized_seed, difficulty_bits=kvpow.POW_DIFFICULTY_BITS)

    if backend is None:
        from ..keyvault._seckey_backend import _SecKeyBackend

        backend = _SecKeyBackend()
    sink = audit_sink if audit_sink is not None else _stderr_audit_sink

    from ..keyvault._exceptions import WrapError
    from ..keyvault.backup import BackupCorrupt
    from ..keyvault.recovery import RecoveryDigestMismatch

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
    except RecoveryDigestMismatch:
        print(
            "Recovery rejected: the verification digest does not match — the Seed "
            "Phrase or Passphrase was mis-transcribed.",
            file=sys.stderr,
        )
        return 1
    except BackupCorrupt as exc:
        print(f"Recovery rejected: backup blob is corrupt — {exc}", file=sys.stderr)
        return 1
    except WrapError as exc:
        print(f"Recovery failed: Secure Enclave error — {exc}", file=sys.stderr)
        return 1
    # L2 (PR #39 review): import_backup has consumed the seed/passphrase;
    # drop the str references (CPython cannot zero an immutable str in
    # place — this shortens the exposure window rather than scrubbing it).
    del seed_phrase, passphrase, normalized_seed
    print(f"Keyvault recovered. Imported key: {key_id}")
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


# -----------------------------------------------------------------------------
# keyvault reset — destroy all key material (irreversible).
# -----------------------------------------------------------------------------

#: Phrase the operator must type to confirm an interactive reset.
_RESET_CONFIRM_PHRASE = "reset"


def _collect_reset_key_ids(root: Path) -> list[str]:
    """Every ``key_id`` whose Secure-Enclave wrapping key ``reset`` must delete.

    The on-disk ``meta.json`` rows are authoritative for the keys actually
    written, but a corrupt or missing meta must not strand SE material — so the
    well-known default key and the audit-log wrapping key are always included.
    ``delete_wrapping_key`` is idempotent, so over-listing is harmless.
    """
    from ..keyvault.api import _DEFAULT_KEY_ID
    from ..keyvault.log_encryption import AUDIT_LOG_KEY_ID

    ids = {_DEFAULT_KEY_ID, AUDIT_LOG_KEY_ID}
    try:
        meta = _storage.load_meta(root)
    except _storage.KeyvaultCorruptError:
        return sorted(ids)
    for row in meta.get("keys", {}).values():
        key_id = row.get("key_id")
        if isinstance(key_id, str):
            ids.add(key_id)
    return sorted(ids)


def _confirm_reset(prompt_io: PromptIO, key_ids: list[str]) -> bool:
    """Show the irreversible-destruction warning and require the operator to type
    the confirmation phrase. Returns True only on an exact (stripped) match.
    """
    print(
        "\n"
        "WARNING: keyvault reset DESTROYS all key material — this cannot be undone.\n"
        "  The only way back is `keyvault recover` with your 24-word Seed Phrase,\n"
        "  Passphrase and backup blob. Without them, any wallet or secret derived\n"
        "  from this keyvault is lost permanently.\n"
        f"  Keys to destroy: {', '.join(key_ids)}\n",
        file=sys.stderr,
    )
    answer = prompt_io.ask_text(f"Type {_RESET_CONFIRM_PHRASE!r} to confirm")
    return answer.strip() == _RESET_CONFIRM_PHRASE


def _delete_wrapping_keys(key_ids: list[str], *, backend: NativeBackend | None) -> None:
    """Best-effort delete of each Secure-Enclave wrapping key. A failure degrades
    to a printed note — the on-disk removal is the authoritative destruction.
    """
    from ..keyvault import wrap
    from ..keyvault._exceptions import WrapError

    if backend is None:
        from ..keyvault._seckey_backend import _SecKeyBackend

        backend = _SecKeyBackend()
    for key_id in key_ids:
        try:
            wrap.delete_wrapping_key(key_id, backend=backend)
        except WrapError as exc:
            print(
                f"note: could not delete Secure Enclave key {key_id!r} ({exc}); "
                "remove it manually via Keychain Access if it lingers.",
                file=sys.stderr,
            )


def reset_keyvault(
    *,
    home: Path | None = None,
    backend: NativeBackend | None = None,
    prompt_io: PromptIO | None = None,
    assume_yes: bool = False,
) -> int:
    """Destroy the keyvault: delete every Secure-Enclave wrapping key and remove
    the on-disk keyvault directory. Irreversible.

    Returns 0 once the keyvault is gone (or was already absent), 1 if the operator
    declines the confirmation. ``assume_yes`` skips the interactive prompt for
    scripted use; tests inject ``prompt_io`` / ``backend``.
    """
    root = _resolve_root(home)
    if not root.exists():
        print("No keyvault found — nothing to reset.", file=sys.stderr)
        return 0

    key_ids = _collect_reset_key_ids(root)
    if not assume_yes:
        if prompt_io is None:
            from .configure import PromptToolkitIO

            prompt_io = PromptToolkitIO()
        if not _confirm_reset(prompt_io, key_ids):
            print("Reset aborted — nothing was deleted.", file=sys.stderr)
            return 1

    _delete_wrapping_keys(key_ids, backend=backend)
    try:
        shutil.rmtree(root)
    except OSError as exc:
        # The Secure-Enclave keys are already deleted, so the keyvault is
        # unrecoverable regardless — but report honestly rather than emit a
        # traceback, and point the operator at the leftover directory.
        print(
            f"Secure Enclave keys deleted, but the keyvault directory could not be "
            f"removed ({exc}); remove {root} manually.",
            file=sys.stderr,
        )
        return 1
    print("Keyvault reset — all key material destroyed.")
    print("Run `hermes-mordred keyvault init` to create a new key.")
    return 0
