"""``hermes mordred keyvault {list,verify-digest,recover}`` — keyvault CLI.

Phase 4 PR8 (``list`` / ``verify-digest``) + PR10 (``recover``).
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

The wizard owns reads over ``~/.hermes/mordred/keyvault/``; ``keyvault``
itself remains the sole writer (PATHS.md).
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Any

from .._home import hermes_home as _hermes_home
from ..keyvault import _storage

if TYPE_CHECKING:
    from ..keyvault.wrap import NativeBackend
    from .configure import PromptIO

__all__ = [
    "cli_list",
    "cli_recover",
    "cli_verify_digest",
    "list_keys",
    "recover",
    "verify_digest",
]


def _resolve_root(home: Path | None) -> Path:
    """Resolve the keyvault root, defaulting the Hermes home via :func:`_hermes_home`.

    The home is resolved here (not deferred to ``resolve_keyvault_dir``'s
    own default) so tests can monkeypatch this module's :func:`_hermes_home`
    to point at a ``tmp_path``.
    """
    return _storage.resolve_keyvault_dir(home if home is not None else _hermes_home())


def list_keys(*, home: Path | None = None) -> int:
    """Print the keyvault's key ids. Returns 0 always (an empty vault is not an error)."""
    meta = _storage.load_meta(_resolve_root(home))
    keys = meta["keys"]
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


def _stderr_audit_sink(entry: dict[str, Any]) -> None:
    """Surface a keyvault audit entry to stderr.

    ``recover`` runs before the keyvault is usable, so there is no
    encrypted audit log to append to yet. The recovery-digest-mismatch
    and DEK-unwrap decisions ``import_backup`` records are shown to the
    operator instead. Persisted recovery auditing is a v2 follow-up.
    """
    event = entry.get("event", "?")
    decision = entry.get("decision", "?")
    print(f"[audit] {event} decision={decision}", file=sys.stderr)


def recover(
    *,
    blob_path: Path,
    home: Path | None = None,
    backend: NativeBackend | None = None,
    prompt_io: PromptIO | None = None,
    audit_sink: Any = None,
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
    seed_phrase = prompt_io.ask_text("24-word Seed Phrase")
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
    print(f"Keyvault recovered. Imported key: {key_id}")
    return 0


# -----------------------------------------------------------------------------
# CLI adapters wired in cli.py.
# -----------------------------------------------------------------------------


def cli_list(args: argparse.Namespace) -> int:
    """argparse handler for ``keyvault list`` (takes no options)."""
    del args
    return list_keys()


def cli_verify_digest(args: argparse.Namespace) -> int:
    """argparse handler for ``keyvault verify-digest`` (takes no options)."""
    del args
    return verify_digest()


def cli_recover(args: argparse.Namespace) -> int:
    """argparse handler for ``keyvault recover --blob <path>``."""
    return recover(blob_path=Path(args.blob))
