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

The wizard owns reads over ``~/.hermes/mordred/keyvault/``; ``keyvault``
itself remains the sole writer (PATHS.md).
"""

from __future__ import annotations

import argparse
import shutil
import sys
from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING, Any

from .._home import hermes_home as _hermes_home
from ..keyvault import _storage

if TYPE_CHECKING:
    from ..keyvault.api import GenerateResult, SeedDisplayHandle
    from ..keyvault.seed_display import SeedDisplaySurface
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


#: Bounded retries at the verification-digest prompt (init_keyvault).
_DIGEST_PROMPT_ATTEMPTS = 5

# OS-specific go-offline steps + the matching offline-verification command.
# Split per platform because the original macOS-only text (menu bar, BSD
# `route get`) was wrong guidance on a Linux/TPM host (UX review 2026-06-11).
_BLACKOUT_STEPS_DARWIN = (
    "    1. Turn Wi-Fi OFF                 (menu bar → Wi-Fi → Off)\n"
    "    2. Unplug Ethernet cables\n"
    "    3. Turn Bluetooth OFF             (blocks PAN / tethering)\n"
    "    4. Disable iPhone Personal Hotspot / USB tethering\n"
    "    5. Stop any VPN or virtual NIC    (Tailscale, ZeroTier, …)\n"
    "\n"
    "  Verify you are offline before retrying:\n"
    "\n"
    "      route get 1.1.1.1\n"
    "\n"
    "  You are offline when the command prints:\n"
    "      route: writing to routing socket: not in table\n"
    "  If instead it shows an `interface:` line with a real NIC\n"
    "  (e.g. `en0`, `en6`, `utun3`), that NIC is still routing —\n"
    "  disable it and re-check before retrying.\n"
)

_BLACKOUT_STEPS_LINUX = (
    "    1. Turn Wi-Fi and WWAN OFF        (nmcli radio all off)\n"
    "    2. Unplug Ethernet cables\n"
    "    3. Turn Bluetooth OFF             (blocks PAN / tethering)\n"
    "    4. Disable USB / phone tethering\n"
    "    5. Stop any VPN or virtual NIC    (Tailscale, ZeroTier, WireGuard, …)\n"
    "\n"
    "  Verify you are offline before retrying:\n"
    "\n"
    "      ip route get 1.1.1.1\n"
    "\n"
    "  You are offline when the command reports the network is\n"
    "  unreachable. If instead it prints a route via a real device\n"
    "  (e.g. `dev eth0`, `dev wlan0`), that interface is still\n"
    "  routing — disable it and re-check before retrying.\n"
)


def _blackout_guidance(platform: str, *, before_passphrase: bool = False) -> str:
    """The go-offline instructions shown when the network blackout check fails.

    ``platform`` is ``sys.platform`` (``"darwin"`` / ``"linux"`` …); unknown
    platforms get the Linux text, whose commands are the more portable set.

    ``before_passphrase`` tailors the header and the closing reassurance to
    where in the ceremony the check tripped. The early pre-check fires before
    anything is typed, so "your passphrase was not saved" would be misleading;
    the late gate (inside ``display_seed``) fires after the passphrase prompt.
    """
    steps = _BLACKOUT_STEPS_DARWIN if platform == "darwin" else _BLACKOUT_STEPS_LINUX
    if before_passphrase:
        header = "  Go offline before you start keyvault init\n"
        closing = "  Nothing has been entered or written yet. Re-run after\n  going offline to begin.\n"
    else:
        header = "  Next step: go offline before the Seed Phrase is shown\n"
        closing = (
            "  Nothing has been written yet — your passphrase was not\n"
            "  saved. Re-run after going offline to continue.\n"
        )
    return (
        "\n"
        "────────────────────────────────────────────────────────────\n"
        + header
        + "────────────────────────────────────────────────────────────\n"
        "\n"
        "  This is the expected safety check, not an error. Mordred\n"
        "  will only reveal your Seed Phrase when the host is fully\n"
        "  air-gapped, so the seed cannot leak over any active link.\n"
        "\n"
        "  Please disconnect every network interface, then re-run\n"
        "  `hermes-mordred keyvault init`:\n"
        "\n" + steps + "\n" + closing + "────────────────────────────────────────────────────────────\n"
    )


def _precheck_blackout_or_refuse(blackout_assert: Callable[..., None] | None) -> int | None:
    """Early air-gap pre-check, run before the passphrase prompt.

    The real security gate is the ``blackout_assert`` inside ``display_seed``
    (defense in depth); this earlier copy only fails *fast* so an online
    operator is told to go offline before typing a passphrase that the late
    gate would otherwise discard (UX review 2026-06-15: the host was probed
    only after the passphrase had been entered twice). On the rare race where
    the link returns between this check and the seed display, the late gate
    still refuses. Returns 1 (after printing) when the host is reachable, else
    None.
    """
    from ..keyvault.network_fallback import BlackoutNotAsserted, resolve_blackout_assert

    assert_fn = blackout_assert if blackout_assert is not None else resolve_blackout_assert()
    try:
        assert_fn()
    except BlackoutNotAsserted:
        print(_blackout_guidance(sys.platform, before_passphrase=True), file=sys.stderr)
        return 1
    return None


class TerminalSeedSurface:
    """A terminal :class:`SeedDisplaySurface` for ``keyvault init``.

    All three methods are safe to call repeatedly — ``display_seed``
    invokes :meth:`clear` on every exit path, possibly twice.
    """

    def banner(self, message: str) -> None:
        print(message, file=sys.stderr)

    def show(self, seed: str) -> None:
        words = seed.split()
        print("\n=== SEED PHRASE — transcribe onto paper now ===")
        for index, word in enumerate(words, start=1):
            print(f"  {index:2}. {word}")
        print("=== END SEED PHRASE ===\n")

    def clear(self) -> None:
        # ANSI clear-screen + cursor-home. Best-effort: harmless on a
        # terminal that does not interpret the escape sequence.
        print("\033[2J\033[H", end="", flush=True)


def _refuse_if_initialised(home: Path | None) -> int | None:
    """Pre-init guard. Returns 1 (after printing to stderr) when the keyvault
    meta is corrupt or already holds a key (v1 is single-key); None to proceed.
    """
    root = _storage.resolve_keyvault_dir(home)
    try:
        existing_meta = _storage.load_meta(root)
    except _storage.KeyvaultCorruptError as exc:
        print(
            f"Keyvault meta.json is corrupt — repair or remove it before init: {exc}",
            file=sys.stderr,
        )
        return 1
    if existing_meta.get("keys"):
        print(
            "Keyvault already initialised — v1 keyvault is single-key. To restore a "
            "different key, use `hermes-mordred keyvault recover`.",
            file=sys.stderr,
        )
        return 1
    return None


def _intro_banner() -> str:
    """The orientation shown before the first Passphrase prompt.

    UX review 2026-06-15: ``keyvault init`` opened straight onto a bare
    ``Choose a Passphrase:`` prompt — the operator had no idea what the
    command does or what that passphrase is for. This explains the
    ceremony, names the Passphrase's role, and warns it is never stored
    *before* anything is typed.
    """
    return (
        "\n"
        "────────────────────────────────────────────────────────────\n"
        "  keyvault init — set up your encrypted keyvault\n"
        "────────────────────────────────────────────────────────────\n"
        "\n"
        "  This creates a new keyvault on this device. In the next\n"
        "  steps you will:\n"
        "\n"
        "    1. Choose a Passphrase (below)\n"
        "    2. Write down a 24-word Seed Phrase shown on screen\n"
        "    3. Verify it on a second, OFFLINE device\n"
        "\n"
        "  The Passphrase below, combined with the Seed Phrase,\n"
        "  protects your keyvault. You will need BOTH (plus a backup\n"
        "  blob) to recover it on another device.\n"
        "\n"
        "  It is never stored anywhere — if you lose it, the keyvault\n"
        "  cannot be recovered. Choose something strong you can keep.\n"
        "  Nothing is written to disk until every step completes.\n"
        "────────────────────────────────────────────────────────────"
    )


def _read_passphrase(prompt_io: PromptIO) -> str | None:
    """Prompt for the passphrase twice. Returns it, or None (after printing) on a
    mismatch or an empty entry.
    """
    passphrase = prompt_io.ask_password("Choose a Passphrase")
    if passphrase != prompt_io.ask_password("Re-enter the Passphrase"):
        print("Passphrases do not match — nothing was written.", file=sys.stderr)
        return None
    if not passphrase:
        print("Passphrase must not be empty.", file=sys.stderr)
        return None
    return passphrase


def _generate_seed_material(passphrase: str, *, store_seed_for_hd: bool) -> tuple[SeedDisplayHandle, bytes, str | None]:
    """Generate the BIP39 seed + seed-bound PoW and compute the verification digest.

    Returns ``(handle, pow_bytes, mnemonic_for_hd)``. The handle holds the seed in
    a wipeable bytearray; ``mnemonic_for_hd`` is the seed string kept only when HD
    storage is requested (else None). The plain seed/normalized copies are local to
    this frame and released on return, shortening their in-memory exposure.
    """
    from ..keyvault import _bip39, api
    from ..keyvault import pow as kvpow

    seed_phrase = _bip39.generate_mnemonic()
    normalized_seed = api._normalize_seed_phrase(seed_phrase)
    pow_bytes = kvpow.compute_pow(normalized_seed, difficulty_bits=kvpow.POW_DIFFICULTY_BITS)
    # expected_digest is intentionally discarded — the operator must recompute it
    # independently on an offline device, which is the mis-transcription cross-check
    # confirm_generate enforces.
    handle, _expected_digest = api.prepare_generate(seed_phrase, passphrase, pow_bytes)
    # HD mode (store_seed_for_hd, Option A) is the deliberate exception: the seed
    # must survive to be SE-encrypted after the key is finalized, so we keep one
    # reference until storage. Otherwise it is dropped when this frame returns so it
    # is GC-eligible during the 60s display + digest prompt. CPython cannot zero an
    # immutable str in place — this shortens the exposure window, it does not scrub
    # the bytes; the handle's bytearray is the one wipeable copy.
    return handle, pow_bytes, (seed_phrase if store_seed_for_hd else None)


def _display_seed_or_refuse(
    handle: SeedDisplayHandle,
    pow_bytes: bytes,
    *,
    surface: SeedDisplaySurface | None,
    display_fn: Callable[[SeedDisplayHandle, SeedDisplaySurface], None] | None,
) -> int | None:
    """Show the offline-digest banner, then display the seed under a network
    blackout. Returns 1 (after printing) if the blackout / capture / expiry guard
    trips, or None on success.
    """
    from ..keyvault import seed_display
    from ..keyvault.api import SeedDisplayExpired
    from ..keyvault.network_fallback import BlackoutNotAsserted
    from ..keyvault.seed_display import SeedDisplayAborted

    if surface is None:
        surface = TerminalSeedSurface()
    show = display_fn if display_fn is not None else seed_display.display_seed
    # The operator needs top4(PoW) to recompute the digest offline; it is derived
    # from the (secret) seed but is itself only a 4-byte mask. The offline tool is
    # `scripts/keyvault_offline_digest.py`; the recipe for preparing the second
    # device is documented in `mordred-docs/mordred/setup.md` §"Offline verification
    # digest".
    surface.banner(
        "\n"
        "────────────────────────────────────────────────────────────\n"
        "  Next: compute the verification digest on your OFFLINE device\n"
        "────────────────────────────────────────────────────────────\n"
        "\n"
        "  On the second (air-gapped) device, run:\n"
        "      python3 scripts/keyvault_offline_digest.py\n"
        "\n"
        "  It will ask for THREE values — transcribe them in this order:\n"
        "\n"
        "    [1] Seed Phrase     →  the 24 words shown below (60s only)\n"
        "    [2] Passphrase      →  the passphrase you just chose\n"
        f"    [3] top4(PoW) hex   →  {pow_bytes[:4].hex()}    ← copy this 8-char string verbatim\n"
        "\n"
        "  The script prints a 64-char digest. Re-enter it on THIS\n"
        "  device at the `Verification digest ...` prompt below.\n"
        "  (Recipe: mordred-docs/mordred/setup.md §Offline verification digest)\n"
        "────────────────────────────────────────────────────────────"
    )

    try:
        show(handle, surface)
    except BlackoutNotAsserted:
        print(_blackout_guidance(sys.platform), file=sys.stderr)
        return 1
    except SeedDisplayAborted as exc:
        print(f"Seed display aborted: screen capture detected ({exc.detector}).", file=sys.stderr)
        return 1
    except SeedDisplayExpired:
        print("Seed display window expired before the digest was confirmed.", file=sys.stderr)
        return 1
    return None


def _prompt_for_digest(prompt_io: PromptIO) -> bytes | None:
    """Bounded re-prompt for the operator's offline verification digest.

    Re-prompts on non-hex input (a typo no longer torches the ceremony), capped at
    ``_DIGEST_PROMPT_ATTEMPTS`` so scripted / non-tty runs cannot loop forever.
    Returns the digest bytes, or None (after printing) once attempts are spent. A
    valid-hex-but-mismatching digest still aborts later in confirm_generate.
    """
    for _ in range(_DIGEST_PROMPT_ATTEMPTS):
        digest_hex = prompt_io.ask_text("Verification digest from your offline device (hex)")
        try:
            return bytes.fromhex(digest_hex.strip())
        except ValueError:
            print(
                "That is not a valid hex digest — paste the 64-character hex string "
                "printed by the offline tool and try again.",
                file=sys.stderr,
            )
    print(
        f"No valid hex digest after {_DIGEST_PROMPT_ATTEMPTS} attempts — nothing was written.",
        file=sys.stderr,
    )
    return None


def _confirm_or_refuse(
    handle: SeedDisplayHandle,
    user_digest: bytes,
    *,
    backend: NativeBackend,
    audit_sink: AuditSink,
    home: Path | None,
) -> GenerateResult | None:
    """Finalize the keyvault iff the offline digest matches. Returns the
    GenerateResult, or None (after printing) on a digest mismatch, an Enclave wrap
    error, or the re-init race guard.
    """
    from ..keyvault import api
    from ..keyvault._exceptions import WrapError
    from ..keyvault.digest import VerificationDigestMismatch

    try:
        return api.confirm_generate(handle, user_digest, backend=backend, audit_sink=audit_sink, home=home)
    except VerificationDigestMismatch:
        print(
            "Verification digest mismatch — the Seed or Passphrase was mis-transcribed. "
            "Nothing was written; rerun `hermes-mordred keyvault init`.",
            file=sys.stderr,
        )
        return None
    except WrapError as exc:
        print(f"Keyvault init failed: Secure Enclave error — {exc}", file=sys.stderr)
        return None
    except RuntimeError as exc:
        # confirm_generate's own re-init guard (a race with the pre-check).
        print(f"Keyvault init refused: {exc}", file=sys.stderr)
        return None


def _provision_audit_log_key(backend: NativeBackend) -> None:
    """Best-effort: provision the audit-log wrapping key so privacy_check's
    encrypted-audit factory engages next session. A failure degrades to a printed
    note — the keyvault is already durably initialised.
    """
    from ..keyvault._exceptions import WrapError
    from ..keyvault.log_encryption import AUDIT_LOG_KEY_ID
    from ..keyvault.wrap import generate_wrapping_key

    try:
        generate_wrapping_key(AUDIT_LOG_KEY_ID, backend=backend)
    except WrapError as exc:
        print(
            f"note: audit-log wrapping key not provisioned ({exc}); the audit log "
            "stays plaintext until the keyvault is repaired.",
            file=sys.stderr,
        )


def _store_seed_for_hd_envelope(
    key_id: str,
    mnemonic: str,
    *,
    backend: NativeBackend,
    audit_sink: AuditSink,
    home: Path | None,
) -> None:
    """Best-effort HD on-ramp: SE-encrypt the just-generated seed so the HD wallet
    can derive Ethereum accounts later. A storage failure degrades to a note.
    """
    # Storing is OFFLINE — store_seed_phrase wraps the DEK with the Enclave *public*
    # key, so it never triggers an authorization prompt. We deliberately do NOT
    # derive an account here: derivation unwraps (ECDH), which on an interactive
    # wrapping key would force a Touch ID prompt at the very end of init. The catch
    # is broad (Exception) because the keyvault is already durable; any storage
    # failure must degrade to a note, not a traceback.
    try:
        from ..keyvault.ethereum import store_seed_phrase

        seed_env_id = store_seed_phrase(key_id, mnemonic, backend=backend, audit_sink=audit_sink, home=home)
        print(f"HD wallet enabled. Seed stored SE-encrypted (envelope {seed_env_id}).")
    except Exception as exc:
        print(
            f"note: HD seed not stored ({exc!r}); the keyvault is still initialised, "
            "but HD derivation is unavailable until the seed is stored.",
            file=sys.stderr,
        )


def init_keyvault(
    *,
    home: Path | None = None,
    backend: NativeBackend | None = None,
    prompt_io: PromptIO | None = None,
    surface: SeedDisplaySurface | None = None,
    audit_sink: AuditSink | None = None,
    display_fn: Callable[[SeedDisplayHandle, SeedDisplaySurface], None] | None = None,
    blackout_assert: Callable[..., None] | None = None,
    store_seed_for_hd: bool = True,
) -> int:
    """Initialise the keyvault: generate the key, display the Seed, finalize.

    Flow (SPEC.md §"``keyvault init`` flow"):

    1. Re-init guard — v1 keyvault is single-key.
    1a. Air-gap pre-check — refuse fast if the host is online, *before* the
        passphrase prompt, so an online operator is not asked to type a
        passphrase that the late blackout gate would discard. ``display_seed``
        re-asserts isolation as the real gate (defense in depth).
    2. Prompt for the Passphrase twice (hidden, must match, non-empty).
    3. Generate a 24-word BIP39 Seed Phrase + the seed-bound PoW.
    4. ``prepare_generate`` — compute the verification digest in memory.
    5. ``display_seed`` — show the Seed under a network blackout for 60s.
    6. The operator computes the digest offline and transcribes it back.
    7. ``confirm_generate`` — finalize only if the digest matches.
    8. If ``store_seed_for_hd``: SE-encrypt the generated seed
       (offline wrap, no prompt) so the HD wallet can derive Ethereum
       accounts later without re-entering the words. Best-effort — the
       keyvault is already durable, so a storage failure degrades to a note.
       Default ``True`` makes encrypted seed storage the standard
       operation. ``False`` keeps the seed paper-only (never persisted).

    ``backend`` / ``prompt_io`` / ``surface`` / ``display_fn`` /
    ``blackout_assert`` default to the production implementations; tests
    inject fakes. Returns 0 on a finalized keyvault, 1 on any refusal
    (already initialised, online host at the pre-check, passphrase mismatch,
    blackout failure, capture abort, expiry, digest mismatch, Enclave error).
    """
    guard = _refuse_if_initialised(home)
    if guard is not None:
        return guard

    # Fail fast if the host is still online — before the operator types a
    # passphrase the late blackout gate would otherwise discard (UX review
    # 2026-06-15). display_seed re-asserts isolation as the real gate.
    refusal = _precheck_blackout_or_refuse(blackout_assert)
    if refusal is not None:
        return refusal

    if prompt_io is None:
        from .configure import PromptToolkitIO

        prompt_io = PromptToolkitIO()
    # Orient the operator before the bare passphrase prompt: what this
    # command does and what the Passphrase protects (UX review 2026-06-15).
    print(_intro_banner(), file=sys.stderr)
    passphrase = _read_passphrase(prompt_io)
    if passphrase is None:
        return 1

    handle, pow_bytes, mnemonic_for_hd = _generate_seed_material(passphrase, store_seed_for_hd=store_seed_for_hd)
    del passphrase

    refusal = _display_seed_or_refuse(handle, pow_bytes, surface=surface, display_fn=display_fn)
    if refusal is not None:
        return refusal

    user_digest = _prompt_for_digest(prompt_io)
    if user_digest is None:
        return 1

    if backend is None:
        from ..keyvault._seckey_backend import _SecKeyBackend

        backend = _SecKeyBackend()
    sink = audit_sink if audit_sink is not None else _stderr_audit_sink

    result = _confirm_or_refuse(handle, user_digest, backend=backend, audit_sink=sink, home=home)
    if result is None:
        return 1

    _provision_audit_log_key(backend)

    # HD mode (Option A): SE-encrypt the just-generated seed so the HD wallet can
    # derive Ethereum accounts later without re-entering the 24 words. Best-effort
    # — the keyvault is already durably initialised at this point.
    if mnemonic_for_hd is not None:
        _store_seed_for_hd_envelope(result.key_id, mnemonic_for_hd, backend=backend, audit_sink=sink, home=home)
        del mnemonic_for_hd

    print(f"Keyvault initialised. Key: {result.key_id}")
    print(
        "Next: `hermes-mordred encryption enable env` to encrypt secrets at rest "
        "(the first enable creates the vault and asks once for a recovery passphrase), "
        "or `hermes-mordred status` for an overview."
    )
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
