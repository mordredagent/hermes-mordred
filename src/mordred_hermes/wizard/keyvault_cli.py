"""``hermes mordred keyvault {list,verify-digest,recover,init}`` — keyvault CLI.

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
import sys
from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING, Any

from .._home import hermes_home as _hermes_home
from ..keyvault import _storage

if TYPE_CHECKING:
    from ..keyvault.api import SeedDisplayHandle
    from ..keyvault.seed_display import SeedDisplaySurface
    from ..keyvault.wrap import AuditSink, NativeBackend
    from .configure import PromptIO

__all__ = [
    "TerminalSeedSurface",
    "cli_enable_se",
    "cli_enable_tpm",
    "cli_init",
    "cli_list",
    "cli_recover",
    "cli_verify_digest",
    "enable_se",
    "enable_tpm",
    "init_keyvault",
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
    # L2 (PR #39 review): import_backup has consumed the seed/passphrase;
    # drop the str references (CPython cannot zero an immutable str in
    # place — this shortens the exposure window rather than scrubbing it).
    del seed_phrase, passphrase, normalized_seed
    print(f"Keyvault recovered. Imported key: {key_id}")
    return 0


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


def init_keyvault(
    *,
    home: Path | None = None,
    backend: NativeBackend | None = None,
    prompt_io: PromptIO | None = None,
    surface: SeedDisplaySurface | None = None,
    audit_sink: AuditSink | None = None,
    display_fn: Callable[[SeedDisplayHandle, SeedDisplaySurface], None] | None = None,
    store_seed_for_hd: bool = False,
) -> int:
    """Initialise the keyvault: generate the key, display the Seed, finalize.

    Flow (SPEC.md §"``keyvault init`` flow"):

    1. Re-init guard — v1 keyvault is single-key.
    2. Prompt for the Passphrase twice (hidden, must match, non-empty).
    3. Generate a 24-word BIP39 Seed Phrase + the seed-bound PoW.
    4. ``prepare_generate`` — compute the verification digest in memory.
    5. ``display_seed`` — show the Seed under a network blackout for 60s.
    6. The operator computes the digest offline and transcribes it back.
    7. ``confirm_generate`` — finalize only if the digest matches.
    8. If ``store_seed_for_hd`` (Option A): SE-encrypt the generated seed
       (offline wrap, no prompt) so the HD wallet can derive Ethereum
       accounts later without re-entering the words. Best-effort — the
       keyvault is already durable, so a storage failure degrades to a note.
       Default ``False`` keeps the seed paper-only (never persisted).

    ``backend`` / ``prompt_io`` / ``surface`` / ``display_fn`` default to
    the production implementations; tests inject fakes. Returns 0 on a
    finalized keyvault, 1 on any refusal (already initialised, passphrase
    mismatch, blackout failure, capture abort, expiry, digest mismatch,
    Enclave error).
    """
    from ..keyvault import _bip39, api, seed_display
    from ..keyvault import pow as kvpow

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
            "different key, use `hermes mordred keyvault recover`.",
            file=sys.stderr,
        )
        return 1

    if prompt_io is None:
        from .configure import PromptToolkitIO

        prompt_io = PromptToolkitIO()
    passphrase = prompt_io.ask_password("Choose a Passphrase")
    if passphrase != prompt_io.ask_password("Re-enter the Passphrase"):
        print("Passphrases do not match — nothing was written.", file=sys.stderr)
        return 1
    if not passphrase:
        print("Passphrase must not be empty.", file=sys.stderr)
        return 1

    # Generate the Seed Phrase and its seed-bound PoW (SPEC §"Proof-of-Work").
    seed_phrase = _bip39.generate_mnemonic()
    normalized_seed = api._normalize_seed_phrase(seed_phrase)
    pow_bytes = kvpow.compute_pow(normalized_seed, difficulty_bits=kvpow.POW_DIFFICULTY_BITS)
    # expected_digest is intentionally discarded — the operator must
    # recompute it independently on an offline device, which is the
    # mis-transcription cross-check confirm_generate enforces.
    handle, _expected_digest = api.prepare_generate(seed_phrase, passphrase, pow_bytes)
    # L2 (PR #39 review): the seed is now held in the handle's wipeable
    # bytearray and the digest is computed; drop the CLI's str references
    # so they are GC-eligible during the 60s seed-display window and the
    # interactive digest prompt instead of pinned for the whole function.
    # CPython cannot zero an immutable str in place — this shortens the
    # exposure window, it does not scrub the bytes; the handle's bytearray
    # is the one wipeable copy.
    #
    # HD mode (store_seed_for_hd, Option A) is the deliberate exception: the
    # seed must survive to be SE-encrypted after the key is finalized, so we
    # keep one reference until storage. The operator opted into at-rest seed
    # storage, so the slightly longer in-memory exposure is inherent.
    mnemonic_for_hd = seed_phrase if store_seed_for_hd else None
    del seed_phrase, normalized_seed, passphrase

    if surface is None:
        surface = TerminalSeedSurface()
    show = display_fn if display_fn is not None else seed_display.display_seed
    # The operator needs top4(PoW) to recompute the digest offline; it is
    # derived from the (secret) seed but is itself only a 4-byte mask.
    # The offline tool is `scripts/keyvault_offline_digest.py`; the recipe
    # for preparing the second device + running the tool is documented in
    # `mordred-docs/mordred/setup.md` §"Offline verification digest".
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

    from ..keyvault._exceptions import WrapError
    from ..keyvault.api import SeedDisplayExpired
    from ..keyvault.digest import VerificationDigestMismatch
    from ..keyvault.network_fallback import BlackoutNotAsserted
    from ..keyvault.seed_display import SeedDisplayAborted

    try:
        show(handle, surface)
    except BlackoutNotAsserted:
        print(
            "\n"
            "────────────────────────────────────────────────────────────\n"
            "  Next step: go offline before the Seed Phrase is shown\n"
            "────────────────────────────────────────────────────────────\n"
            "\n"
            "  This is the expected safety check, not an error. Mordred\n"
            "  will only reveal your Seed Phrase when the host is fully\n"
            "  air-gapped, so the seed cannot leak over any active link.\n"
            "\n"
            "  Please disconnect every network interface, then re-run\n"
            "  `hermes-mordred keyvault init`:\n"
            "\n"
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
            "\n"
            "  Nothing has been written yet — your passphrase was not\n"
            "  saved. Re-run after going offline to continue.\n"
            "────────────────────────────────────────────────────────────\n",
            file=sys.stderr,
        )
        return 1
    except SeedDisplayAborted as exc:
        print(f"Seed display aborted: screen capture detected ({exc.detector}).", file=sys.stderr)
        return 1
    except SeedDisplayExpired:
        print("Seed display window expired before the digest was confirmed.", file=sys.stderr)
        return 1

    digest_hex = prompt_io.ask_text("Verification digest from your offline device (hex)")
    try:
        user_digest = bytes.fromhex(digest_hex.strip())
    except ValueError:
        print("That is not a valid hex digest — nothing was written.", file=sys.stderr)
        return 1

    if backend is None:
        from ..keyvault._seckey_backend import _SecKeyBackend

        backend = _SecKeyBackend()
    sink = audit_sink if audit_sink is not None else _stderr_audit_sink

    try:
        result = api.confirm_generate(handle, user_digest, backend=backend, audit_sink=sink, home=home)
    except VerificationDigestMismatch:
        print(
            "Verification digest mismatch — the Seed or Passphrase was mis-transcribed. "
            "Nothing was written; rerun `hermes mordred keyvault init`.",
            file=sys.stderr,
        )
        return 1
    except WrapError as exc:
        print(f"Keyvault init failed: Secure Enclave error — {exc}", file=sys.stderr)
        return 1
    except RuntimeError as exc:
        # confirm_generate's own re-init guard (a race with the pre-check).
        print(f"Keyvault init refused: {exc}", file=sys.stderr)
        return 1

    # L465: provision the audit-log wrapping key so privacy_check's
    # encrypted-audit factory (privacy_check.audit.make_audit_writer)
    # engages on the next session. Best-effort — the keyvault is already
    # durably initialised; if this fails the audit log simply stays
    # plaintext until repaired.
    try:
        from ..keyvault.log_encryption import AUDIT_LOG_KEY_ID
        from ..keyvault.wrap import generate_wrapping_key

        generate_wrapping_key(AUDIT_LOG_KEY_ID, backend=backend)
    except WrapError as exc:
        print(
            f"note: audit-log wrapping key not provisioned ({exc}); the audit log "
            "stays plaintext until the keyvault is repaired.",
            file=sys.stderr,
        )

    # HD mode (Option A): SE-encrypt the just-generated seed so the HD wallet
    # can derive Ethereum accounts later without re-entering the 24 words. The
    # keyvault is already durably initialised at this point, so a storage
    # failure is surfaced as a note rather than failing the whole init.
    if mnemonic_for_hd is not None:
        # Storing is OFFLINE — store_seed_phrase wraps the DEK with the
        # Enclave *public* key, so it never triggers an authorization prompt.
        # We deliberately do NOT derive an account here: derivation unwraps
        # (ECDH), which on an interactive wrapping key would force a Touch ID
        # prompt at the very end of init. Derivation happens on demand later.
        # The catch is broad (Exception) because the keyvault is already
        # durable; any storage failure must degrade to a note, not a traceback.
        try:
            from ..keyvault.ethereum import store_seed_phrase

            sink = audit_sink if audit_sink is not None else _stderr_audit_sink
            seed_env_id = store_seed_phrase(result.key_id, mnemonic_for_hd, backend=backend, audit_sink=sink, home=home)
            print(f"HD wallet enabled. Seed stored SE-encrypted (envelope {seed_env_id}).")
        except Exception as exc:
            print(
                f"note: HD seed not stored ({exc!r}); the keyvault is still initialised, "
                "but HD derivation is unavailable until the seed is stored.",
                file=sys.stderr,
            )
        finally:
            del mnemonic_for_hd

    print(f"Keyvault initialised. Key: {result.key_id}")
    return 0


# -----------------------------------------------------------------------------
# enable-se — build + ad-hoc-sign + install the Secure Enclave helper.
#
# Upgrades the keyvault wrapping key from the software P-256 fallback to the
# real hardware Secure Enclave via the CryptoKit ``dataRepresentation`` helper
# (``native/sekey-helper``). That helper needs only an ad-hoc codesign — no
# entitlement, no provisioning profile, no paid Apple Developer account.
#
# Each step is a module-level seam so the orchestration is unit-testable with
# no Swift toolchain and no Secure Enclave (the build / probe are mocked).
# -----------------------------------------------------------------------------


def _se_platform_reason() -> str | None:
    """Return why the SE helper can't be built here, or ``None`` when it can.

    The CryptoKit ``SecureEnclave`` APIs exist only on macOS (Apple Silicon or
    a T2 Mac). A coarse ``Darwin`` guard is enough; true SE *presence* is
    confirmed by the post-install probe.
    """
    import platform

    if platform.system() != "Darwin":
        return f"Secure Enclave requires macOS on Apple Silicon (this host is {platform.system() or 'unknown'})"
    return None


def _missing_build_tools() -> list[str]:
    """Return the build tools (``swift``, ``codesign``) not found on ``PATH``."""
    import shutil

    return [tool for tool in ("swift", "codesign") if shutil.which(tool) is None]


def _locate_sekey_source() -> Path | None:
    """Locate the ``sekey-helper`` source tree (delegates to ``_seckey_helper``)."""
    from ..keyvault import _seckey_helper

    return _seckey_helper._locate_helper_source()


def _run_sekey_build(src: Path, *, install_dir: Path | None, unattended: bool | None) -> tuple[int, str]:
    """Run ``build.sh`` in ``src``; return ``(returncode, combined_output)``.

    ``install_dir`` / ``unattended`` are forwarded as the env vars the build
    script and helper honour (``MORDRED_SEKEY_INSTALL_DIR`` /
    ``MORDRED_SEKEY_UNATTENDED``).
    """
    import os
    import subprocess

    env = dict(os.environ)
    if install_dir is not None:
        env["MORDRED_SEKEY_INSTALL_DIR"] = str(install_dir)
    if unattended is not None:
        env["MORDRED_SEKEY_UNATTENDED"] = "1" if unattended else "0"
    try:
        proc = subprocess.run(
            ["bash", str(src / "build.sh")],
            cwd=str(src),
            env=env,
            capture_output=True,
            text=True,
            timeout=600,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return 1, f"failed to run build.sh: {exc}"
    return proc.returncode, (proc.stdout or "") + (proc.stderr or "")


def _verify_sekey_helper(*, install_dir: Path | None = None) -> bool:
    """Probe the freshly-installed helper to confirm Secure Enclave access.

    When ``install_dir`` is given (``enable-se --install-dir``), the binary just
    installed there is preferred — ``_find_helper`` only searches
    ``MORDRED_SEKEY_HELPER`` / ``~/.local/bin`` / ``PATH``, so a custom,
    not-on-PATH install dir would otherwise yield a false verification failure.
    (Mirror of :func:`_verify_tpmkey_helper`.)
    """
    from ..keyvault import _seckey_helper

    binary: str | None = None
    if install_dir is not None:
        candidate = install_dir / _seckey_helper._HELPER_NAME
        if candidate.is_file():
            binary = str(candidate)
    if binary is None:
        binary = _seckey_helper._find_helper()
    if binary is None:
        return False
    try:
        _seckey_helper._HelperSecKeyOps(binary).probe()
        return True
    except Exception:
        return False


def enable_se(
    *,
    install_dir: Path | None = None,
    unattended: bool | None = None,
    home: Path | None = None,
) -> int:
    """Build + ad-hoc-sign + install the SE helper, then verify it works.

    Returns ``0`` on success, ``1`` on any guard / build / verify failure. On
    failure the keyvault keeps using the software P-256 fallback, so the
    at-rest guarantee never downgrades. ``home`` is accepted for symmetry with
    the other keyvault commands; the helper resolves its key-blob store from
    ``HERMES_HOME`` itself.
    """
    del home  # the helper resolves its store via HERMES_HOME; accepted for symmetry

    reason = _se_platform_reason()
    if reason is not None:
        print(f"error: {reason}", file=sys.stderr)
        return 1

    missing = _missing_build_tools()
    if missing:
        print(
            f"error: missing build tool(s): {', '.join(missing)}. "
            "Install the Xcode command-line tools first (xcode-select --install).",
            file=sys.stderr,
        )
        return 1

    src = _locate_sekey_source()
    if src is None:
        print(
            "error: could not locate the sekey-helper sources (native/sekey-helper). "
            "Build from a source checkout of mordred-hermes.",
            file=sys.stderr,
        )
        return 1

    rc, output = _run_sekey_build(src, install_dir=install_dir, unattended=unattended)
    if rc != 0:
        print(f"error: sekey-helper build failed:\n{output}", file=sys.stderr)
        return 1

    if not _verify_sekey_helper(install_dir=install_dir):
        print(
            "error: helper installed but the Secure Enclave probe failed; "
            "the keyvault will keep using the software fallback.",
            file=sys.stderr,
        )
        return 1

    print(output.strip() or "Secure Enclave helper installed.")
    print("Hardware Secure Enclave is now active for the keyvault.")
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


def cli_init(args: argparse.Namespace) -> int:
    """argparse handler for ``keyvault init`` (``--store-seed-for-hd`` opt-in)."""
    return init_keyvault(store_seed_for_hd=getattr(args, "store_seed_for_hd", False))


def cli_enable_se(args: argparse.Namespace) -> int:
    """argparse handler for ``keyvault enable-se [--install-dir P] [--unattended]``.

    ``--unattended`` absent → ``None`` (let ``MORDRED_SEKEY_UNATTENDED`` / the
    interactive default decide), not ``False``.
    """
    install_dir = Path(args.install_dir) if getattr(args, "install_dir", None) else None
    unattended = True if getattr(args, "unattended", False) else None
    return enable_se(install_dir=install_dir, unattended=unattended)


# -----------------------------------------------------------------------------
# enable-tpm — build + install the Linux TPM 2.0 helper (v2-OS2 Phase 2c).
#
# The Linux counterpart to enable-se: builds the ``mordred-hermes-tpmkey`` Rust
# helper (``native/tpmkey-helper``) and verifies it. The TPM is Tier 2
# (machine-bound) — the key cannot leave the chip, but there is no per-use
# user-presence gate, so (unlike enable-se) there is no ``--unattended`` flag.
# Each step is a module-level seam so the orchestration is unit-testable with
# no Rust toolchain and no TPM.
# -----------------------------------------------------------------------------


def _tpm_platform_reason() -> str | None:
    """Return why the TPM helper can't be built here, or ``None`` when it can.

    The ``tss-esapi`` / libtss2 backend is Linux-only (Windows TPM via CNG is a
    separate future helper). A coarse ``Linux`` guard is enough; true TPM
    *presence* is confirmed by the post-install probe.
    """
    import platform

    if platform.system() != "Linux":
        return f"TPM 2.0 keyvault requires Linux (this host is {platform.system() or 'unknown'})"
    return None


def _missing_tpm_build_tools() -> list[str]:
    """Return the build tools (``cargo``) not found on ``PATH``."""
    import shutil

    return [tool for tool in ("cargo",) if shutil.which(tool) is None]


def _locate_tpmkey_source() -> Path | None:
    """Locate the ``tpmkey-helper`` source tree (delegates to ``_seckey_helper``)."""
    from ..keyvault import _seckey_helper

    return _seckey_helper._locate_tpmkey_source()


def _run_tpmkey_build(src: Path, *, install_dir: Path | None) -> tuple[int, str]:
    """Run ``build.sh`` in ``src``; return ``(returncode, combined_output)``.

    ``install_dir`` is forwarded as ``MORDRED_TPMKEY_INSTALL_DIR``. The TPM is
    Tier 2 with no per-use gate, so there is no ``unattended`` env var (cf.
    :func:`_run_sekey_build`).
    """
    import os
    import subprocess

    env = dict(os.environ)
    if install_dir is not None:
        env["MORDRED_TPMKEY_INSTALL_DIR"] = str(install_dir)
    try:
        proc = subprocess.run(
            ["bash", str(src / "build.sh")],
            cwd=str(src),
            env=env,
            capture_output=True,
            text=True,
            timeout=600,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return 1, f"failed to run build.sh: {exc}"
    return proc.returncode, (proc.stdout or "") + (proc.stderr or "")


def _verify_tpmkey_helper(*, install_dir: Path | None = None) -> bool:
    """Probe the freshly-installed helper to confirm TPM access.

    When ``install_dir`` is given (``enable-tpm --install-dir``), the binary
    just installed there is preferred — ``find_tpmkey_helper`` only searches
    ``MORDRED_TPMKEY_HELPER`` / ``~/.local/bin`` / ``PATH``, so a custom,
    not-on-PATH install dir would otherwise yield a false verification failure.
    """
    from ..keyvault import _seckey_helper

    binary: str | None = None
    if install_dir is not None:
        candidate = install_dir / _seckey_helper._TPM_HELPER_NAME
        if candidate.is_file():
            binary = str(candidate)
    if binary is None:
        binary = _seckey_helper.find_tpmkey_helper()
    if binary is None:
        return False
    try:
        _seckey_helper._HelperSecKeyOps(binary).probe()
        return True
    except Exception:
        return False


def enable_tpm(
    *,
    install_dir: Path | None = None,
    home: Path | None = None,
) -> int:
    """Build + install the TPM helper, then verify it works.

    Returns ``0`` on success, ``1`` on any guard / build / verify failure. On
    failure the keyvault keeps using the software P-256 fallback, so the
    at-rest guarantee never downgrades. ``home`` is accepted for symmetry with
    the other keyvault commands; the helper resolves its key-blob store from
    ``HERMES_HOME`` itself.
    """
    del home  # the helper resolves its store via HERMES_HOME; accepted for symmetry

    reason = _tpm_platform_reason()
    if reason is not None:
        print(f"error: {reason}", file=sys.stderr)
        return 1

    missing = _missing_tpm_build_tools()
    if missing:
        print(
            f"error: missing build tool(s): {', '.join(missing)}. "
            "Install the Rust toolchain first (https://rustup.rs).",
            file=sys.stderr,
        )
        return 1

    src = _locate_tpmkey_source()
    if src is None:
        print(
            "error: could not locate the tpmkey-helper sources (native/tpmkey-helper). "
            "Build from a source checkout of mordred-hermes.",
            file=sys.stderr,
        )
        return 1

    rc, output = _run_tpmkey_build(src, install_dir=install_dir)
    if rc != 0:
        print(f"error: tpmkey-helper build failed:\n{output}", file=sys.stderr)
        return 1

    if not _verify_tpmkey_helper(install_dir=install_dir):
        print(
            "error: helper installed but the TPM probe did not succeed, so no "
            "hardware key is active. On Linux the keyvault fails closed (there is "
            "no software fallback off macOS), so keyvault operations needing a "
            "hardware key error until a working helper is in place. Note: the "
            "v2-OS2 Phase 2a helper has no TPM backend yet — that lands in Phase "
            "2b — so this failure is expected until then.",
            file=sys.stderr,
        )
        return 1

    print(output.strip() or "TPM 2.0 helper installed.")
    print("Hardware TPM 2.0 is now active for the keyvault.")
    return 0


def cli_enable_tpm(args: argparse.Namespace) -> int:
    """argparse handler for ``keyvault enable-tpm [--install-dir P]``.

    The TPM is Tier 2 (machine-bound) with no per-use gate, so there is no
    ``--unattended`` flag (cf. :func:`cli_enable_se`).
    """
    install_dir = Path(args.install_dir) if getattr(args, "install_dir", None) else None
    return enable_tpm(install_dir=install_dir)
