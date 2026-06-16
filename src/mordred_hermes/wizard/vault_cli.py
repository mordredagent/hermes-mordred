"""``hermes mordred vault {status,...}`` — at-rest vault CLI.

Design note: ``mordred-docs/mordred/SECRETS_ENV_ENCRYPTION.ja.md`` §8.2.

The at-rest vault (``keyvault/{vault,manifest,anchor,file_container}.py``)
generalises secret-at-rest encryption beyond the legacy keyvault. This module
exposes its **cold-path** commands — open via
:func:`mordred_hermes.keyvault.vault.recover_vault` (the passphrase recovery
sidecar), which needs neither the Secure-Enclave ``NativeBackend`` nor the
device-bound anchor store, so they work on any platform and on a vault copied
to another machine.

A cold-path open is **read-only** (no device anchor to commit against);
enrolling requires re-keying onto a device first.

Heavy imports (the cryptography-backed vault modules) stay function-local so
this module imports on any platform, matching ``keyvault_cli.py``.
"""

from __future__ import annotations

import argparse
import contextlib
import sys
from pathlib import Path
from typing import TYPE_CHECKING

from .._home import hermes_home as _hermes_home
from ..keyvault import _identity

if TYPE_CHECKING:
    from ..keyvault.anchor import AnchorStore
    from ..keyvault.vault import OpenVault
    from ..keyvault.wrap import NativeBackend
    from .configure import PromptIO

__all__ = [
    "add",
    "cat",
    "change_passphrase",
    "cli_add",
    "cli_cat",
    "cli_change_passphrase",
    "cli_init",
    "cli_migrate",
    "cli_status",
    "ensure_initialised",
    "init",
    "migrate",
    "status",
]


def _resolve_root(root: str | None) -> Path:
    """Resolve the vault root, defaulting to ``<hermes home>/mordred/vault``.

    Delegates to :func:`mordred_hermes.keyvault._identity.resolve_root` — the
    shared derivation the runtime decrypt shim also uses — so the CLI and the
    shim resolve the same root (and thus the same :func:`_vault_identity`) for a
    given input. A user-supplied root is resolved to an absolute, normalized path
    so spelling differences (relative path, ``..``, cwd) never yield a different
    vault identity.
    """
    return _identity.resolve_root(root)


def _display_name(name: str) -> str:
    """Render an enrolled name safely for the terminal.

    Enrolled names are arbitrary strings; one containing control characters
    (e.g. ANSI escapes) would otherwise inject into the operator's terminal
    when listed. Non-printable names are shown backslash-escaped.
    """
    return name if name.isprintable() else name.encode("unicode_escape").decode("ascii")


def _vault_identity(root: Path) -> str:
    """Stable id (SE wrapping-key tag + Keychain anchor account) for a vault root.

    Delegates to :func:`mordred_hermes.keyvault._identity.vault_identity` — the
    shared derivation the runtime decrypt shim also uses, so the CLI and the shim
    open the same vault for a given root.
    """
    return _identity.vault_identity(root)


def _open_cold_path(root: Path, *, prompt_io: PromptIO | None) -> OpenVault | None:
    """Open a vault read-only via the passphrase recovery sidecar.

    Prompts for the passphrase and opens through
    :func:`...vault.recover_vault` — no Secure-Enclave backend, no device
    anchor. Fail-closed: a non-vault root, a missing recovery sidecar, a wrong
    passphrase, or a tampered manifest/sidecar each print a reason to stderr
    and return ``None``. On success returns the opened (read-only) vault; the
    caller owns closing it.
    """
    from cryptography.exceptions import InvalidTag

    from ..keyvault import backup, manifest, recovery, vault

    if prompt_io is None:
        from .configure import PromptToolkitIO

        prompt_io = PromptToolkitIO()
    passphrase = prompt_io.ask_password("Vault passphrase")

    try:
        return vault.recover_vault(root, passphrase)
    except vault.VaultError as exc:
        print(f"Not a recoverable vault at {root}: {exc}", file=sys.stderr)
        return None
    except recovery.RecoveryDigestMismatch:
        print(
            "Vault rejected: the recovery sidecar does not match the manifest (substituted wmk / tampering).",
            file=sys.stderr,
        )
        return None
    except manifest.ManifestError:
        print("Vault rejected: the manifest failed authentication (tampering).", file=sys.stderr)
        return None
    except backup.BackupCorrupt as exc:
        print(f"Vault rejected: the recovery sidecar is corrupt — {exc}", file=sys.stderr)
        return None
    except InvalidTag:
        print("Wrong passphrase — vault not opened.", file=sys.stderr)
        return None
    except OSError as exc:
        print(f"Cannot read vault at {root}: {exc}", file=sys.stderr)
        return None
    finally:
        # CPython cannot zero an immutable str in place; dropping the reference
        # shortens the exposure window, it does not scrub the bytes.
        del passphrase


def _open_hot_path_or_report(
    root: Path, *, backend: NativeBackend | None = None, store: AnchorStore | None = None
) -> OpenVault | None:
    """Open the vault at ``root`` on the **hot path**, or report and return ``None``.

    The shared open used by :func:`add` / :func:`migrate` / :func:`set_memory_key`:
    opens via the device wrapping key (Secure Enclave or its software fallback,
    no passphrase). ``backend`` / ``store`` default to the production
    implementations; tests inject fakes. On any fail-closed open error a reason is
    printed to stderr and ``None`` is returned (a freshness-pin mismatch is
    surfaced as possible tampering, an uninitialised vault points at ``vault
    init``). The caller owns closing the returned vault.
    """
    from ..keyvault import anchor, manifest, vault
    from ..keyvault._exceptions import WrapError

    key_id = anchor_label = _vault_identity(root)
    if backend is None:
        from ..keyvault._seckey_backend import _SecKeyBackend

        backend = _SecKeyBackend()
    if store is None:
        from ..keyvault._anchor_keychain import KeychainAnchorStore

        store = KeychainAnchorStore()

    try:
        return vault.open_vault(root, key_id=key_id, backend=backend, store=store, anchor_label=anchor_label)
    except anchor.AnchorMissing:
        print(f"no vault at {root} — run `vault init` first.", file=sys.stderr)
    except (anchor.AnchorMismatch, anchor.AnchorCorrupt) as exc:
        # A freshness-pin mismatch is the anchor's whole purpose — surface it as
        # possible tampering / rollback, not a generic open failure.
        print(f"vault freshness check failed at {root} (possible tampering): {exc}", file=sys.stderr)
    except (anchor.AnchorError, vault.VaultError, manifest.ManifestError, OSError) as exc:
        print(f"cannot open vault at {root}: {exc}", file=sys.stderr)
    except WrapError as exc:
        print(f"cannot open vault at {root}: device key store error — {exc}", file=sys.stderr)
    return None


def status(*, root: Path, prompt_io: PromptIO | None = None, as_json: bool = False) -> int:
    """Print a vault's generation and enrolled file names (cold path).

    Opens read-only via :func:`_open_cold_path`. Enrolled *names* are listed;
    file *contents* are never decrypted or printed. Returns 0 on a successful
    open, 1 on any fail-closed open error (reason already on stderr).
    """
    import json

    opened = _open_cold_path(root, prompt_io=prompt_io)
    if opened is None:
        return 1
    try:
        names = sorted(opened.list_files())
        if as_json:
            body = {
                "root": str(root),
                "generation": opened.generation,
                "files": names,
                "read_only": True,
            }
            print(json.dumps(body, indent=2))
            return 0
        print(f"Vault at {root}")
        print(f"  generation: {opened.generation}")
        print(f"  files: {len(names)}")
        for name in names:
            print(f"    {_display_name(name)}")
        print("  (read-only: opened via passphrase recovery)")
    finally:
        opened.close()
    return 0


def cat(*, root: Path, name: str, prompt_io: PromptIO | None = None) -> int:
    """Write one enrolled file's decrypted bytes to stdout (cold path).

    Opens read-only via :func:`_open_cold_path`, decrypts file ``name``, and
    writes its raw bytes to stdout — binary-safe, byte-exact, no trailing
    newline added. Fail-closed: a failed open, or a name that is absent /
    unreadable / fails its content-address or AEAD check, prints a reason to
    stderr and returns 1. Returns 0 on success.
    """
    from ..keyvault import vault

    opened = _open_cold_path(root, prompt_io=prompt_io)
    if opened is None:
        return 1
    try:
        data = opened.read_file(name)
    except vault.VaultError as exc:
        print(f"cannot read {name!r}: {exc}", file=sys.stderr)
        return 1
    finally:
        opened.close()

    try:
        sys.stdout.buffer.write(data)
        sys.stdout.buffer.flush()
    except BrokenPipeError:
        # Downstream closed early (e.g. `vault cat … | head`); not an error.
        return 0
    except OSError as exc:
        print(f"failed writing {name!r} to stdout: {exc}", file=sys.stderr)
        return 1
    return 0


def init(
    *,
    root: Path,
    prompt_io: PromptIO | None = None,
    backend: NativeBackend | None = None,
    store: AnchorStore | None = None,
) -> int:
    """Create a fresh encrypted vault at ``root`` sealed under a new passphrase.

    Seals one master under both the device wrapping key (hot path) and an
    Argon2id passphrase recovery sidecar (cold path). The wrapping key prefers
    the Secure Enclave and transparently falls back to a software key when the
    Enclave is unavailable (e.g. a non-provisioned interpreter); the cold path
    is unaffected either way.

    Refuses to clobber an already-initialised vault (its anchor is present).
    ``backend`` / ``store`` / ``prompt_io`` default to the production
    implementations; tests inject fakes. Returns 0 on success, 1 on a re-init,
    a passphrase mismatch / empty passphrase, or a Secure-Enclave / Keychain
    error.
    """
    from ..keyvault import anchor, vault
    from ..keyvault._exceptions import WrapError, WrapKeyNotFound

    key_id = anchor_label = _vault_identity(root)

    if backend is None:
        from ..keyvault._seckey_backend import _SecKeyBackend

        backend = _SecKeyBackend()
    if store is None:
        from ..keyvault._anchor_keychain import KeychainAnchorStore

        store = KeychainAnchorStore()

    # Re-init guard before prompting: an existing anchor means a live vault. A
    # Keychain read failure here is fail-closed (we cannot prove the vault is
    # absent, so we must not risk clobbering one).
    try:
        already_initialised = store.read(anchor_label) is not None
    except (anchor.AnchorError, OSError) as exc:
        print(f"Cannot determine vault state at {root}: {exc}", file=sys.stderr)
        return 1
    if already_initialised:
        print(f"A vault is already initialised at {root} — refusing to clobber it.", file=sys.stderr)
        return 1

    if prompt_io is None:
        from .configure import PromptToolkitIO

        prompt_io = PromptToolkitIO()
    # Teach the two-key model at creation time — the single most confusing point
    # for newcomers (vault has ONE master key opened two ways): the device key is
    # the everyday opener; the passphrase is the cold-path backup, not something
    # typed day to day. Saying so up front pre-empts "do I type this every time?"
    # and "is the passphrase the only key?".
    print("This vault can be opened two ways:")
    print("  • this device          — automatically, no typing (Secure Enclave, or a software key if unavailable)")
    print("  • a recovery passphrase — your backup, used only if this device is lost or replaced")
    print("Next you'll set the recovery passphrase. You will NOT need to type it day to day.")
    print()
    passphrase = prompt_io.ask_password("Choose a vault recovery passphrase")
    if not passphrase:
        print("Passphrase must not be empty — nothing was written.", file=sys.stderr)
        return 1
    if passphrase != prompt_io.ask_password("Re-enter the passphrase"):
        print("Passphrases do not match — nothing was written.", file=sys.stderr)
        return 1

    try:
        # Ensure the device wrapping key exists (init seals under it). A
        # pre-existing key from a crashed earlier init is reused — not an error.
        with contextlib.suppress(WrapKeyNotFound):
            backend.generate_enclave_key(key_id)
        # Create the vault, then close immediately — init enrolls nothing, and
        # the context manager guarantees the in-RAM master is zeroed on exit.
        with vault.init_vault(
            root, key_id=key_id, passphrase=passphrase, backend=backend, store=store, anchor_label=anchor_label
        ):
            pass
    except vault.VaultError as exc:
        # A concurrent init won the anchor race after our pre-check.
        print(f"Vault init refused: {exc}", file=sys.stderr)
        return 1
    except (anchor.AnchorError, WrapError, OSError) as exc:
        print(f"Vault init failed: device key store / anchor error — {exc}", file=sys.stderr)
        return 1
    finally:
        del passphrase

    print(f"Vault initialised at {root}.")
    print("  Day to day: this device opens the vault automatically — you won't be asked for the passphrase.")
    print(
        "  If this device is lost: the recovery passphrase is the ONLY way back in — "
        "store it safely (e.g. a password manager)."
    )
    return 0


def ensure_initialised(
    *,
    root: Path,
    prompt_io: PromptIO | None = None,
    backend: NativeBackend | None = None,
    store: AnchorStore | None = None,
) -> int:
    """Create the vault if it is missing; no-op (return 0) if it already exists.

    The high-level ``encryption enable`` path *drives* the vault (USAGE §4, "the
    three storage layers"): a first enable on a fresh install creates the vault
    inline — prompting once for a recovery passphrase via :func:`init` — instead
    of failing with a "run ``vault init``" error. An already-initialised vault is
    left untouched, so repeat enables never re-prompt.

    Returns 0 when the vault exists (or was just created), 1 on a create failure
    (passphrase mismatch / empty, Secure-Enclave / Keychain error) or when the
    vault state cannot be determined (fail-closed, mirroring :func:`init`).
    """
    from ..keyvault import anchor

    if store is None:
        from ..keyvault._anchor_keychain import KeychainAnchorStore

        store = KeychainAnchorStore()

    anchor_label = _vault_identity(root)
    try:
        if store.read(anchor_label) is not None:
            return 0  # vault already initialised — nothing to do
    except (anchor.AnchorError, OSError) as exc:
        # Fail-closed: we cannot prove the vault is absent, so do not risk
        # clobbering one with a fresh init (matches the guard in `init`).
        print(f"Cannot determine vault state at {root}: {exc}", file=sys.stderr)
        return 1

    print(f"No vault yet at {root} — creating one (this is where `encryption` stores secrets at rest).")
    # `store` is already resolved above, so `init` reuses this instance rather than
    # opening a second Keychain connection — keep the resolution before delegating.
    return init(root=root, prompt_io=prompt_io, backend=backend, store=store)


def change_passphrase(
    *,
    root: Path,
    prompt_io: PromptIO | None = None,
    backend: NativeBackend | None = None,
    store: AnchorStore | None = None,
) -> int:
    """Change the vault's recovery passphrase, keeping the master key unchanged.

    Tries the device key first — no old passphrase needed, the everyday "I forgot
    the passphrase but this machine still works" path. If the device key / anchor
    is unavailable (non-macOS, or a vault copied here), falls back to asking for
    the current passphrase. Only the recovery sidecar is rewritten; no enrolled
    file is re-encrypted and the device-key open is unaffected.

    Returns 0 on success, 1 on any failure (no vault, empty / mismatched new
    passphrase, wrong current passphrase, or an unrecoverable device error).
    """
    from cryptography.exceptions import InvalidTag

    from ..keyvault import anchor, recovery, vault
    from ..keyvault._exceptions import WrapError

    key_id = anchor_label = _vault_identity(root)

    # The recovery sidecar is the one file we rewrite; its absence means there is
    # no vault to rotate. Do NOT create one here (unlike `encryption enable`).
    if not (root / "recovery.mrkv").exists():
        print(
            f"No vault at {root} — nothing to rotate. Run `encryption enable env` first.",
            file=sys.stderr,
        )
        return 1

    if backend is None:
        from ..keyvault._seckey_backend import _SecKeyBackend

        backend = _SecKeyBackend()
    if store is None:
        from ..keyvault._anchor_keychain import KeychainAnchorStore

        store = KeychainAnchorStore()
    if prompt_io is None:
        from .configure import PromptToolkitIO

        prompt_io = PromptToolkitIO()

    new_passphrase = prompt_io.ask_password("Choose a NEW recovery passphrase")
    if not new_passphrase:
        print("Passphrase must not be empty — nothing was changed.", file=sys.stderr)
        return 1
    if new_passphrase != prompt_io.ask_password("Re-enter the new passphrase"):
        print("Passphrases do not match — nothing was changed.", file=sys.stderr)
        return 1

    try:
        # Device-key path first — no need to know the old passphrase.
        vault.change_passphrase(
            root,
            new_passphrase=new_passphrase,
            old_passphrase=None,
            key_id=key_id,
            backend=backend,
            store=store,
            anchor_label=anchor_label,
        )
    except (anchor.AnchorError, WrapError):
        # Device key / anchor unusable here — fall back to the cold path, which is
        # authorized by the current passphrase instead.
        print("This device's key can't authorize the change here — enter your CURRENT passphrase to continue.")
        old_passphrase = prompt_io.ask_password("Current recovery passphrase")
        try:
            vault.change_passphrase(
                root,
                new_passphrase=new_passphrase,
                old_passphrase=old_passphrase,
                key_id=key_id,
                backend=backend,
                store=store,
                anchor_label=anchor_label,
            )
        except (vault.VaultError, recovery.RecoveryDigestMismatch, InvalidTag, ValueError, OSError) as exc:
            print(f"Could not change the passphrase: {exc}", file=sys.stderr)
            return 1
        finally:
            del old_passphrase
    except (vault.VaultError, ValueError, OSError) as exc:
        # OSError covers a disk failure in the atomic sidecar write and a
        # wrong-mode .lock (KeyvaultPermissionError) — surface as a clean exit 1,
        # not a traceback. (AnchorError / WrapError are handled above as the
        # device-unavailable fallback, so they never reach here.)
        print(f"Could not change the passphrase: {exc}", file=sys.stderr)
        return 1
    finally:
        del new_passphrase

    print("Recovery passphrase changed.")
    print("  Your device key is unchanged — day-to-day automatic opening still works exactly as before.")
    print("  Only the backup passphrase changed. Store the new one safely (e.g. a password manager).")
    return 0


def add(
    *,
    root: Path,
    name: str,
    source: Path,
    backend: NativeBackend | None = None,
    store: AnchorStore | None = None,
) -> int:
    """Enroll ``source``'s bytes into the vault at ``root`` under ``name``.

    Opens the vault on the **hot path** (the device wrapping key — Secure
    Enclave or its software fallback, no passphrase) via
    :func:`...vault.open_vault`, then commits the encrypted file. Enrolling an
    existing ``name`` supersedes it (a new generation).

    Note: the plaintext ``source`` file is **not** removed — the operator owns
    shredding it if the on-disk plaintext is no longer wanted.

    ``backend`` / ``store`` default to the production implementations; tests
    inject fakes. Returns 0 on success, 1 on an uninitialised / unverifiable
    vault, an unreadable source, or a device key-store error.
    """
    from ..keyvault import anchor, vault
    from ..keyvault._exceptions import WrapError

    try:
        plaintext = source.read_bytes()
    except OSError as exc:
        print(f"cannot read source file {source}: {exc}", file=sys.stderr)
        return 1

    opened = _open_hot_path_or_report(root, backend=backend, store=store)
    if opened is None:
        return 1

    try:
        opened.enroll_file(name, plaintext)
        generation = opened.generation
    except (vault.VaultError, anchor.AnchorError, WrapError, OSError) as exc:
        print(f"cannot add {name!r}: {exc}", file=sys.stderr)
        return 1
    finally:
        opened.close()

    print(f"Added {name!r} to the vault at {root} (now at generation {generation}).")
    return 0


def migrate(
    *,
    root: Path,
    sources: list[Path],
    backend: NativeBackend | None = None,
    store: AnchorStore | None = None,
) -> int:
    """Batch-import each plaintext file in ``sources`` into the vault at ``root``.

    A batch :func:`add`: opens the vault **once** on the hot path (the device
    wrapping key — Secure Enclave or its software fallback, no passphrase) and
    enrolls every source under its basename (``source.name``), so importing the
    operator's existing plaintext (``~/.hermes/.env`` / ``config.yaml``) is one
    command.

    **Read-all-then-enroll-all**: every source is read up front, so an
    unreadable path or a duplicate basename aborts *before* the vault is touched
    — a typo never leaves a half-migrated vault. (A rare device error mid-enroll
    can still leave the files committed before it enrolled; each
    :meth:`enroll_file` is its own crash-safe generation.) A consequence is that
    all source plaintexts coexist in RAM from the read phase until return —
    acceptable under the §2 threat model, which excludes live-RAM attackers.
    Like :func:`add`, the plaintext sources are **not** removed — the operator
    owns shredding them.

    ``backend`` / ``store`` default to the production implementations; tests
    inject fakes. Returns 0 on success (an empty ``sources`` is a no-op success),
    1 on a duplicate name, an unreadable source, an uninitialised / unverifiable
    vault, or a device key-store error.
    """
    if not sources:
        print("Nothing to migrate.")
        return 0

    # Each source enrolls under its basename; a name claimed by two sources is
    # ambiguous (which one wins?) — refuse before any I/O, enroll nothing.
    by_name: dict[str, Path] = {}
    for source in sources:
        name = source.name
        if name in by_name:
            print(
                f"refusing to migrate: {name!r} maps to more than one source "
                f"({by_name[name]}, {source}) — migrate them under distinct names.",
                file=sys.stderr,
            )
            return 1
        by_name[name] = source

    # Read every plaintext first so a bad path fails the whole run before the
    # first commit (read-all-then-enroll-all: no partially migrated vault).
    plaintexts: list[tuple[str, bytes]] = []
    for name, source in by_name.items():
        try:
            plaintexts.append((name, source.read_bytes()))
        except OSError as exc:
            print(f"cannot read source file {source}: {exc}", file=sys.stderr)
            return 1

    from ..keyvault import anchor, vault
    from ..keyvault._exceptions import WrapError

    opened = _open_hot_path_or_report(root, backend=backend, store=store)
    if opened is None:
        return 1

    enrolled = 0
    try:
        for name, plaintext in plaintexts:
            opened.enroll_file(name, plaintext)
            enrolled += 1
        generation = opened.generation
    except (vault.VaultError, anchor.AnchorError, WrapError, OSError) as exc:
        # `enrolled` is the index of the file that failed (incremented only after
        # a successful enroll). Bounds-guard the lookup so a failure raised
        # anywhere in the try — even after the loop — still fails closed with a
        # message rather than an IndexError traceback.
        failed = plaintexts[enrolled][0] if enrolled < len(plaintexts) else "<unknown>"
        print(
            f"cannot migrate {failed!r} ({enrolled} of {len(plaintexts)} already enrolled): {exc}",
            file=sys.stderr,
        )
        return 1
    finally:
        opened.close()

    listed = ", ".join(_display_name(n) for n, _ in plaintexts)
    print(f"Migrated {len(plaintexts)} file(s) into the vault at {root} (now at generation {generation}): {listed}.")
    return 0


# -----------------------------------------------------------------------------
# CLI adapters wired in cli.py.
# -----------------------------------------------------------------------------


def cli_add(args: argparse.Namespace) -> int:
    """argparse handler for ``vault add <name> <source> [--root PATH]``."""
    return add(root=_resolve_root(getattr(args, "root", None)), name=args.name, source=Path(args.source))


def _default_migrate_sources() -> list[Path]:
    """The canonical Hermes plaintext files to import — those that exist.

    The vault's reason for being (design §8.2): the operator's existing
    ``<hermes home>/.env`` and ``<hermes home>/config.yaml``. Absent ones are
    skipped so a no-argument ``vault migrate`` imports whatever is actually
    there. Resolved via this module's :func:`_hermes_home` so tests can
    monkeypatch the home.
    """
    home = _hermes_home()
    # Order is intentional and asserted by tests: .env before config.yaml.
    return [p for p in (home / ".env", home / "config.yaml") if p.is_file()]


def cli_migrate(args: argparse.Namespace) -> int:
    """argparse handler for ``vault migrate [SOURCE ...] [--root PATH]``.

    With explicit ``SOURCE`` paths, migrates exactly those. With none, imports
    the canonical Hermes plaintext set (:func:`_default_migrate_sources`). When
    neither is available, prints guidance and returns 1 rather than silently
    doing nothing.
    """
    explicit = [Path(s) for s in (getattr(args, "source", None) or [])]
    sources = explicit if explicit else _default_migrate_sources()
    if not sources:
        print(
            "Nothing to migrate: no .env or config.yaml under the Hermes home. "
            "Pass file paths explicitly to migrate other files.",
            file=sys.stderr,
        )
        return 1
    return migrate(root=_resolve_root(getattr(args, "root", None)), sources=sources)


def cli_init(args: argparse.Namespace) -> int:
    """argparse handler for ``vault init [--root PATH]``."""
    return init(root=_resolve_root(getattr(args, "root", None)))


def cli_change_passphrase(args: argparse.Namespace) -> int:
    """argparse handler for ``vault change-passphrase [--root PATH]`` (and its
    ``encryption change-passphrase`` alias)."""
    return change_passphrase(root=_resolve_root(getattr(args, "root", None)))


def cli_status(args: argparse.Namespace) -> int:
    """argparse handler for ``vault status [--root PATH] [--json]``."""
    return status(
        root=_resolve_root(getattr(args, "root", None)),
        as_json=bool(getattr(args, "json", False)),
    )


def cli_cat(args: argparse.Namespace) -> int:
    """argparse handler for ``vault cat <name> [--root PATH]``."""
    return cat(root=_resolve_root(getattr(args, "root", None)), name=args.name)
