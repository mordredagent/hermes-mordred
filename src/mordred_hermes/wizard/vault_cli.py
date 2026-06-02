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
import os
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
    "cli_add",
    "cli_cat",
    "cli_init",
    "cli_migrate",
    "cli_set_memory_key",
    "cli_status",
    "init",
    "migrate",
    "set_memory_key",
    "status",
]

_MEMORY_KEY_ENV = "HERMES_MEMORY_KEY"


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


def status(*, root: Path, prompt_io: PromptIO | None = None) -> int:
    """Print a vault's generation and enrolled file names (cold path).

    Opens read-only via :func:`_open_cold_path`. Enrolled *names* are listed;
    file *contents* are never decrypted or printed. Returns 0 on a successful
    open, 1 on any fail-closed open error (reason already on stderr).
    """
    opened = _open_cold_path(root, prompt_io=prompt_io)
    if opened is None:
        return 1
    try:
        names = sorted(opened.list_files())
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
    print("  At-rest protection uses this device's key store (Secure Enclave when available, else a software key).")
    print("  Keep your recovery passphrase safe — it is the only way to open this vault if the device is lost.")
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


def _generate_memory_key() -> str:
    """A fresh URL-safe base64 256-bit key for ``HERMES_MEMORY_KEY``.

    Matches the format Hermes upstream (``tools/memory_tool.py``) accepts — a
    URL-safe base64 encoding of 32 random bytes (AES-256). Replicated here rather
    than imported so this plugin does not couple to the upstream module path; the
    format contract is pinned by ``tests/test_keyvault_memory_integration.py``.
    """
    import base64
    import secrets

    return base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("ascii")


def _is_valid_memory_key(value: str | None) -> bool:
    """Whether ``value`` decodes to a 32-byte AES-256 key.

    Mirrors upstream ``tools/memory_tool.py:_decode_memory_key`` (plain URL-safe
    base64, or a ``base64:`` / ``hex:`` prefix; exactly 32 bytes). A key this
    command treats as "already set" must be one the memory encryptor will accept —
    an empty or wrong-length assignment is *not* usable and should be replaced.
    """
    if not value:
        return False
    import base64

    raw = value.strip()
    # dotenv strips one pair of surrounding quotes; mirror that so a quoted key
    # (e.g. HERMES_MEMORY_KEY="base64:...") is validated as the runtime sees it.
    if len(raw) >= 2 and raw[0] in "\"'" and raw[-1] == raw[0]:
        raw = raw[1:-1]
    if raw.startswith("base64:"):
        raw = raw[len("base64:") :].strip()
    elif raw.startswith("hex:"):
        try:
            return len(bytes.fromhex(raw[len("hex:") :].strip())) == 32
        except ValueError:
            return False
    padding = "=" * (-len(raw) % 4)
    try:
        return len(base64.urlsafe_b64decode(raw + padding)) == 32
    except (ValueError, TypeError):
        return False


def _effective_memory_key(text: str) -> str | None:
    """The ``HERMES_MEMORY_KEY`` value the runtime shim would use, or ``None``.

    Parsed with ``dotenv_values`` (last-wins, no interpolation, quotes stripped) —
    exactly the value :func:`...keyvault._runtime_env.inject_vault_env` injects at
    startup, so this decision matches what Hermes actually keys memory on.
    """
    import io

    from dotenv import dotenv_values

    return dotenv_values(stream=io.StringIO(text), interpolate=False).get(_MEMORY_KEY_ENV)


def _ambient_memory_key() -> str | None:
    """An existing valid ``HERMES_MEMORY_KEY`` from the live env or the plaintext home ``.env``.

    A user who already enabled ``memory.encryption`` has their key in
    ``os.environ`` (Hermes loads ``~/.hermes/.env`` into the environment at
    startup) or still in the plaintext ``~/.hermes/.env`` not yet migrated into the
    vault. ``set-memory-key`` must **adopt** that key rather than mint a new one —
    a fresh key would override theirs at startup and orphan memories encrypted
    under it. Returns the env value first (it is what the memory tool reads), then
    the plaintext ``.env`` value; ``None`` if neither holds a usable key.
    """
    env_value = os.environ.get(_MEMORY_KEY_ENV)
    if _is_valid_memory_key(env_value):
        return env_value
    try:
        text = (_hermes_home() / ".env").read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return None
    candidate = _effective_memory_key(text)
    return candidate if _is_valid_memory_key(candidate) else None


def _any_valid_memory_key(text: str) -> bool:
    """Whether *any* ``HERMES_MEMORY_KEY`` binding in the ``.env`` is a usable key.

    Distinct from the *effective* (last-wins) value: a malformed ``.env`` whose
    last binding is invalid may still carry a valid earlier one that encrypted
    existing memories. That ambiguity is a refuse-or-rotate signal, not something
    to silently overwrite. Uses ``python-dotenv``'s own parser, so a value's
    quotes / trailing comment / ``export`` prefix are handled exactly as the
    runtime would.
    """
    import io

    from dotenv.parser import parse_stream

    return any(
        binding.key == _MEMORY_KEY_ENV and _is_valid_memory_key(binding.value)
        for binding in parse_stream(io.StringIO(text))
    )


def _env_with_memory_key(text: str, value: str) -> str:
    """Return ``.env`` text with exactly one effective ``HERMES_MEMORY_KEY``.

    **Drops every ``HERMES_MEMORY_KEY`` binding** ``python-dotenv`` recognises —
    assignment, bare key (``KEY`` → ``None``), ``export``-prefixed, quoted, or
    comment-trailed — preserving all other lines **verbatim** (via the parser's
    original text), then appends a single fresh assignment as the last (effective)
    entry. Delegating removal to dotenv's own parser means a stray form can't be
    left behind to shadow the written key. Ends with a trailing newline.
    """
    import io

    from dotenv.parser import parse_stream

    kept = "".join(
        binding.original.string for binding in parse_stream(io.StringIO(text)) if binding.key != _MEMORY_KEY_ENV
    )
    if kept and not kept.endswith("\n"):
        kept += "\n"
    return f"{kept}{_MEMORY_KEY_ENV}={value}\n"


def _print_memory_config_hint() -> None:
    """Tell the operator how to turn on memory encryption (never prints the key)."""
    print("To turn on agent-memory encryption, add this to your Hermes config.yaml:")
    print()
    print("  memory:")
    print("    encryption:")
    print("      enabled: true")
    print()
    print(
        f"The key stays protected at rest by the vault; the runtime shim injects {_MEMORY_KEY_ENV} into the "
        "environment at startup so Hermes can encrypt ~/.hermes/memories/*.md with it."
    )


def set_memory_key(
    *,
    root: Path,
    rotate: bool = False,
    backend: NativeBackend | None = None,
    store: AnchorStore | None = None,
) -> int:
    """Ensure the vault ``.env`` carries a usable ``HERMES_MEMORY_KEY`` (the agent-memory on-ramp).

    Hermes encrypts ``~/.hermes/memories/*.md`` with AES-256-GCM keyed by the
    ``HERMES_MEMORY_KEY`` environment variable (upstream ``tools/memory_tool.py``).
    Keeping that key in the vault ``.env`` means the device wrapping key protects
    it at rest and the runtime decrypt shim
    (:mod:`mordred_hermes.keyvault._runtime_env`) injects it into the environment
    at startup. The key is never printed.

    Opens the vault on the **hot path** (the device wrapping key — Secure Enclave
    or its software fallback, no passphrase) and decides off the *effective*
    (dotenv last-wins) ``HERMES_MEMORY_KEY``, so it never silently switches the key
    Hermes is actually using:

    - **Already usable** (the effective value decodes to 32 bytes) and no
      ``rotate`` → no-op; the ``.env`` is left untouched.
    - **No usable key** → write one and re-enroll, collapsing the file to a single
      assignment. Without ``rotate`` it **adopts** a key the user is already using
      (live env, then the plaintext home ``.env``) so migrating into the vault
      keeps existing encrypted memories readable; otherwise it mints a fresh key.
    - **Malformed** (the effective value is invalid but an earlier assignment is a
      valid key) and no ``rotate`` → **refuse** (rc 1) rather than guess which key
      encrypted existing memories.
    - ``rotate`` → always mint a fresh key, warning that memories encrypted under
      the previous key can no longer be decrypted.

    ``backend`` / ``store`` default to the production implementations; tests inject
    fakes. Returns 0 on success (no-op, store, or adoption), 1 on an uninitialised
    / unverifiable vault, a non-UTF-8 or unreadable enrolled ``.env``, a
    malformed-``.env`` refusal, or a device key-store error.
    """
    from ..keyvault import anchor, vault
    from ..keyvault._exceptions import WrapError

    opened = _open_hot_path_or_report(root, backend=backend, store=store)
    if opened is None:
        return 1

    try:
        if ".env" in opened.list_files():
            try:
                existing = opened.read_file(".env").decode("utf-8")
            except UnicodeDecodeError:
                print(
                    f"the enrolled .env at {root} is not valid UTF-8 — cannot merge {_MEMORY_KEY_ENV}.",
                    file=sys.stderr,
                )
                return 1
            except (vault.VaultError, OSError) as exc:
                # OSError covers _storage.KeyvaultPermissionError (bad mode / symlink /
                # I/O) so a read failure fails closed with rc 1, like open / enroll.
                print(f"cannot read the enrolled .env at {root}: {exc}", file=sys.stderr)
                return 1
        else:
            existing = ""

        # Decide off the *effective* (dotenv last-wins) value — exactly what the
        # runtime shim keys memory on — so we never silently switch the key Hermes
        # is actually using.
        effective_valid = _is_valid_memory_key(_effective_memory_key(existing))
        if effective_valid and not rotate:
            # The runtime already has a usable key; leave the file untouched.
            print(
                f"{_MEMORY_KEY_ENV} is already set in the vault .env at {root} — leaving it unchanged "
                "(pass --rotate to replace it)."
            )
            _print_memory_config_hint()
            return 0

        # No usable *effective* key, yet some assignment is a valid key: the .env is
        # malformed (e.g. a valid key shadowed by a later invalid duplicate). We
        # cannot know which key encrypted existing memories, so refuse rather than
        # guess — and never regenerate, which would orphan recoverable data.
        if not rotate and _any_valid_memory_key(existing):
            print(
                f"the vault .env at {root} has a {_MEMORY_KEY_ENV} whose effective (last) value is not a "
                f"usable 32-byte key, but an earlier assignment is. Refusing to guess which key encrypted "
                f"existing memories: fix the .env by hand, or pass --rotate to replace it (which orphans "
                f"memories encrypted under the old key).",
                file=sys.stderr,
            )
            return 1

        # Choose the key to write. Without --rotate, ADOPT a key the user is already
        # using (live env / plaintext home .env) so migrating into the vault keeps
        # existing encrypted memories readable; mint a fresh key only for genuine
        # first-time setup. With --rotate, always mint fresh.
        adopted = None if rotate else _ambient_memory_key()
        chosen = adopted if adopted is not None else _generate_memory_key()

        # Rotation (always fresh) orphans whatever usable key was in effect — in the
        # vault .env or the ambient env. A first-time / adopting store orphans nothing.
        orphan_risk = rotate and (_any_valid_memory_key(existing) or _ambient_memory_key() is not None)

        new_text = _env_with_memory_key(existing, chosen)
        try:
            opened.enroll_file(".env", new_text.encode("utf-8"))
            generation = opened.generation
        except (vault.VaultError, anchor.AnchorError, WrapError, OSError) as exc:
            print(f"cannot store {_MEMORY_KEY_ENV}: {exc}", file=sys.stderr)
            return 1

        if adopted is not None:
            verb = "Adopted the existing"
        elif orphan_risk:
            verb = "Rotated"
        else:
            verb = "Stored"
        print(f"{verb} {_MEMORY_KEY_ENV} in the vault .env at {root} (now at generation {generation}).")
        if orphan_risk:
            # Rotation replaces a *usable* key, orphaning memories encrypted under it
            # (upstream has no auto re-key), so AES-GCM decryption of existing files
            # fails on the next run. Warn loudly — re-keying / clearing is the
            # operator's job. (Replacing an absent/invalid key encrypted nothing.)
            print(
                "warning: rotated the memory key. Agent-memory files already encrypted under the previous "
                "key (~/.hermes/memories/*.md) can no longer be decrypted — re-encrypt or clear them before "
                "the next run.",
                file=sys.stderr,
            )
        _print_memory_config_hint()
        return 0
    finally:
        opened.close()


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


def cli_status(args: argparse.Namespace) -> int:
    """argparse handler for ``vault status [--root PATH]``."""
    return status(root=_resolve_root(getattr(args, "root", None)))


def cli_cat(args: argparse.Namespace) -> int:
    """argparse handler for ``vault cat <name> [--root PATH]``."""
    return cat(root=_resolve_root(getattr(args, "root", None)), name=args.name)


def cli_set_memory_key(args: argparse.Namespace) -> int:
    """argparse handler for ``vault set-memory-key [--root PATH] [--rotate]``."""
    return set_memory_key(root=_resolve_root(getattr(args, "root", None)), rotate=bool(getattr(args, "rotate", False)))
