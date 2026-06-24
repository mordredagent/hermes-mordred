"""At-rest vault file commands: inspect and enroll.

The commands that read a vault's listing / contents or enroll plaintext into it,
as opposed to creating or re-keying it (those live in
:mod:`mordred_hermes.wizard._vault_lifecycle`):

* :func:`status` -- list a vault's generation + enrolled names (cold path, read-only).
* :func:`cat` -- write one enrolled file's decrypted bytes to stdout (cold path).
* :func:`add` -- enroll one plaintext file (hot path, device key).
* :func:`migrate` -- batch-enroll several plaintext files in one open (hot path).

They share the open / display helpers in
:mod:`mordred_hermes.wizard._vault_open`; the argparse adapters that wrap them
live in :mod:`mordred_hermes.wizard.vault_cli`, which re-exports these so
existing callers and tests resolve them unchanged. Heavy cryptography-backed
imports stay function-local so this module imports on any platform.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import TYPE_CHECKING

from ._vault_open import _display_name, _open_cold_path, _open_hot_path_or_report

if TYPE_CHECKING:
    from ..keyvault.anchor import AnchorStore
    from ..keyvault.wrap import NativeBackend
    from .configure import PromptIO


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
