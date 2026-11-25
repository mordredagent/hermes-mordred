"""``keyvault init --backup-file PATH``: a keyvault whose recovery is a file, not paper.

The paper ceremony (:func:`._keyvault_init.init_keyvault` without a backup
file) shows the 24-word seed under a network blackout and asks for a digest
computed on a second, offline device. This flow never shows the seed:

1. the re-init and output-path guards run before any prompt;
2. the Passphrase is chosen (twice, hidden);
3. the seed is generated and the keyvault finalised against the digest the
   seed and Passphrase produce (nothing is transcribed, so nothing can be
   mistranscribed);
4. the seed is stored encrypted under the new key (``bip39.seed.v1``), as
   the paper flow does by default;
5. the whole keyvault, seed included, is exported to ``PATH``: an Argon2id
   key from the Passphrase protects it (``keyvault export``'s format).

The file and the Passphrase together restore the keyvault on another
device (``keyvault recover --blob PATH``, pressing Enter at the Seed Phrase
prompt). Whoever holds both holds the keyvault: the file has to be kept as a
secret, apart from the Passphrase.

With ``embed_passphrase`` (``setup --no-prompts``) nobody chooses a
Passphrase: the flow session carries a generated one, and the file holds it
too (:mod:`..keyvault._backup_file`), so the file alone restores the keyvault.
"""

from __future__ import annotations

import contextlib
import sys
from pathlib import Path
from typing import TYPE_CHECKING

from . import _term
from ._defaults import resolve_backend, resolve_prompt_io
from ._windows_gates import unported_refusal

if TYPE_CHECKING:
    from ..keyvault.wrap import AuditSink, NativeBackend
    from ._flow_session import FlowSession
    from .configure import PromptIO

__all__ = ["init_keyvault_with_backup_file"]


def _self_contained_banner(backup_file: Path) -> str:
    return (
        "\n"
        "  Creating your encrypted keyvault. Its backup file goes to:\n"
        "\n"
        f"      {_term.terminal_safe(str(backup_file))}\n"
        "\n"
        "  That file alone restores the keyvault on another Mac: keep it\n"
        "  somewhere other than this Mac, and keep it private.\n"
    )


def _intro_banner(backup_file: Path) -> str:
    return (
        "\n"
        "────────────────────────────────────────────────────────────\n"
        "  keyvault init — set up your encrypted keyvault\n"
        "────────────────────────────────────────────────────────────\n"
        "\n"
        "  This creates a new keyvault on this device and saves its\n"
        "  backup file to:\n"
        "\n"
        f"      {_term.terminal_safe(str(backup_file))}\n"
        "\n"
        "  Choose a Passphrase below. The backup file and the\n"
        "  Passphrase together restore the keyvault on another device;\n"
        "  you do not have to write anything down.\n"
        "\n"
        "  Keep the file somewhere other than this device, and keep the\n"
        "  Passphrase apart from it: whoever has both has the keyvault.\n"
        "  The Passphrase is never stored; without it the file is useless.\n"
        "────────────────────────────────────────────────────────────"
    )


def _refusal(home: Path | None, backup_file: Path) -> int | None:
    """The guards that run before any prompt; the exit code (already reported) or ``None``."""
    from ._keyvault_init import _refuse_if_initialised
    from .keyvault_export_cli import _preflight_output

    unported = unported_refusal("secret_store", "keyvault init")
    if unported is not None:
        return unported
    guard = _refuse_if_initialised(home)
    if guard is not None:
        return guard
    return None if _preflight_output(backup_file) else 1


def _passphrase_for(
    backup_file: Path, prompt_io: PromptIO | None, flow_session: FlowSession | None, *, embed: bool
) -> str | None:
    """The flow's generated passphrase (``embed``), else one chosen twice at the prompt; ``None`` (reported)."""
    from ._keyvault_init import _SETUP_SHARED_PASSPHRASE_NOTE, _read_passphrase

    if embed:
        if flow_session is None or not flow_session.passphrase:
            _term.emit_error("internal: a self-contained backup needs the flow's generated passphrase.")
            return None
        print(_self_contained_banner(backup_file), file=sys.stderr)
        return flow_session.passphrase
    print(_intro_banner(backup_file), file=sys.stderr)
    if flow_session is not None:
        print(_SETUP_SHARED_PASSPHRASE_NOTE, file=sys.stderr)
    return _read_passphrase(resolve_prompt_io(prompt_io), flow_session)


def _report_saved(key_id: str, backup_file: Path, *, embed: bool) -> None:
    shown = _term.terminal_safe(str(backup_file))
    print(f"Keyvault initialised. Key: {key_id}")
    print(f"Backup file saved: {shown} (mode 0600).")
    if embed:
        print("Keep it somewhere other than this Mac and keep it private: it alone restores the keyvault.")
        return
    print(
        "Keep it somewhere other than this device, apart from the Passphrase. To restore on another device: "
        f"`hermes-mordred keyvault recover --blob {shown}` and press Enter at the Seed Phrase prompt."
    )


def init_keyvault_with_backup_file(
    *,
    backup_file: Path,
    home: Path | None = None,
    backend: NativeBackend | None = None,
    prompt_io: PromptIO | None = None,
    audit_sink: AuditSink | None = None,
    unattended: bool | None = None,
    flow_session: FlowSession | None = None,
    embed_passphrase: bool = False,
) -> int:
    """Initialise the keyvault and save its backup to ``backup_file``; 0, or 1 (reported)."""
    from ..keyvault import _backup_file, api
    from ..keyvault.api import SeedDisplayExpired
    from ..keyvault.ethereum import store_seed_phrase
    from ._keyvault_init import (
        _confirm_or_refuse,
        _generate_seed_material,
        _provision_audit_log_key,
        _stderr_audit_sink,
    )
    from .keyvault_export_cli import _publish_backup

    backup_file = backup_file.expanduser()
    refusal = _refusal(home, backup_file)
    if refusal is not None:
        return refusal

    passphrase = _passphrase_for(backup_file, prompt_io, flow_session, embed=embed_passphrase)
    if passphrase is None:
        return 1

    handle, pow_bytes, seed_phrase = _generate_seed_material(passphrase, store_seed_for_hd=True)
    assert seed_phrase is not None  # store_seed_for_hd=True keeps it
    backend = resolve_backend(backend)
    sink = audit_sink if audit_sink is not None else _stderr_audit_sink
    try:
        # Nobody transcribes the seed here, so the digest the seed and Passphrase
        # produce is the one the keyvault commits to.
        result = _confirm_or_refuse(
            handle, handle.expected_digest(), backend=backend, audit_sink=sink, home=home, unattended=unattended
        )
    finally:
        with contextlib.suppress(SeedDisplayExpired):
            handle.consume()  # wipes the handle's copy of the seed
    if result is None:
        return 1

    _provision_audit_log_key(backend, home=home)
    blob: bytes | None = None
    try:
        store_seed_phrase(result.key_id, seed_phrase, backend=backend, audit_sink=sink, home=home)
    except Exception:
        # Never interpolate the exception: a lower layer could carry the seed.
        seed_phrase = None
        passphrase = None
        if embed_passphrase:
            # The one-step installer starts unbacked keys over on its next run.
            _term.emit_error(
                "The keys were created, but their backup file could not be made. "
                "Open the Mordred installer again: it starts the keys over (nothing was encrypted with them yet)."
            )
            return 1
        _term.emit_error(
            "The keyvault was created, but its seed could not be stored, so no backup file can be made. "
            "Start over with `hermes-mordred keyvault reset --yes`, then run this again "
            "(nothing has been encrypted with it yet)."
        )
        return 1
    try:
        # Opening each envelope for the export can ask for Touch ID (interactive keys).
        blob = api.export_backup(
            result.key_id,
            passphrase,
            backend=backend,
            audit_sink=sink,
            home=home,
            seed_phrase=seed_phrase,
            pow_bytes=pow_bytes,
        )
        published = _publish_backup(backup_file, _backup_file.pack(passphrase, blob) if embed_passphrase else blob)
    except Exception:
        # Never interpolate the exception: a lower layer could carry the seed or Passphrase.
        published = False
        _term.emit_error("The keyvault was created, but its backup file could not be made.")
    finally:
        # CPython cannot zero an immutable str; dropping the references shortens their life.
        seed_phrase = None
        passphrase = None
        blob = None
    if not published and embed_passphrase:
        # The passphrase lived only in this run (and the file it could not
        # write): the installer starts these keys over on its next run.
        _term.emit_error(
            "Open the Mordred installer again: it starts the keys over (nothing was encrypted with them yet)."
        )
        return 1
    if not published:
        # The seed is stored, so the passphrase alone makes the same file later.
        _term.emit_error(
            "Make it now with `hermes-mordred keyvault export --output "
            f"{_term.terminal_safe(str(backup_file))}` (it asks for the Passphrase, and Touch ID); "
            "without it this keyvault cannot be restored on another device."
        )
        return 1

    _report_saved(result.key_id, backup_file, embed=embed_passphrase)
    return 0
