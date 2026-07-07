"""Shared open / identity helpers for the at-rest vault CLI.

These are the side-effect-light primitives reused by the vault commands in
:mod:`mordred_hermes.wizard._vault_lifecycle` and
:mod:`mordred_hermes.wizard._vault_entries`:

* :func:`_resolve_root` / :func:`_vault_identity` -- the shared root / identity
  derivation (delegating to :mod:`..keyvault._identity`) the runtime decrypt
  shim also uses, so the CLI and the shim agree on a vault for a given input.
* :func:`_open_cold_path` -- read-only open via the passphrase recovery sidecar.
* :func:`_open_hot_path_or_report` -- device-key (Secure Enclave / software
  fallback) open, fail-closed with a printed reason.
* :func:`_build_device_auth` -- tolerant SE-backend + keychain-store construction.
* :func:`_display_name` -- control-character-safe rendering of enrolled names.

``keyvault_cli.py`` keeps the parallel shape for the legacy keyvault; the heavy
cryptography-backed imports stay function-local so this module imports on any
platform. :mod:`mordred_hermes.wizard.vault_cli` re-exports the public-by-use
names (``_resolve_root`` / ``_open_hot_path_or_report`` / ``_vault_identity``).
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from ..keyvault import _identity
from . import _term

if TYPE_CHECKING:
    from ..keyvault.anchor import AnchorStore
    from ..keyvault.vault import OpenVault
    from ..keyvault.wrap import NativeBackend
    from .configure import PromptIO


def _vault_present(root: Path) -> bool:
    """Whether a vault exists at ``root`` (a manifest on disk) — no key needed."""
    return any(root.glob("manifest.*.mvmf"))


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
        _term.emit_error(f"Not a recoverable vault at {root}: {exc}")
        return None
    except recovery.RecoveryDigestMismatch:
        _term.emit_error(
            "Vault rejected: the recovery sidecar does not match the manifest (substituted wmk / tampering)."
        )
        return None
    except manifest.ManifestError:
        _term.emit_error("Vault rejected: the manifest failed authentication (tampering).")
        return None
    except backup.BackupCorrupt as exc:
        _term.emit_error(f"Vault rejected: the recovery sidecar is corrupt — {exc}")
        return None
    except InvalidTag:
        _term.emit_error("Wrong passphrase — vault not opened.")
        return None
    except OSError as exc:
        _term.emit_error(f"Cannot read vault at {root}: {exc}")
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
        _term.emit_error(f"no vault at {root} — run `vault init` first.")
    except (anchor.AnchorMismatch, anchor.AnchorCorrupt) as exc:
        # A freshness-pin mismatch is the anchor's whole purpose — surface it as
        # possible tampering / rollback, not a generic open failure.
        _term.emit_error(f"vault freshness check failed at {root} (possible tampering): {exc}")
    except (anchor.AnchorError, vault.VaultError, manifest.ManifestError, OSError) as exc:
        _term.emit_error(f"cannot open vault at {root}: {exc}")
    except WrapError as exc:
        _term.emit_error(f"cannot open vault at {root}: device key store error — {exc}")
    return None


def _build_device_auth(
    backend: NativeBackend | None, store: AnchorStore | None
) -> tuple[NativeBackend | None, AnchorStore | None]:
    """Construct the SE backend + keychain store for the device rotation path.

    Tolerant by design: off-macOS the SE backend / keychain modules don't import,
    so a failure returns ``(None, None)`` and the caller falls through to the
    passphrase (cold) path instead of crashing before it. Injected values
    (tests / callers that already have them) are returned unchanged.
    """
    if backend is not None and store is not None:
        return backend, store
    try:
        if backend is None:
            from ..keyvault._seckey_backend import _SecKeyBackend

            backend = _SecKeyBackend()
        if store is None:
            from ..keyvault._anchor_keychain import KeychainAnchorStore

            store = KeychainAnchorStore()
    except ImportError:
        return None, None
    return backend, store
