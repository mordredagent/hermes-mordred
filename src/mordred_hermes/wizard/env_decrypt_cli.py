"""``hermes mordred encryption {enable,disable,purge} env`` — .env at-rest toggle.

The ``.env`` target mirrors config.yaml's toggle but with ``.env``'s memory-only
runtime model: on enable the plaintext is removed (the runtime shim injects the
enrolled copy into ``os.environ`` at startup — see
:mod:`mordred_hermes.keyvault._runtime_env`), so no secret is left at rest.

Three state transitions (not symmetric — documented per verb):

- **enable**  — enroll ``<home>/.env`` into the vault, clear the opt-out marker,
  and (on macOS) remove the plaintext. Off macOS the runtime shim is a no-op, so
  the plaintext is kept to avoid stranding Hermes.
- **disable** — restore a readable plaintext ``<home>/.env`` (decrypting from the
  vault if enable had removed it; never overwriting a diverging on-disk copy) and
  write the opt-out marker so the runtime stops injecting. *Reversible*: the vault
  copy is kept.
- **purge**   — restore the plaintext, ``unenroll_file('.env')`` from the vault,
  and clear the marker. *Destructive*: back to plain, unencrypted.

Heavy imports stay function-local so this module imports on any platform.
"""

from __future__ import annotations

import sys
from typing import TYPE_CHECKING

from ..keyvault._runtime_env import _env_optout_marker_path

if TYPE_CHECKING:
    from pathlib import Path

    from ..keyvault.anchor import AnchorStore
    from ..keyvault.wrap import NativeBackend
    from .configure import PromptIO

__all__ = ["disable", "enable", "purge"]

_ENV_NAME = ".env"


def _vault_present(root: Path) -> bool:
    """Whether a vault exists at ``root`` (a manifest on disk) — no key needed."""
    return any(root.glob("manifest.*.mvmf"))


def _read_vault_env(
    root: Path,
    backend: NativeBackend | None,
    store: AnchorStore | None,
) -> bytes | None:
    """The enrolled ``.env`` bytes, or ``None`` if the vault has none / cannot open."""
    from . import vault_cli

    opened = vault_cli._open_hot_path_or_report(root, backend=backend, store=store)
    if opened is None:
        return None
    try:
        return opened.read_file(_ENV_NAME) if _ENV_NAME in opened.list_files() else None
    finally:
        opened.close()


def _write_optout_marker(home: Path) -> None:
    marker = _env_optout_marker_path(home)
    marker.parent.mkdir(parents=True, exist_ok=True)
    marker.write_text("opt-out\n", encoding="utf-8")


def _restore_plaintext(
    *,
    home: Path,
    root: Path,
    backend: NativeBackend | None,
    store: AnchorStore | None,
) -> int:
    """Guarantee a readable plaintext ``<home>/.env`` without losing operator edits.

    - No vault here → nothing enrolled to restore; keep whatever plaintext exists.
    - Vault present, ``.env`` enrolled, plaintext missing → decrypt it back.
    - Vault present, ``.env`` enrolled, plaintext **present** → keep the on-disk
      copy (it is the live one); warn if it diverges from the vault copy rather
      than silently overwriting it.

    Returns 0 normally; 1 only when the plaintext is missing *and* the vault is
    present but cannot be opened to recover it (fail-closed — do not pretend a
    secret is on disk when it is not).
    """
    from ..keyvault import _storage
    from . import vault_cli

    env_path = home / _ENV_NAME
    if not _vault_present(root):
        return 0

    opened = vault_cli._open_hot_path_or_report(root, backend=backend, store=store)
    if opened is None:
        return 0 if env_path.exists() else 1
    try:
        if _ENV_NAME not in opened.list_files():
            return 0
        vault_bytes = opened.read_file(_ENV_NAME)
    finally:
        opened.close()

    if env_path.exists():
        if env_path.read_bytes() != vault_bytes:
            print(
                f"warning: .env drift — the on-disk {env_path} differs from the vault copy; "
                "keeping the on-disk one (not overwriting).",
                file=sys.stderr,
            )
        return 0

    _storage.atomic_write(env_path, vault_bytes)
    return 0


def enable(
    *,
    home: Path,
    root: Path,
    platform: str,
    backend: NativeBackend | None = None,
    store: AnchorStore | None = None,
    prompt_io: PromptIO | None = None,
) -> int:
    """Enroll ``<home>/.env`` into the vault and turn runtime injection on.

    If no vault exists yet, one is created first (prompting once for a recovery
    passphrase) — ``encryption enable`` drives the vault, so a fresh install need
    not run ``vault init`` by hand. Returns 0 on success, 1 when there is no
    ``.env`` to protect, the vault cannot be created, or the enroll fails
    (unverifiable vault, device key-store error). On macOS the plaintext is
    removed only after a clean enroll, so a failure never strands the operator
    without a readable ``.env``.
    """
    from . import vault_cli

    env_path = home / _ENV_NAME
    if not env_path.is_file():
        print(f"no .env at {env_path} — nothing to protect.", file=sys.stderr)
        return 1

    rc = vault_cli.ensure_initialised(root=root, prompt_io=prompt_io, backend=backend, store=store)
    if rc != 0:
        return rc  # could not create the vault (reason already printed)

    rc = vault_cli.add(root=root, name=_ENV_NAME, source=env_path, backend=backend, store=store)
    if rc != 0:
        return rc  # vault_cli.add already printed the reason

    _env_optout_marker_path(home).unlink(missing_ok=True)  # injection ON

    if platform == "darwin":
        # Only remove the plaintext if it provably matches the enrolled copy: a
        # concurrent edit between add()'s read and now must NOT be deleted
        # unvaulted, and an unlink failure must NOT be reported as success while
        # the plaintext remains at rest.
        enrolled = _read_vault_env(root, backend, store)
        try:
            current: bytes | None = env_path.read_bytes()
        except OSError:
            current = None
        if enrolled is None or current != enrolled:
            print(
                "warning: .env was enrolled but the on-disk copy no longer matches the vault "
                "(changed during enable?) — leaving the plaintext in place; re-run enable.",
                file=sys.stderr,
            )
            return 0
        try:
            env_path.unlink()
        except OSError as exc:
            print(
                f"warning: .env enrolled but the plaintext at {env_path} could not be removed: {exc} "
                "— remove it by hand (it is still readable at rest).",
                file=sys.stderr,
            )
            return 0
        print(".env is now vault-managed; the plaintext was removed (the runtime injects it at startup).")
    else:
        print(
            ".env enrolled into the vault, but the runtime decrypt shim is macOS-only — the plaintext was "
            "kept so Hermes still reads it on this OS (status: inactive on this OS)."
        )
    return 0


def disable(
    *,
    home: Path,
    root: Path,
    backend: NativeBackend | None = None,
    store: AnchorStore | None = None,
) -> int:
    """Restore a readable plaintext ``.env`` and stop runtime injection (reversible).

    The vault copy is left intact so re-enabling is immediate. Returns 0 on
    success, 1 only when a sealed-away plaintext cannot be recovered from the
    vault (fail-closed).
    """
    rc = _restore_plaintext(home=home, root=root, backend=backend, store=store)
    if rc != 0:
        return rc
    _write_optout_marker(home)
    print(".env decryption disabled (opt-out marker written); the vault copy is kept for re-enable.")
    return 0


def purge(
    *,
    home: Path,
    root: Path,
    backend: NativeBackend | None = None,
    store: AnchorStore | None = None,
) -> int:
    """Remove ``.env`` from the vault entirely, restoring the plaintext first.

    Destructive: the encrypted copy is gone afterwards. The vault copy is never
    lost silently — if it is the only copy it is restored to ``<home>/.env``, and
    if the on-disk ``.env`` *diverges* from it the vault copy is saved to a
    ``.env.vault-purged`` sidecar before unenrolling. Returns 0 on success, 1 when
    the vault is present but cannot be opened to recover / unenroll.
    """
    from ..keyvault import _storage, anchor, vault
    from . import vault_cli

    env_path = home / _ENV_NAME

    if _vault_present(root):
        opened = vault_cli._open_hot_path_or_report(root, backend=backend, store=store)
        if opened is None:
            return 0 if env_path.exists() else 1
        try:
            if _ENV_NAME in opened.list_files():
                vault_bytes = opened.read_file(_ENV_NAME)
                if not env_path.exists():
                    _storage.atomic_write(env_path, vault_bytes)  # restore the only copy
                elif env_path.read_bytes() != vault_bytes:
                    backup = home / ".env.vault-purged"
                    _storage.atomic_write(backup, vault_bytes)
                    print(
                        f"warning: on-disk .env differs from the vault copy — saved the vault copy to {backup} "
                        "before purging (nothing is lost).",
                        file=sys.stderr,
                    )
                opened.unenroll_file(_ENV_NAME)
        except (vault.VaultError, anchor.AnchorError, OSError) as exc:
            print(f"cannot purge .env from the vault: {exc}", file=sys.stderr)
            return 1
        finally:
            opened.close()

    _env_optout_marker_path(home).unlink(missing_ok=True)
    print(".env purged from the vault; the plaintext is on disk and unencrypted.")
    return 0
