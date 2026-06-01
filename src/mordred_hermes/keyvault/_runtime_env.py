"""Runtime env transparent-decrypt shim (design note §8.2 item 3).

Injects the vault-enrolled ``.env`` into the process environment at startup so an
unattended Hermes process (telegram / gateway / cron) reads secrets from the
at-rest vault instead of plaintext on disk. Opens on the **hot path** (device key
— Secure Enclave or its software fallback, no passphrase) and is **fail-closed**.

Heavy imports (the cryptography-backed vault modules, dotenv) stay function-local
so this module imports on any platform, matching ``wizard/vault_cli.py``.
"""

from __future__ import annotations

import io
import os
import sys
from collections.abc import MutableMapping
from typing import TYPE_CHECKING

from ._identity import default_vault_root, vault_identity

if TYPE_CHECKING:
    from pathlib import Path

    from .anchor import AnchorStore
    from .wrap import NativeBackend

__all__ = ["inject_vault_env", "install_vault_env_decrypt"]


def inject_vault_env(
    *,
    root: Path,
    environ: MutableMapping[str, str],
    backend: NativeBackend | None = None,
    store: AnchorStore | None = None,
    name: str = ".env",
) -> int:
    """Decrypt the vault-enrolled ``name`` (``.env``) at ``root`` into ``environ``.

    Opens the vault on the hot path and injects each ``KEY=value`` from the
    enrolled ``name`` into ``environ`` with **override** semantics — matching
    Hermes's own ``load_hermes_dotenv(override=True)``, where ``~/.hermes/.env``
    is authoritative over stale shell values.

    **Fail-closed**: if a vault is present at ``root`` but cannot be opened,
    verified, or read, the underlying error propagates — the process must not
    start with unverified secret provisioning. If no vault is present (no anchor),
    returns 0, so Hermes runs unchanged when at-rest encryption is not set up; a
    vault present but with no enrolled ``name`` also returns 0.

    ``backend`` / ``store`` default to the production implementations; tests
    inject fakes. Returns the number of variables injected.
    """
    from dotenv import dotenv_values

    from . import vault

    key_id = anchor_label = vault_identity(root)

    if backend is None:
        from ._seckey_backend import _SecKeyBackend

        backend = _SecKeyBackend()
    if store is None:
        from ._anchor_keychain import KeychainAnchorStore

        store = KeychainAnchorStore()

    # No anchor → no vault here: a clean no-op. A read *error* (e.g. locked
    # Keychain) is NOT swallowed — it propagates fail-closed, since we cannot
    # prove the vault is absent.
    if store.read(anchor_label) is None:
        return 0

    opened = vault.open_vault(root, key_id=key_id, backend=backend, store=store, anchor_label=anchor_label)
    try:
        if name not in opened.list_files():
            return 0
        plaintext = opened.read_file(name)
    finally:
        opened.close()

    values = dotenv_values(stream=io.StringIO(plaintext.decode("utf-8")))
    injected = 0
    for env_key, env_value in values.items():
        if env_value is None:  # a bare ``KEY`` with no ``=value`` parses to None — skip it
            continue
        environ[env_key] = env_value
        injected += 1
    return injected


def install_vault_env_decrypt(*, environ: MutableMapping[str, str] | None = None) -> int:
    """Install the runtime env decrypt at startup (called from the plugin ``register()``).

    **macOS-only**: the unattended hot path needs a device key store (Secure
    Enclave or its software fallback), which is macOS-specific. On other platforms
    this is a no-op so Hermes runs unchanged. Injects into ``os.environ`` by
    default. Returns the number of variables injected.
    """
    if sys.platform != "darwin":
        return 0
    if environ is None:
        environ = os.environ
    return inject_vault_env(root=default_vault_root(), environ=environ)
