"""``hermes mordred encryption {enable,disable,purge} memory`` — agent-memory toggle.

Agent-memory encryption is two coupled pieces:

1. the ``HERMES_MEMORY_KEY`` in the vault ``.env`` (protected at rest by the
   device key, injected into the environment at startup), managed by
   :func:`mordred_hermes.wizard.vault_memory_key.set_memory_key`, and
2. the ``memory.encryption.enabled`` flag in ``config.yaml`` that tells upstream
   ``tools/memory_tool.py`` to actually AES-256-GCM-encrypt
   ``~/.hermes/memories/*.md``.

``vault set-memory-key`` only ever wrote the key and *printed a hint* about the
flag. This target writes the flag for real (round-trip ``ruamel`` so the rest of
config.yaml is preserved) and gives memory encryption a real disable/purge:

- **enable**  — ensure the key + set the flag true.
- **disable** — set the flag false but keep the key (suspend: reversible). Existing
  encrypted memories become unreadable until re-enabled — warned, not migrated.
- **purge**   — set the flag false and strip the key from the vault ``.env``.
  Destructive: memories encrypted under it can no longer be decrypted.

Heavy imports stay function-local so this module imports on any platform.
"""

from __future__ import annotations

import io
from typing import TYPE_CHECKING

from . import _term
from ._vault_open import _vault_present
from .vault_memory_key import _MEMORY_KEY_ENV

if TYPE_CHECKING:
    from pathlib import Path

    from ..keyvault.anchor import AnchorStore
    from ..keyvault.wrap import NativeBackend
    from .configure import PromptIO

__all__ = ["disable", "enable", "purge"]

_CONFIG_NAME = "config.yaml"
_MEMORIES_DIR = "memories"
# Upstream tools/memory_tool.py encrypted-payload header (``_MEMORY_ENCRYPTION_HEADER``).
_ENC_HEADER = b"HERMES-MEMORY-ENC-v1"


def _set_encryption_flag(home: Path, *, enabled: bool) -> int:
    """Round-trip ``config.yaml`` and set ``memory.encryption.enabled``.

    Preserves every other key / comment (``ruamel`` round-trip). Creates the
    nested ``memory.encryption`` block (and the file itself) when absent. Returns
    0 on success, 1 if config.yaml exists but is not a mapping (refuse to clobber
    an unexpected shape).
    """
    from ruamel.yaml.comments import CommentedMap

    from .policy_writer import _atomic_write_text, _round_trip_yaml

    path = home / _CONFIG_NAME
    # Share PolicyWriter's ruamel instance (indent 2/4/2, preserve_quotes,
    # width=4096) instead of a bare YAML() -- a bare instance's default indent
    # settings reformat every sequence in the file (e.g. `plugins.enabled`
    # written by PolicyWriter at offset 2 collapses to offset 0), so a
    # `configure` run right after an `encryption enable memory` run would see
    # gratuitous diff churn on unrelated lists.
    yaml = _round_trip_yaml()
    if path.exists():
        data = yaml.load(path.read_text(encoding="utf-8"))
        if data is None:
            data = CommentedMap()
        elif not isinstance(data, dict):
            _term.emit_error(f"{path} is not a YAML mapping — refusing to edit it.")
            return 1
    else:
        data = CommentedMap()

    # Create missing nodes, but never CLOBBER an existing non-mapping value at
    # ``memory`` / ``memory.encryption`` — that would silently drop the operator's
    # config. Refuse instead.
    memory = data.get("memory")
    if memory is None:
        memory = CommentedMap()
        data["memory"] = memory
    elif not isinstance(memory, dict):
        _term.emit_error(f"{path}: 'memory' is not a mapping — refusing to edit it.")
        return 1
    encryption = memory.get("encryption")
    if encryption is None:
        encryption = CommentedMap()
        memory["encryption"] = encryption
    elif not isinstance(encryption, dict):
        _term.emit_error(f"{path}: 'memory.encryption' is not a mapping — refusing to edit it.")
        return 1
    encryption["enabled"] = enabled

    # Atomic write via PolicyWriter's shared helper (tmpfile + os.replace, plus
    # an idempotent no-write-if-unchanged short-circuit) instead of hand-rolling
    # the same tempfile.mkstemp + os.replace dance again (see
    # PolicyWriter._edit_config for the same io.StringIO() + yaml.dump idiom).
    # Not _storage.atomic_write — that enforces vault mode 0o600; config.yaml is
    # a normal user-readable config file.
    buf = io.StringIO()
    yaml.dump(data, buf)
    _atomic_write_text(path, buf.getvalue())
    return 0


def _has_encrypted_memories(home: Path) -> bool:
    """Whether any ``~/.hermes/memories/*.md`` is actually encrypted.

    Checks the upstream payload header (``HERMES-MEMORY-ENC-v1``) rather than mere
    file existence, so a vault with only plaintext memories does not trigger the
    "unreadable until re-enabled" warning.
    """
    memories = home / _MEMORIES_DIR
    if not memories.is_dir():
        return False
    for path in memories.glob("*.md"):
        try:
            with path.open("rb") as fh:
                if fh.read(len(_ENC_HEADER)) == _ENC_HEADER:
                    return True
        except OSError:
            continue
    return False


def _strip_memory_key(text: str) -> str:
    """Drop every ``HERMES_MEMORY_KEY`` binding, preserving other lines verbatim.

    Mirrors the removal half of
    :func:`mordred_hermes.wizard.vault_memory_key._env_with_memory_key` but appends
    nothing — used by ``purge`` to take the key out of the vault ``.env``.
    """
    from dotenv.parser import parse_stream

    kept = "".join(
        binding.original.string for binding in parse_stream(io.StringIO(text)) if binding.key != _MEMORY_KEY_ENV
    )
    if kept and not kept.endswith("\n"):
        kept += "\n"
    return kept


def enable(
    *,
    home: Path,
    root: Path,
    backend: NativeBackend | None = None,
    store: AnchorStore | None = None,
    prompt_io: PromptIO | None = None,
) -> int:
    """Ensure the memory key in the vault and turn the config flag on.

    If no vault exists yet, one is created first (prompting once for a recovery
    passphrase) — ``encryption enable`` drives the vault, so a fresh install need
    not run ``vault init`` by hand. Returns 0 on success, 1 when the vault cannot
    be created or opened, a device key-store error (propagated from
    :func:`set_memory_key`), or an unexpected config.yaml shape.
    """
    from . import vault_cli, vault_memory_key

    rc = vault_cli.ensure_initialised(root=root, prompt_io=prompt_io, backend=backend, store=store)
    if rc != 0:
        return rc  # could not create the vault (reason already printed)

    rc = vault_memory_key.set_memory_key(root=root, rotate=False, backend=backend, store=store)
    if rc != 0:
        return rc
    rc = _set_encryption_flag(home, enabled=True)
    if rc != 0:
        return rc
    print("Agent-memory encryption enabled (key sealed in the vault .env; config flag set).")
    return 0


def disable(*, home: Path) -> int:
    """Set the config flag false but keep the key (suspend — reversible).

    The key stays in the vault, so re-enabling restores readability. Always
    returns 0; warns when encrypted memories exist (they cannot be read while the
    flag is off).
    """
    rc = _set_encryption_flag(home, enabled=False)
    if rc != 0:
        return rc
    if _has_encrypted_memories(home):
        _term.emit_warn(
            "agent-memory encryption disabled, but ~/.hermes/memories/*.md are still encrypted — "
            "they cannot be read until you re-enable it (the key is kept in the vault). To remove encryption "
            "for good, use 'encryption purge memory'."
        )
    print("Agent-memory encryption disabled (config flag off; the key is kept in the vault for re-enable).")
    return 0


def purge(
    *,
    home: Path,
    root: Path,
    backend: NativeBackend | None = None,
    store: AnchorStore | None = None,
) -> int:
    """Set the flag false and strip the memory key from the vault ``.env``.

    Destructive: once the key is gone, memories encrypted under it can no longer
    be decrypted. Returns 0 on success, 1 on a config-shape error or a vault
    open / re-enroll failure.
    """
    from ..keyvault import anchor, vault
    from . import vault_cli

    rc = _set_encryption_flag(home, enabled=False)
    if rc != 0:
        return rc

    if _vault_present(root):
        opened = vault_cli._open_hot_path_or_report(root, backend=backend, store=store)
        if opened is None:
            return 1
        with opened:
            try:
                if ".env" in opened.list_files():
                    stripped = _strip_memory_key(opened.read_file(".env").decode("utf-8"))
                    opened.enroll_file(".env", stripped.encode("utf-8"))
            except (vault.VaultError, anchor.AnchorError, OSError, UnicodeDecodeError) as exc:
                _term.emit_error(f"cannot strip {_MEMORY_KEY_ENV} from the vault .env: {exc}")
                return 1

    print(
        f"Agent-memory encryption purged ({_MEMORY_KEY_ENV} removed from the vault; config flag off). "
        "Memories encrypted under the old key can no longer be decrypted."
    )
    return 0
