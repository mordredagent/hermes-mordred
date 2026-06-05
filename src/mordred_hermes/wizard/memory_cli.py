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

import contextlib
import io
import sys
from typing import TYPE_CHECKING

from .vault_memory_key import _MEMORY_KEY_ENV

if TYPE_CHECKING:
    from pathlib import Path

    from ..keyvault.anchor import AnchorStore
    from ..keyvault.wrap import NativeBackend

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
    import os
    import tempfile

    from ruamel.yaml import YAML
    from ruamel.yaml.comments import CommentedMap

    path = home / _CONFIG_NAME
    yaml = YAML()  # round-trip mode preserves comments + ordering
    if path.exists():
        data = yaml.load(path.read_text(encoding="utf-8"))
        if data is None:
            data = CommentedMap()
        elif not isinstance(data, dict):
            print(f"{path} is not a YAML mapping — refusing to edit it.", file=sys.stderr)
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
        print(f"{path}: 'memory' is not a mapping — refusing to edit it.", file=sys.stderr)
        return 1
    encryption = memory.get("encryption")
    if encryption is None:
        encryption = CommentedMap()
        memory["encryption"] = encryption
    elif not isinstance(encryption, dict):
        print(f"{path}: 'memory.encryption' is not a mapping — refusing to edit it.", file=sys.stderr)
        return 1
    encryption["enabled"] = enabled

    # Atomic write: dump into a temp file in the same dir, then os.replace it in
    # one rename so a crash mid-write can never truncate config.yaml. (Not
    # _storage.atomic_write — that enforces vault mode 0o600; config.yaml is a
    # normal user-readable config file.)
    home.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(home), prefix=".config.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            yaml.dump(data, fh)
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise
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
) -> int:
    """Ensure the memory key in the vault and turn the config flag on.

    Returns 0 on success, 1 on an uninitialised / unverifiable vault, a device
    key-store error (propagated from :func:`set_memory_key`), or an unexpected
    config.yaml shape.
    """
    from . import vault_memory_key

    rc = vault_memory_key.set_memory_key(root=root, rotate=False, backend=backend, store=store)
    if rc != 0:
        return rc
    rc = _set_encryption_flag(home, enabled=True)
    if rc != 0:
        return rc
    print("agent-memory encryption enabled (key sealed in the vault .env; config flag set).")
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
        print(
            "warning: agent-memory encryption disabled, but ~/.hermes/memories/*.md are still encrypted — "
            "they cannot be read until you re-enable it (the key is kept in the vault). To remove encryption "
            "for good, use 'encryption purge memory'.",
            file=sys.stderr,
        )
    print("agent-memory encryption disabled (config flag off; the key is kept in the vault for re-enable).")
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

    if any(root.glob("manifest.*.mvmf")):
        opened = vault_cli._open_hot_path_or_report(root, backend=backend, store=store)
        if opened is None:
            return 1
        try:
            if ".env" in opened.list_files():
                stripped = _strip_memory_key(opened.read_file(".env").decode("utf-8"))
                opened.enroll_file(".env", stripped.encode("utf-8"))
        except (vault.VaultError, anchor.AnchorError, OSError, UnicodeDecodeError) as exc:
            print(f"cannot strip {_MEMORY_KEY_ENV} from the vault .env: {exc}", file=sys.stderr)
            return 1
        finally:
            opened.close()

    print(
        f"agent-memory encryption purged ({_MEMORY_KEY_ENV} removed from the vault; config flag off). "
        "Memories encrypted under the old key can no longer be decrypted.",
        file=sys.stderr,
    )
    return 0
