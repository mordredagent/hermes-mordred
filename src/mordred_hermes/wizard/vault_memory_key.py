"""``hermes mordred vault set-memory-key`` — the agent-memory on-ramp.

Extracted from :mod:`mordred_hermes.wizard.vault_cli` for cohesion: this module
owns everything specific to ``HERMES_MEMORY_KEY`` (generation / validation, the
``.env`` merge logic, and the ``set-memory-key`` orchestration). It reuses the
shared vault helpers (``_resolve_root`` / ``_open_hot_path_or_report``) from
``vault_cli`` — a one-directional import, so there is no cycle.

Heavy imports (the cryptography-backed vault modules) stay function-local so
this module imports on any platform, matching ``vault_cli.py``.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from typing import TYPE_CHECKING

from .._home import hermes_home as _hermes_home
from .vault_cli import _open_hot_path_or_report, _resolve_root

if TYPE_CHECKING:
    from ..keyvault.anchor import AnchorStore
    from ..keyvault.vault import OpenVault
    from ..keyvault.wrap import NativeBackend

_MEMORY_KEY_ENV = "HERMES_MEMORY_KEY"


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
        existing = _read_enrolled_env(opened, root)
        if existing is None:
            return 1

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

        verb = _store_verb_label(adopted=adopted, orphan_risk=orphan_risk)
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


def _read_enrolled_env(opened: OpenVault, root: Path) -> str | None:
    """Return the enrolled ``.env`` text (``""`` when absent), or ``None`` on a
    read failure (the reason is printed to stderr; the caller fails closed).
    """
    from ..keyvault import vault

    if ".env" not in opened.list_files():
        return ""
    try:
        return opened.read_file(".env").decode("utf-8")
    except UnicodeDecodeError:
        print(
            f"the enrolled .env at {root} is not valid UTF-8 — cannot merge {_MEMORY_KEY_ENV}.",
            file=sys.stderr,
        )
        return None
    except (vault.VaultError, OSError) as exc:
        # OSError covers _storage.KeyvaultPermissionError (bad mode / symlink /
        # I/O) so a read failure fails closed with rc 1, like open / enroll.
        print(f"cannot read the enrolled .env at {root}: {exc}", file=sys.stderr)
        return None


def _store_verb_label(*, adopted: str | None, orphan_risk: bool) -> str:
    """Past-tense verb for the success line: adopt an existing key, rotate, or store."""
    if adopted is not None:
        return "Adopted the existing"
    if orphan_risk:
        return "Rotated"
    return "Stored"


def cli_set_memory_key(args: argparse.Namespace) -> int:
    """argparse handler for ``vault set-memory-key [--root PATH] [--rotate]``."""
    return set_memory_key(root=_resolve_root(getattr(args, "root", None)), rotate=bool(getattr(args, "rotate", False)))


__all__ = ["cli_set_memory_key", "set_memory_key"]
