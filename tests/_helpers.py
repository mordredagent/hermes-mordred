"""Shared per-module test helpers with byte-identical bodies, deduplicated
from multiple test modules (test-infrastructure refactor).

``_init_empty_vault`` was duplicated verbatim across ``test_keyvault_env_reseal.py``,
``test_wizard_config_decrypt_cli.py``, ``test_wizard_encryption_cli.py``,
``test_wizard_env_decrypt_cli.py``, and ``test_wizard_memory_cli.py``.

``_writer`` was duplicated verbatim across ``test_configure.py``,
``test_policy_writer.py``, ``test_upgrade.py``, and ``test_wizard_network_init.py``
(``test_openclaw_migration.py`` has a deliberately different body — its own
``_writer`` namespaces paths under a ``hermes/`` subdirectory — and keeps its
own copy).

``FakeAuditWriter`` was duplicated verbatim (as ``_FakeAuditWriter``) across
``test_enforce.py``, ``test_enforce_audit.py``, ``test_enforce_prompt.py``,
``test_harness_detect.py``, and ``integration/test_llm_local.py``; each of
those modules now imports this shared copy under its original
``_FakeAuditWriter`` local name so call sites are unchanged.

``FakePluginContext`` consolidates the near-identical ``_FakeCtx`` /
``_FakeContext`` PluginContext stand-ins from ``_network_hooks_helpers.py``,
``test_keyvault_session_reseal.py``, ``test_llm_guard_register.py``, and
``test_imports.py``. Three of those four already recorded ``hooks`` as a
``list[tuple[str, callback]]``; ``test_keyvault_session_reseal.py`` alone
tracked a separate ``list[str]`` of just the names plus a second
``registered`` tuple list. This shared version keeps the majority
``hooks: list[tuple[str, callback]]`` shape as the single source of truth
and exposes ``hook_names`` / ``callbacks_for`` as views over it, so
``test_keyvault_session_reseal.py`` reads through those instead of a
duplicate name-only list — the checks themselves are unchanged, only how
they reach the data.

Not a ``test_*`` module, so pytest does not collect it.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

from mordred_hermes.keyvault import _identity, vault
from mordred_hermes.wizard.policy_writer import PolicyWriter

from ._keyvault_fakes import FakeAnchorStore, FakeBackend

_PASSPHRASE = "correct horse battery staple"


class FakeAuditWriter:
    """Captures audit appends so tests can assert reason / decision / fields."""

    def __init__(self) -> None:
        self.entries: list[dict[str, Any]] = []

    def append(self, entry: Mapping[str, Any]) -> None:
        self.entries.append(entry)


class FakePluginContext:
    """Hermes ``PluginContext`` stand-in shared by hook-registration tests.

    ``hooks`` records every ``register_hook`` call as a ``(hook_name,
    callback)`` pair. ``hook_names`` and ``callbacks_for`` are convenience
    views derived from ``hooks``. ``raise_on`` simulates a host that
    rejects specific hook names, so callers can prove ``register()``
    survives a host rejection. ``register_cli_command`` / ``register_provider``
    are no-ops some plugins' ``register()`` calls incidentally.
    """

    def __init__(self, *, raise_on: set[str] | None = None) -> None:
        self.hooks: list[tuple[str, Callable[..., Any]]] = []
        self._raise_on = raise_on or set()

    @property
    def hook_names(self) -> list[str]:
        return [name for name, _ in self.hooks]

    def register_hook(self, hook_name: str, callback: Callable[..., Any]) -> None:
        if hook_name in self._raise_on:
            raise RuntimeError("host rejected hook")
        self.hooks.append((hook_name, callback))

    def callbacks_for(self, hook_name: str) -> list[Any]:
        return [callback for name, callback in self.hooks if name == hook_name]

    def register_cli_command(self, *args: object, **kwargs: object) -> None:
        return None

    def register_provider(self, *args: object, **kwargs: object) -> None:
        return None


def _init_empty_vault(root: Path, backend: FakeBackend, store: FakeAnchorStore) -> None:
    key_id = anchor_label = _identity.vault_identity(root)
    backend.generate_enclave_key(key_id)
    vault.init_vault(
        root, key_id=key_id, passphrase=_PASSPHRASE, backend=backend, store=store, anchor_label=anchor_label
    ).close()


def _writer(tmp_path: Path) -> PolicyWriter:
    return PolicyWriter(
        config_path=tmp_path / "config.yaml",
        policy_json_path=tmp_path / "mordred" / "policy.json",
        mordred_dir=tmp_path / "mordred",
    )
