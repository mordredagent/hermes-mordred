"""Tests for ``hermes mordred encryption {enable,disable,purge} memory``.

Agent-memory encryption is two coupled pieces: the ``HERMES_MEMORY_KEY`` in the
vault ``.env`` (protected at rest, injected at startup) and the
``memory.encryption.enabled`` flag in ``config.yaml`` that tells upstream
``tools/memory_tool.py`` to actually encrypt ``~/.hermes/memories/*.md``. Today
``vault set-memory-key`` writes the key but only *prints a hint* about the flag;
this target writes the flag for real and gives it disable/purge.

State transitions (not symmetric):

- **enable**  — ensure the key in the vault ``.env`` and set the config flag true.
- **disable** — set the flag false but **keep the key** (suspend: reversible).
  Warns that already-encrypted memories are unreadable until re-enabled.
- **purge**   — set the flag false and **remove the key** from the vault ``.env``.
  Destructive: memories encrypted under it can no longer be decrypted.

Built on the software fakes so the real hot-path open/enroll runs on any platform.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from mordred_hermes.keyvault import _identity, vault
from mordred_hermes.wizard import memory_cli
from mordred_hermes.wizard.vault_memory_key import _MEMORY_KEY_ENV, _is_valid_memory_key

from ._keyvault_fakes import FakeAnchorStore, FakeBackend, FixedPassphrasePromptIO

_PASSPHRASE = "correct horse battery staple"


def _init_empty_vault(root: Path, backend: FakeBackend, store: FakeAnchorStore) -> None:
    key_id = anchor_label = _identity.vault_identity(root)
    backend.generate_enclave_key(key_id)
    vault.init_vault(
        root, key_id=key_id, passphrase=_PASSPHRASE, backend=backend, store=store, anchor_label=anchor_label
    ).close()


def _vault_env_text(root: Path, backend: FakeBackend, store: FakeAnchorStore) -> str:
    key_id = anchor_label = _identity.vault_identity(root)
    with vault.open_vault(root, key_id=key_id, backend=backend, store=store, anchor_label=anchor_label) as opened:
        return opened.read_file(".env").decode("utf-8") if ".env" in opened.list_files() else ""


def _raw_flag(home: Path) -> object:
    """The actual ``memory.encryption.enabled`` value (True / False / None)."""
    from ruamel.yaml import YAML

    text = (home / "config.yaml").read_text(encoding="utf-8")
    data = YAML(typ="safe").load(text)
    if not isinstance(data, dict):
        return None
    memory = data.get("memory")
    encryption = memory.get("encryption") if isinstance(memory, dict) else None
    return encryption.get("enabled") if isinstance(encryption, dict) else None


def _effective_key(text: str) -> str | None:
    from mordred_hermes.wizard.vault_memory_key import _effective_memory_key

    return _effective_memory_key(text)


# -----------------------------------------------------------------------------
# enable
# -----------------------------------------------------------------------------
class TestEnable:
    def test_sets_flag_true_and_writes_key(self, tmp_path: Path) -> None:
        root, home = tmp_path / "v", tmp_path / "home"
        home.mkdir()
        backend, store = FakeBackend(), FakeAnchorStore()
        _init_empty_vault(root, backend, store)
        (home / "config.yaml").write_text("model: gpt-x\n", encoding="utf-8")

        rc = memory_cli.enable(home=home, root=root, backend=backend, store=store)
        assert rc == 0
        assert _raw_flag(home) is True
        assert _is_valid_memory_key(_effective_key(_vault_env_text(root, backend, store)))

    def test_preserves_other_config_keys(self, tmp_path: Path) -> None:
        root, home = tmp_path / "v", tmp_path / "home"
        home.mkdir()
        backend, store = FakeBackend(), FakeAnchorStore()
        _init_empty_vault(root, backend, store)
        (home / "config.yaml").write_text("model: gpt-x\nfoo: bar\n", encoding="utf-8")

        memory_cli.enable(home=home, root=root, backend=backend, store=store)
        from ruamel.yaml import YAML

        data = YAML(typ="safe").load((home / "config.yaml").read_text(encoding="utf-8"))
        assert data["model"] == "gpt-x"
        assert data["foo"] == "bar"
        assert data["memory"]["encryption"]["enabled"] is True

    def test_missing_vault_is_auto_created_then_key_set(self, tmp_path: Path) -> None:
        """A first memory enable on a fresh install creates the vault inline
        (prompting once), seals the key, and sets the flag — no manual init."""
        root, home = tmp_path / "v", tmp_path / "home"
        home.mkdir()
        (home / "config.yaml").write_text("model: x\n", encoding="utf-8")
        backend, store = FakeBackend(), FakeAnchorStore()

        rc = memory_cli.enable(
            home=home, root=root, backend=backend, store=store, prompt_io=FixedPassphrasePromptIO(_PASSPHRASE)
        )
        assert rc == 0
        assert _MEMORY_KEY_ENV in _vault_env_text(root, backend, store)
        assert _raw_flag(home) is True

    def test_vault_create_refused_is_error(self, tmp_path: Path) -> None:
        """An empty passphrase refuses the vault create: enable fails."""
        root, home = tmp_path / "v", tmp_path / "home"
        home.mkdir()
        (home / "config.yaml").write_text("model: x\n", encoding="utf-8")
        rc = memory_cli.enable(
            home=home,
            root=root,
            backend=FakeBackend(),
            store=FakeAnchorStore(),
            prompt_io=FixedPassphrasePromptIO(""),
        )
        assert rc == 1


# -----------------------------------------------------------------------------
# disable (suspend — reversible)
# -----------------------------------------------------------------------------
class TestDisable:
    def test_sets_flag_false_keeps_key(self, tmp_path: Path) -> None:
        root, home = tmp_path / "v", tmp_path / "home"
        home.mkdir()
        backend, store = FakeBackend(), FakeAnchorStore()
        _init_empty_vault(root, backend, store)
        (home / "config.yaml").write_text("model: x\n", encoding="utf-8")
        memory_cli.enable(home=home, root=root, backend=backend, store=store)

        rc = memory_cli.disable(home=home)
        assert rc == 0
        assert _raw_flag(home) is False
        # key is KEPT in the vault so re-enabling restores readability
        assert _is_valid_memory_key(_effective_key(_vault_env_text(root, backend, store)))

    def test_warns_when_encrypted_memories_present(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        root, home = tmp_path / "v", tmp_path / "home"
        home.mkdir()
        backend, store = FakeBackend(), FakeAnchorStore()
        _init_empty_vault(root, backend, store)
        (home / "config.yaml").write_text("model: x\n", encoding="utf-8")
        memory_cli.enable(home=home, root=root, backend=backend, store=store)
        (home / "memories").mkdir()
        # upstream encrypted payload carries the HERMES-MEMORY-ENC-v1 header
        (home / "memories" / "note.md").write_text("HERMES-MEMORY-ENC-v1\n<ciphertext>", encoding="utf-8")

        memory_cli.disable(home=home)
        assert "re-enable" in capsys.readouterr().err.lower()

    def test_no_warning_on_plaintext_memories(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        root, home = tmp_path / "v", tmp_path / "home"
        home.mkdir()
        backend, store = FakeBackend(), FakeAnchorStore()
        _init_empty_vault(root, backend, store)
        (home / "config.yaml").write_text("model: x\n", encoding="utf-8")
        memory_cli.enable(home=home, root=root, backend=backend, store=store)
        (home / "memories").mkdir()
        (home / "memories" / "note.md").write_text("# just plaintext notes\n", encoding="utf-8")

        memory_cli.disable(home=home)
        # a plaintext memory file (no encryption header) must NOT trigger the warning
        assert "re-enable" not in capsys.readouterr().err.lower()

    def test_idempotent_no_config(self, tmp_path: Path) -> None:
        home = tmp_path / "home"
        home.mkdir()
        rc = memory_cli.disable(home=home)
        assert rc == 0
        assert _raw_flag(home) is False


# -----------------------------------------------------------------------------
# purge (destructive)
# -----------------------------------------------------------------------------
class TestPurge:
    def test_removes_key_and_sets_flag_false(self, tmp_path: Path) -> None:
        root, home = tmp_path / "v", tmp_path / "home"
        home.mkdir()
        backend, store = FakeBackend(), FakeAnchorStore()
        _init_empty_vault(root, backend, store)
        (home / "config.yaml").write_text("model: x\n", encoding="utf-8")
        memory_cli.enable(home=home, root=root, backend=backend, store=store)

        rc = memory_cli.purge(home=home, root=root, backend=backend, store=store)
        assert rc == 0
        assert _raw_flag(home) is False
        assert _MEMORY_KEY_ENV not in _vault_env_text(root, backend, store)


# -----------------------------------------------------------------------------
# _set_encryption_flag must round-trip config.yaml through PolicyWriter's
# shared ruamel instance, not a bare YAML(). A bare YAML() uses ruamel's
# default indent settings, which reformat every sequence already in the file
# (e.g. a `plugins.enabled` list PolicyWriter wrote at dash-indent offset 2
# collapses to offset 0) -- so alternating `configure` / `network init` /
# `upgrade` with `encryption {enable,disable,purge} memory` caused gratuitous
# config.yaml diff churn on lists that were never touched by this command.
# -----------------------------------------------------------------------------
class TestSetEncryptionFlagPreservesFormatting:
    def test_plugins_enabled_list_formatting_survives_round_trip(self, tmp_path: Path) -> None:
        from mordred_hermes.wizard.policy_writer import PolicySnapshot, PolicyWriter

        home = tmp_path / "home"
        home.mkdir()
        # Seed config.yaml exactly the way PolicyWriter writes it (indent
        # mapping=2, sequence=4, offset=2) so the test reproduces the real
        # on-disk shape rather than a hand-authored approximation of it.
        writer = PolicyWriter(
            config_path=home / "config.yaml",
            policy_json_path=home / "mordred" / "policy.json",
            mordred_dir=home / "mordred",
        )
        writer.write(PolicySnapshot(policy="lenient"))
        before = (home / "config.yaml").read_text(encoding="utf-8")
        enabled_block = (
            "  enabled:\n"
            "    - mordred_privacy_check\n"
            "    - mordred_wizard\n"
            "    - mordred_llm_guard\n"
            "    - mordred_network\n"
            "    - mordred_keyvault\n"
        )
        assert enabled_block in before, "test setup must reproduce PolicyWriter's offset-2 dash indent"

        rc = memory_cli._set_encryption_flag(home, enabled=True)
        assert rc == 0

        after = (home / "config.yaml").read_text(encoding="utf-8")
        # The plugins.enabled block's indentation must be byte-identical --
        # only the new memory.encryption.enabled key was added. A bare YAML()
        # would instead collapse the dash indent to offset 0.
        assert enabled_block in after
        assert after.startswith(before.rstrip("\n"))
