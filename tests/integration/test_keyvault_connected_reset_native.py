"""Explicit isolated real-helper reset acceptance; no account or network I/O."""

from __future__ import annotations

import os
import sys
import uuid
from pathlib import Path

import pytest

pytestmark = pytest.mark.integration


def test_connected_reset_native_helper(monkeypatch):
    if os.environ.get("MORDRED_RESET_NATIVE_TEST") != "1":
        pytest.skip("requires explicit MORDRED_RESET_NATIVE_TEST=1")
    assert sys.platform in {"darwin", "linux"}, "POSIX native helper required"
    selected = os.environ.get("MORDRED_RESET_TEST_ROOT")
    assert selected, "explicit retained synthetic root required"
    root = Path(selected)
    assert root.is_absolute() and root == root.resolve(strict=True)
    assert root != Path.home() / ".hermes" and Path.home() / ".hermes" not in root.parents
    helper_env = "MORDRED_SEKEY_HELPER" if sys.platform == "darwin" else "MORDRED_TPMKEY_HELPER"
    helper = os.environ.get(helper_env)
    assert helper and Path(helper).is_absolute() and Path(helper).is_file()
    assert not os.environ.get("MORDRED_TPM_TEST"), "emulator is not native acceptance"
    home = root / ("connected-reset-" + uuid.uuid4().hex)
    home.mkdir(mode=0o700)
    monkeypatch.setenv("HERMES_HOME", str(home))
    for name in ("MORDRED_SEKEY_STORE", "MORDRED_TPMKEY_STORE", "HERMES_MEMORY_KEY"):
        monkeypatch.delenv(name, raising=False)
    from mordred_hermes.extension.telegram.secrets import TelegramSecrets
    from mordred_hermes.extension.telegram.tee import TeeSecretStore
    from mordred_hermes.imports.mail.secrets import MailCredentials, MailSecretStore
    from mordred_hermes.keyvault import _storage, api
    from mordred_hermes.keyvault._seckey_backend import _SecKeyBackend
    from mordred_hermes.wizard.keyvault_cli import reset_keyvault

    print(f"Retained native reset fixture: {home}")
    mail = MailSecretStore(home / "mordred/mail", audit_sink=lambda _e: None)
    telegram = TeeSecretStore(home / "mordred/telegram", audit_sink=lambda _e: None)
    mail_value = MailCredentials(
        "synthetic@example.invalid",
        "synthetic-password",
        "imap.example.invalid",
        993,
        ("synthetic@example.invalid",),
        "mail",
        False,
        {"inbox": "INBOX"},
    )
    telegram_value = TelegramSecrets(1, "ab" * 16, b"x" * 32, session="SYNTHETIC-SESSION")
    for _ in range(2):  # provision after reset verifies that no pending evidence blocks re-init
        backend = _SecKeyBackend(sw_ops=None, legacy_ops=None)
        seed, passphrase, proof = "synthetic reset seed", "synthetic passphrase", bytes(range(32))
        prepared, digest = api.prepare_generate(seed, passphrase, proof)
        prepared.consume()
        api.generate(
            seed,
            passphrase,
            proof,
            digest,
            key_id="reset-test",
            backend=backend,
            audit_sink=lambda _e: None,
            home=home,
            unattended=True,
        )
        api.encrypt(
            "reset-test", b"synthetic local secret", "test", backend=backend, audit_sink=lambda _e: None, home=home
        )
        mail.ensure_key(require_presence=False)
        mail.store(mail_value, require_presence=False)
        telegram.ensure_key(require_presence=False)
        telegram.store(telegram_value)
        assert mail.load() == mail_value
        assert telegram.load() == telegram_value
        leaf = "sekey" if sys.platform == "darwin" else "tpm"
        retained = home / "mordred/keyvault" / leaf / "unrelated-owner.bin"
        _storage.atomic_write(retained, b"KEEP INDEPENDENT HELPER MATERIAL")
        before = retained.stat().st_ino
        assert reset_keyvault(home=home, assume_yes=True) == 0
        assert not (home / "mordred/keyvault/meta.json").exists()
        assert not any((home / "mordred/keyvault").glob("ciphertexts/*/*/*.gcm"))
        assert not mail.sealed_path.exists()
        assert not telegram.sealed_path.exists()
        assert retained.stat().st_ino == before
        assert retained.read_bytes() == b"KEEP INDEPENDENT HELPER MATERIAL"
        assert not _storage.reset_journal_path(home / "mordred/keyvault").exists()
