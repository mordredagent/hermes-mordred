"""Attended presence acceptance. Retains its synthetic home for inspection.

See native/sekey-helper/README.md, Bounded presence sessions. Requires -s and
an operator to count actual OS prompts and perform lock/sleep. It never uses an
existing profile, installs a production helper, or connects to Telegram/mail.
"""

from __future__ import annotations

import os
import sys
import time
import uuid
from pathlib import Path

import pytest

pytestmark = pytest.mark.integration


@pytest.mark.parametrize("purpose", ["telegram", "mail"])
def test_attended_presence(purpose, monkeypatch):
    if os.environ.get("MORDRED_PRESENCE_LIVE") != "1":
        pytest.skip("requires attended MORDRED_PRESENCE_LIVE=1")
    assert sys.platform == "darwin"
    selected = os.environ.get("MORDRED_PRESENCE_TEST_ROOT", "")
    helper = os.environ.get("MORDRED_SEKEY_HELPER", "")
    assert selected and helper, "explicit synthetic root and candidate helper required"
    root = Path(selected).resolve(strict=True)
    production = Path.home() / ".hermes"
    assert root != production and production not in root.parents
    assert Path(helper).is_absolute() and Path(helper).is_file()
    scenario = os.environ.get("MORDRED_PRESENCE_SCENARIO", "within-window")
    assert scenario in {"within-window", "expiry", "lock", "sleep", "deny"}
    home = root / ("presence-" + uuid.uuid4().hex)
    home.mkdir(mode=0o700)
    monkeypatch.setenv("HERMES_HOME", str(home))
    monkeypatch.delenv("MORDRED_SEKEY_STORE", raising=False)
    monkeypatch.delenv("MORDRED_SEKEY_UNATTENDED", raising=False)
    from mordred_hermes.keyvault import _presence as presence
    from mordred_hermes.keyvault._seckey_helper import _run_helper

    assert _run_helper(helper, {"cmd": "capabilities"}).get("presence_session") == 1
    audit = []
    if purpose == "telegram":
        from mordred_hermes.extension.telegram.secrets import TelegramSecrets
        from mordred_hermes.extension.telegram.tee import TeeSecretStore

        store = TeeSecretStore(home / "mordred/telegram", audit_sink=audit.append)
        credentials = TelegramSecrets(1, "ab" * 16, b"x" * 32, session="synthetic-session")
    else:
        from mordred_hermes.imports.mail.secrets import MailSecretStore
        from tests._mail_sync_helpers import generic_creds

        store = MailSecretStore(home / "mordred/mail", audit_sink=audit.append)
        credentials = generic_creds()
    store.ensure_key(require_presence=True)
    store.store(credentials)
    (home / "config.yaml").write_text("plugins:\n  mordred_keyvault:\n    presence_reuse_seconds: 300\n")
    print(f"\nRetained synthetic home: {home}\nScenario: {purpose}/{scenario}; count every OS prompt.")
    try:
        with presence.presence_scope(home, ("manual", "isolated-session"), purpose):
            assert store.load() == credentials  # approve first prompt
            entries = list(presence._pool._entries.values())
            assert len(entries) == 1, "streaming path must be active"
            channel = entries[0].channel
            if scenario == "within-window":
                assert store.load() == credentials
                assert store.load() == credentials
                expected_prompts, expected_decrypts = "1", 3
            elif scenario == "expiry":
                print("Waiting 301 seconds; do not lock or sleep for this scenario.", flush=True)
                time.sleep(301)
                assert not channel.alive()
                assert store.load() == credentials
                expected_prompts, expected_decrypts = "2", 2
            elif scenario in {"lock", "sleep"}:
                input(f"{scenario.title()} this Mac, resume/unlock, then press Enter here: ")
                assert not channel.alive(), "OS notification must revoke the helper before another request"
                assert store.load() == credentials
                expected_prompts, expected_decrypts = "2", 2
            else:
                presence.revoke(home=home)
                print("Deny/cancel the next authentication prompt.", flush=True)
                from mordred_hermes.extension.telegram.secrets import TelegramSecretsError
                from mordred_hermes.imports.mail.secrets import MailSecretsError

                with pytest.raises((TelegramSecretsError, MailSecretsError)):
                    store.load()
                assert not presence._pool._entries, "denial must discard all reuse for this operation"
                assert store.load() == credentials  # explicit next operation; approve
                expected_prompts, expected_decrypts = "3", 2
            assert sum(e.get("reason") == "keyvault.unwrap_authorized" for e in audit) == expected_decrypts
            observed = input(f"Actual OS prompt count (expected {expected_prompts}): ").strip()
            assert observed == expected_prompts
    finally:
        presence.revoke(home=home)
        # Keep keys and source confined to the retained synthetic root. Cleanup
        # can be done with the normal authenticated forget flow after inspection.
