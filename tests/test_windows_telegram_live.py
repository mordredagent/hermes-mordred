"""Explicitly gated ordinary-user CNG Telegram custody in a new retained task profile.

Set MORDRED_TEST_WINDOWS_TELEGRAM_LIVE=1 and MORDRED_WINDOWS_CUSTODY_TEST_ROOT
only in an authorized Windows native validation run. The root must already
exist; each run creates a UUID child profile, enrolls a fresh CNG ``telegram``
role, seals SYNTHETIC credentials, writes a synthetic archive, reloads both in a
fresh process and finally runs the forget ceremony. No Telegram account, API
credential, phone number, network or model is used. A failure preserves the
profile and journals for explicit reconciliation and reports only its path.
"""

from __future__ import annotations

import os
import subprocess
import sys
import uuid
from pathlib import Path

import pytest

pytestmark = pytest.mark.integration

_RELOAD = """
import sys
from pathlib import Path
from mordred_hermes.extension.telegram import store
from mordred_hermes.extension.telegram.windows_secrets import WindowsCustodySecretStore
home = Path(sys.argv[1])
value = WindowsCustodySecretStore(home, audit_sink=lambda entry: None).load()
assert value is not None and value.session == "SYNTHETIC-SESSION-NOT-A-REAL-ACCOUNT"
archive = store.ArchiveStore(value.store_key, home / "mordred" / "telegram")
assert [m.text for m in archive.load_messages(1)] == ["synthetic"]
print("reloaded", flush=True)
"""


@pytest.mark.skipif(
    sys.platform != "win32" or os.environ.get("MORDRED_TEST_WINDOWS_TELEGRAM_LIVE") != "1",
    reason="explicit ordinary-user Windows CNG Telegram custody validation only",
)
def test_real_cng_telegram_role_seals_reloads_and_forgets_synthetic_state():
    from mordred_hermes._private_fs import open_confidential_directory
    from mordred_hermes.extension.telegram import secrets, store
    from mordred_hermes.extension.telegram.windows_secrets import WindowsCustodySecretStore
    from mordred_hermes.keyvault._windows_custody import windows_custody_session

    value = os.environ.get("MORDRED_WINDOWS_CUSTODY_TEST_ROOT")
    if not value:
        pytest.fail("a retained isolated validation root is required")
    root = Path(value)
    with open_confidential_directory(root):
        pass
    home = root / ("telegram-" + uuid.uuid4().hex)
    print(f"Isolated Telegram custody fixture: {home}")
    with windows_custody_session(home, create=True) as session:
        session.enroll_role("telegram")
    vault = WindowsCustodySecretStore(home, audit_sink=lambda entry: None)
    with pytest.raises(secrets.TelegramSecretsError, match="presence_unsupported"):
        vault.ensure_key()
    vault.ensure_key(require_presence=False)
    synthetic = secrets.TelegramSecrets(
        api_id=1,
        api_hash="0" * 32,
        store_key=os.urandom(32),
        session="SYNTHETIC-SESSION-NOT-A-REAL-ACCOUNT",
    )
    vault.store(synthetic)
    archive_root = home / "mordred" / "telegram"
    archive = store.ArchiveStore(synthetic.store_key, archive_root)
    archive.save_index(store.ArchiveIndex(account_label="synthetic"))
    archive.append_messages(1, [store.StoredMessage(id=1, date=1, sender="synthetic", text="synthetic")])
    reloaded = subprocess.run(
        [sys.executable, "-c", _RELOAD, str(home)], capture_output=True, text=True, timeout=120, check=False
    )
    assert reloaded.returncode == 0 and reloaded.stdout.strip() == "reloaded", "fresh-process reload failed"
    store.wipe_archive(archive_root, forget=True)
    assert not (archive_root / "credentials.sealed").exists()
    assert not (archive_root / "index.enc").exists()
    with windows_custody_session(home) as session:
        status = session.role_status("telegram")
        assert status.current is None and not status.retained and not status.pending
        # Only this run's freshly enrolled generation existed, so it was the one deleted.
        assert session.role_status("memory").current is None
