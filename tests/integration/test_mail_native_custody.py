"""Credential-only native mail acceptance; fixtures retained on every failure.

MORDRED_MAIL_NATIVE_TEST=1 requires a private synthetic root and an explicit
installed native helper. This exercises MMC1 credentials and authenticated
retirement, NOT shared SQLCipher collection qualification (Task 15). No account
connection occurs. Native database eligibility is never enabled by this gate.
"""

from __future__ import annotations

import os
import sys
import uuid
from pathlib import Path

import pytest

pytestmark = pytest.mark.integration


def test_native_mail_custody_roundtrip_and_role_isolation(monkeypatch):
    if os.environ.get("MORDRED_MAIL_NATIVE_TEST") != "1":
        pytest.skip("requires explicit MORDRED_MAIL_NATIVE_TEST=1")
    if sys.platform not in {"linux", "win32"}:
        pytest.fail("explicit native mail gate requires Linux TPM or Windows CNG")
    selected = os.environ.get("MORDRED_DBCRYPT_TEST_ROOT")
    if not selected:
        pytest.fail("explicit native mail gate requires a retained synthetic root")
    root = Path(selected)
    assert root.is_absolute() and root == root.resolve(strict=True)
    production = Path.home() / ".hermes"
    assert root != production and production not in root.parents, "production Hermes home is forbidden"
    helper = os.environ.get("MORDRED_TPMKEY_HELPER" if sys.platform == "linux" else "MORDRED_WINKEY_HELPER")
    assert helper and Path(helper).is_absolute() and Path(helper).is_file(), "explicit installed helper required"
    assert not os.environ.get("MORDRED_TPM_TEST"), "emulator opt-in is forbidden in native acceptance"
    home = root / ("mail-native-" + uuid.uuid4().hex)
    monkeypatch.setenv("HERMES_HOME", str(home))
    monkeypatch.delenv("HERMES_MEMORY_KEY", raising=False)
    monkeypatch.delenv("MORDRED_TPMKEY_STORE", raising=False)
    from mordred_hermes._private_fs import open_confidential_directory, open_private_directory
    from mordred_hermes.imports.mail.secrets import MailCredentials, MailSecretStore

    directory = open_confidential_directory if sys.platform == "win32" else open_private_directory
    with directory(root), directory(home, create=True):
        pass
    print(f"Retained native mail fixture: {home}")
    store = MailSecretStore(home / "mordred/mail", audit_sink=lambda _entry: None)
    assert store.ensure_key(require_presence=False) is False
    credentials = MailCredentials(
        "synthetic@example.invalid",
        "synthetic-test-password",
        "imap.example.invalid",
        993,
        ("synthetic@example.invalid",),
        "mail",
        False,
        {"inbox": "INBOX"},
    )
    store.store(credentials, require_presence=False)
    assert store.sealed_path.read_bytes().startswith(b"MMC1")
    assert store.load() == credentials
    if sys.platform == "win32":
        from mordred_hermes.keyvault._windows_custody import windows_custody_session

        with windows_custody_session(home) as session:
            telegram = session.enroll_role("telegram")
            mail = session.lease("mail")
            assert mail.native_key_id != telegram.native_key_id
        assert store.forget() is True
        with windows_custody_session(home) as session:
            session.validate_lease(telegram)
            assert session.role_status("mail").current is None
            assert session.role_status("memory").current is None
    else:
        from mordred_hermes.keyvault import wrap
        from mordred_hermes.keyvault._exceptions import WrapKeyNotFound
        from mordred_hermes.keyvault._mail_key import mail_backend

        assert store.forget() is True
        with pytest.raises(WrapKeyNotFound):
            wrap.get_wrapping_key_public("mordred-hermes.mail.credentials.v1", backend=mail_backend(home=home))
    assert not store.residue()
