"""Explicit native mail acceptance; failures retain every fixture and source key.

Run only with MORDRED_MAIL_NATIVE_TEST=1, an existing private synthetic
MORDRED_DBCRYPT_TEST_ROOT, and an explicit installed native helper. No emulator,
portable backend, credentials, mail connection or consumer activation is used.
Linux success retains native sources too: POSIX mail retirement needs Task 12's
concrete owner and must never be replaced with an unbrokered native delete.
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
    env_name = "MORDRED_TPMKEY_HELPER" if sys.platform == "linux" else "MORDRED_WINKEY_HELPER"
    helper = os.environ.get(env_name)
    assert helper and Path(helper).is_absolute() and Path(helper).is_file(), "explicit installed helper required"
    assert not os.environ.get("MORDRED_TPM_TEST"), "emulator opt-in is forbidden in native acceptance"
    home = root / ("mail-native-" + uuid.uuid4().hex)
    monkeypatch.setenv("HERMES_HOME", str(home))
    monkeypatch.delenv("HERMES_MEMORY_KEY", raising=False)
    monkeypatch.delenv("MORDRED_TPMKEY_STORE", raising=False)
    from mordred_hermes._database_contracts import DatabaseRefused
    from mordred_hermes._private_fs import open_confidential_directory
    from mordred_hermes.keyvault import wrap
    from mordred_hermes.keyvault._mail_key import mail_backend, mail_key_id

    with open_confidential_directory(root), open_confidential_directory(home, create=True):
        pass
    print(f"Retained native mail fixture: {home}")
    key_id = mail_key_id(home)
    if sys.platform == "win32":
        from mordred_hermes.keyvault._windows_custody import upgrade_manifest_v2, windows_custody_session

        upgrade_manifest_v2(home=home)
        with windows_custody_session(home) as session:
            mail = session.enroll_role("mail")
            assert session.role_status("memory").current is None
            assert session.role_status("audit").current is None
            telegram = session.enroll_role("telegram")
            assert mail.native_key_id != telegram.native_key_id
            foreign = wrap.wrap_dek(b"T" * 32, telegram.native_key_id, backend=session.backend_for(telegram))
    else:
        mail_backend(home=home).generate_enclave_key(key_id, unattended=True)
        foreign = None
    backend = mail_backend(home=home)
    sealed = wrap.wrap_dek(b"M" * 32, key_id, backend=backend)
    assert wrap.unwrap_dek(sealed, key_id, backend=mail_backend(home=home), audit_sink=lambda entry: None) == b"M" * 32
    for other_id in ("mordred.memory", "mordred-hermes.telegram.credentials.v1"):
        with pytest.raises(DatabaseRefused):
            backend.get_enclave_public_key(other_id)
    if sys.platform == "win32":
        from mordred_hermes.keyvault._exceptions import WrapError

        with pytest.raises(WrapError):
            wrap.unwrap_dek(foreign, key_id, backend=backend, audit_sink=lambda entry: None)
        # Cleanup only after every assertion passed, through genuine owner permits.
        with windows_custody_session(home) as session:
            session.delete_role(mail, erase_authorized=True)
            session.delete_role(telegram, erase_authorized=True)
    else:
        other_home = root / ("mail-native-other-" + uuid.uuid4().hex)
        with open_confidential_directory(other_home, create=True):
            pass
        print(f"Retained independent native mail fixture: {other_home}")
        other = mail_backend(home=other_home)
        other.generate_enclave_key(mail_key_id(other_home), unattended=True)
        from mordred_hermes.keyvault._exceptions import WrapError

        with pytest.raises(WrapError):
            wrap.unwrap_dek(sealed, key_id, backend=other, audit_sink=lambda entry: None)
