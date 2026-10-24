"""Native mail source stays independent and never activates a mail consumer."""

import importlib.util
from types import SimpleNamespace

import pytest

from mordred_hermes._database_contracts import DatabaseRefused
from mordred_hermes.keyvault import wrap
from mordred_hermes.keyvault._database_mutation import database_key_mutation
from mordred_hermes.keyvault._exceptions import WrapError
from tests.test_windows_custody import fs as fs


def mail_module():
    assert importlib.util.find_spec("mordred_hermes.keyvault._mail_key") is not None, "native mail source is missing"
    from mordred_hermes.keyvault import _mail_key

    return _mail_key


def test_mail_cannot_unseal_telegram_or_database_key(fs, monkeypatch):
    mail = mail_module()
    c, _, home, backend = fs
    monkeypatch.setattr(mail, "sys", SimpleNamespace(platform="win32"))
    monkeypatch.setattr(c, "windows_backend", lambda: backend)
    with (
        database_key_mutation(root=home, generation=None) as lease,
        c.windows_custody_session(home, create=True, backend=backend) as session,
    ):
        session.enroll_memory(database_lease=lease)
        session.enroll_role("telegram")
    c.upgrade_manifest_v2(home=home)
    with (
        database_key_mutation(root=home, generation=None) as lease,
        c.windows_custody_session(home, backend=backend) as session,
    ):
        session.enroll_role("mail")
        roles = [session.lease(role) for role in ("memory", "telegram", "mail")]
        assert len({role.native_key_id for role in roles}) == 3
        foreign = [wrap.wrap_dek(b"F" * 32, role.native_key_id, backend=backend) for role in roles[:2]]
    selected = mail.mail_backend(home=home)
    key_id = mail.mail_key_id(home)
    assert key_id == "mordred-hermes.mail.credentials.v1"
    sealed = wrap.wrap_dek(b"M" * 32, key_id, backend=selected)
    assert wrap.unwrap_dek(sealed, key_id, backend=selected, audit_sink=lambda entry: None) == b"M" * 32
    for role, blob in zip(roles[:2], foreign, strict=True):
        with pytest.raises((WrapError, DatabaseRefused)):
            wrap.unwrap_dek(blob, key_id, backend=selected, audit_sink=lambda entry: None)
        with pytest.raises(DatabaseRefused):
            selected.get_enclave_public_key(role.native_key_id)
        # Even a foreign public key wrapped under the mail wire identifier
        # cannot authenticate through mail's distinct native private key.
        foreign_public = backend.get_enclave_public_key(role.native_key_id)
        foreign_backend = SimpleNamespace(get_enclave_public_key=lambda key_id, public=foreign_public: public)
        forged_header = wrap.wrap_dek(b"F" * 32, key_id, backend=foreign_backend)
        with pytest.raises(WrapError):
            wrap.unwrap_dek(forged_header, key_id, backend=selected, audit_sink=lambda entry: None)
    with pytest.raises(DatabaseRefused):
        selected.generate_enclave_key(key_id)
    with pytest.raises(DatabaseRefused):
        selected.delete_enclave_key(key_id)


def test_read_backend_never_upgrades_or_enrolls(fs, monkeypatch):
    mail = mail_module()
    c, _, home, backend = fs
    monkeypatch.setattr(mail, "sys", SimpleNamespace(platform="win32"))
    monkeypatch.setattr(c, "windows_backend", lambda: backend)
    selected = mail.mail_backend(home=home)
    with pytest.raises((c.CustodyError, DatabaseRefused)):
        selected.get_enclave_public_key(mail.mail_key_id(home))
    assert backend.calls == []
    assert not (home / "mordred").exists()


def test_mail_logical_id_is_reserved_from_main_vault():
    from mordred_hermes.keyvault._native_key_id import InvalidMainKeyId, validate_main_key_id

    with pytest.raises(InvalidMainKeyId):
        validate_main_key_id("mordred-hermes.mail.credentials.v1")


@pytest.mark.parametrize("platform", ["linux", "darwin", "unsupported"])
def test_missing_native_helper_has_no_portable_fallback(tmp_path, monkeypatch, platform):
    mail = mail_module()
    from mordred_hermes.keyvault import _seckey_helper

    monkeypatch.setattr(mail, "sys", SimpleNamespace(platform=platform))
    monkeypatch.setattr(_seckey_helper, "_helper_ops_or_none", lambda finder: None)
    with pytest.raises(DatabaseRefused):
        mail.mail_backend(home=tmp_path)


@pytest.mark.parametrize("platform,store_name", [("linux", "tpm"), ("darwin", "sekey")])
def test_posix_mail_preserves_logical_tag_and_binds_home_without_fallback(tmp_path, monkeypatch, platform, store_name):
    """Wrong store/tag routing would strand existing macOS mail or mix Linux homes."""
    mail = mail_module()
    from mordred_hermes.keyvault import _seckey_backend, _seckey_helper
    from mordred_hermes.keyvault._seckey_errors import _application_tag
    from tests._keyvault_fakes import FakeBackend

    monkeypatch.setattr(mail, "sys", SimpleNamespace(platform=platform))
    monkeypatch.setattr(_seckey_backend, "sys", SimpleNamespace(platform=platform))
    monkeypatch.delenv("MORDRED_SEKEY_STORE", raising=False)
    monkeypatch.setenv("MORDRED_TPMKEY_STORE", str(tmp_path / "unrelated-ambient"))
    ops = _seckey_helper._HelperSecKeyOps("test-only-helper")
    monkeypatch.setattr(_seckey_helper, "_helper_ops_or_none", lambda finder: ops)
    stores = {}
    seen = []

    def invoke(binary, payload, *, env_override=None):
        assert binary == "test-only-helper"
        seen.append((env_override, payload["tag_hex"]))
        native = stores.setdefault(env_override, FakeBackend())
        selector = payload["tag_hex"]
        if payload["cmd"] == "generate":
            return {"public_key_hex": native.generate_enclave_key(selector).hex()}
        if payload["cmd"] == "public_key":
            return {"public_key_hex": native.get_enclave_public_key(selector).hex()}
        if payload["cmd"] == "ecdh":
            return {"shared_hex": native.enclave_ecdh(selector, bytes.fromhex(payload["peer_pub_hex"])).hex()}
        raise AssertionError("unexpected native operation")

    monkeypatch.setattr(_seckey_helper, "_run_helper", invoke)
    home = tmp_path / "home"
    backend = mail.mail_backend(home=home)
    public = backend.generate_enclave_key(mail.mail_key_id(home), unattended=True)
    # An existing macOS key is found by the exact historical logical application tag.
    sealed = wrap.wrap_dek(b"M" * 32, mail.KEY_ID, backend=backend)
    assert (
        wrap.unwrap_dek(sealed, mail.KEY_ID, backend=mail.mail_backend(home=home), audit_sink=lambda entry: None)
        == b"M" * 32
    )
    other = mail.mail_backend(home=tmp_path / "other")
    assert other.generate_enclave_key(mail.KEY_ID, unattended=True) != public
    with pytest.raises(WrapError):
        wrap.unwrap_dek(sealed, mail.KEY_ID, backend=other, audit_sink=lambda entry: None)
    with pytest.raises(DatabaseRefused):
        backend.get_enclave_public_key("mordred-hermes.telegram.credentials.v1")
    assert {tag for _, tag in seen} == {_application_tag("mordred-hermes.mail.credentials.v1").hex()}
    assert seen[0][0] == (
        f"MORDRED_{store_name.upper()}KEY_STORE" if store_name == "tpm" else "MORDRED_SEKEY_STORE",
        str(home / "mordred/keyvault" / store_name),
    )
    with pytest.raises(DatabaseRefused):
        backend.delete_enclave_key(mail.KEY_ID)
