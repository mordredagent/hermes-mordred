"""Native NTFS wizard Telegram ceremony on Windows (C6-telegram).

Real confidential/private admission, binary SID, physical home identity and
the real ``win32`` platform decisions (nothing patches ``_platform`` or
``host_platform``). Injected seams: the CNG backend, C4 helper presence, C4
structural runtime admission, the Windows memory predicate and a synthetic
Telegram client (no network, no account). Host-skipped off Windows; selected
by the scoped Windows CI job. The real CNG flow is the gated live recipe
(``tests/test_wizard_windows_telegram_live.py``).
"""

from __future__ import annotations

import json
import os

import pytest

from mordred_hermes._private_fs import open_private_directory
from mordred_hermes.extension.telegram import hardening
from mordred_hermes.keyvault import _memory_storage as storage
from mordred_hermes.keyvault import _seckey_helper, wrap
from mordred_hermes.keyvault import _windows_custody as custody
from mordred_hermes.wizard import _windows_telegram, keyvault_windows_cli, telegram_cli, telegram_setup_cli
from tests._keyvault_fakes import FakeBackend
from tests.test_private_fs_confidential_windows import descriptor
from tests.test_private_fs_confidential_windows import shared_home as shared_home

pytestmark = pytest.mark.skipif(os.name != "nt", reason="actual NTFS wizard Telegram custody routing")

SESSION = "SYNTHETIC-SESSION-NOT-A-REAL-ACCOUNT"


class _Client:
    def __init__(self):
        self.session = SESSION
        self.logged_out = False

    async def connect(self):
        return None

    async def disconnect(self):
        return None

    async def send_code_request(self, phone):
        return None

    async def sign_in(self, **kwargs):
        return object()

    async def is_user_authorized(self):
        return True

    async def log_out(self):
        self.logged_out = True


@pytest.fixture
def native(shared_home, monkeypatch):
    home = shared_home
    backend = FakeBackend()
    helper = str(home.parent / "bin" / "mordred-hermes-winkey.exe")
    monkeypatch.setattr(_seckey_helper, "find_winkey_helper", lambda: helper)
    monkeypatch.setattr(storage, "windows_memory_runtime_admitted", lambda executable=None: True)
    monkeypatch.setattr(custody, "windows_backend", lambda: backend)
    monkeypatch.setattr(_windows_telegram, "memory_active", lambda home=None: True)
    monkeypatch.setattr(hardening, "harden_process", lambda: None)
    monkeypatch.setattr("mordred_hermes.extension.telegram.client.save_session", lambda client: client.session)
    monkeypatch.setenv("HERMES_HOME", str(home))
    monkeypatch.delenv(telegram_cli.API_ID_ENV, raising=False)
    monkeypatch.delenv(telegram_cli.API_HASH_ENV, raising=False)
    return home, backend


def _answers(mapping):
    def answer(prompt):
        for key, value in mapping.items():
            if key in prompt:
                return value
        raise AssertionError(f"unexpected prompt: {prompt!r}")

    return answer


def generated(backend) -> int:
    return sum(1 for call in backend.calls if call[0] == "generate")


def test_native_telegram_ceremony_through_a_case_alias_enrolls_once(native, capsys):
    home, backend = native
    parent = descriptor(home)
    alias = home.with_name(home.name.upper())
    assert keyvault_windows_cli.native_init(home=alias, roles=["telegram"]) == 0
    assert keyvault_windows_cli.native_init(home=home, roles=["telegram"]) == 0
    out = capsys.readouterr().out
    assert out.count("enrolled now") == 1 and out.count("already enrolled (unchanged)") == 1
    assert generated(backend) == 1
    assert not (home / "mordred" / "telegram").exists()
    assert descriptor(home) == parent, "no ACL repair on the inherited home"


def test_native_login_logout_and_forget_keep_memory_and_audit(native, capsys):
    home, backend = native
    assert keyvault_windows_cli.native_init(home=home, roles=["memory", "audit", "telegram"]) == 0
    client = _Client()
    rc = telegram_cli.telegram_login(
        input_fn=_answers({"api_id": "1", "Phone number": "+10", "Login code": "1"}),
        secret_fn=_answers({"api_hash": "0" * 32}),
        client_factory=lambda *args, **kwargs: client,
        acknowledge_machine_bound=True,
    )
    assert rc == 0
    sealed = home / "mordred" / "telegram" / "credentials.sealed"
    assert sealed.exists()
    assert telegram_cli.telegram_logout(client_factory=lambda *a, **k: client, input_fn=_answers({})) == 0
    assert sealed.exists() and client.logged_out
    confirm = _answers({"Type 'forget telegram'": "forget telegram"})
    assert telegram_cli.telegram_logout(forget=True, client_factory=lambda *a, **k: client, input_fn=confirm) == 0
    assert not sealed.exists()
    with custody.windows_custody_session(home, backend=backend) as session:
        assert session.role_status("telegram").current is None
        assert session.memory_state().lease is not None
        assert session.role_status("audit").current is not None
    assert generated(backend) == 3


def test_native_doctor_is_load_only(native, monkeypatch, capsys):
    home, backend = native
    assert keyvault_windows_cli.native_init(home=home, roles=["telegram"]) == 0
    calls = list(backend.calls)

    def forbidden(*args, **kwargs):
        raise AssertionError("doctor constructed a native backend or unwrapped")

    monkeypatch.setattr(custody, "windows_backend", forbidden)
    monkeypatch.setattr(wrap, "unwrap_dek", forbidden)
    capsys.readouterr()
    telegram_setup_cli.telegram_doctor(as_json=True)
    report = {row["name"]: row for row in json.loads(capsys.readouterr().out)}
    assert report["telegram_custody"]["ok"] is True
    assert report["capability.presence"]["ok"] is False
    assert backend.calls == calls


def test_native_copied_home_refuses_setup(native, monkeypatch, capsys):
    home, backend = native
    assert keyvault_windows_cli.native_init(home=home, roles=["telegram"]) == 0
    copied = home.parent / "copied telegram home"
    with open_private_directory(copied, create=True):
        pass
    with open_private_directory(copied / "mordred", create=True) as directory, directory.transaction() as tx:
        tx.create_bytes("windows-custody.json", (home / "mordred" / "windows-custody.json").read_bytes())
    monkeypatch.setenv("HERMES_HOME", str(copied))
    calls = list(backend.calls)
    assert telegram_setup_cli.telegram_setup(input_fn=_answers({}), secret_fn=_answers({})) == 1
    assert "(custody-broken)" in capsys.readouterr().err
    assert backend.calls == calls
