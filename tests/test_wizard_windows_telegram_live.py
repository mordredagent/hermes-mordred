"""Explicit real-CNG wizard Telegram ceremony on a fresh UUID profile (C6-telegram live recipe).

Gated: Windows, an ordinary token, ``MORDRED_TEST_WINDOWS_TELEGRAM_WIZARD_LIVE=1``,
an existing retained ``MORDRED_WINDOWS_CUSTODY_TEST_ROOT`` and an owned helper
in ``MORDRED_WINKEY_HELPER``. Through the real CLI and wizard functions it runs
``keyvault native init --role telegram`` (a fresh CNG telegram key), the
machine-bound login with SYNTHETIC credentials and a synthetic Telegram client
(no account, phone number, network or model), a fresh-process reload of the
sealed credentials, a synthetic archive, ``telegram doctor --json``
(load-only), ``telegram logout`` (archive, credentials and role kept) and
``telegram logout --forget`` (typed confirmation; credentials, archive and the
telegram role deleted). Only
the new profile and its own key are created. A failure preserves the profile
and its journals (no recursive removal); only paths and shapes are printed.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import uuid
from pathlib import Path

import pytest

pytestmark = pytest.mark.integration

SESSION = "SYNTHETIC-SESSION-NOT-A-REAL-ACCOUNT"
_RELOAD = """
import sys
from pathlib import Path
from mordred_hermes.extension.telegram.windows_secrets import WindowsCustodySecretStore
value = WindowsCustodySecretStore(Path(sys.argv[1]), audit_sink=lambda entry: None).load()
assert value is not None and value.session == "SYNTHETIC-SESSION-NOT-A-REAL-ACCOUNT"
print("reloaded", flush=True)
"""


class _SyntheticClient:
    def __init__(self):
        self.session = SESSION

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
        return None


def _answers(mapping):
    def answer(prompt):
        for key, value in mapping.items():
            if key in prompt:
                return value
        raise AssertionError(f"unexpected prompt: {prompt!r}")

    return answer


@pytest.mark.skipif(
    os.name != "nt" or os.environ.get("MORDRED_TEST_WINDOWS_TELEGRAM_WIZARD_LIVE") != "1",
    reason="explicit ordinary-user Windows CNG wizard Telegram acceptance",
)
def test_wizard_telegram_ceremony_login_logout_forget_real_cng(monkeypatch, capsys):
    import ctypes

    from mordred_hermes._private_fs import open_confidential_directory
    from mordred_hermes.extension.telegram import store
    from mordred_hermes.extension.telegram.windows_secrets import WindowsCustodySecretStore
    from mordred_hermes.keyvault._windows_custody import windows_custody_session
    from mordred_hermes.wizard import cli, telegram_cli

    assert not ctypes.windll.shell32.IsUserAnAdmin(), "ordinary-user acceptance required"
    assert os.environ.get("MORDRED_WINKEY_HELPER"), "explicit owned helper required"
    root_value = os.environ.get("MORDRED_WINDOWS_CUSTODY_TEST_ROOT")
    assert root_value, "explicit retained isolated root required"
    root = Path(root_value)
    with open_confidential_directory(root):
        pass
    home = root / ("wizard-telegram-" + uuid.uuid4().hex)
    monkeypatch.setenv("HERMES_HOME", str(home))
    monkeypatch.delenv(telegram_cli.API_ID_ENV, raising=False)
    monkeypatch.delenv(telegram_cli.API_HASH_ENV, raising=False)
    monkeypatch.setattr("mordred_hermes.extension.telegram.client.save_session", lambda client: client.session)
    client = _SyntheticClient()
    try:
        with open_confidential_directory(home, create=True):
            pass
        assert cli.main(["keyvault", "native", "init", "--role", "telegram"]) == 0
        with windows_custody_session(home) as owner:
            assert owner.role_status("telegram").current is not None
            assert owner.memory_state().lease is None, "the telegram ceremony enrolls nothing else"

        rc = telegram_cli.telegram_login(
            input_fn=_answers({"api_id": "1", "Phone number": "+10", "Login code": "1"}),
            secret_fn=_answers({"api_hash": "0" * 32}),
            client_factory=lambda *args, **kwargs: client,
            acknowledge_machine_bound=True,
        )
        assert rc == 0
        reloaded = subprocess.run(
            [sys.executable, "-c", _RELOAD, str(home)], capture_output=True, text=True, timeout=120, check=False
        )
        assert reloaded.returncode == 0 and reloaded.stdout.strip() == "reloaded", "fresh-process reload failed"
        sealed = WindowsCustodySecretStore(home, audit_sink=lambda entry: None).load()
        archive_root = home / "mordred" / "telegram"
        archive = store.ArchiveStore(sealed.store_key, archive_root)
        archive.save_index(store.ArchiveIndex(account_label="synthetic"))
        archive.append_messages(1, [store.StoredMessage(id=1, date=1, sender="synthetic", text="synthetic")])

        capsys.readouterr()
        cli.main(["telegram", "doctor", "--json"])
        report = {row["name"]: row["ok"] for row in json.loads(capsys.readouterr().out)}
        print(json.dumps({"telegram_custody": report["telegram_custody"], "login": report["login"]}))
        assert report["telegram_custody"] is True and report["login"] is True

        assert telegram_cli.telegram_logout(client_factory=lambda *a, **k: client, input_fn=_answers({})) == 0
        assert (archive_root / "credentials.sealed").exists() and (archive_root / "index.enc").exists()
        confirm = _answers({"Type 'forget telegram'": "forget telegram"})
        rc = telegram_cli.telegram_logout(forget=True, client_factory=lambda *a, **k: client, input_fn=confirm)
        assert rc == 0
        assert not (archive_root / "credentials.sealed").exists() and not (archive_root / "index.enc").exists()
        with windows_custody_session(home) as owner:
            status = owner.role_status("telegram")
            assert status.current is None and not status.retained and not status.pending
    except BaseException as exc:
        exc.add_note(f"retained isolated wizard Telegram profile and journals: {home}")
        raise
