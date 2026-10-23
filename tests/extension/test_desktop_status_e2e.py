"""The REAL Desktop status chain: ``/status?client_version=4`` and ``/imports/status`` end to end.

Nothing on the status path is replaced (``_seams.open_store_readonly``, the
Telegram store, ``run_checks``, the mail flags, ``imap_status``): only native
boundaries are (the Secure Enclave helper). A real SQLCipher ``mordred.db``
is written with the key derived from ``HERMES_MEMORY_KEY``; the process
``sqlite3`` is a real shim whose key provider, like ``dbcrypt._PROVIDER``, the
shared protection gate and the vault injector, fails the test if called.
"""

from __future__ import annotations

import sqlite3
import sys
from pathlib import Path

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("sqlcipher3")

from fastapi import FastAPI
from fastapi.testclient import TestClient

from mordred_hermes import dbcrypt
from mordred_hermes._private_fs import open_private_directory
from mordred_hermes.activity._paths import store_path
from mordred_hermes.dbcrypt import _key, _shim
from mordred_hermes.desktop import api
from mordred_hermes.imports.store import ImportStore
from mordred_hermes.keyvault.memory_crypto import decode_key
from tests.imports._factories import authored, tg_conv

MEMORY_KEY = "hex:" + "3c" * 32
PREFIX = "/api/plugins/mordred"


def _tree(path: Path) -> list[str]:
    return sorted(str(p.relative_to(path)) for p in path.rglob("*"))


def _forbidden(*_args: object, **_kwargs: object) -> object:
    raise AssertionError("the status path called something that can unlock the vault or prompt")


def _no_helper(*_args: object, **_kwargs: object) -> object:
    from mordred_hermes.extension.telegram.secrets import TelegramSecretsError

    raise TelegramSecretsError("tee_unavailable")  # the native SE boundary: no helper on this host


@pytest.fixture
def cold_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    home = tmp_path / "home"
    with open_private_directory(home, create=True):
        pass
    monkeypatch.setenv("HERMES_HOME", str(home))
    monkeypatch.setattr(sys, "platform", "darwin")
    monkeypatch.setattr("mordred_hermes.extension.telegram.tee.hardware_backend", _no_helper)
    monkeypatch.setattr(dbcrypt, "_PROVIDER", _forbidden)
    monkeypatch.setattr("mordred_hermes.dbcrypt._key.KeyProvider", _forbidden)
    monkeypatch.setattr("mordred_hermes.dbcrypt._key._inject_vault_env", _forbidden)
    monkeypatch.setattr("mordred_hermes.activity._gate.check_protection", _forbidden)
    monkeypatch.setattr("mordred_hermes.imports.store.check_protection", _forbidden)
    monkeypatch.setattr("mordred_hermes.keyvault._anchor_keychain.default_anchor_store", _forbidden)
    return home


def _client() -> TestClient:
    app = FastAPI()
    app.include_router(api.router, prefix=PREFIX)
    return TestClient(app)


def _protected_store(home: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """An armed home, a real SQLCipher store with one Telegram conversation, and a shim that may not unlock."""
    key = _key.derive(decode_key(MEMORY_KEY))
    writer = _shim.build_module(key=lambda: key, home=lambda: home, has_key=lambda: True)
    store = ImportStore(store_path(home), writer.connect)
    store.initialize(home)
    run = store.run_begin("telegram")
    written = store.write_thread(
        run, [authored(1, text="SECRET one"), authored(2, text="SECRET two")], conversation=tg_conv()
    )
    store.run_commit(run, {"inserted": written.inserted})
    dbcrypt.arm(home)
    process = _shim.build_module(key=_forbidden, home=lambda: home, has_key=lambda: True)  # type: ignore[arg-type]
    monkeypatch.setitem(sys.modules, "sqlite3", process)
    monkeypatch.setitem(sys.modules, "sqlite3.dbapi2", process)
    monkeypatch.setenv("HERMES_MEMORY_KEY", MEMORY_KEY)
    assert _shim.is_installed()
    with pytest.raises(sqlite3.DatabaseError):  # the file really is ciphertext to plain SQLite
        plain = _shim.stdlib_sqlite3().connect(f"file:{store_path(home)}?mode=ro", uri=True)
        try:
            plain.execute("SELECT count(*) FROM sqlite_master").fetchone()
        finally:
            plain.close()


def test_the_real_status_chain_reads_counts_through_sqlcipher_without_unlocking(
    cold_home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _protected_store(cold_home, monkeypatch)
    before = _tree(cold_home)
    with _client() as http:
        status = http.get(f"{PREFIX}/status?client_version=4").json()
        light = http.get(f"{PREFIX}/imports/status").json()
    assert status["imports"] == {
        "available": True,
        "code": None,
        "sources": {
            "telegram": {"conversations": 1, "messages": 2, "parts": 2},
            "mail": {"conversations": 0, "messages": 0, "parts": 0},
        },
    }
    assert light["imports"] == status["imports"] and light["mail"] == {"configured": False}
    assert status["databases"]["armed"] is True and status["databases"]["runtime_protected"] is True
    assert status["telegram_archive"] == {"legacy": None} and status["telegram_api"] is False
    assert "SECRET" not in str(status) + str(light)
    assert _tree(cold_home) == before  # read-only: no sidecar, no directory, no lock appeared


@pytest.mark.parametrize("value", [None, "", "not-a-key", "hex:" + "3c" * 16])
def test_without_valid_key_material_the_real_chain_answers_no_key(
    cold_home: Path, monkeypatch: pytest.MonkeyPatch, value: str | None
) -> None:
    _protected_store(cold_home, monkeypatch)
    if value is None:
        monkeypatch.delenv("HERMES_MEMORY_KEY")
    else:
        monkeypatch.setenv("HERMES_MEMORY_KEY", value)
    with _client() as http:
        status = http.get(f"{PREFIX}/status?client_version=4").json()
    assert status["imports"] == {"available": False, "code": "no_key", "sources": {}}
    assert status["databases"]["runtime_protected"] is False


def test_a_cold_status_creates_nothing_in_a_fresh_home(cold_home: Path) -> None:
    """Finding 3: not even <home>/mordred/telegram (the Telegram flags read used to create it)."""
    with _client() as http:
        status = http.get(f"{PREFIX}/status?client_version=4").json()
        old = http.get(f"{PREFIX}/status").json()
    assert status["ok"] is True and old["ok"] is True
    assert status["imports"]["code"] == "not_armed" and status["mail"] == {"configured": False}
    assert _tree(cold_home) == []
