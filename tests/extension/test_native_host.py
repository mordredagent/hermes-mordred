"""The native host: only the Mordred extension finds the server and gets approval tickets."""

from __future__ import annotations

import io
import json
import stat
from pathlib import Path

import pytest

from mordred_hermes.extension import api as extension_api
from mordred_hermes.extension import native_host

STORE = native_host.STORE_EXTENSION_ID
DEV = "bglmcglbgfdookbdidoopgcpghdclpki"
OTHER = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"


@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    return tmp_path


def test_the_allowed_ids_start_empty_and_only_take_extension_ids(home):
    assert native_host.allowed_extension_ids(home) is None  # not set up: any extension, as before
    assert native_host.allow_extension_ids(home, [STORE, DEV]) == {STORE, DEV}
    assert native_host.allow_extension_ids(home, [STORE]) == {STORE, DEV}  # added, never dropped
    with pytest.raises(ValueError):
        native_host.allow_extension_ids(home, ["not-an-id"])
    assert stat.S_IMODE((home / "mordred" / "extension-ids").stat().st_mode) == 0o600


@pytest.mark.parametrize(
    ("origin", "expected"),
    [
        (f"chrome-extension://{STORE}/", STORE),
        (f"chrome-extension://{STORE}", STORE),
        (f"moz-extension://{STORE}", None),
        ("chrome-extension://short/", None),
        (None, None),
    ],
)
def test_an_origin_names_its_extension(origin, expected):
    assert native_host.extension_id_of(origin) == expected


def test_the_host_answers_only_the_allowed_extension_from_a_verified_browser(home):
    native_host.allow_extension_ids(home, [STORE])
    native_host.ensure_secret(home)
    native_host.write_endpoint(home, "127.0.0.1", 47711)
    discover = {"type": "discover"}
    assert native_host.answer(discover, home=home, extension_id=STORE, parent_ok=True) == {
        "ok": True,
        "url": "ws://127.0.0.1:47711/ext",
    }
    assert native_host.answer(discover, home=home, extension_id=OTHER, parent_ok=True)["error"] == (
        "extension_not_allowed"
    )
    assert native_host.answer(discover, home=home, extension_id=None, parent_ok=True)["ok"] is False
    assert native_host.answer(discover, home=home, extension_id=STORE, parent_ok=False)["error"] == (
        "browser_not_verified"
    )
    attested = native_host.answer({"type": "attest", "code": "ABCDE"}, home=home, extension_id=STORE, parent_ok=True)
    secret = native_host.read_secret(home)
    assert secret is not None
    assert native_host.ticket_valid(secret, STORE, "ABCDE", attested["ticket"])
    assert not native_host.ticket_valid(secret, STORE, "ABCDF", attested["ticket"])  # another code
    assert not native_host.ticket_valid(secret, OTHER, "ABCDE", attested["ticket"])  # another extension
    bad = native_host.answer({"type": "attest", "code": ""}, home=home, extension_id=STORE, parent_ok=True)
    assert bad["error"] == "invalid_request"


def test_messages_use_the_browsers_length_prefixed_frames():
    stream = io.BytesIO()
    native_host._write_message(stream, {"type": "discover"})
    stream.seek(0)
    assert native_host._read_message(stream) == {"type": "discover"}
    assert native_host._read_message(stream) is None  # the browser closed the pipe
    huge = io.BytesIO((10**7).to_bytes(4, "little") + b"{}")
    with pytest.raises(ValueError):
        native_host._read_message(huge)


def test_install_registers_with_each_installed_browser(home, tmp_path):
    support = tmp_path / "support"
    (support / "BraveSoftware" / "Brave-Browser").mkdir(parents=True)
    launcher = tmp_path / "hermes-mordred"
    native_host.allow_extension_ids(home, [STORE, DEV])
    written = native_host.install(home, launcher, support=support)
    assert written == [support / "BraveSoftware/Brave-Browser/NativeMessagingHosts/com.mordred.hermes.json"]
    data = json.loads(written[0].read_text())
    assert data["name"] == "com.mordred.hermes" and data["type"] == "stdio"
    assert data["allowed_origins"] == [f"chrome-extension://{DEV}/", f"chrome-extension://{STORE}/"]
    script = Path(data["path"])
    assert script.read_text() == (
        f'#!/bin/sh\nHERMES_HOME="{home}"\nexport HERMES_HOME\nexec "{launcher}" extension native-host "$@"\n'
    )
    assert script.stat().st_mode & 0o111
    assert native_host.read_secret(home) is not None
    assert not (support / "Google").exists()  # no Chrome here: nothing written for it


def test_install_without_ids_accepts_the_store_extension(home, tmp_path):
    native_host.install(home, tmp_path / "hermes-mordred", support=tmp_path / "none")
    assert native_host.allowed_extension_ids(home) == {STORE}


def test_the_server_accepts_only_the_named_extensions_once_they_are_set(home):
    assert extension_api._is_extension_origin(f"chrome-extension://{OTHER}")  # not set up: any extension
    native_host.allow_extension_ids(home, [STORE])
    assert extension_api._is_extension_origin(f"chrome-extension://{STORE}")
    assert not extension_api._is_extension_origin(f"chrome-extension://{OTHER}")
    assert not extension_api._is_extension_origin(f"moz-extension://{STORE}")


def test_a_new_browser_needs_the_hosts_ticket_once_the_host_is_installed(home):
    origin = f"chrome-extension://{STORE}"
    assert extension_api._enrollment_attested(origin, "ABCDE", None)  # no host: as before
    native_host.ensure_secret(home)
    secret = native_host.read_secret(home)
    assert secret is not None
    assert not extension_api._enrollment_attested(origin, "ABCDE", None)
    assert not extension_api._enrollment_attested(origin, "ABCDE", "forged")
    good = native_host.ticket(secret, STORE, "ABCDE")
    assert extension_api._enrollment_attested(origin, "ABCDE", good)
    assert not extension_api._enrollment_attested(f"chrome-extension://{OTHER}", "ABCDE", good)
