"""Explicit real-CNG Desktop API flow on a fresh UUID profile (C11 live recipe).

Gated: Windows, an ordinary token, ``MORDRED_TEST_WINDOWS_DESKTOP_LIVE=1``, an
existing retained ``MORDRED_WINDOWS_CUSTODY_TEST_ROOT`` and an owned helper in
``MORDRED_WINKEY_HELPER``. Run it with the interpreter of the packaged Hermes
Desktop runtime (or the installed Hermes venv): with ``MORDRED_HERMES_PYTHON``
unset, the Desktop routing proves the interpreter serving the API
(``sys.executable``), exactly as inside Hermes Desktop. Every gateway must be
stopped. Through the real Desktop router it reads ``/status?client_version=3``
and ``/hardware/build`` (helper state, never a build), enables memory with both
acknowledgements (capabilities -> gate -> ceremony -> proof -> lifecycle),
reads ``/memory/status`` and disables memory again. The profile keeps its own
fresh CNG key (purge stays a CLI ceremony); failures preserve the profile and
journals and only its path is printed. The packaged Desktop UI steps (launch,
page render, restart) are the manual part of the recipe in ``docs/dev/CI.md``.
"""

from __future__ import annotations

import os
import sys
import uuid
from pathlib import Path

import pytest

pytestmark = pytest.mark.integration

ACKS = {"acknowledge_cng_no_recovery": True, "acknowledge_no_presence": True}
CONTENT = b"synthetic desktop smoke\n\xc2\xa7\nsecond entry"


@pytest.mark.skipif(
    os.name != "nt" or os.environ.get("MORDRED_TEST_WINDOWS_DESKTOP_LIVE") != "1",
    reason="explicit ordinary-user Windows CNG Desktop acceptance",
)
def test_desktop_status_helper_memory_enable_and_disable_real_cng(monkeypatch):
    import ctypes

    pytest.importorskip("fastapi")
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from mordred_hermes._private_fs import open_confidential_directory, open_private_directory
    from mordred_hermes.desktop import api
    from mordred_hermes.keyvault.memory_crypto import is_sealed

    assert not ctypes.windll.shell32.IsUserAnAdmin(), "ordinary-user acceptance required"
    assert os.environ.get("MORDRED_WINKEY_HELPER"), "explicit owned helper required"
    root_value = os.environ.get("MORDRED_WINDOWS_CUSTODY_TEST_ROOT")
    assert root_value, "explicit retained isolated root required"
    root = Path(root_value)
    with open_confidential_directory(root):
        pass
    home = root / ("desktop-memory-" + uuid.uuid4().hex)
    monkeypatch.setenv("HERMES_HOME", str(home))
    monkeypatch.setattr(api, "_home", lambda: home)
    app = FastAPI()
    app.include_router(api.router, prefix="/api/plugins/mordred")
    http = TestClient(app)
    base = "/api/plugins/mordred"
    try:
        with open_confidential_directory(home, create=True):
            pass
        with open_private_directory(home / "memories", create=True) as directory, directory.transaction() as tx:
            tx.create_bytes("MEMORY.md", CONTENT)

        status = http.get(f"{base}/status?client_version=3").json()
        assert status["hardware_kind"] == "cng" and status["user_presence_supported"] is False
        assert [row["name"] for row in status["capabilities"]][:3] == [
            "memory_custody",
            "native_audit",
            "telegram_hardware",
        ]
        helper = http.post(f"{base}/hardware/build", json={}).json()
        assert helper["built"] is False and helper["helper"]["state"] in ("validated", "installed")

        enabled = http.post(f"{base}/memory/enable", json=ACKS).json()
        assert enabled["ok"] is True, enabled
        expected = None if os.environ.get("MORDRED_HERMES_PYTHON") else sys.executable
        if expected is not None:
            assert os.path.normcase(enabled["runtime"]["python"]) == os.path.normcase(expected)
        assert is_sealed((home / "memories" / "MEMORY.md").read_bytes())
        memory = http.get(f"{base}/memory/status").json()
        assert memory["memory"]["state"] == "on" and memory["gateways"]["state"] == "known"

        disabled = http.post(f"{base}/memory/disable", json={}).json()
        assert disabled["ok"] is True and disabled["key_kept"] is True, disabled
        assert (home / "memories" / "MEMORY.md").read_bytes().replace(b"\r\n", b"\n") == CONTENT
    except BaseException:
        print(f"preserved Desktop live profile: {home}")
        raise
    print(f"Desktop live profile (keeps its CNG memory key until `encryption purge memory --yes`): {home}")
