"""Desktop storage observation never obtains native or SQL authority."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("fastapi")

from mordred_hermes import dbcrypt
from mordred_hermes.desktop import _seams
from tests._activity_protection import native_root as native_root
from tests._activity_protection import protected_runtime as protected_runtime


def _snapshot(home: Path) -> list[tuple[str, int, bytes | None]]:
    return sorted(
        (str(path.relative_to(home)), path.stat().st_mode, path.read_bytes() if path.is_file() else None)
        for path in home.rglob("*")
    )


def test_desktop_poll_does_not_prompt_or_enroll(desktop: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    """Opening SQL for counts or calling provider/custody during any repeated poll is a regression."""
    from mordred_hermes.dbcrypt import _migrate

    calls: list[str] = []

    def forbidden(*args: Any, **kwargs: Any) -> Any:
        calls.append("authority or SQL")
        raise AssertionError("passive status may not obtain authority, open SQL or enroll")

    monkeypatch.setattr("mordred_hermes.dbcrypt._key.KeyProvider", forbidden)
    monkeypatch.setattr(_seams, "open_store_readonly", forbidden)
    monkeypatch.setattr(_seams, "imap_status", forbidden)
    monkeypatch.setattr(_migrate, "discover", forbidden)
    monkeypatch.setattr(_migrate, "schedule", forbidden)
    monkeypatch.setattr(dbcrypt, "arm", forbidden)
    before = _snapshot(desktop.home)
    for _ in range(3):
        status = desktop.get("/status?client_version=4")
        imports = desktop.get("/imports/status")
        desktop.get("/databases/status")
        assert status["imports"]["sources"] == {}
        assert imports["imports"]["available"] is False
    assert calls == []
    assert _snapshot(desktop.home) == before


@pytest.mark.parametrize(
    ("configured", "capability", "authenticated", "expected"),
    [
        (False, "unknown", False, {"supported": True, "armed": False, "runtime_protected": False}),
        (True, "unknown", True, {"supported": True, "armed": True, "runtime_protected": False}),
        (True, "available", True, {"supported": True, "armed": True, "runtime_protected": True}),
        (True, "available", False, {"supported": True, "armed": True, "runtime_protected": False}),
        (True, "unavailable", True, {"supported": False}),
    ],
)
def test_database_status_projection_preserves_exact_v4_schema(
    configured: bool, capability: Any, authenticated: bool, expected: dict[str, object]
) -> None:
    from mordred_hermes.desktop import _databases

    status = dbcrypt.DatabaseStatus(configured, None, capability, authenticated, "private arbitrary reason")
    projected = _databases.database_status_projection(status)
    if capability != "unavailable":
        expected = {
            **expected,
            "encrypt_pending": None,
            "decrypt_pending": None,
            "journal": None,
            "databases": [],
            "plaintext_backups": None,
        }
    assert projected == expected
    assert "private arbitrary reason" not in repr(projected)


def test_server_acceptance_does_not_claim_windows11_support(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A server evidence artifact does not admit workstation editions such as Windows 11."""
    from types import SimpleNamespace

    from mordred_hermes.dbcrypt import _capability, _windows_vfs
    from mordred_hermes.desktop import _databases

    (tmp_path / "server-storage-acceptance.json").write_text('{"accepted": true}', encoding="utf-8")
    monkeypatch.setattr(_capability, "sys", SimpleNamespace(platform="win32"))
    monkeypatch.setattr(_windows_vfs, "windows_edition_admitted", lambda: False)
    status = dbcrypt.database_status(tmp_path)
    assert status.capability == "unavailable"
    assert status.reason == "Windows workstation editions are not qualified"
    assert _databases.database_status_projection(status) == {"supported": False}


def test_server_edition_proceeds_past_admission(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from types import SimpleNamespace

    from mordred_hermes.dbcrypt import _capability, _windows_vfs

    monkeypatch.setattr(_capability, "sys", SimpleNamespace(platform="win32"))
    monkeypatch.setattr(_windows_vfs, "windows_edition_admitted", lambda: True)
    monkeypatch.setattr(_windows_vfs, "driver_distribution_qualified", lambda: True)
    monkeypatch.setattr(_windows_vfs, "packaged_library_path", lambda: tmp_path / "owned.dll")
    monkeypatch.setattr(_capability, "_driver_present", lambda: True)
    assert dbcrypt.database_status(tmp_path).capability == "unknown"


def test_unknown_database_status_never_schedules(desktop: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    from mordred_hermes.desktop import _databases

    facts = _databases.database_status_projection(dbcrypt.DatabaseStatus(False, 0, "unknown", False, None))
    assert _databases.encrypt_answer(desktop.home, facts) == {
        "ok": True,
        "action": "attention",
        "code": "databases_failed",
    }
    assert not (desktop.home / "mordred" / "db-encryption.pending").exists()


def test_unknown_database_status_is_not_ready_or_empty_on_page() -> None:
    from tests._desktop_page import render_page

    result = render_page("""
const db = {supported: true, armed: true, runtime_protected: false,
  encrypt_pending: null, decrypt_pending: null, journal: null, databases: [], plaintext_backups: null}
const text = node => typeof node === 'string' || typeof node === 'number' ? String(node)
  : !node || typeof node !== 'object' ? '' : Array.isArray(node) ? node.map(text).join('')
  : text(node.props && node.props.children)
console.log(JSON.stringify({state: databaseState(db), table: text(DatabaseTable({rows: [], unknown: true})),
  fact: databasesFact(db, databaseState(db)),
  step: text(DatabasesStep({id:'databases', n:'1.3', state:'attention', status:{databases:db}, refresh:()=>{}}))}))
""")
    assert result["state"] == {"code": "databases_failed"}
    assert "not checked" in result["table"].lower()
    assert "not checked" in result["fact"].lower()
    assert "unknown" in result["step"].lower()
    assert "No Hermes database files" not in result["step"]
    assert "Database encryption: on" not in result["step"]


def test_passive_unknown_does_not_block_foreground_or_claim_zero_mail() -> None:
    from tests._desktop_page import render_page

    result = render_page("""
const status = {platform:'darwin', hardware_kind:'secure_enclave', telegram_supported:true,
  databases:{supported:true, armed:true, runtime_protected:false,
    encrypt_pending:null, decrypt_pending:null, journal:null, databases:[], plaintext_backups:null},
  imports:{available:false, code:'store_unavailable', sources:{}},
  mail:{configured:true, account:'work', gmail:true, scope:['all'], touch_id:true}}
console.log(JSON.stringify({blocker:storeBlocker(status),
  row:mailRow(status,'macos',Date.now()), history:mailHistory(status.mail)}))
""")
    assert result["blocker"] is None  # explicit operation must let the real gate decide
    assert "0 messages" not in result["row"]["detail"]
    assert "not checked" in result["row"]["detail"]
    assert "never fetched" not in result["row"]["detail"]
    assert result["history"] == ["Fetch history: not checked by passive status."]


def test_activity_mail_tools_refuse_lost_authority(
    protected_runtime: Any, desktop: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Real Authority/SQLCipher plus synthetic custody: terminal loss returns no records or new rows."""
    import asyncio
    import json
    from types import SimpleNamespace

    from mordred_hermes._database_contracts import DatabaseRefused
    from mordred_hermes.activity import _history_access, tools
    from mordred_hermes.activity._gate import open_store
    from mordred_hermes.desktop import api
    from mordred_hermes.extension.telegram import mail_tool
    from mordred_hermes.imports.mail import imap_sync
    from mordred_hermes.imports.store import ImportRefused, open_import_store
    from tests._activity_history_helpers import ENABLED, Seq, seed_episode, write_config
    from tests._mail_sync_helpers import FakeSecrets, gmail_creds, gmail_server, make_env

    home, provider, backend = protected_runtime
    monkeypatch.setenv("HERMES_HOME", str(home))
    monkeypatch.setattr(api, "_home", lambda: home)
    marker = "TASK14PRIVATERECORD"
    write_config(home, ENABLED)
    monkeypatch.setattr(_history_access, "audit_history_unavailable", lambda *a, **kw: None)
    credentials = FakeSecrets(gmail_creds())
    env = make_env(home, None, gmail_server(), credentials, open_store=open_import_store)
    monkeypatch.setattr(imap_sync, "default_env", lambda *args: env)
    local = SimpleNamespace(model="m", base_url="http://127.0.0.1:11434/v1")
    assert provider.current_authority is None
    synced = json.loads(asyncio.run(mail_tool.mordred_mail_sync({}, parent_agent=local)))
    assert synced["error"] is None and synced["inserted"] > 0
    assert credentials.loads == 1
    authority = provider.current_authority
    assert authority is not None
    assert sum(op == "ecdh" for op, _ in backend.calls) == 1
    activity_store = open_store(home)
    seed_episode(activity_store, Seq(), episode="task14-episode", task=marker)
    assert marker in tools.browser_history({"query": marker}, session_id="task14-before")
    store = open_import_store(home)
    before_calls = list(backend.calls)
    binding = home / "mordred/db-key-source.json"
    original = binding.read_bytes()
    changed = json.loads(original)
    changed["generation"] = "f" * 32
    binding.write_text(json.dumps(changed), encoding="utf-8")
    path = home / "plugin-data/mordred/mordred.db"
    database_before = path.read_bytes()

    activity_result = json.loads(tools.browser_history({"query": marker}, session_id="task14-after"))
    assert activity_result["status"] == "unavailable"
    assert marker not in repr(activity_result)
    assert authority.terminal
    # Restoring metadata cannot revive a terminal capability, even on a new explicit call.
    binding.write_bytes(original)
    for _ in range(2):
        result = json.loads(asyncio.run(mail_tool.mordred_mail_sync({}, parent_agent=local)))
        assert result["error"] == "no_key"
        assert result["inserted"] == 0
        assert "restart Hermes" in result["note"]
        assert marker not in repr(result)
    with pytest.raises(DatabaseRefused):
        authority.check()
    monkeypatch.setattr(_seams, "run_fetch", imap_sync.run_fetch)
    monkeypatch.setattr(_seams, "fetch_env", lambda home: env)
    started = desktop.post("/mail/fetch", {})
    job = desktop.wait_job(started["job_id"])
    assert job["state"] == "failed" and job["error"] == "no_key"
    assert job["progress"]["result"]["inserted"] == 0
    assert marker not in repr(job)
    assert credentials.loads == 1
    assert provider.current_authority is authority
    assert backend.calls == before_calls
    assert path.read_bytes() == database_before
    with pytest.raises(ImportRefused) as caught:
        store.status()
    assert getattr(caught.value, "code", None) == "store_unavailable"


@pytest.mark.parametrize("platform", ["linux", "win32"])
def test_native_platform_status_consumes_shared_projection_without_authentication(
    desktop: Any, monkeypatch: pytest.MonkeyPatch, platform: str
) -> None:
    import asyncio

    from mordred_hermes.desktop import _status_v4

    # An adapter contract test, not native eligibility or platform acceptance.
    monkeypatch.setattr(
        dbcrypt, "database_status", lambda home: dbcrypt.DatabaseStatus(True, None, "available", False, None)
    )
    result = asyncio.run(_status_v4.sections(platform, desktop.home))
    assert result["databases"] == {
        "supported": True,
        "armed": True,
        "encrypt_pending": None,
        "decrypt_pending": None,
        "journal": None,
        "runtime_protected": False,
        "databases": [],
        "plaintext_backups": None,
    }
    assert result["imports"] == {"available": False, "code": "store_unavailable", "sources": {}}


def test_database_operation_uses_shared_unavailability_and_never_schedules_unknown(
    desktop: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    from types import SimpleNamespace

    from mordred_hermes.desktop import api

    monkeypatch.setattr(api, "sys", SimpleNamespace(platform="linux"))
    monkeypatch.setattr(
        dbcrypt, "database_status", lambda home: dbcrypt.DatabaseStatus(True, 1, "available", False, None)
    )
    assert desktop.post("/databases/encrypt") == {"ok": True, "action": "attention", "code": "databases_failed"}
    monkeypatch.setattr(
        dbcrypt, "database_status", lambda home: dbcrypt.DatabaseStatus(True, 1, "unavailable", False, None)
    )
    assert desktop.post("/databases/encrypt") == {"ok": False, "error": "databases_unsupported"}
    assert not (desktop.home / "mordred/db-encryption.pending").exists()


def test_mail_tool_visibility_never_authenticates_or_opens_sql(
    protected_runtime: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Synthetic custody plus real passive flags/gate; tool discovery must leave root authority cold."""
    import sqlite3

    from mordred_hermes.extension.telegram import mail_tool

    home, provider, backend = protected_runtime
    (home / "config.yaml").write_text("model:\n  default: m\n  base_url: http://127.0.0.1:11434/v1\n", encoding="utf-8")
    mail = home / "mordred/mail"
    mail.mkdir(mode=0o700)
    (mail / "credentials.sealed").write_bytes(b"MMC1 flags-only observation")
    (mail / "credentials.meta.json").write_text('{"account":"mail","roles":["all"]}', encoding="utf-8")
    for path in mail.iterdir():
        path.chmod(0o600)
    before = _snapshot(home)
    native_calls = list(backend.calls)

    def forbidden(*args: Any, **kwargs: Any) -> Any:
        pytest.fail("passive tool visibility attempted native authority or SQL")

    monkeypatch.setattr("mordred_hermes.dbcrypt._authority.Authority.acquire", forbidden)
    monkeypatch.setattr(sqlite3, "connect", forbidden)
    monkeypatch.setattr("sqlcipher3.dbapi2.connect", forbidden)
    assert provider.current_authority is None
    for _ in range(3):
        assert mail_tool.mail_sync_available() is True
    assert provider.current_authority is None
    assert backend.calls == native_calls
    assert _snapshot(home) == before
