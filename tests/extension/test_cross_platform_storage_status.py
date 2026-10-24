"""Desktop storage observation never obtains native or SQL authority."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("fastapi")

from mordred_hermes import dbcrypt
from mordred_hermes.desktop import _seams


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
    """A server evidence artifact does not change the real closed Desktop/native qualification gates."""
    from types import SimpleNamespace

    from mordred_hermes.dbcrypt import _capability, _windows_vfs
    from mordred_hermes.desktop import _databases

    (tmp_path / "server-storage-acceptance.json").write_text('{"accepted": true}', encoding="utf-8")
    monkeypatch.setattr(_capability, "sys", SimpleNamespace(platform="win32"))
    assert _windows_vfs.NATIVE_QUALIFIED is False
    assert _databases.database_status_projection(dbcrypt.database_status(tmp_path)) == {"supported": False}


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
