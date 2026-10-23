"""``/status?client_version=4``, ``/imports/status`` and ``/databases/status``: closed, cold, non-unlocking."""

from __future__ import annotations

import asyncio
import json
import os
import sqlite3
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

pytest.importorskip("fastapi")

from mordred_hermes.desktop import _projections, _seams, _status_v4, api

from ._desktop_support import (
    ADDRESS,
    EXTRA,
    FOLDER,
    FakeMailSecrets,
    FakeReadonlyStore,
    FakeRefused,
    store_status,
)

REAL_STORE_REFUSAL = _seams.store_refusal
V4_KEYS = {"vault", "databases", "imports", "mail", "telegram_archive"}
VALID_KEY = "hex:" + "11" * 32


def _tree(path: Path) -> list[str]:
    return sorted(str(p.relative_to(path)) for p in path.rglob("*"))


def _flags(**extra: Any) -> dict[str, Any]:
    return {
        "version": 1,
        "account": "work",
        "gmail": True,
        "roles": ["all"],
        "touch_id": True,
        "setup_id": "x" * 32,
        **extra,
    }


def test_v3_keeps_its_keys_and_v4_adds_exactly_the_new_sections(desktop: Any) -> None:
    old = desktop.get("/status?client_version=3")
    new = desktop.get("/status?client_version=4")
    assert not V4_KEYS & set(old)
    assert set(new) - set(old) == V4_KEYS
    assert new["telegram_archive"] == {"legacy": None}
    assert new["imports"] == {
        "available": True,
        "code": None,
        "sources": {
            "telegram": {"conversations": 3, "messages": 25, "parts": 25},
            "mail": {"conversations": 0, "messages": 0, "parts": 0},
        },
    }
    assert new["mail"] == {"configured": False}
    assert set(new["vault"]) == {"exists", "env_enrolled", "env_injecting", "optout", "unattended"}
    assert new["vault"]["unattended"] is None  # the effective policy is not readable: never the requested one
    assert set(new["databases"]) == {
        "supported",
        "armed",
        "encrypt_pending",
        "decrypt_pending",
        "journal",
        "runtime_protected",
        "databases",
        "plaintext_backups",
    }


@pytest.mark.parametrize("code", sorted(_projections.IMPORT_STATE_CODES))
def test_every_store_refusal_is_a_state(desktop: Any, monkeypatch: pytest.MonkeyPatch, code: str) -> None:
    monkeypatch.setattr(_seams, "store_refusal", REAL_STORE_REFUSAL)

    def refuse(home: Path) -> Any:
        raise FakeRefused(code)

    monkeypatch.setattr(_seams, "open_store_readonly", refuse)
    status = desktop.get("/status?client_version=4")
    assert status["imports"] == {"available": False, "code": code, "sources": {}}


@pytest.mark.parametrize("code", ["conflict", "run_not_open", "Some free text", None])
def test_unknown_refusals_map_to_store_unavailable(desktop: Any, monkeypatch: pytest.MonkeyPatch, code: Any) -> None:
    monkeypatch.setattr(_seams, "store_refusal", REAL_STORE_REFUSAL)

    def refuse(home: Path) -> Any:
        raise FakeRefused(code) if code is not None else RuntimeError(ADDRESS)

    monkeypatch.setattr(_seams, "open_store_readonly", refuse)
    imports = desktop.get("/imports/status")["imports"]
    assert imports == {"available": False, "code": "store_unavailable", "sources": {}}


def test_store_refusal_uses_the_store_mapping_when_present(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[Any] = []

    def refusal_code(exc: BaseException) -> str:
        calls.append(exc)
        return "disk_full"

    monkeypatch.setattr(_seams, "library", lambda module, name: refusal_code)
    assert REAL_STORE_REFUSAL(FakeRefused("x")) == "disk_full" and len(calls) == 1


def test_projections_drop_canary_fields_and_corrupt_values(desktop: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    status = store_status(mail=(1, 2, 3))
    status["sources"]["telegram"]["title"] = ADDRESS
    status["sources"]["canary"] = {"conversations": 9, "note": EXTRA}
    status["sources"]["mail"]["messages"] = "lots"  # corrupt: not an int
    status["address"] = ADDRESS
    monkeypatch.setattr(_seams, "open_store_readonly", lambda home: FakeReadonlyStore(status))
    flags = _flags(address=ADDRESS, gmail="yes", touch_id=None)
    monkeypatch.setattr(_seams, "mail_secret_store", lambda: FakeMailSecrets(flags))

    def imap_status(store: Any, seen: Any) -> Any:
        assert seen is flags
        return {
            "configured": True,
            "account": "work",
            "address": ADDRESS,
            "last_fetch": {"at": 1_700_000_000, "error": "not a code " + ADDRESS, "partial": "no", "x": FOLDER},
            "last_success": {"at": -5, "who": ADDRESS},
            "cursors": {
                "all": {"forward": {"uid": 7, "uidvalidity": 9, "name": FOLDER}, "backfill": {"low": True}},
                FOLDER: {"forward": {"uid": 1}},
            },
            "folder": FOLDER,
        }

    monkeypatch.setattr(_seams, "imap_status", imap_status)
    result = desktop.get("/imports/status")
    assert result == {
        "ok": True,
        "imports": {
            "available": True,
            "code": None,
            "sources": {
                "telegram": {"conversations": 3, "messages": 25, "parts": 25},
                "mail": {"conversations": 1, "messages": 0, "parts": 3},
            },
        },
        "mail": {
            "configured": True,
            "account": "work",
            "gmail": None,
            "scope": ["all"],
            "touch_id": None,
            "last_attempt": {"at": 1_700_000_000, "error": "fetch_failed", "partial": None},
            "last_success": None,
            "cursors": {"all": {"forward": {"uidvalidity": 9, "uid": 7}, "backfill": {}}},
        },
        "telegram_archive": {"legacy": None},
    }
    assert not desktop.leaked(result, desktop.get("/status?client_version=4"))


def test_last_fetch_is_the_last_attempt_and_last_success_is_kept(desktop: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(_seams, "mail_secret_store", lambda: FakeMailSecrets(_flags()))
    attempt = {"at": 200, "error": "imap_auth_failed", "partial": False}
    monkeypatch.setattr(
        _seams,
        "imap_status",
        lambda store, flags: {"configured": True, "last_fetch": attempt, "last_success": {"at": 100}, "cursors": {}},
    )
    mail = desktop.get("/status?client_version=4")["mail"]
    assert mail["last_attempt"] == attempt and mail["last_success"] == {"at": 100}
    # An imap_status of an older Mordred: one flat record, a success when it had no error.
    monkeypatch.setattr(
        _seams,
        "imap_status",
        lambda store, flags: {"configured": True, "last_fetch": {"at": 50, "error": None, "partial": True}},
    )
    mail = desktop.get("/imports/status")["mail"]
    assert mail["last_attempt"] == {"at": 50, "error": None, "partial": True} and mail["last_success"] == {"at": 50}


def test_mail_from_flags_only_when_the_store_is_unavailable(desktop: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse(home: Path) -> Any:
        raise FakeRefused("no_key")

    def never(store: Any, flags: Any) -> Any:
        pytest.fail("imap_status needs the store")

    monkeypatch.setattr(_seams, "open_store_readonly", refuse)
    monkeypatch.setattr(_seams, "imap_status", never)
    monkeypatch.setattr(_seams, "mail_secret_store", lambda: FakeMailSecrets(_flags()))
    result = desktop.get("/imports/status")
    assert result["imports"]["code"] == "no_key"
    assert result["mail"] == {"configured": True, "account": "work", "gmail": True, "scope": ["all"], "touch_id": True}


@pytest.mark.parametrize(
    "secret_store",
    [
        FakeMailSecrets(raises=FakeRefused("credentials_left")),  # flags() raises for a sealed file without flags
        FakeMailSecrets(None, residue=True),  # flags without a sealed file
        FakeMailSecrets({"account": "BAD LABEL", "address": ADDRESS}, residue=True),
    ],
)
def test_residue_is_reported_as_credentials_left(
    desktop: Any, monkeypatch: pytest.MonkeyPatch, secret_store: Any
) -> None:
    monkeypatch.setattr(_seams, "mail_secret_store", lambda: secret_store)
    mail = desktop.get("/status?client_version=4")["mail"]
    assert mail == {"configured": False, "residue": "credentials_left"}


def test_a_broken_flags_reader_is_not_configured_and_logs_no_text(
    desktop: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(_seams, "mail_secret_store", lambda: FakeMailSecrets(raises=OSError(ADDRESS)))
    assert desktop.get("/imports/status")["mail"] == {"configured": False}
    assert not desktop.leaked()


@pytest.mark.parametrize(
    ("value", "valid"),
    [(None, False), ("", False), ("not-a-key", False), ("hex:" + "11" * 16, False), (VALID_KEY, True)],
)
def test_status_never_unlocks_and_checks_key_material_by_value(
    desktop: Any, monkeypatch: pytest.MonkeyPatch, value: str | None, valid: bool
) -> None:
    """Absent, empty, malformed and valid keys: no provider, no gate, no Keychain is ever called."""
    from mordred_hermes import dbcrypt
    from mordred_hermes.dbcrypt import _shim

    def forbidden(*args: Any, **kwargs: Any) -> Any:
        pytest.fail("the status path must not call anything that could unlock or prompt")

    monkeypatch.setattr(dbcrypt, "_PROVIDER", forbidden)
    monkeypatch.setattr("mordred_hermes.dbcrypt._key.KeyProvider", forbidden)
    monkeypatch.setattr("mordred_hermes.dbcrypt._key._inject_vault_env", forbidden)
    monkeypatch.setattr("mordred_hermes.activity._gate.check_protection", forbidden)
    monkeypatch.setattr("mordred_hermes.keyvault._anchor_keychain.default_anchor_store", forbidden)
    monkeypatch.setattr("mordred_hermes.keyvault._anchor_keychain.KeychainAnchorStore.read", forbidden)
    monkeypatch.setattr(_shim, "is_installed", lambda: True)
    dbcrypt.arm(desktop.home)
    if value is None:
        monkeypatch.delenv("HERMES_MEMORY_KEY", raising=False)
    else:
        monkeypatch.setenv("HERMES_MEMORY_KEY", value)
    before = _tree(desktop.home)
    status = desktop.get("/status?client_version=4")
    assert status["databases"]["armed"] is True
    assert status["databases"]["runtime_protected"] is valid
    assert desktop.get("/databases/status")["runtime_protected"] is valid
    assert _tree(desktop.home) == before  # nothing created: no directory, no store, no lock


@pytest.mark.parametrize("marker", ["db-encryption.pending", "db-decryption.pending", "db-encryption.journal.json"])
def test_pending_work_means_not_runtime_protected(desktop: Any, monkeypatch: pytest.MonkeyPatch, marker: str) -> None:
    from mordred_hermes import dbcrypt
    from mordred_hermes.dbcrypt import _shim

    monkeypatch.setattr(_shim, "is_installed", lambda: True)
    monkeypatch.setenv("HERMES_MEMORY_KEY", VALID_KEY)
    dbcrypt.arm(desktop.home)
    (desktop.home / "mordred" / marker).write_text("1\n", encoding="utf-8")
    databases = desktop.get("/databases/status")
    assert databases["runtime_protected"] is False
    key = {"db-encryption.pending": "encrypt_pending", "db-decryption.pending": "decrypt_pending"}.get(
        marker, "journal"
    )
    assert databases[key] is True


def test_databases_status_discovers_without_a_key(desktop: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(_seams, "sqlcipher_available", lambda: True)
    with sqlite3.connect(desktop.home / "state.db") as conn:
        conn.execute("CREATE TABLE t (x)")
    (desktop.home / "kanban.db").write_bytes(b"\x01" * 4096)  # ciphertext (or damage): unreadable without a key
    (desktop.home / "backups").mkdir()
    (desktop.home / "backups" / "hermes-1.zip").write_bytes(b"zip")
    databases = desktop.get("/databases/status")
    assert databases["ok"] is True and databases["supported"] is True and databases["armed"] is False
    assert sorted((d["relative"], d["state"]) for d in databases["databases"]) == [
        ("kanban.db", "unreadable"),
        ("state.db", "plaintext"),
    ]
    assert databases["plaintext_backups"] == 1 and databases["runtime_protected"] is False


def test_a_failing_discovery_is_a_code_not_a_500(desktop: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(home: Path, key: Any) -> Any:
        raise PermissionError(str(desktop.home))

    monkeypatch.setattr("mordred_hermes.dbcrypt._migrate.discover", boom)
    databases = desktop.get("/status?client_version=4")["databases"]
    assert databases["code"] == "databases_failed"


def test_vault_facts_come_from_files_only(desktop: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("mordred_hermes.wizard.encryption_cli._enrolled_names", lambda root: {".env"})
    root = desktop.home / "mordred" / "vault"
    root.mkdir(parents=True)
    (root / "manifest.1.mvmf").write_bytes(b"m")
    assert desktop.get("/status?client_version=4")["vault"] == {
        "exists": True,
        "env_enrolled": True,
        "env_injecting": True,
        "optout": False,
        "unattended": None,
    }
    (desktop.home / "mordred" / "env-vault.optout").write_text("opt-out\n", encoding="utf-8")
    vault = desktop.get("/status?client_version=4")["vault"]
    assert vault["optout"] is True and vault["env_injecting"] is False


def test_a_broken_vault_reader_reports_no_vault(desktop: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(root: Path) -> Any:
        raise RuntimeError(ADDRESS)

    monkeypatch.setattr("mordred_hermes.wizard.encryption_cli._enrolled_names", boom)
    assert desktop.get("/status?client_version=4")["vault"]["exists"] is False
    assert not desktop.leaked()


@pytest.mark.parametrize("platform", ["linux", "win32", "freebsd"])
def test_other_platforms_get_fixed_unsupported_sections(platform: str) -> None:
    sections = asyncio.run(_status_v4.sections(platform, Path("/nonexistent")))
    assert sections == {
        "vault": {"exists": False, "env_enrolled": False, "env_injecting": False, "optout": False, "unattended": None},
        "databases": {"supported": False},
        "imports": {"available": False, "code": "unsupported_platform", "sources": {}},
        "mail": {"configured": False},
        "telegram_archive": {"legacy": None},
    }
    assert _status_v4.imports_sections(Path("/nonexistent"), platform)["imports"]["code"] == "unsupported_platform"


def test_linux_status_v4_carries_the_unsupported_sections(desktop: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(api, "sys", SimpleNamespace(platform="linux"))
    status = desktop.get("/status?client_version=4")
    assert status["databases"] == {"supported": False} and status["imports"]["code"] == "unsupported_platform"
    old = desktop.get("/status?client_version=1")
    assert not V4_KEYS & set(old)


def test_windows_status_v4_adds_the_sections(monkeypatch: pytest.MonkeyPatch) -> None:
    from mordred_hermes.desktop import _windows

    monkeypatch.setattr(api, "sys", SimpleNamespace(platform="win32"))
    monkeypatch.setattr(_windows, "status_payload", lambda home, store: {"telegram_supported": False})
    monkeypatch.setattr(api, "_store", lambda: None)

    async def model_ok() -> dict[str, Any]:
        return {"ok": True}

    monkeypatch.setattr(api, "hermes_model_check", model_ok)
    assert not V4_KEYS & set(asyncio.run(api.status(client_version=3)))
    assert set(asyncio.run(api.status(client_version=4))) >= V4_KEYS


def test_status_lists_running_jobs_by_kind(desktop: Any) -> None:
    import threading

    gate = threading.Event()

    async def work(job: Any) -> None:
        await job.run_sync(gate.wait, 5)

    async def start() -> Any:
        return api._start_job("mail_fetch", work)

    job = desktop.http.portal.call(start)
    try:
        jobs = desktop.get("/status?client_version=4")["jobs"]
        assert [j["kind"] for j in jobs] == ["mail_fetch"]
    finally:
        gate.set()
    assert desktop.wait_job(job.job_id)["state"] == "done"


def test_status_output_is_json_clean(desktop: Any) -> None:
    status = desktop.get("/status?client_version=4")
    assert json.loads(json.dumps(status)) == status and os.environ.get("HERMES_HOME")
