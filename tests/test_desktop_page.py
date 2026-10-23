"""The Hermes Desktop page on macOS and Linux: framework, step states and copy.

POSIX counterpart of ``test_desktop_windows_page.py`` on the same harness
(``tests/_desktop_page.py``). The page asks for ``/status?client_version=4``
(the start-up notice for 3), picks its layout from ``platform`` and
``hardware_kind``, and derives every step state and overview row from status
fields only: facts first, then unmet prerequisites, then registry jobs, then
page state. A status without the version 4 keys (``databases``, ``imports``,
``mail``) is an older Mordred: the databases and mail steps then ask for an
update, never ``done`` or ``blocked``.
"""

from __future__ import annotations

import asyncio
import copy
import json
import re
import shutil
import subprocess
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from mordred_hermes.imports.mail.imap import IMAP_HINTS
from mordred_hermes.imports.mail.imap_sync import ERROR_CODES, RESULT_FIELDS
from mordred_hermes.imports.mail.setup_flow import SETUP_ERROR_CODES
from mordred_hermes.imports.store import REFUSAL_CODES

from ._desktop_page import block, render_page, source

FIXTURES = Path(__file__).parent / "fixtures" / "desktop"
WINDOWS_SCENARIOS = FIXTURES / "windows_scenarios.js"
WINDOWS_SNAPSHOT = FIXTURES / "windows_page.json"

SDK_NAMES = {"host", "Button", "Checkbox", "Input", "ROUTES_AREA", "SIDEBAR_NAV_AREA", "PALETTE_AREA"}
IMPORT_SOURCES = {"@hermes/plugin-sdk", "react/jsx-runtime", "react"}
BLOCKER_CODES = (
    "needs_hermes_model",
    "needs_enclave",
    "needs_vault",
    "needs_memory",
    "needs_databases",
    "needs_restart",
    "needs_login",
    "needs_question_model",
)
IMAP_HINT_CODES = ("authentication_failed", "server_alert", "login_disabled", "gmail_app_password_length")
# `status.imports.code`: the read-only status path's complete refusal mapping (SPEC
# "Imports status"); each has an overview phrase and a MESSAGES entry.
STORE_GATE_CODES = (
    "not_armed",
    "conversion_pending",
    "unprotected_process",
    "no_key",
    "plaintext_store",
    "store_unavailable",
    "busy",
    "profile_mismatch",
    "schema_newer",
    "unkeyed_connection",
    "store_uninitialised",
    "unsupported_platform",
    "disk_full",
)
# The design's new page codes (MailSetupError, databases, forget warnings, ...).
PAGE_CODES = (
    "databases_unsupported",
    "databases_key_missing",
    "databases_failed",
    "databases_busy",
    "vault_anchor_stale",
    "mail_already_configured",
    "mail_setup_flow_expired",
    "mail_fetch_busy",
    "mail_not_configured",
    "invalid_address",
    "invalid_host",
    "invalid_account",
    "invalid_password",
    "too_many_addresses",
    "imap_auth_failed",
    "imap_unreachable",
    "imap_protocol",
    "imap_command_refused",
    "routing_unavailable",
    "egress_unsupported",
    "import_store_unavailable",
    "credentials_changed",
    "credentials_left",
    "key_left",
    "account_unknown",
    "fetch_failed",
    "run_failed",
    "sync_in_progress",
    "store_path_unsafe",
    "tee_unavailable",
    "tee_auth_cancelled",
    "mordred_update_required",
    "mail_forget_confirm_mismatch",
    "mail_secrets_corrupt",
    "mail_store_path_unsafe",
    "job_not_found",
    # The vault and memory ceremonies (second design revision).
    "vault_required",
    "vault_exists",
    "vault_flow_expired",
    "passphrase_reused",
    "env_optout",
    "env_required",
    "memory_operation_in_progress",
    "memory_encryption_failed",
    "invalid_body",
)
STEP_KEYS = (
    "enclave",
    "vault",
    "memory",
    "databases",
    "hermes_model",
    "question_model",
    "telegram",
    "telegram_import",
    "mail",
)
NOW_MS = 1_800_000_000_000


# -- status fixtures ---------------------------------------------------------------------------


def mac(
    *,
    hardware: bool = True,
    memory: bool = True,
    model: bool = True,
    llm: bool = True,
    login: bool = True,
    jobs: tuple[dict[str, Any], ...] = (),
    **extra: Any,
) -> dict[str, Any]:
    status: dict[str, Any] = {
        "ok": True,
        "platform": "darwin",
        "telegram_supported": True,
        "telegram_platform_supported": True,
        "hardware_kind": "secure_enclave",
        "user_presence_supported": True,
        "hermes_model": {"model": "e2ee-deepseek-v4-flash", "kind": "venice", "private": model, "ok": model},
        # The details are English; the page must not read them.
        "checks": {
            "hardware": {"ok": hardware, "detail": "Secure Enclave helper installed"},
            "secure_enclave": {"ok": hardware, "detail": "Secure Enclave"},
            "memory_encryption": {"ok": memory, "detail": "memory encrypted"},
            "login": {"ok": login, "detail": "logged in"},
            "privacy_llm": {"ok": llm, "detail": "venice (model); configured"},
        },
        "hermes_venice_key": False,
        "telegram_api": True,
        "jobs": list(jobs),
    }
    status.update(extra)
    return status


def linux(**kwargs: Any) -> dict[str, Any]:
    status = mac(**kwargs)
    status.update(platform="linux", hardware_kind="tpm", user_presence_supported=False)
    return status


# `/status.vault` (facts; `unattended` is the key's effective policy).
VAULT_READY = {"exists": True, "env_enrolled": True, "env_injecting": True, "optout": False, "unattended": True}
VAULT_NONE = {"exists": False, "env_enrolled": False, "env_injecting": False, "optout": False, "unattended": None}


def v4(
    *,
    vault: dict[str, Any] | None = VAULT_READY,
    armed: bool = True,
    protected: bool | None = None,
    encrypt_pending: bool = False,
    decrypt_pending: bool = False,
    journal: bool = False,
    rows: tuple[tuple[str, str], ...] | None = None,
    backups: int = 0,
    available: bool = True,
    code: str | None = None,
    telegram: tuple[int, int] = (3, 25),
    mail_messages: int = 0,
    mail: dict[str, Any] | None = None,
    supported: bool = True,
) -> dict[str, Any]:
    sources = {
        "telegram": {"conversations": telegram[0], "messages": telegram[1], "parts": telegram[1]},
        "mail": {"conversations": mail_messages, "messages": mail_messages, "parts": mail_messages},
    }
    if rows is None:
        rows = (("state.db", "unreadable" if armed else "plaintext"),)
    status: dict[str, Any] = {
        "databases": {
            "supported": supported,
            "armed": armed,
            "encrypt_pending": encrypt_pending,
            "decrypt_pending": decrypt_pending,
            "journal": journal,
            # This process opened its databases protected (it started after arming).
            "runtime_protected": armed if protected is None else protected,
            "databases": [{"relative": relative, "state": state} for relative, state in rows],
            "plaintext_backups": backups,
        },
        "imports": {"available": available, "code": code, "sources": sources if available else {}},
        "mail": mail if mail is not None else {"configured": False},
    }
    if vault is not None:
        status["vault"] = dict(vault)
    return status


def job(kind: str, job_id: str = "j1") -> dict[str, Any]:
    return {"job_id": job_id, "kind": kind, "state": "running", "error": None, "progress": {"message": "…"}}


MAIL_SET_UP = {
    "configured": True,
    "account": "work",
    "gmail": True,
    "scope": ["all"],
    "touch_id": True,
    "last_success": {"at": NOW_MS // 1000 - 7200},
    "last_attempt": {"at": NOW_MS // 1000 - 7200, "error": None, "partial": False},
    "residue": None,
}
MAIL_FAILED = {
    **MAIL_SET_UP,
    "last_attempt": {"at": NOW_MS // 1000 - 60, "error": "imap_auth_failed", "partial": False},
}
SYNC_COUNTS = {"syncing": False, "progress": None, "last_error": None, "dialog_count": 3, "message_count": 25}
OLD = "mordred_update_required"

# (status, /sync answer, expected states): "state", "state:blocker" or "state:code"; None = no such step.
STATE_CASES = {
    "fresh mac, older API": (
        mac(hardware=False, memory=False, model=False, llm=False, login=False),
        None,
        {
            "enclave": "next",
            "vault": None,
            "memory": "blocked:needs_enclave",
            "databases": f"attention:{OLD}",
            "hermes_model": "todo",
            "question_model": "blocked:needs_enclave",
            "telegram": "blocked:needs_enclave",
            "telegram_import": "blocked:needs_enclave",
            "mail": f"attention:{OLD}",
        },
    ),
    "helper build running (restored from status.jobs)": (
        mac(hardware=False, memory=False, model=False, llm=False, login=False, jobs=(job("enclave"),)),
        None,
        {
            "enclave": "running",
            "vault": None,
            "memory": "blocked:needs_enclave",
            "databases": f"attention:{OLD}",
            "hermes_model": "next",
            "question_model": "blocked:needs_enclave",
            "telegram": "blocked:needs_enclave",
            "telegram_import": "blocked:needs_enclave",
            "mail": f"attention:{OLD}",
        },
    ),
    "facts beat a running job": (
        mac(model=False, llm=False, login=False, jobs=(job("enclave"),)),
        None,
        {
            "enclave": "done",
            "vault": None,
            "memory": "done",
            "databases": f"attention:{OLD}",
            "hermes_model": "next",
            "question_model": "blocked:needs_hermes_model",
            "telegram": "blocked:needs_hermes_model",
            "telegram_import": "blocked:needs_hermes_model",
            "mail": f"attention:{OLD}",
        },
    ),
    "model private, no question model": (
        mac(llm=False, login=False),
        None,
        {
            "enclave": "done",
            "vault": None,
            "memory": "done",
            "databases": f"attention:{OLD}",
            "hermes_model": "done",
            "question_model": "next",
            "telegram": "blocked:needs_question_model",
            "telegram_import": "blocked:needs_question_model",
            "mail": f"attention:{OLD}",
        },
    ),
    "memory off blocks Telegram": (
        mac(memory=False, login=False),
        None,
        {
            "enclave": "done",
            "vault": None,
            "memory": "next",
            "databases": f"attention:{OLD}",
            "hermes_model": "done",
            "question_model": "done",
            "telegram": "blocked:needs_memory",
            "telegram_import": "blocked:needs_memory",
            "mail": f"attention:{OLD}",
        },
    ),
    "logged in, older API, counts unknown": (
        mac(),
        None,
        {
            "enclave": "done",
            "vault": None,
            "memory": "done",
            "databases": f"attention:{OLD}",
            "hermes_model": "done",
            "question_model": "done",
            "telegram": "done",
            "telegram_import": "next",
            "mail": f"attention:{OLD}",
        },
    ),
    "older API, in-process counts": (
        mac(),
        SYNC_COUNTS,
        {
            "enclave": "done",
            "vault": None,
            "memory": "done",
            "databases": f"attention:{OLD}",
            "hermes_model": "done",
            "question_model": "done",
            "telegram": "done",
            "telegram_import": "done",
            "mail": f"attention:{OLD}",
        },
    ),
    "first import running (page state)": (
        mac(),
        {**SYNC_COUNTS, "syncing": True, "message_count": 0},
        {
            "enclave": "done",
            "vault": None,
            "memory": "done",
            "databases": f"attention:{OLD}",
            "hermes_model": "done",
            "question_model": "done",
            "telegram": "done",
            "telegram_import": "running",
            "mail": f"attention:{OLD}",
        },
    ),
    "last import stopped": (
        mac(),
        {**SYNC_COUNTS, "message_count": 0, "last_error": "telegram_rate_limited"},
        {
            "enclave": "done",
            "vault": None,
            "memory": "done",
            "databases": f"attention:{OLD}",
            "hermes_model": "done",
            "question_model": "done",
            "telegram": "done",
            "telegram_import": "attention:telegram_rate_limited",
            "mail": f"attention:{OLD}",
        },
    ),
    "v4, databases plaintext": (
        mac(**v4(armed=False, available=False, code="not_armed")),
        None,
        {
            "enclave": "done",
            "vault": "done",
            "memory": "done",
            "databases": "next",
            "hermes_model": "done",
            "question_model": "done",
            "telegram": "done",
            "telegram_import": "blocked:needs_databases",
            "mail": "blocked:needs_databases",
        },
    ),
    "v4, conversion scheduled": (
        mac(**v4(armed=False, encrypt_pending=True, available=False, code="conversion_pending")),
        None,
        {
            "enclave": "done",
            "vault": "done",
            "memory": "done",
            "databases": "next:restart",
            "hermes_model": "done",
            "question_model": "done",
            "telegram": "done",
            "telegram_import": "blocked:needs_restart",
            "mail": "blocked:needs_restart",
        },
    ),
    "v4, armed but Hermes not restarted": (
        mac(**v4(protected=False, available=False, code="unprotected_process")),
        None,
        {
            "enclave": "done",
            "vault": "done",
            "memory": "done",
            "databases": "next:restart",
            "hermes_model": "done",
            "question_model": "done",
            "telegram": "done",
            "telegram_import": "blocked:needs_restart",
            "mail": "blocked:needs_restart",
        },
    ),
    "v4, databases need memory": (
        mac(memory=False, login=False, **v4(armed=False, available=False, code="not_armed")),
        None,
        {
            "enclave": "done",
            "vault": "done",
            "memory": "next",
            "databases": "blocked:needs_memory",
            "hermes_model": "done",
            "question_model": "done",
            "telegram": "blocked:needs_memory",
            "telegram_import": "blocked:needs_memory",
            "mail": "blocked:needs_memory",
        },
    ),
    "v4, store counts, mail not set up": (
        mac(**v4()),
        {**SYNC_COUNTS, "message_count": 0},
        {
            "enclave": "done",
            "vault": "done",
            "memory": "done",
            "databases": "done",
            "hermes_model": "done",
            "question_model": "done",
            "telegram": "done",
            "telegram_import": "done",
            "mail": "next",
        },
    ),
    "v4, store gate refuses with no_key": (
        mac(**v4(available=False, code="no_key")),
        None,
        {
            "enclave": "done",
            "vault": "done",
            "memory": "done",
            "databases": "done",
            "hermes_model": "done",
            "question_model": "done",
            "telegram": "done",
            "telegram_import": "attention:no_key",
            "mail": "next",
        },
    ),
    "v4, mail fetch failed": (
        mac(**v4(mail=MAIL_FAILED)),
        None,
        {
            "enclave": "done",
            "vault": "done",
            "memory": "done",
            "databases": "done",
            "hermes_model": "done",
            "question_model": "done",
            "telegram": "done",
            "telegram_import": "done",
            "mail": "attention:imap_auth_failed",
        },
    ),
    "v4, mail fetch job while set up (facts first)": (
        mac(jobs=(job("mail_fetch"),), **v4(mail=MAIL_SET_UP)),
        None,
        {
            "enclave": "done",
            "vault": "done",
            "memory": "done",
            "databases": "done",
            "hermes_model": "done",
            "question_model": "done",
            "telegram": "done",
            "telegram_import": "done",
            "mail": "done",
        },
    ),
    "v4, databases unsupported": (
        mac(**v4(armed=False, supported=False, available=False, code="not_armed")),
        None,
        {
            "enclave": "done",
            "vault": "done",
            "memory": "done",
            "databases": "attention:databases_unsupported",
            "hermes_model": "done",
            "question_model": "done",
            "telegram": "done",
            "telegram_import": "blocked:needs_databases",
            "mail": "blocked:needs_databases",
        },
    ),
    "linux, no databases and no mail": (
        linux(memory=False, login=False),
        None,
        {
            "enclave": "done",
            "vault": None,
            "memory": "next",
            "databases": None,
            "hermes_model": "done",
            "question_model": "done",
            "telegram": "blocked:needs_memory",
            "telegram_import": "blocked:needs_memory",
            "mail": None,
        },
    ),
}


# The vault (1.2a) and memory (1.2b) split of the version 4 API.
STATE_CASES.update(
    {
        "v4, no helper yet": (
            mac(hardware=False, memory=False, login=False, **v4(vault=VAULT_NONE, armed=False)),
            None,
            {
                "enclave": "next",
                "vault": "blocked:needs_enclave",
                "memory": "blocked:needs_enclave",
                "databases": "blocked:needs_enclave",
                "hermes_model": "done",
                "question_model": "done",
                "telegram": "blocked:needs_enclave",
                "telegram_import": "blocked:needs_enclave",
                "mail": "blocked:needs_enclave",
            },
        ),
        "v4, vault not created": (
            mac(memory=False, login=False, **v4(vault=VAULT_NONE, armed=False)),
            None,
            {
                "enclave": "done",
                "vault": "next",
                "memory": "blocked:needs_vault",
                "databases": "blocked:needs_memory",
                "hermes_model": "done",
                "question_model": "done",
                "telegram": "blocked:needs_memory",
                "telegram_import": "blocked:needs_memory",
                "mail": "blocked:needs_memory",
            },
        ),
        "v4, vault created, Hermes not restarted": (
            mac(memory=False, login=False, **v4(vault={**VAULT_READY, "env_injecting": False}, armed=False)),
            None,
            {
                "enclave": "done",
                "vault": "done",
                "memory": "blocked:needs_vault",
                "databases": "blocked:needs_memory",
                "hermes_model": "done",
                "question_model": "done",
                "telegram": "blocked:needs_memory",
                "telegram_import": "blocked:needs_memory",
                "mail": "blocked:needs_memory",
            },
        ),
        "v4, .env encryption opted out": (
            mac(memory=False, login=False, **v4(vault={**VAULT_NONE, "exists": True, "optout": True}, armed=False)),
            None,
            {
                "enclave": "done",
                "vault": "attention:env_optout",
                "memory": "blocked:needs_vault",
                "databases": "blocked:needs_memory",
                "hermes_model": "done",
                "question_model": "done",
                "telegram": "blocked:needs_memory",
                "telegram_import": "blocked:needs_memory",
                "mail": "blocked:needs_memory",
            },
        ),
        "v4, memory already on from an older ceremony": (
            mac(**v4(vault={**VAULT_NONE, "exists": True})),
            None,
            {
                "enclave": "done",
                "vault": "next",
                "memory": "done",
                "databases": "done",
                "hermes_model": "done",
                "question_model": "done",
                "telegram": "done",
                "telegram_import": "done",
                "mail": "todo",
            },
        ),
    }
)


def ready_but(**changes: str) -> dict[str, str | None]:
    """Every step done on a fully set-up v4 Mac, except `changes`."""
    states: dict[str, str | None] = dict.fromkeys(STEP_KEYS, "done")
    states["mail"] = "next"
    states.update(changes)
    return states


# Step 1.3 over the databases facts (the second design revision's total table).
STATE_CASES.update(
    {
        "v4, databases armed in a home with a new plaintext file": (
            mac(**v4(rows=(("state.db", "unreadable"), ("kanban.db", "plaintext")))),
            None,
            ready_but(databases="attention:plaintext_in_armed_home"),
        ),
        "v4, databases armed with a stale encrypt request": (
            mac(**v4(encrypt_pending=True)),
            None,
            ready_but(databases="attention:stale_pending"),
        ),
        "v4, databases decryption pending": (
            mac(**v4(decrypt_pending=True)),
            None,
            ready_but(databases="attention:decrypt_pending"),
        ),
        "v4, databases journal left": (
            mac(**v4(journal=True)),
            None,
            ready_but(databases="attention:journal"),
        ),
        "v4, nothing plaintext but not armed": (
            mac(**v4(armed=False, rows=(), available=False, code="not_armed")),
            None,
            ready_but(databases="next", telegram_import="blocked:needs_databases", mail="blocked:needs_databases"),
        ),
    }
)


# Step 2.5 over the mail facts (`last_attempt` / `last_success`, residue).
STATE_CASES.update(
    {
        "v4, mail set up, never fetched": (
            mac(**v4(mail={**MAIL_SET_UP, "last_success": None, "last_attempt": None})),
            None,
            ready_but(mail="done"),
        ),
        "v4, mail partial last attempt": (
            mac(**v4(mail={**MAIL_SET_UP, "last_attempt": {"at": 1, "error": None, "partial": True}})),
            None,
            ready_but(mail="done"),
        ),
        "v4, mail credentials left over": (
            mac(**v4(mail={"configured": False, "residue": "credentials_left"})),
            None,
            ready_but(mail="attention:credentials_left"),
        ),
    }
)


STATE_CASES.update(
    {
        # The first import creates the store: no failure, Telegram import is simply next.
        "v4, store not created yet": (
            mac(**v4(available=False, code="store_uninitialised")),
            None,
            ready_but(telegram_import="next", mail="todo"),
        ),
    }
)


def compact(states: dict[str, Any]) -> dict[str, str | None]:
    result: dict[str, str | None] = {}
    for key in STEP_KEYS:
        entry = states.get(key)
        if entry is None:
            result[key] = None
            continue
        detail = entry.get("blocker") or entry.get("code") or ("restart" if entry.get("restart") else None)
        result[key] = f"{entry['state']}:{detail}" if detail else entry["state"]
    return result


def page_states(status: dict[str, Any], sync: dict[str, Any] | None = None) -> dict[str, Any]:
    return render_page(f"console.log(JSON.stringify(stepStates({json.dumps(status)}, {json.dumps(sync)})))")


# -- module shape --------------------------------------------------------------------------------


@pytest.mark.skipif(shutil.which("node") is None, reason="Node.js is not installed")
def test_page_is_a_valid_es_module():
    completed = subprocess.run(
        ["node", "--input-type=module", "--check"],
        input=source(),
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=60,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr


def test_sdk_import_line_is_exactly_the_allowlisted_names():
    text = source()
    sources = set(re.findall(r"^import [\s\S]*? from '([^']+)'$", text, re.M))
    assert sources == IMPORT_SOURCES
    match = re.search(r"^import \{([^}]*)\} from '@hermes/plugin-sdk'$", text, re.M)
    assert match, "the SDK import is one named-import statement"
    names = {name.strip() for name in match.group(1).split(",") if name.strip()}
    assert names == SDK_NAMES, "a named export the installed Desktop lacks removes the whole page"
    assert text.count("from '@hermes/plugin-sdk'") == 1
    assert "import * as" not in text


def test_page_requests_status_version_4_and_the_startup_notice_version_3():
    text = source()
    assert "const STATUS_PATH = '/status?client_version=4'" in text
    assert "const STARTUP_STATUS_PATH = '/status?client_version=3'" in text
    result = render_page("""
const paths = []
rest = async path => {paths.push(path); return path.startsWith('/status') ? {ok: true} : {ok: true, check: null}}
await probe()
let startup = null
plugin.register({rest, register: () => {}, onEvent: () => {}, setTimeout: fn => {startup = fn}})
paths.length = 0
await startup()
console.log(JSON.stringify({startup: paths}))
""")
    assert result["startup"][0] == "/status?client_version=3"
    page = render_page("""
const paths = []
rest = async path => {paths.push(path); return {ok: false, error: 'unknown'}}
await probe()
console.log(JSON.stringify(paths))
""")
    assert page == ["/status?client_version=4"]


@pytest.mark.parametrize("platform", ["darwin", "linux"])
def test_backend_answers_version_4_like_version_3(monkeypatch, platform, tmp_path):
    """Version 4 is version 3 plus the five page keys (vault, databases, imports, mail, telegram_archive)."""
    pytest.importorskip("fastapi")
    from mordred_hermes.desktop import api
    from mordred_hermes.wizard import telegram_setup_cli

    monkeypatch.setattr(api, "sys", SimpleNamespace(platform=platform))
    monkeypatch.setattr(api, "_home", lambda: tmp_path)
    monkeypatch.setattr(telegram_setup_cli, "run_checks", lambda: [telegram_setup_cli.Check("hardware", True, "ok")])

    async def model():
        return {"ok": True}

    monkeypatch.setattr(api, "hermes_model_check", model)
    monkeypatch.setattr(api, "_store", lambda: SimpleNamespace(flags=lambda: {}))
    monkeypatch.setattr(api, "_hermes_venice_key", lambda: None)
    v3 = asyncio.run(api.status(client_version=3))
    v4 = asyncio.run(api.status(client_version=4))
    page_keys = {"vault", "databases", "imports", "mail", "telegram_archive"}
    assert set(v4) - set(v3) == page_keys
    assert {key: value for key, value in v4.items() if key not in page_keys} == v3


@pytest.mark.parametrize(
    "status,layout",
    [
        ({"platform": "darwin", "hardware_kind": "secure_enclave", "telegram_supported": True}, "macos"),
        ({"platform": "linux", "hardware_kind": "tpm", "telegram_supported": True}, "linux"),
        ({"platform": "win32", "hardware_kind": "cng", "telegram_supported": False}, "windows"),
        ({"platform": "darwin", "hardware_kind": None, "telegram_supported": True}, "unsupported"),
        ({"platform": "darwin", "hardware_kind": "secure_enclave", "telegram_supported": False}, "unsupported"),
        ({"platform": "freebsd", "hardware_kind": None, "telegram_supported": False}, "unsupported"),
        # English detail text naming the Secure Enclave never picks the macOS page.
        (
            {
                "platform": "linux",
                "hardware_kind": "tpm",
                "telegram_supported": True,
                "checks": {"hardware": {"ok": True, "detail": "Secure Enclave (macOS)"}},
            },
            "linux",
        ),
    ],
)
def test_layout_is_chosen_by_platform_metadata_never_by_text(status, layout):
    assert render_page(f"console.log(JSON.stringify(pageLayout({json.dumps(status)})))") == layout


def test_layout_selection_reads_only_metadata_fields():
    text = source()
    body = text[text.index("function pageLayout(") : text.index("function reportsV4(")]
    assert "status.platform === 'darwin' && status.hardware_kind === 'secure_enclave'" in body
    assert "status.hardware_kind === 'tpm'" in body and "status.hardware_kind === 'cng'" in body
    assert "detail" not in body and ".includes(" not in body and ".test(" not in body


def test_every_code_the_page_knows_has_an_entry():
    messages, hints, blockers, numbers = (
        block("MESSAGES"),
        block("IMAP_HINTS"),
        block("BLOCKERS"),
        block("STEP_NUMBERS"),
    )
    library = set(ERROR_CODES) | set(SETUP_ERROR_CODES) | set(REFUSAL_CODES)
    for code in sorted(set(PAGE_CODES) | library | set(STORE_GATE_CODES) | set(MAIL_CODES)):
        assert re.search(rf"^  {re.escape(code)}:", messages, re.M), code
    assert set(IMAP_HINT_CODES) == set(IMAP_HINTS)
    for hint in IMAP_HINT_CODES:
        assert re.search(rf"^  {hint}:", hints, re.M), hint
    for code in BLOCKER_CODES:
        entry = re.search(rf"^  {code}: \{{ step: '(\w+)', text: '[^']+' \}},$", blockers, re.M)
        assert entry, code
        assert re.search(rf"^  {entry.group(1)}: '", numbers, re.M), f"{code} points at a numbered step"
    gates = block("STORE_GATES")
    for code in STORE_GATE_CODES:
        assert re.search(rf"^  {code}:", gates, re.M), code
    badges = block("STATE_BADGES")
    for state in ("done", "next", "todo", "blocked", "running", "attention"):
        assert re.search(rf"^  {state}: \{{ glyph: '[^']*', text: '[A-Z][a-z ]+' \}},$", badges, re.M), state
    # Every blocker and attention code the page itself computes is in its table.
    text = source()
    assert set(re.findall(r"'(needs_\w+)'", text)) == set(BLOCKER_CODES)
    for code in ("mordred_update_required", "databases_unsupported", "import_store_unavailable", "job_not_found"):
        assert re.search(rf"^  {code}:", messages, re.M), code


def test_explain_uses_the_imap_hint_and_mail_wording():
    result = render_page("""
console.log(JSON.stringify({
  hinted: new MordredError('imap_auth_failed', {hint: 'gmail_app_password_length'}).message,
  unknown: new MordredError('imap_auth_failed', {hint: 'free text from a server'}).message,
  plain: explain('imap_auth_failed'),
  mail: explainMail('secrets_corrupt'),
  shared: explainMail('imap_unreachable'),
}))
""")
    assert result["hinted"].startswith("A Gmail app password is exactly 16 letters")
    assert result["unknown"] == result["plain"] == "The login was refused. Nothing was stored."
    assert "mailbox" in result["mail"] and "Telegram" not in result["mail"]
    assert result["shared"].startswith("The server could not be reached")


def test_sync_in_progress_names_both_writers():
    assert "sync_in_progress: 'A Telegram import or a mail fetch is already running.'" in source()


def test_no_hex_colour_literal_outside_var_fallbacks():
    text = source()
    offenders = [
        text[max(0, m.start() - 40) : m.end()]
        for m in re.finditer(r"#[0-9a-fA-F]{3,8}\b", text)
        if not re.search(r"var\(--[\w-]+,\s*$", text[: m.start()])
    ]
    assert offenders == []
    assert "'1px solid #" not in text


# -- step states ---------------------------------------------------------------------------------


@pytest.mark.parametrize("name", list(STATE_CASES))
def test_step_states_come_from_status_fields(name):
    status, sync, expected = STATE_CASES[name]
    assert compact(page_states(status, sync)) == expected


def test_a_running_build_carries_its_job_id_and_only_one_step_is_next():
    states = page_states(mac(hardware=False, memory=False, model=False, jobs=(job("hardware", "build-7"),)))
    assert states["enclave"] == {"state": "running", "job": "build-7"}
    assert [key for key, value in states.items() if value["state"] == "next"] == ["hermes_model"]


def headings(script_status: dict[str, Any], sync: dict[str, Any] | None = None) -> dict[str, Any]:
    return render_page(
        """
const status = STATUS
const tree = PageBody({status, health: null, sync: SYNC, refresh: () => {}})
const steps = {}, groups = []
const text = node => typeof node === 'string' ? node : !node || typeof node !== 'object' ? ''
  : Array.isArray(node) ? node.map(text).join('') : text(node.props && node.props.children)
const visit = (node, section) => {
  if (!node || typeof node !== 'object') return
  if (Array.isArray(node)) { node.forEach(child => visit(child, section)); return }
  if (node.type === 'section') section = node
  if (node.type === 'h3' && node.props.id) {
    steps[node.props.id] = {text: text(node), labelled: section && section.props['aria-labelledby'] === node.props.id,
      focusable: node.props.tabIndex === -1}
  }
  if (node.type === 'h2' && section) {
    groups.push({id: node.props.id, text: text(node), labelled: section.props['aria-labelledby'] === node.props.id,
      focusable: node.props.tabIndex === -1})
  }
  const children = node.props && node.props.children
  ;(Array.isArray(children) ? children : [children]).forEach(child => visit(child, section))
}
visit(tree, null)
console.log(JSON.stringify({steps, groups}))
""".replace("STATUS", json.dumps(script_status)).replace("SYNC", json.dumps(sync))
    )


BADGE_TEXT = {
    "done": "Done",
    "next": "Next",
    "todo": "To do",
    "blocked": "Blocked",
    "running": "Running",
    "attention": "Needs attention",
}


@pytest.mark.parametrize(
    "name", ["fresh mac, older API", "v4, conversion scheduled", "linux, no databases and no mail"]
)
def test_rendered_page_shows_each_step_in_its_computed_state(name):
    status, sync, expected = STATE_CASES[name]
    rendered = headings(status, sync)
    shown = {key.removeprefix("mordred-step-"): value for key, value in rendered["steps"].items()}
    assert set(shown) == {key for key, value in expected.items() if value is not None}
    for key, value in expected.items():
        if value is None:
            continue
        state = value.split(":")[0]
        assert shown[key]["text"].endswith(BADGE_TEXT[state]), (key, shown[key]["text"])
        assert shown[key]["labelled"] and shown[key]["focusable"], key
    titles = [group["text"] for group in rendered["groups"]]
    protect = "1  Protect this host" if name.startswith("linux") else "1  Protect this Mac"
    assert titles == ["Overview", protect, "2  Connect", "3  Ask Hermes", "4  Maintenance"]
    assert all(group["labelled"] for group in rendered["groups"])
    assert all(group["focusable"] for group in rendered["groups"][1:])


@pytest.mark.parametrize(
    "status,titles,goto",
    [
        (
            mac(memory=False, login=False, **v4(vault=VAULT_NONE, armed=False)),
            {"vault": "1.2a  Create the vault", "memory": "1.2b  Encrypt Hermes memory"},
            {"Go to step 1.2a", "Go to step 1.2b"},
        ),
        (mac(memory=False, login=False), {"memory": "1.2  Encrypt Hermes memory and secrets"}, {"Go to step 1.2"}),
        (linux(memory=False, login=False), {"memory": "1.2  Encrypt Hermes memory"}, {"Go to step 1.2"}),
    ],
    ids=["macos-v4", "macos-older-api", "linux"],
)
def test_memory_is_step_1_2_unless_the_vault_is_its_own_step(status, titles, goto):
    rendered = headings(status)
    shown = {key.removeprefix("mordred-step-"): value["text"] for key, value in rendered["steps"].items()}
    for key, title in titles.items():
        assert shown[key].startswith(title), shown[key]
    assert ("vault" in shown) is ("vault" in titles)
    buttons = render_page(
        """
const tree = PageBody({status: STATUS, health: null, refresh: () => {}})
const out = new Set()
const visit = node => {
  if (!node || typeof node !== 'object') return
  if (Array.isArray(node)) { node.forEach(visit); return }
  if (node.type === 'button' && String(node.props.children).startsWith('Go to step')) out.add(node.props.children)
  const c = node.props && node.props.children
  ;(Array.isArray(c) ? c : [c]).forEach(visit)
}
visit(tree)
console.log(JSON.stringify([...out]))
""".replace("STATUS", json.dumps(status))
    )
    assert set(buttons) == goto


def page_text(status: dict[str, Any]) -> str:
    return render_page(
        """
const text = node => typeof node === 'string' || typeof node === 'number' ? String(node)
  : !node || typeof node !== 'object' ? '' : Array.isArray(node) ? node.map(text).join('')
  : text(node.props && node.props.children)
console.log(JSON.stringify(text(PageBody({status: STATUS, health: null, refresh: () => {}}))))
""".replace("STATUS", json.dumps(status))
    )


MIGRATE_HINT = (
    "Your Telegram history may still be in the older archive; run hermes-mordred telegram migrate-store "
    "--commit in Terminal to move it into Mordred\u2019s store."
)


@pytest.mark.parametrize(
    "status,shown",
    [
        (mac(**v4(telegram=(0, 0))), True),
        (mac(**v4(available=False, code="store_uninitialised")), True),
        (mac(**v4()), False),
        (mac(**v4(available=False, code="no_key")), False),
        (mac(login=False, **v4(telegram=(0, 0))), False),
        (mac(), False),
        (linux(), False),
    ],
    ids=["empty-store", "store-not-created", "imported", "store-locked", "logged-out", "older-api", "linux"],
)
def test_telegram_import_points_to_migrate_store_when_the_store_has_no_telegram_message(status, shown):
    assert (MIGRATE_HINT in page_text(status)) is shown


def test_telegram_import_counts_are_store_totals():
    text = page_text(mac(**v4()))
    assert "3 chats · 25 messages in Mordred\u2019s store (all accounts)." in text


def test_status_refreshes_are_coalesced_and_polled_every_10_seconds_while_a_job_runs():
    assert "const STATUS_POLL_MS = 10_000" in source()
    assert "setInterval(refresh, STATUS_POLL_MS)" in source()
    result = render_page("""
const reads = [], gates = []
rest = path => {
  if (!path.startsWith('/status')) return Promise.resolve({ok: true})
  reads.push(path)
  return new Promise(resolve => gates.push(resolve))
}
const flush = () => new Promise(resolve => setImmediate(resolve))
cursor = 0
SetupPage({})
effects.forEach(effect => effect())
const refresh = [...jobListeners][0]
const pending = [refresh(), refresh(), refresh()]
const first = reads.length
gates.shift()({ok: true, platform: 'darwin'})
await flush()
const second = reads.length
gates.shift()({ok: true, platform: 'darwin'})
await Promise.all(pending)
await flush()
console.log(JSON.stringify({first, second, total: reads.length}))
""")
    assert result == {"first": 1, "second": 2, "total": 2}


SYNC_RUNNING = {
    "syncing": True,
    "progress": {"dialogs_done": 1, "dialogs_total": 3, "messages_imported": 10},
    "last_error": None,
    "dialog_count": 3,
    "message_count": 10,
}
SYNC_DONE = {**SYNC_RUNNING, "syncing": False, "progress": None, "message_count": 40}


def test_a_finished_telegram_import_refreshes_the_counts_and_the_step():
    """The import is not a registry job: its end (seen through /sync) triggers one status read."""
    before = mac(**v4(telegram=(0, 0)))
    after = mac(**v4(telegram=(3, 40)))
    result = render_page(
        """
const intervals = []
globalThis.setInterval = (fn, ms) => { intervals.push(ms); return 0 }
globalThis.clearInterval = () => {}
const original = jsx
let body = null
jsx = jsxs = (type, props) => type === PageBody ? (body = props, {type: 'PageBody', props: {}}) : original(type, props)
const statuses = [BEFORE, AFTER]
const reads = []
rest = async path => {
  if (!path.startsWith('/status')) return {ok: true}
  reads.push(path)
  return statuses[Math.min(reads.length - 1, statuses.length - 1)]
}
const flush = async () => { for (let i = 0; i < 10; i++) await new Promise(r => setImmediate(r)) }
const page = () => { cursor = 0; effects.length = 0; return SetupPage({}) }
const text = node => typeof node === 'string' || typeof node === 'number' ? String(node)
  : !node || typeof node !== 'object' ? '' : Array.isArray(node) ? node.map(text).join('')
  : text(node.props && node.props.children)
const out = {}
page()
effects.slice().forEach(f => f())
await flush()
page()
out.first = reads.length
body.onSync(RUNNING); await flush(); page()
out.whileRunning = reads.length
effects.find(f => String(f).includes('STATUS_POLL_MS'))()
out.intervals = intervals.slice()
body.onSync(DONE); await flush(); page()
out.afterDone = reads.length
body.onSync(DONE); await flush()
out.repeated = reads.length
body.onSync({...DONE, message_count: 41, last_error: 'telegram_rate_limited'}); await flush(); page()
out.afterError = reads.length
body.onSync({...DONE, message_count: 42, last_error: 'telegram_rate_limited'}); await flush()
out.sameError = reads.length
jsx = jsxs = original
// A fresh render of the page body with what SetupPage now hands it (hooks are numbered globally).
states = []
cursor = 0
out.text = text(PageBody({...body, sync: DONE}))
console.log(JSON.stringify(out))
""".replace("BEFORE", json.dumps(before))
        .replace("AFTER", json.dumps(after))
        .replace("RUNNING", json.dumps(SYNC_RUNNING))
        .replace("DONE", json.dumps(SYNC_DONE))
    )
    assert result["first"] == 1 and result["whileRunning"] == 1
    assert result["intervals"] == [10_000], "counts are re-read at most every 10 s while the import runs"
    assert result["afterDone"] == 2 and result["repeated"] == 2
    assert result["afterError"] == 3 and result["sameError"] == 3
    text = result["text"]
    assert "connected · 3 chats · 40 messages in Mordred\u2019s store (all accounts)" in text
    assert "Import Telegram messages\u2713 Done" in text
    assert "3 chats · 40 messages in Mordred\u2019s store (all accounts)." in text


SYNC_IDLE = {"syncing": False, "progress": None, "last_error": None, "dialog_count": 0, "message_count": 0}


@pytest.mark.parametrize(
    "polls",
    [
        # Finished before any poll saw it running: the first idle answer is its completion.
        [{**SYNC_IDLE, "dialog_count": 2, "message_count": 9}],
        # Seen running first: the busy → idle rule refreshes, and only once.
        [SYNC_RUNNING, {**SYNC_IDLE, "dialog_count": 2, "message_count": 9}],
    ],
    ids=["idle-to-idle", "busy-to-idle"],
)
def test_an_import_started_here_refreshes_the_counts_once_even_between_polls(polls):
    before = mac(**v4(telegram=(0, 0)))
    after = mac(**v4(telegram=(2, 9)))
    result = render_page(
        """
globalThis.setInterval = () => 0
globalThis.clearInterval = () => {}
const original = jsx
let body = null
jsx = jsxs = (type, props) => type === PageBody ? (body = props, {type: 'PageBody', props: {}}) : original(type, props)
const statuses = [BEFORE, AFTER]
const reads = []
const polls = POLLS
rest = async (path, init) => {
  if (path.startsWith('/status')) {
    reads.push(path)
    return statuses[Math.min(reads.length - 1, statuses.length - 1)]
  }
  if (path === '/sync') return init && init.method === 'POST' ? {ok: true} : polls.length ? polls.shift() : LAST
  return {ok: true}
}
const flush = async () => { for (let i = 0; i < 10; i++) await new Promise(r => setImmediate(r)) }
const page = () => { cursor = 0; effects.length = 0; return SetupPage({}) }
const text = node => typeof node === 'string' || typeof node === 'number' ? String(node)
  : !node || typeof node !== 'object' ? '' : Array.isArray(node) ? node.map(text).join('')
  : text(node.props && node.props.children)
const out = {}
page()
effects.slice().forEach(f => f())
await flush()
page()
// The import step's first poll, before anything was started: idle, nothing to refresh.
body.onSync(IDLE)
await flush()
out.beforeStart = reads.length
// The real import step (its hooks numbered apart from SetupPage's), started by its button.
const step = () => { cursor = 1000; effects.length = 0; return ImportStep({id: 'telegram_import', n: '2.4',
  state: 'next', title: 'Import Telegram messages', refresh: body.refresh, onSync: body.onSync,
  onStarted: body.onImportStarted}) }
let tree = step()
await find(tree, n => n.type === 'button' && n.props.children === 'Import').props.onClick()
await flush()
// The step's next polls (its interval), until the import is seen idle.
while (polls.length) { body.onSync(await rest('/sync')); await flush() }
out.afterImport = reads.length
// Later polls of the same idle state, or of another one, never read the status again.
body.onSync(LAST); await flush()
body.onSync({...LAST, message_count: 10}); await flush()
out.later = reads.length
page()
cursor = 2000
out.text = text(PageBody({...body}))
console.log(JSON.stringify(out))
""".replace("BEFORE", json.dumps(before))
        .replace("AFTER", json.dumps(after))
        .replace("POLLS", json.dumps(polls))
        .replace("LAST", json.dumps(polls[-1]))
        .replace("IDLE", json.dumps(SYNC_IDLE))
    )
    assert result["beforeStart"] == 1
    assert result["afterImport"] == 2, "exactly one extra status read for the finished import"
    assert result["later"] == 2
    text = result["text"]
    assert "connected · 2 chats · 9 messages in Mordred\u2019s store (all accounts)" in text
    assert "Import Telegram messages\u2713 Done" in text


def test_windows_and_unsupported_statuses_keep_their_pages():
    result = render_page("""
jsx = jsxs = (type, props) => ({type: typeof type === 'function' ? type.name : type, props})
const refresh = () => {}
const windows = PageBody({status: {hardware_kind: 'cng', platform: 'win32', telegram_supported: true}, refresh})
const other = PageBody({status: {platform: 'darwin', hardware_kind: null, telegram_supported: false}, refresh})
console.log(JSON.stringify({windows: windows.props.children.map(c => c && c.type),
  other: other.props.children.map(c => c && c.type)}))
""")
    assert result["windows"] == ["HealthLine", "UpdatePanel", "WindowsSetup", "UninstallSection"]
    assert result["other"] == ["HealthLine", "UpdatePanel", "section", "UninstallSection"]


# -- the Step component ------------------------------------------------------------------------


def step_tree(props: str, script: str = "") -> Any:
    return render_page(
        """
const child = {type: 'input', props: {'aria-label': 'Body field'}}
const view = () => {cursor = 0; return Step(PROPS)}
let tree = view()
SCRIPT
console.log(JSON.stringify(tree))
""".replace("PROPS", props).replace("SCRIPT", script)
    )


def test_done_step_collapses_into_a_summary_with_a_labelled_toggle():
    collapsed = step_tree(
        "{id: 'memory', n: '1.2', title: 'Memory', state: 'done', summary: 'On.', why: 'Because.', children: child}"
    )
    text = json.dumps(collapsed)
    assert "On." in text and "Body field" not in text and "Why this step?" not in text
    opened = step_tree(
        "{id: 'memory', n: '1.2', title: 'Memory', state: 'done', summary: 'On.', why: 'Because.', children: child}",
        "await find(tree, n => n.type === 'button').props.onClick(); tree = view()",
    )
    toggle = render_page("""
const tree = Step({id: 'memory', n: '1.2', title: 'Memory', state: 'done', toggle: 'Change',
  children: {type: 'input', props: {}}})
console.log(JSON.stringify(find(tree, n => n.type === 'button').props))
""")
    assert toggle["aria-expanded"] is False and toggle["aria-controls"] == "mordred-step-memory-details"
    assert toggle["children"] == "Change"
    details = json.dumps(opened)
    assert "Body field" in details and "Why this step?" in details and '"id": "mordred-step-memory-details"' in details


def test_blocked_step_replaces_its_body_with_the_reason_and_a_go_to_button():
    tree = step_tree(
        "{id: 'telegram_import', n: '2.4', title: 'Import', state: 'blocked', blocker: 'needs_restart', "
        "children: child}"
    )
    text = json.dumps(tree, ensure_ascii=False)
    assert "Restart Hermes Desktop to finish step 1.3." in text
    assert "Go to step 1.3" in text and "Body field" not in text
    result = render_page("""
const calls = []
globalThis.document = {getElementById: id => ({scrollIntoView: o => calls.push(['scroll', id, o.block]),
  focus: o => calls.push(['focus', id, o.preventScroll])})}
const tree = Step({id: 'mail', n: '2.5', title: 'Mail', state: 'blocked', blocker: 'needs_memory'})
find(tree, n => n.type === 'button').props.onClick()
console.log(JSON.stringify(calls))
""")
    assert result == [["scroll", "mordred-step-memory", "start"], ["focus", "mordred-step-memory", True]]


def test_running_step_announces_progress_and_disables_its_controls():
    tree = step_tree(
        "{id: 'enclave', n: '1.1', title: 'Helper', state: 'running', progress: 'Building…', children: child}"
    )
    status = render_page("""
const tree = Step({id: 'enclave', n: '1.1', title: 'Helper', state: 'running', progress: 'Building…',
  children: {type: 'input', props: {}}})
console.log(JSON.stringify({status: find(tree, n => n.props && n.props.role === 'status').props,
  fieldset: find(tree, n => n.type === 'fieldset').props}))
""")
    assert status["status"]["aria-live"] == "polite" and "Building…" in status["status"]["children"]
    assert status["fieldset"]["disabled"] is True and status["fieldset"]["children"]["type"] == "input"
    assert "Running" in json.dumps(tree)


def test_attention_step_shows_the_failure_as_an_alert_above_the_body():
    tree = step_tree(
        "{id: 'memory', n: '1.2', title: 'Memory', state: 'attention', "
        "failure: new MordredError('memory_encryption_failed'), children: child}"
    )
    alert = render_page("""
const tree = Step({id: 'memory', n: '1.2', title: 'Memory', state: 'attention',
  failure: new MordredError('memory_encryption_failed')})
console.log(JSON.stringify(find(tree, n => n.props && n.props.role === 'alert').props))
""")
    assert alert["tabIndex"] == -1 and "could not be turned on" in json.dumps(alert)
    assert "Body field" in json.dumps(tree)


def test_every_state_is_announced_as_text():
    result = render_page("""
const out = {}
for (const state of ['done', 'next', 'todo', 'blocked', 'running', 'attention']) {
  const tree = Step({id: 'x', n: '9.9', title: 'T', state})
  const badge = find(tree, n => n.type === 'h3').props.children[1]
  out[state] = badge.props.children.filter(Boolean).map(c => ({hidden: c.props['aria-hidden'] === true,
    text: c.props.children,
    visuallyHidden: Boolean(c.props.style && c.props.style.clip)}))
}
console.log(JSON.stringify(out))
""")
    for state, text in BADGE_TEXT.items():
        spoken = [part for part in result[state] if not part["hidden"]]
        assert [part["text"] for part in spoken] == [text], state
    assert result["todo"][0]["visuallyHidden"] is True


def test_steps_without_state_render_exactly_as_before():
    """Windows passes `done`: the card keeps its old heading, border and hidden body."""
    result = render_page("""
const child = {type: 'p', props: {children: 'body'}}
console.log(JSON.stringify({done: Step({n: 2, title: 'Encrypt Hermes memory', done: true, children: child}),
  open: Step({n: 5, title: 'Connect Telegram (read-only)', done: false, children: child})}))
""")
    border = {"border": "1px solid var(--border, #333)", "borderRadius": 10, "padding": 16, "marginBottom": 12}
    assert result["done"] == {
        "type": "section",
        "props": {
            "style": border,
            "children": [
                {"type": "h3", "props": {"style": {"margin": "0 0 8px"}, "children": "\u2713  Encrypt Hermes memory"}},
                None,
            ],
        },
    }
    assert result["open"]["props"]["children"][0]["props"]["children"] == "5  Connect Telegram (read-only)"
    assert result["open"]["props"]["children"][1] == {"type": "p", "props": {"children": "body"}}


def test_radio_group_is_a_fieldset_with_a_legend():
    result = render_page("""
let picked = null
const tree = RadioGroup({legend: 'Which folder holds your sent mail?', name: 'sent', value: 'b',
  options: [{value: 'a', label: 'Sent'}, {value: 'b', label: 'Gesendet', detail: 'German'}],
  onChange: v => {picked = v}})
find(tree, n => n.type === 'input' && n.props.value === 'a').props.onChange()
console.log(JSON.stringify({tree, picked}))
""")
    assert result["tree"]["type"] == "fieldset"
    assert result["tree"]["props"]["children"][0] == {
        "type": "legend",
        "props": {"style": {"padding": 0, "marginBottom": 4}, "children": "Which folder holds your sent mail?"},
    }
    assert result["picked"] == "a"
    assert '"checked": true' in json.dumps(result["tree"])


# -- overview ------------------------------------------------------------------------------------


def rows(status: dict[str, Any], sync: dict[str, Any] | None = None) -> dict[str, tuple[str, str]]:
    result = render_page(
        f"console.log(JSON.stringify(overviewRows({json.dumps(status)}, {json.dumps(sync)}, {NOW_MS})))"
    )
    return {row["key"]: (row["dot"], row["detail"]) for row in result}


def test_overview_from_an_older_api_asks_for_an_update_and_uses_in_process_counts():
    result = rows(mac(), SYNC_COUNTS)
    assert result["model"] == ("done", "e2ee-deepseek-v4-flash (Venice private)")
    assert result["protection"] == (
        "attention",
        "Secure Enclave · memory encrypted · databases: Update Mordred to use this",
    )
    assert result["telegram"] == ("done", "connected · 3 chats · 25 messages")
    assert result["mail"] == ("attention", "Update Mordred to use this")
    # In-process counts restart at 0 with the backend: never "nothing imported".
    assert rows(mac())["telegram"] == ("done", "connected")


def test_overview_on_linux_says_databases_and_mail_are_not_available():
    result = rows(linux(memory=False, login=False))
    assert result["protection"] == ("partial", "TPM 2.0 · memory not encrypted · Databases: not available on Linux")
    assert result["mail"] == ("not_started", "not available on Linux")
    assert result["telegram"] == ("not_started", "not connected")


def test_overview_from_version_4_reads_the_store_and_the_mailbox_label():
    result = rows(mac(**v4(mail=MAIL_SET_UP, mail_messages=40)), {**SYNC_COUNTS, "message_count": 0})
    assert result["protection"] == ("done", "Secure Enclave · vault · memory encrypted · databases on")
    assert result["telegram"] == ("done", "connected · 3 chats · 25 messages in Mordred\u2019s store (all accounts)")
    assert result["mail"] == ("done", "account work · 40 messages · last fetch 2 hours ago (complete)")
    failed = rows(mac(**v4(mail=MAIL_FAILED)))
    assert failed["mail"] == ("attention", "account work · 0 messages · last fetch 1 minute ago (imap_auth_failed)")
    odd = rows(mac(**v4(mail={**MAIL_FAILED, "last_attempt": {"at": NOW_MS // 1000 - 60, "error": "<b>x</b>"}})))
    assert odd["mail"] == ("attention", "account work · 0 messages · last fetch 1 minute ago (failed)")
    partial = {**MAIL_SET_UP, "last_attempt": {"at": NOW_MS // 1000 - 300, "error": None, "partial": True}}
    assert rows(mac(**v4(mail=partial)))["mail"] == (
        "done",
        "account work · 0 messages · last fetch 5 minutes ago (partial)",
    )
    never = {**MAIL_SET_UP, "last_success": None, "last_attempt": None}
    assert rows(mac(**v4(mail=never)))["mail"] == ("done", "account work · 0 messages · never fetched")
    residue = rows(mac(**v4(mail={"configured": False, "residue": "credentials_left"})))
    assert residue["mail"] == ("attention", "leftover credentials · remove them in step 2.5")
    restart = rows(mac(**v4(protected=False, available=False, code="unprotected_process")))
    assert restart["protection"] == (
        "partial",
        "Secure Enclave · vault · memory encrypted · databases: restart Hermes Desktop",
    )
    attention = rows(mac(**v4(journal=True)))
    assert attention["protection"] == (
        "attention",
        "Secure Enclave · vault · memory encrypted · databases: needs attention",
    )
    pending = rows(mac(**v4(armed=False, encrypt_pending=True, available=False, code="conversion_pending")))
    assert pending["protection"] == (
        "partial",
        "Secure Enclave · vault · memory encrypted · databases: converting at next restart",
    )
    assert pending["telegram"] == ("partial", "connected · counts after a restart")
    nothing = ("partial", "connected · nothing in Mordred\u2019s store yet")
    assert rows(mac(**v4(telegram=(0, 0))))["telegram"] == nothing
    assert rows(mac(**v4(available=False, code="store_uninitialised")))["telegram"] == nothing
    assert rows(mac(**v4()))["mail"] == ("not_started", "not set up")


@pytest.mark.parametrize(
    "vault,memory,expected",
    [
        (VAULT_NONE, False, ("partial", "Secure Enclave · no vault · memory not encrypted · databases off")),
        (
            {**VAULT_READY, "env_enrolled": False},
            False,
            ("partial", "Secure Enclave · vault without .env · memory not encrypted · databases off"),
        ),
        (
            {**VAULT_NONE, "exists": True, "optout": True},
            False,
            ("attention", "Secure Enclave · vault without .env · memory not encrypted · databases off"),
        ),
        (None, True, ("partial", "Secure Enclave · memory encrypted · databases off")),
    ],
    ids=["no-vault", "vault-without-env", "env-opted-out", "api-without-vault"],
)
def test_overview_protection_row_names_the_vault(vault, memory, expected):
    status = mac(memory=memory, **v4(vault=vault, armed=False, available=False, code="not_armed"))
    assert rows(status)["protection"] == expected


def test_overview_model_row_states():
    unverified = mac()
    unverified["hermes_model"] = {"model": "deepseek-v4-flash", "kind": "venice", "private": None, "ok": False}
    assert rows(unverified)["model"] == ("partial", "deepseek-v4-flash (not verified with Venice yet)")
    public = mac()
    public["hermes_model"] = {"model": "gpt-x", "kind": "other", "private": None, "ok": False}
    assert rows(public)["model"] == ("attention", "gpt-x · not private")
    local = mac()
    local["hermes_model"] = {"model": "qwen", "kind": "local", "private": True, "ok": True}
    assert rows(local)["model"] == ("done", "qwen (local, this host only)")


@pytest.mark.parametrize("status,label", [(mac(), "Go to Protect this Mac"), (linux(), "Go to Protect this host")])
def test_overview_go_link_names_its_group_and_focuses_the_heading(status, label):
    result = render_page(
        """
const calls = []
globalThis.document = {getElementById: id => ({scrollIntoView: () => calls.push(['scroll', id]),
  focus: () => calls.push(['focus', id])})}
const status = STATUS
const tree = Overview({rows: overviewRows(status), layout: pageLayout(status)})
const go = find(tree, n => n.type === 'button' && n.props['aria-label'] === 'LABEL')
go.props.onClick()
console.log(JSON.stringify({calls, text: go.props.children}))
""".replace("STATUS", json.dumps(status)).replace("LABEL", label)
    )
    assert result == {"calls": [["scroll", "mordred-group-protect"], ["focus", "mordred-group-protect"]], "text": "Go"}


# -- memory, secrets, refresh --------------------------------------------------------------------


# RestartHermesControl has its own hooks; the harness numbers hooks globally, so it is
# kept opaque here (its behaviour is covered by test_desktop_windows_page.py).
MEMORY_SCRIPT = """
const render = jsx
jsx = jsxs = (type, props) =>
  type === RestartHermesControl ? {type: 'RestartHermesControl', props} : render(type, props)
const requests = []
rest = async (path, init) => {requests.push([path, init.body]); return RESPONSE}
let refreshes = 0
const refresh = () => {refreshes++}
const view = () => {cursor = 0; return MemoryStep({id: 'memory', n: '1.2', state: 'next', refresh, hardwareKind: KIND})}
let tree = view()
SETUP
await find(tree, n => n.type === 'button' && n.props.children === 'Turn on memory encryption').props.onClick()
tree = view()
const buttons = []
const visit = node => {
  if (!node || typeof node !== 'object') return
  if (Array.isArray(node)) { node.forEach(visit); return }
  if (node.type === 'button') buttons.push(node.props.children)
  if (node.type === 'RestartHermesControl') buttons.push('Restart Hermes Desktop')
  const c = node.props && node.props.children
  ;(Array.isArray(c) ? c : [c]).forEach(visit)
}
visit(tree)
console.log(JSON.stringify({requests, refreshes, buttons, tree}))
"""


def memory(response: dict[str, Any], setup: str = "", kind: str = "secure_enclave", split: bool = False) -> Any:
    return render_page(
        MEMORY_SCRIPT.replace("RESPONSE", json.dumps(response))
        .replace("SETUP", setup)
        .replace("KIND", json.dumps(kind) + (", split: true" if split else ""))
    )


def test_memory_step_sends_unattended_by_default_and_shows_the_restart_control():
    result = memory({"ok": True, "restart_required": True})
    assert result["requests"] == [["/memory/enable", {"unattended": True}]]
    assert result["refreshes"] == 1
    assert "Restart Hermes Desktop" in result["buttons"]
    assert "Ask for Touch ID every time Hermes unlocks the vault" in json.dumps(result["tree"])


def test_memory_step_asks_for_touch_id_every_time_when_ticked():
    tick = "find(tree, n => n.type === 'checkbox').props.onCheckedChange(true); tree = view()"
    result = memory({"ok": True, "restart_required": True}, tick)
    assert result["requests"] == [["/memory/enable", {"unattended": False}]]


def test_memory_step_on_linux_sends_only_the_tpm_acknowledgement():
    result = memory({"ok": True, "restart_required": True}, kind="tpm")
    assert result["requests"] == [["/memory/enable", {"acknowledge_tpm_no_recovery": True}]]
    assert "Touch ID" not in json.dumps(result["tree"])


def test_memory_step_shows_the_passphrase_once_then_the_restart_control():
    result = memory({"ok": True, "restart_required": True, "recovery_passphrase": "alpha bravo"})
    assert "alpha bravo" in json.dumps(result["tree"]) and "Restart Hermes Desktop" not in result["buttons"]
    after = render_page(
        MEMORY_SCRIPT.replace("RESPONSE", json.dumps({"ok": True, "recovery_passphrase": "alpha bravo"}))
        .replace("SETUP", "")
        .replace("KIND", '"secure_enclave"')
        .replace(
            "const buttons = []",
            "find(tree, n => n.type === 'checkbox').props.onCheckedChange(true); tree = view()\n"
            "find(tree, n => n.type === 'button' && n.props.children === 'Continue').props.onClick(); tree = view()\n"
            "const buttons = []",
        )
    )
    assert "alpha bravo" not in json.dumps(after["tree"])
    assert "Restart Hermes Desktop" in after["buttons"]


def test_memory_failure_is_an_alert_and_not_a_toast():
    result = memory({"ok": False, "error": "memory_encryption_failed"})
    text = json.dumps(result["tree"])
    assert '"role": "alert"' in text and "could not be turned on" in text


# A component under test with scripted API answers. RestartHermesControl is kept opaque
# (its own hooks would shift the harness's global hook numbering). `answers` are popped
# in order; an answer {"throw": code} makes rest() reject like a transport failure, and
# "HOLD" stays pending until the script calls held.shift()(answer) (a late answer).
COMPONENT_SCRIPT = """
const render = jsx
jsx = jsxs = (type, props) =>
  type === RestartHermesControl ? {type: 'RestartHermesControl', props} : render(type, props)
const requests = []
const answers = ANSWERS
const held = []
rest = async (path, init) => {
  requests.push(init && init.body !== undefined ? [path, init.body] : [path])
  const answer = answers.shift()
  if (answer === 'HOLD') return new Promise(resolve => held.push(resolve))
  if (answer && answer.throw) throw new Error(answer.throw)
  return answer
}
const copied = []
const clipboard = {writeText: t => copied.push(t)}
Object.defineProperty(globalThis, 'navigator', {value: {clipboard}, configurable: true})
let refreshes = 0
const refresh = () => {refreshes++}
const view = () => {cursor = 0; effects.length = 0; return COMPONENT}
const text = node => typeof node === 'string' || typeof node === 'number' ? String(node)
  : !node || typeof node !== 'object' ? '' : Array.isArray(node) ? node.map(text).join('')
  : text(node.props && node.props.children)
const button = (tree, label) => find(tree, n => n.type === 'button' && n.props.children === label)
const press = (tree, label) => {
  const found = button(tree, label)
  if (!found) throw new Error(`no button ${label}`)
  return found.props.onClick()
}
const field = (tree, label) => find(tree, n => n.type === 'input' && n.props['aria-label'] === label)
const type = (tree, label, value) => field(tree, label).props.onChange({target: {value}})
const tick = (tree, label, value = true) =>
  find(find(tree, n => n.type === 'label' && text(n).includes(label)), n => n.type === 'checkbox')
    .props.onCheckedChange(value)
const labels = tree => {
  const out = []
  const visit = node => {
    if (!node || typeof node !== 'object') return
    if (Array.isArray(node)) { node.forEach(visit); return }
    if (node.type === 'button') out.push(node.props.children)
    if (node.type === 'RestartHermesControl') out.push('Restart Hermes Desktop')
    const c = node.props && node.props.children
    ;(Array.isArray(c) ? c : [c]).forEach(visit)
  }
  visit(tree)
  return out
}
const unmount = () => {
  const cleanups = effects.map(f => f()).filter(c => typeof c === 'function')
  cleanups.forEach(c => c())
}
const out = {}
let tree = view()
SCRIPT
console.log(JSON.stringify({requests, refreshes, notifications, copied, out, text: text(tree), buttons: labels(tree),
  tree}))
"""


def component(component_js: str, answers: list[Any], script: str = "") -> Any:
    return render_page(
        COMPONENT_SCRIPT.replace("COMPONENT", component_js)
        .replace("ANSWERS", json.dumps(answers))
        .replace("SCRIPT", script)
    )


WORDS = ["anchor", "bravo", "cactus", "delta", "ember", "falcon", "garden", "harbor"]
PREPARED = {"ok": True, "flow_id": "v1", "passphrase": WORDS}


def vault_step(vault: dict[str, Any], state: str = "next", code: str | None = None) -> str:
    return (
        f"VaultStep({{id: 'vault', n: '1.2a', state: {json.dumps(state)}, code: {json.dumps(code)}, "
        f"vault: {json.dumps(vault)}, refresh}})"
    )


PREPARE = "await press(tree, 'Create the vault'); tree = view()\n"
SAVED = "tick(tree, 'I have written it down'); tree = view()\n"
COMMIT = "await press(tree, 'Create the vault'); tree = view()\n"


def test_vault_step_shows_the_passphrase_before_anything_is_created():
    result = component(vault_step(VAULT_NONE), [PREPARED], PREPARE)
    assert result["requests"] == [["/vault/prepare", {}]]
    words = render_page_words(result["tree"])
    assert words == WORDS
    assert "nothing is created until you continue" in result["text"]
    create = [b for b in result["buttons"] if b == "Create the vault"]
    assert create == ["Create the vault"]
    assert "Ask for Touch ID every time Hermes unlocks the vault" in result["text"]
    # Not ticked yet: the commit stays disabled, and pressing it anyway sends nothing.
    gated = component(vault_step(VAULT_NONE), [PREPARED], PREPARE + COMMIT)
    assert gated["requests"] == [["/vault/prepare", {}]]
    assert '"disabled": true' in json.dumps(find_button(gated["tree"], "Create the vault"))


def render_page_words(tree: Any) -> list[str]:
    words: list[str] = []

    def visit(node: Any) -> None:
        if isinstance(node, list):
            for child in node:
                visit(child)
            return
        if not isinstance(node, dict):
            return
        if node.get("type") == "li":
            words.append(node["props"]["children"])
        visit(node.get("props", {}).get("children"))

    visit(tree)
    return words


def find_button(tree: Any, label: str) -> dict[str, Any] | None:
    if isinstance(tree, list):
        for child in tree:
            found = find_button(child, label)
            if found:
                return found
        return None
    if not isinstance(tree, dict):
        return None
    if tree.get("type") == "button" and tree["props"].get("children") == label:
        return tree
    return find_button(tree.get("props", {}).get("children"), label)


@pytest.mark.parametrize("ask,unattended", [(False, True), (True, False)])
def test_vault_commit_sends_the_touch_id_choice_and_drops_the_passphrase(ask, unattended):
    script = PREPARE + SAVED
    if ask:
        script += "tick(tree, 'Ask for Touch ID every time'); tree = view()\n"
    result = component(vault_step(VAULT_NONE), [PREPARED, {"ok": True}], script + COMMIT)
    assert result["requests"] == [["/vault/prepare", {}], ["/vault/v1/commit", {"unattended": unattended}]]
    assert result["refreshes"] == 1
    assert render_page_words(result["tree"]) == []
    assert "Vault created and .env moved into it." in result["text"]
    assert "Restart Hermes Desktop" in result["buttons"]
    assert result["notifications"] == [{"kind": "success", "message": "Vault created."}]
    for word in WORDS:
        assert word not in json.dumps(result["notifications"])
        assert word not in result["text"]


def test_vault_passphrase_is_selectable_text_never_copied_or_notified():
    """A clipboard manager would keep the recovery passphrase: no copy button, only selectable words."""
    result = component(vault_step(VAULT_NONE), [PREPARED], PREPARE)
    assert not any("Copy" in str(label) for label in result["buttons"])
    words = find_tree(result["tree"], "ol")
    assert words["props"]["style"]["userSelect"] == "text"
    assert (
        "clipboard" not in source()[source().index("function VaultCommitCard") : source().index("function VaultStep")]
    )
    assert result["copied"] == [] and result["notifications"] == []


@pytest.mark.parametrize(
    "script",
    [
        "press(tree, 'Cancel'); tree = view()\n",
        "unmount(); tree = view()\n",
    ],
    ids=["cancel", "unmount"],
)
def test_vault_passphrase_is_dropped_on_cancel_and_unmount(script):
    result = component(vault_step(VAULT_NONE), [PREPARED], PREPARE + SAVED + script)
    assert render_page_words(result["tree"]) == []
    assert all(word not in json.dumps(result["tree"]) for word in WORDS)
    assert result["requests"] == [["/vault/prepare", {}]]


# `/vault/prepare` for an existing vault whose .env is not enrolled: no passphrase exists.
REUSE = {"ok": True, "flow_id": "v2", "passphrase": None, "passphrase_reused": True}
MOVE = "await press(tree, 'Move .env into the vault'); tree = view()\n"


@pytest.mark.parametrize("ask,unattended", [(False, True), (True, False)])
def test_an_existing_vault_skips_the_passphrase_card_and_commits_straight_away(ask, unattended):
    script = MOVE + "out.card = text(tree)\nout.disabled = button(tree, 'Move .env into the vault').props.disabled\n"
    if ask:
        script += "tick(tree, 'Ask for Touch ID every time'); tree = view()\n"
    result = component(
        vault_step({**VAULT_NONE, "exists": True}), [REUSE, {"ok": True, "passphrase_reused": True}], script + MOVE
    )
    card = result["out"]["card"]
    assert (
        "The vault already exists; its recovery passphrase is the one shown when it was created. "
        ".env will be moved into it." in card
    )
    assert "I have written it down" not in card and "Your recovery passphrase" not in card
    assert "Ask for Touch ID every time Hermes unlocks the vault" in card
    assert result["out"]["disabled"] is False
    assert result["requests"] == [["/vault/prepare", {}], ["/vault/v2/commit", {"unattended": unattended}]]
    assert (
        ".env was moved into the existing vault; its recovery passphrase is the one shown when it was created."
        in (result["text"])
    )
    assert "the words shown here were not used" not in result["text"]
    assert result["notifications"] == [{"kind": "success", "message": ".env moved into the existing vault."}]


def test_words_shown_but_an_existing_vault_kept_says_they_were_not_used():
    result = component(
        vault_step(VAULT_NONE), [PREPARED, {"ok": True, "passphrase_reused": True}], PREPARE + SAVED + COMMIT
    )
    assert "the words shown here were not used" in result["text"]


@pytest.mark.parametrize(
    "answer",
    [
        {"ok": True, "flow_id": "v3", "passphrase": None},
        {"ok": True, "flow_id": "v3", "passphrase": []},
        {"ok": True, "passphrase": WORDS},
    ],
    ids=["no-words-not-reused", "empty-words", "no-flow"],
)
def test_a_malformed_prepare_answer_shows_no_card(answer):
    result = component(vault_step(VAULT_NONE), [answer], PREPARE)
    assert "Your recovery passphrase" not in result["text"] and "Move .env into the vault" not in result["buttons"]
    assert '"role": "alert"' in json.dumps(result["tree"])


@pytest.mark.parametrize(
    "code,kept",
    [
        ("vault_flow_expired", False),
        ("vault_exists", False),
        ("env_optout", False),
        ("memory_operation_in_progress", True),
    ],
)
def test_vault_commit_failures_end_the_flow_unless_the_ceremony_was_busy(code, kept):
    result = component(vault_step(VAULT_NONE), [PREPARED, {"ok": False, "error": code}], PREPARE + SAVED + COMMIT)
    assert (render_page_words(result["tree"]) == WORDS) is kept
    alert = json.dumps(result["tree"], ensure_ascii=False)
    assert '"role": "alert"' in alert
    assert result["refreshes"] == 1
    assert result["notifications"] == []


def test_vault_step_states_from_status():
    optout = component(vault_step({**VAULT_NONE, "exists": True, "optout": True}, "attention", "env_optout"), [])
    assert "hermes-mordred encryption enable env" in optout["text"]
    assert "Create the vault" not in optout["buttons"] and "Move .env into the vault" not in optout["buttons"]
    done = component(vault_step(VAULT_READY, "done"), [])
    assert "On · .env is in the vault · opens without Touch ID while you are logged in." in done["text"]
    assert "Restart Hermes Desktop" not in done["buttons"]
    attended = component(vault_step({**VAULT_READY, "unattended": False}, "done"), [])
    assert "Touch ID on every unlock" in attended["text"]
    waiting = component(vault_step({**VAULT_READY, "env_injecting": False}, "done"), [])
    assert "Restart Hermes Desktop so Hermes reads .env from the vault" in waiting["text"]
    assert "Restart Hermes Desktop" in waiting["buttons"]


ANCHOR = "mordred-hermes.vault.0123456789abcdef"
REMEDY = f"security delete-generic-password -s mordred-hermes.vault.anchor -a {ANCHOR}"


@pytest.mark.parametrize(
    "info,command,note",
    [
        ({"anchor_store": "legacy", "anchor_identity": ANCHOR, "remedy": REMEDY}, True, "Run this command in Terminal"),
        ({"anchor_store": "legacy", "anchor_identity": ANCHOR}, False, "An anchor remains"),
        ({"anchor_store": "helper", "anchor_identity": ANCHOR}, False, "held by the hardware helper"),
        ({"anchor_store": "unknown", "anchor_identity": ANCHOR}, False, "An anchor remains"),
        # Only the exact command renders; anything else falls back to the note.
        ({"anchor_store": "legacy", "remedy": REMEDY + "; rm -rf ~"}, False, "An anchor remains"),
        ({"anchor_store": "__proto__"}, False, "An anchor remains"),
    ],
    ids=["legacy-with-remedy", "legacy-without-remedy", "helper", "unknown", "bad-remedy", "odd-store"],
)
def test_stale_anchor_shows_the_command_only_when_the_api_sends_it(info, command, note):
    result = render_page(
        """
const error = new MordredError('vault_anchor_stale', INFO)
const tree = StepFailure({error})
const code = find(tree, n => n.type === 'code')
const copy = find(tree, n => n.type === 'button')
console.log(JSON.stringify({tree, code: code && code.props.children, copy: copy && copy.props.children}))
""".replace("INFO", json.dumps(info))
    )
    text = json.dumps(result["tree"], ensure_ascii=False)
    assert note in text
    assert "Nothing was changed" not in text
    if command:
        assert result["code"] == REMEDY and result["copy"] == "Copy command"
    else:
        assert result["code"] is None and result["copy"] is None
        assert "security delete-generic-password" not in text


def test_vault_commit_failure_with_a_stale_anchor_renders_its_remedy():
    answer = {
        "ok": False,
        "error": "vault_anchor_stale",
        "anchor_store": "legacy",
        "anchor_identity": ANCHOR,
        "remedy": REMEDY,
    }
    result = component(vault_step(VAULT_NONE), [PREPARED, answer], PREPARE + SAVED + COMMIT)
    assert REMEDY in result["text"] and "Copy command" in result["buttons"]
    assert render_page_words(result["tree"]) == []


def test_memory_retry_line_names_only_codes_the_page_knows():
    unknown = memory({"ok": False, "error": "secret_canary"}, kind="secure_enclave", split=True)
    text = json.dumps(unknown["tree"], ensure_ascii=False)
    assert "Vault created, memory encryption failed; retry." in text
    assert "secret_canary" not in text
    assert "The request failed." in text, "StepFailure falls back to the fixed sentence"


def test_unknown_fetch_codes_are_never_shown_verbatim():
    failed = {**MAIL_SET_UP, "last_attempt": {"at": NOW_MS // 1000 - 60, "error": "secret_canary", "partial": False}}
    assert rows(mac(**v4(mail=failed)))["mail"] == (
        "attention",
        "account work · 0 messages · last fetch 1 minute ago (failed)",
    )
    card = component(mail_step(mac(**v4(mail=failed)), "attention", "failed"), [], FAST)
    assert "Last attempt: 1 minute ago (failed)." in card["text"] and "secret_canary" not in json.dumps(card["tree"])
    parts = render_page(
        "console.log(JSON.stringify(resultParts({error: 'secret_canary', partial_reason: 'secret_canary'})))"
    )
    assert parts == []


def test_memory_step_after_the_vault_encrypts_memory_only():
    result = memory({"ok": True}, kind="secure_enclave", split=True)
    assert result["requests"] == [["/memory/enable", {}]]
    text = json.dumps(result["tree"], ensure_ascii=False)
    assert "Touch ID every time" not in text and "Encrypt Hermes memory" in text
    assert "and secrets" not in text
    assert "Restart Hermes Desktop" in result["buttons"]
    failed = memory({"ok": False, "error": "memory_encryption_failed"}, kind="secure_enclave", split=True)
    failed_text = json.dumps(failed["tree"], ensure_ascii=False)
    assert "Vault created, memory encryption failed (memory_encryption_failed); retry." in failed_text
    assert '"role": "alert"' in failed_text


# -- step 1.3: databases ---------------------------------------------------------------------------


def databases_step(status: dict[str, Any], state: str = "next", code: str | None = None, restart: bool = False) -> str:
    return (
        f"DatabasesStep({{id: 'databases', n: '1.3', state: {json.dumps(state)}, code: {json.dumps(code)}, "
        f"restart: {json.dumps(restart)}, status: {json.dumps(status)}, refresh}})"
    )


PLAINTEXT_HOME = mac(
    **v4(armed=False, rows=(("state.db", "plaintext"), ("kanban.db", "unreadable")), backups=2, available=False)
)
SCHEDULED_TEXT = "Scheduled. Hermes Desktop keeps its databases open, so they are encrypted the next time Hermes starts"
ARMED_TEXT = "Database encryption is on, but this Hermes Desktop started before it."


def test_databases_table_is_the_preview():
    result = component(databases_step(PLAINTEXT_HOME), [])
    assert result["requests"] == []
    text = result["text"]
    assert "state.dbwill encrypt" in text and "kanban.dbencrypted or unreadable" in text
    assert "2 backup archives in your Hermes home may contain plaintext copies" in text
    assert "Encrypt databases" in result["buttons"]
    single = component(databases_step(mac(**v4(armed=False, backups=1, available=False))), [])
    assert "1 backup archive in your Hermes home" in single["text"]
    empty = component(databases_step(mac(**v4(armed=False, rows=(), available=False))), [])
    assert "No Hermes database files were found yet." in empty["text"]


def test_encrypt_databases_schedules_and_offers_the_restart():
    script = "await press(tree, 'Encrypt databases'); tree = view()\n"
    result = component(
        databases_step(PLAINTEXT_HOME), [{"ok": True, "action": "scheduled", "restart_required": True}], script
    )
    assert result["requests"] == [["/databases/encrypt", {}]]
    assert SCHEDULED_TEXT in result["text"]
    assert "Restart Hermes Desktop" in result["buttons"] and "Encrypt databases" not in result["buttons"]
    assert result["refreshes"] == 1
    restart = component(
        databases_step(mac(**v4(protected=False))),
        [{"ok": True, "action": "needs_restart", "restart_required": True}],
        script,
    )
    assert ARMED_TEXT in restart["text"] and SCHEDULED_TEXT not in restart["text"]
    assert "Restart Hermes Desktop" in restart["buttons"] and "Encrypt databases" not in restart["buttons"]
    done = component(databases_step(PLAINTEXT_HOME), [{"ok": True, "action": "done"}], script)
    assert done["refreshes"] == 1 and "Restart Hermes Desktop" not in done["buttons"]
    assert '"role": "alert"' not in json.dumps(done["tree"])
    unknown = component(databases_step(PLAINTEXT_HOME), [{"ok": True, "action": "nothing"}], script)
    assert '"role": "alert"' in json.dumps(unknown["tree"]) and unknown["refreshes"] == 1


@pytest.mark.parametrize(
    "answer,phrase",
    [
        (
            {"ok": False, "error": "plaintext_in_armed_home"},
            "Quit Hermes Desktop, then run hermes-mordred databases encrypt",
        ),
        ({"ok": True, "action": "attention", "code": "plaintext_in_armed_home"}, "hermes-mordred databases encrypt"),
        ({"ok": False, "error": "stale_pending"}, "older conversion request is still pending"),
        ({"ok": False, "error": "decrypt_pending"}, "Database decryption is pending"),
        ({"ok": False, "error": "journal"}, "left its journal. Run hermes-mordred databases status"),
        ({"ok": False, "error": "databases_failed"}, "The step shows the current state again"),
        ({"ok": False, "error": "databases_unsupported"}, "Database encryption needs macOS with SQLCipher"),
    ],
)
def test_encrypt_databases_failures_are_explained_and_the_status_is_read_again(answer, phrase):
    result = component(
        databases_step(PLAINTEXT_HOME), [answer], "await press(tree, 'Encrypt databases'); tree = view()\n"
    )
    alert = json.dumps(result["tree"], ensure_ascii=False)
    assert '"role": "alert"' in alert and phrase in result["text"]
    if answer.get("error") == "databases_failed":
        # Scheduling may have half-happened: the page re-reads the facts, it never says "nothing changed".
        assert "Nothing was changed" not in result["text"]
    assert result["refreshes"] == 1


@pytest.mark.parametrize(
    "status,text",
    [
        (mac(**v4(armed=False, encrypt_pending=True, available=False)), SCHEDULED_TEXT),
        (mac(**v4(protected=False)), ARMED_TEXT),
    ],
    ids=["scheduled", "armed-before-this-start"],
)
def test_databases_waiting_for_a_restart_offer_only_the_restart(status, text):
    result = component(databases_step(status, restart=True), [])
    assert text in result["text"]
    assert result["buttons"] == ["Restart Hermes Desktop"]


@pytest.mark.parametrize("code", ["plaintext_in_armed_home", "stale_pending", "decrypt_pending", "journal"])
def test_databases_attention_from_status_points_to_terminal_without_an_encrypt_button(code):
    result = component(databases_step(mac(**v4(journal=True)), "attention", code), [])
    assert "hermes-mordred databases" in result["text"]
    assert "Encrypt databases" not in result["buttons"]
    assert '"role": "alert"' in json.dumps(result["tree"])


def test_databases_done_says_encrypted_or_unreadable_never_databases_encrypted():
    status = mac(**v4(rows=(("state.db", "unreadable"), ("kanban.db", "unreadable"))))
    result = component(databases_step(status, "done"), [])
    assert "Database encryption: on (2 files encrypted or unreadable)." in result["text"]
    assert "databases encrypted" not in result["text"].lower()


# -- step 2.5: mail --------------------------------------------------------------------------------

# Mail codes beyond the library sets checked directly (SETUP_ERROR_CODES, ERROR_CODES,
# REFUSAL_CODES): the forget refusals and warnings (imports/mail/forget.py) and the
# page's own codes; the setup codes are repeated here as the design's failure table.
MAIL_CODES = (
    "invalid_address",
    "invalid_host",
    "invalid_account",
    "invalid_password",
    "too_many_addresses",
    "mail_already_configured",
    "mail_setup_flow_expired",
    "mail_setup_busy",
    "mail_setup_stale",
    "invalid_selection",
    "sync_in_progress",
    "store_path_unsafe",
    "tee_unavailable",
    "tee_auth_cancelled",
    "touch_id_policy_mismatch",
    "imap_unreachable",
    "imap_auth_failed",
    "imap_protocol",
    "imap_command_refused",
    "routing_unavailable",
    "egress_unsupported",
    "account_mismatch",
    "credentials_changed",
    "credentials_left",
    "key_left",
    "account_unknown",
    "forget_confirm_mismatch",
    "mail_fetch_busy",
    "mail_fetch_timeout",
)
APP_PASSWORD = "abcd efgh ijkl mnop"
ADDRESS = "owner.canary@gmail.com"
MAIL_V4 = mac(**v4(mail_messages=40))
SET_UP = mac(**v4(mail=MAIL_SET_UP, mail_messages=40))
# Polls without waiting, a fixed clock, and a first render that uses both.
FAST = "globalThis.setTimeout = fn => {fn(); return 0}\nDate.now = () => NOW\ntree = view()\n".replace(
    "NOW", str(NOW_MS)
)


def mail_step(status: dict[str, Any], state: str = "next", code: str | None = None) -> str:
    return (
        f"MailStep({{id: 'mail', n: '2.5', state: {json.dumps(state)}, code: {json.dumps(code)}, "
        f"status: {json.dumps(status)}, refresh}})"
    )


FILL = (
    (
        "type(tree, 'Mail address', ADDRESS); tree = view()\n"
        "type(tree, 'Other addresses that are yours', 'me@work.example, alias@example.org;  third@example.net'); "
        "tree = view()\n"
        "type(tree, 'App password', APP_PASSWORD); tree = view()\n"
    )
    .replace("ADDRESS", json.dumps(ADDRESS))
    .replace("APP_PASSWORD", json.dumps(APP_PASSWORD))
)
CONNECT = "await press(tree, 'Connect mailbox'); tree = view()\n"
FIELDS = """
out.fields = {address: field(tree, 'Mail address'), others: field(tree, 'Other addresses that are yours'),
  server: field(tree, 'IMAP server'), account: field(tree, 'Account label'), password: field(tree, 'App password')}
for (const key in out.fields) out.fields[key] = out.fields[key] ? out.fields[key].props.value : null
"""
DONE = {"ok": True, "flow_id": "m1", "step": "done", "question": None, "gmail": True, "account": "mail"}
CLEARED = {"address": "", "others": "", "server": "", "account": "mail", "password": ""}


def test_mail_setup_sends_the_form_and_prefills_the_gmail_server():
    prefilled = component(mail_step(MAIL_V4), [], FILL + FIELDS)
    assert prefilled["out"]["fields"]["server"] == "imap.gmail.com"
    assert prefilled["out"]["fields"]["account"] == "mail"
    result = component(mail_step(MAIL_V4), [DONE], FILL + CONNECT + FIELDS)
    assert result["requests"] == [
        [
            "/mail/setup/start",
            {
                "address": ADDRESS,
                "account": "mail",
                "extra_addresses": ["me@work.example", "alias@example.org", "third@example.net"],
                "app_password": APP_PASSWORD,
                "touch_id": True,
                "imap_host": "imap.gmail.com",
            },
        ]
    ]
    assert result["out"]["fields"] == CLEARED
    assert result["notifications"] == [{"kind": "success", "message": "Mailbox connected (read-only)."}]
    assert "Mailbox connected (read-only)." in result["text"]
    assert result["refreshes"] == 1
    assert APP_PASSWORD not in json.dumps(result["tree"]) and ADDRESS not in json.dumps(result["tree"])


def test_mail_setup_with_another_server_a_label_and_no_touch_id():
    script = (
        "type(tree, 'IMAP server', 'imap.example.org'); tree = view()\n"
        "type(tree, 'Mail address', 'me@example.org'); tree = view()\n"
        "type(tree, 'Account label', ' work '); tree = view()\n"
        "type(tree, 'App password', 'secret-canary'); tree = view()\n"
        "tick(tree, 'Allow syncing without Touch ID'); tree = view()\n" + CONNECT
    )
    result = component(mail_step(MAIL_V4), [DONE], script)
    assert result["requests"] == [
        [
            "/mail/setup/start",
            {
                "address": "me@example.org",
                "account": "work",
                "extra_addresses": [],
                "app_password": "secret-canary",
                "touch_id": False,
                "imap_host": "imap.example.org",
            },
        ]
    ]
    # Without a server and a Gmail address, the backend's default applies (no imap_host).
    bare = component(
        mail_step(MAIL_V4),
        [DONE],
        "type(tree, 'Mail address', 'me@example.org'); tree = view()\n"
        "type(tree, 'App password', 'x'); tree = view()\n" + CONNECT,
    )
    assert "imap_host" not in bare["requests"][0][1]


def test_mail_connect_waits_for_an_address_and_a_password():
    result = component(mail_step(MAIL_V4), [], "")
    assert find_button(result["tree"], "Connect mailbox")["props"]["disabled"] is True
    assert "Before you start (Gmail). Create an app password" in result["text"]
    assert "https://myaccount.google.com/apppasswords" in result["text"]
    assert "never reach the chat, the model, the tools, plugin or browser storage, or logs" in result["text"]
    assert "reader mode" in result["text"] and "never sees" not in result["text"]


FOLDERS = {
    "ok": True,
    "flow_id": "m7",
    "step": "folders",
    "question": "sent",
    "gmail": False,
    "account": "mail",
    "folders": [{"id": "f-sent", "display": "Gesendet"}, {"id": "f-arch", "display": "Archiv"}],
}


@pytest.mark.parametrize("choice,selection", [("Gesendet", "f-sent"), ("No sent folder", None)])
def test_mail_folder_question_sends_the_selection(choice, selection):
    script = (
        FILL
        + CONNECT
        + "out.legend = text(find(tree, n => n.type === 'legend'))\n"
        + "out.disabled = button(tree, 'Finish').props.disabled\n"
        + "out.options = []\n"
        + "find(tree, n => { if (n.type === 'label' && find(n, m => m.props && m.props.type === 'radio'))"
        + " out.options.push(text(n)); return false })\n"
        + "find(find(tree, n => n.type === 'label' && text(n) === CHOICE), n => n.props && n.props.type === 'radio')"
        + ".props.onChange(); tree = view()\n"
        + "await press(tree, 'Finish'); tree = view()\n"
    ).replace("CHOICE", json.dumps(choice))
    result = component(mail_step(MAIL_V4), [FOLDERS, {"ok": True, "step": "done"}], script)
    assert result["out"]["legend"] == "Which folder holds your sent mail? (optional)"
    assert result["out"]["disabled"] is True
    assert result["out"]["options"] == ["Gesendet", "Archiv", "No sent folder"]
    assert result["requests"][1] == ["/mail/setup/m7/finish", {"selection": selection}]
    assert "Gesendet" not in json.dumps(result["tree"]) and "Mailbox connected (read-only)." in result["text"]


def test_gmail_all_mail_question_has_no_none_choice():
    answer = {**FOLDERS, "question": "all_mail", "gmail": True}
    result = component(mail_step(MAIL_V4), [answer], FILL + CONNECT)
    assert "Which folder holds all your mail (Gmail\u2019s “All Mail”)?" in result["text"]
    assert "No sent folder" not in result["text"]


@pytest.mark.parametrize(
    "script,expected",
    [
        ("await press(tree, 'Cancel'); tree = view()\n", [["/mail/setup/m7/cancel", {}]]),
        ("unmount(); tree = view()\n", [["/mail/setup/m7/cancel", {}]]),
    ],
    ids=["cancel", "unmount"],
)
def test_a_pending_mail_flow_is_cancelled_on_cancel_and_unmount(script, expected):
    result = component(mail_step(MAIL_V4), [FOLDERS, {"ok": True}], FILL + CONNECT + script + FIELDS)
    assert result["requests"][1:] == expected
    assert "Gesendet" not in json.dumps(result["tree"])
    assert result["out"]["fields"] == CLEARED


def test_a_pending_mail_flow_is_cancelled_when_the_step_becomes_blocked():
    step = (
        "MailStep({id: 'mail', n: '2.5', state: globalThis.stepState || 'next', blocker: 'needs_restart', "
        f"status: {json.dumps(MAIL_V4)}, refresh}})"
    )
    script = (
        FILL + CONNECT + "globalThis.stepState = 'blocked'; tree = view()\neffects.forEach(f => f()); tree = view()\n"
    )
    result = component(step, [FOLDERS, {"ok": True}], script)
    assert result["requests"][1:] == [["/mail/setup/m7/cancel", {}]]
    assert "Gesendet" not in json.dumps(result["tree"])


# A start answered after the card went away (or was superseded) must release the backend's
# single pending flow at once, or a new setup gets mail_setup_busy until the TTL expires.
LATE_START = FILL + "const pending = press(tree, 'Connect mailbox')\n"
RELEASE = "held.shift()(ANSWER)\nawait pending\ntree = view()\n"


def late_step(status: dict[str, Any]) -> str:
    return (
        "MailStep({id: 'mail', n: '2.5', state: globalThis.stepState || 'next', blocker: 'needs_restart', "
        f"status: {json.dumps(status)}, refresh}})"
    )


@pytest.mark.parametrize("answer,flow", [(FOLDERS, "m7"), (DONE, "m1")], ids=["folders", "done"])
@pytest.mark.parametrize(
    "leave",
    [
        "unmount()\n",
        "globalThis.stepState = 'blocked'; tree = view(); effects.forEach(f => f())\n",
        "globalThis.stepState = 'done'; tree = view(); effects.forEach(f => f())\n",
    ],
    ids=["unmount", "blocked", "done"],
)
def test_a_late_setup_answer_is_cancelled_and_never_shown(answer, flow, leave):
    script = LATE_START + leave + RELEASE.replace("ANSWER", json.dumps(answer))
    result = component(late_step(MAIL_V4), ["HOLD", {"ok": True}], script)
    assert result["requests"][0][0] == "/mail/setup/start"
    assert result["requests"][1:] == [[f"/mail/setup/{flow}/cancel", {}]]
    tree = json.dumps(result["tree"], ensure_ascii=False)
    assert "Gesendet" not in tree and "Archiv" not in tree and "Mailbox connected" not in tree
    assert result["notifications"] == []
    # A late `done` sealed a mailbox: a mounted page reads the status again; nothing else.
    expected = 1 if answer is DONE and not leave.startswith("unmount") else 0
    assert result["refreshes"] == expected


def test_a_superseded_setup_start_is_cancelled_and_the_newer_one_applies():
    newer = {**FOLDERS, "flow_id": "m8"}
    script = (
        FILL
        + "const first = press(tree, 'Connect mailbox')\n"
        + "const second = press(tree, 'Connect mailbox')\n"
        + f"held.shift()({json.dumps(FOLDERS)})\nawait first\n"
        + f"held.shift()({json.dumps(newer)})\nawait second\ntree = view()\n"
        + "out.finish = Boolean(button(tree, 'Finish'))\n"
    )
    result = component(late_step(MAIL_V4), ["HOLD", "HOLD", {"ok": True}], script)
    assert [request[0] for request in result["requests"]] == [
        "/mail/setup/start",
        "/mail/setup/start",
        "/mail/setup/m7/cancel",
    ]
    assert result["out"]["finish"] is True and "Gesendet" in json.dumps(result["tree"])
    finish = component(
        late_step(MAIL_V4),
        ["HOLD", "HOLD", {"ok": True}, {"ok": True, "step": "done"}],
        script
        + "find(find(tree, n => n.type === 'label' && text(n) === 'Archiv'), n => n.props && n.props.type === 'radio')"
        + ".props.onChange(); tree = view()\nawait press(tree, 'Finish'); tree = view()\n",
    )
    assert finish["requests"][-1] == ["/mail/setup/m8/finish", {"selection": "f-arch"}]


def test_a_late_setup_failure_after_unmount_shows_nothing():
    script = (
        LATE_START + "unmount()\n" + RELEASE.replace("ANSWER", json.dumps({"ok": False, "error": "imap_unreachable"}))
    )
    result = component(late_step(MAIL_V4), ["HOLD"], script)
    assert result["requests"][1:] == []
    assert '"role": "alert"' not in json.dumps(result["tree"])


@pytest.mark.parametrize("code,kept", [("invalid_selection", True), ("mail_setup_stale", False)])
def test_mail_finish_failures_keep_the_flow_only_for_a_retry(code, kept):
    script = (
        FILL
        + CONNECT
        + "find(find(tree, n => n.type === 'label' && text(n) === 'Archiv'), n => n.props && n.props.type === 'radio')"
        + ".props.onChange(); tree = view()\n"
        + "await press(tree, 'Finish'); tree = view()\n"
    )
    result = component(mail_step(MAIL_V4), [FOLDERS, {"ok": False, "error": code}, {"ok": True}], script)
    assert ("Archiv" in json.dumps(result["tree"])) is kept
    assert (["/mail/setup/m7/cancel", {}] in result["requests"]) is not kept
    assert '"role": "alert"' in json.dumps(result["tree"])


@pytest.mark.parametrize(
    "answer,phrase",
    [
        ({"error": "imap_auth_failed", "hint": "authentication_failed"}, "The server rejected the address or the app"),
        ({"error": "imap_auth_failed", "hint": "server_alert"}, "The server refused the login with an alert"),
        ({"error": "imap_auth_failed", "hint": "login_disabled"}, "does not allow password login over IMAP"),
        ({"error": "imap_auth_failed", "hint": "gmail_app_password_length"}, "exactly 16 letters"),
        ({"error": "imap_auth_failed"}, "The login was refused. Nothing was stored."),
        ({"error": "imap_unreachable"}, "The server could not be reached"),
        ({"error": "sync_in_progress"}, "A mail fetch or import is running (from Hermes or Terminal)"),
        ({"error": "mail_already_configured"}, "A mailbox is already set up. Remove it below first."),
        ({"error": "mail_setup_busy"}, "Another mail setup is waiting for its folder choice"),
        ({"error": "touch_id_policy_mismatch"}, "Touch ID setting differs from your choice"),
        ({"error": "invalid_address"}, "Enter a mail address"),
        ({"error": "invalid_host"}, "Enter the IMAP server name"),
        ({"error": "invalid_account"}, "The account label must start with a lowercase letter"),
        ({"error": "invalid_password"}, "1 to 256 printable characters"),
        ({"error": "too_many_addresses"}, "at most 20 other addresses"),
    ],
)
def test_mail_setup_failures_are_explained_and_clear_every_input(answer, phrase):
    result = component(mail_step(MAIL_V4), [{"ok": False, **answer}], FILL + CONNECT + FIELDS)
    assert phrase in result["text"]
    assert '"role": "alert"' in json.dumps(result["tree"])
    assert result["out"]["fields"] == CLEARED
    assert result["notifications"] == []
    assert APP_PASSWORD not in json.dumps(result["tree"])


def test_mail_inputs_are_cleared_on_unmount_and_never_shown_after_a_transport_failure():
    unmounted = component(mail_step(MAIL_V4), [], FILL + "unmount(); tree = view()\n" + FIELDS)
    assert unmounted["out"]["fields"] == CLEARED
    broken = component(mail_step(MAIL_V4), [{"throw": "network down"}], FILL + CONNECT + FIELDS)
    assert broken["out"]["fields"] == CLEARED
    assert APP_PASSWORD not in json.dumps(broken["tree"]) + json.dumps(broken["notifications"])


def test_mail_set_up_card_shows_label_scope_policy_history_and_counts():
    result = component(mail_step(SET_UP, "done"), [], FAST)
    text = result["text"]
    assert "Account work · Gmail (All Mail with labels) · Touch ID on each fetch" in text
    assert text.count("Account work") == 1
    assert "Last successful fetch: 2 hours ago." in text and "Last attempt" not in text
    assert "40 messages in Mordred\u2019s store (all accounts)." in text
    assert (
        "Fetch new mail here (reliable). You can also say “sync my mail” in a Hermes chat; if Hermes fails to reach "
        "the tool, see the note on tools.tool_search in Mordred\u2019s USAGE guide. A mail sync or fetch gives Hermes "
        "counts only." in text
    )
    assert "Fetch new mail" in result["buttons"] and "Remove mailbox" in result["buttons"]
    assert field_value(result["tree"], "Fetch at most N messages") == "2000"
    generic = {**MAIL_SET_UP, "gmail": False, "scope": ["inbox", "sent"], "touch_id": False}
    other = component(mail_step(mac(**v4(mail=generic)), "done"), [], FAST)
    assert "Account work · inbox and sent folder · syncs without Touch ID" in other["text"]
    assert "May show a Touch ID prompt." not in other["text"]


def field_value(tree: Any, label: str) -> Any:
    if isinstance(tree, list):
        for child in tree:
            found = field_value(child, label)
            if found is not None:
                return found
        return None
    if not isinstance(tree, dict):
        return None
    props = tree.get("props", {})
    if tree.get("type") == "input" and props.get("aria-label") == label:
        return props.get("value")
    return field_value(props.get("children"), label)


def test_mail_last_attempt_failure_is_the_step_attention():
    result = component(mail_step(mac(**v4(mail=MAIL_FAILED)), "attention", "imap_auth_failed"), [], FAST)
    assert "The fetch stopped: the mail server refused the login." in result["text"]
    assert "Nothing was stored" not in result["text"]
    assert "Last successful fetch: 2 hours ago." in result["text"]
    assert "Last attempt: 1 minute ago (imap_auth_failed)." in result["text"]
    assert "Fetch new mail" in result["buttons"]


FETCHED = {
    "inserted": 37,
    "duplicates": 0,
    "revised": 0,
    "conflicts": 0,
    "fetched": 39,
    "skipped": 2,
    "skipped_oversize": 0,
    "excluded_history": 0,
    "merge_skipped": 0,
    "mailboxes": 1,
    "batches": 1,
    "gmail": True,
    "cursor_reset": False,
    "dry_run": False,
    "partial": True,
    "partial_reason": "time_budget",
    "abandoned": False,
    "lock_retained": False,
    "error": None,
}
FETCH = "await press(tree, 'Fetch new mail'); tree = view()\n"


def test_fetch_sends_the_limits_follows_the_job_and_shows_counts_only():
    script = (
        FAST
        + "type(tree, 'Fetch at most N messages', '100'); tree = view()\n"
        + "tick(tree, 'Also fetch older mail since'); tree = view()\n"
        + "type(tree, 'Fetch older mail since', '2026-01-01'); tree = view()\n"
        + FETCH
        + "out.max = field(tree, 'Fetch at most N messages').props.value\n"
    )
    done = {"ok": True, "job_id": "j9", "kind": "mail_fetch", "state": "done", "progress": {"result": FETCHED}}
    result = component(mail_step(SET_UP, "done"), [{"ok": True, "job_id": "j9"}, done], script)
    assert result["requests"] == [["/mail/fetch", {"max": 100, "since": "2026-01-01"}], ["/jobs/j9"]]
    assert (
        "Result (counts only): inserted 37 · fetched 39 · skipped 2 · mailboxes 1 · batches 1 · Gmail: yes · "
        "partial: yes · stopped by: the time limit." in result["text"]
    )
    assert "Fetch again to continue." in result["text"]
    assert result["out"]["max"] == "2000"
    assert result["refreshes"] == 1
    plain = component(mail_step(SET_UP, "done"), [{"ok": True, "job_id": "j9"}, done], FAST + FETCH)
    assert plain["requests"][0] == ["/mail/fetch", {"max": 2000}]


@pytest.mark.parametrize(
    "script",
    [
        "type(tree, 'Fetch at most N messages', '0'); tree = view()\n",
        "type(tree, 'Fetch at most N messages', '2001'); tree = view()\n",
        "type(tree, 'Fetch at most N messages', '12.5'); tree = view()\n",
        "tick(tree, 'Also fetch older mail since'); tree = view()\n",
    ],
    ids=["zero", "above-2000", "fraction", "since-without-date"],
)
def test_fetch_is_disabled_for_invalid_limits(script):
    result = component(mail_step(SET_UP, "done"), [], script + FETCH)
    assert result["requests"] == []
    assert find_button(result["tree"], "Fetch new mail")["props"]["disabled"] is True


def test_fetch_result_renders_only_result_fields_in_their_order():
    fields = render_page("console.log(JSON.stringify(RESULT_FIELDS))")
    assert {key for key, _ in fields} == set(RESULT_FIELDS) and len(fields) == len(RESULT_FIELDS)
    everything = {key: (True if isinstance(value, bool) else 3) for key, value in FETCHED.items()}
    everything.update(partial_reason="max_messages", error="imap_protocol")
    # Anything outside the closed serializer never renders, nor does free text in a known key.
    everything.update(subject="Hello canary", address="someone@example.org")
    result = render_page(f"console.log(JSON.stringify(resultParts({json.dumps(everything)})))")
    assert len(result) == len(fields)
    for (key, label), part in zip(fields, result, strict=True):
        assert part.startswith(f"{label} ") or part.startswith(f"{label}: "), (key, part)
    assert "canary" not in json.dumps(result) and "someone@example.org" not in json.dumps(result)
    assert result[0] == "inserted 3" and result[-1] == "error: imap_protocol"
    assert "stopped by: the message limit" in result
    free = render_page("console.log(JSON.stringify(resultParts({error: 'Login failed for someone@example.org'})))")
    assert free == []
    nothing = render_page("console.log(JSON.stringify(resultParts({inserted: 0, partial: false, error: null})))")
    assert nothing == []


@pytest.mark.parametrize(
    "end,phrase",
    [
        (
            {"ok": True, "state": "failed", "error": "imap_unreachable", "progress": {}},
            "The fetch stopped: the mail server could not be reached",
        ),
        ({"ok": True, "state": "failed", "error": "tee_auth_cancelled", "progress": {}}, "Touch ID was cancelled."),
        ({"ok": False, "error": "job_not_found"}, "The backend no longer reports that job"),
    ],
)
def test_a_failed_or_lost_fetch_job_is_the_step_attention(end, phrase):
    result = component(mail_step(SET_UP, "done"), [{"ok": True, "job_id": "j9"}, end], FAST + FETCH)
    assert phrase in result["text"]
    assert '"role": "alert"' in json.dumps(result["tree"])


def test_fetch_attaches_to_an_already_running_job():
    done = {"ok": True, "state": "done", "progress": {"result": {**FETCHED, "partial": False, "partial_reason": None}}}
    result = component(
        mail_step(SET_UP, "done"), [{"ok": True, "job_id": "j3", "already_running": True}, done], FAST + FETCH
    )
    assert result["requests"] == [["/mail/fetch", {"max": 2000}], ["/jobs/j3"]]
    assert "A fetch was already running; its result appears here when it ends." in result["text"]
    assert "Result (counts only): inserted 37" in result["text"] and "Fetch again" not in result["text"]


def test_a_running_fetch_in_status_jobs_shows_running_and_is_followed():
    status = mac(jobs=(job("mail_fetch", "j5"),), **v4(mail=MAIL_SET_UP))
    running = component(mail_step(status, "done"), [], FAST)
    assert "Fetching new mail… this may take up to about 10 minutes" in running["text"]
    assert "Fetching…" in running["buttons"]
    assert '"disabled": true' in json.dumps(find_tree(running["tree"], "fieldset"))
    done = {"ok": True, "state": "done", "progress": {"result": FETCHED}}
    followed = component(
        mail_step(status, "done"),
        [done],
        FAST + "effects.map(f => f()); await new Promise(r => setImmediate(r)); tree = view()\n",
    )
    assert followed["requests"] == [["/jobs/j5"]]
    assert "Result (counts only): inserted 37" in followed["text"]


def find_tree(tree: Any, kind: str) -> Any:
    if isinstance(tree, list):
        for child in tree:
            found = find_tree(child, kind)
            if found is not None:
                return found
        return None
    if not isinstance(tree, dict):
        return None
    if tree.get("type") == kind:
        return tree
    return find_tree(tree.get("props", {}).get("children"), kind)


PURGE_LABEL = "Also delete every message imported under account work (including Takeout imports)"
REMOVE_ALL = "await press(tree, 'Remove mailbox and delete its mail'); tree = view()\n"


def test_remove_with_mail_requires_the_typed_phrase_before_calling():
    script = (
        f"tick(tree, {json.dumps(PURGE_LABEL)}); tree = view()\n"
        "type(tree, 'Type delete my data to confirm', 'delete my dat'); tree = view()\n" + REMOVE_ALL
    )
    result = component(mail_step(SET_UP, "done"), [], script)
    assert result["requests"] == []
    assert "Type delete my data exactly to also delete the fetched mail." in result["text"]
    assert field_value(result["tree"], "Type delete my data to confirm") is None


def test_remove_mailbox_with_its_mail_and_show_the_outcome():
    script = (
        f"tick(tree, {json.dumps(PURGE_LABEL)}); tree = view()\n"
        "type(tree, 'Type delete my data to confirm', ' delete my data '); tree = view()\n" + REMOVE_ALL
    )
    answer = {
        "ok": True,
        "had_credentials": True,
        "deleted_messages": 40,
        "cursors_deleted": 2,
        "warnings": ["key_left"],
    }
    result = component(mail_step(SET_UP, "done"), [answer], script)
    assert result["requests"] == [["/mail/forget", {"rows": True, "confirm": "delete my data"}]]
    assert "Mailbox removed. 40 messages and 2 cursors deleted." in result["text"]
    assert "The mailbox key in the Secure Enclave could not be deleted" in result["text"]
    assert result["notifications"] == [{"kind": "success", "message": "Mailbox removed."}]
    assert result["refreshes"] == 1
    plain = component(
        mail_step(SET_UP, "done"),
        [{"ok": True, "had_credentials": True, "deleted_messages": 0, "cursors_deleted": 0, "warnings": []}],
        "await press(tree, 'Remove mailbox'); tree = view()\n",
    )
    assert plain["requests"] == [["/mail/forget", {"rows": False}]]
    assert "Account label to remove" not in json.dumps(plain["tree"])


def test_leftover_credentials_offer_remove_with_the_account_field():
    status = mac(**v4(mail={"configured": False, "residue": "credentials_left"}))
    script = (
        "type(tree, 'Account label to remove', 'work'); tree = view()\n"
        "await press(tree, 'Remove mailbox'); tree = view()\n"
    )
    answer = {"ok": True, "had_credentials": True, "deleted_messages": 0, "cursors_deleted": 0, "warnings": []}
    result = component(mail_step(status, "attention", "credentials_left"), [answer], script)
    assert result["requests"] == [["/mail/forget", {"rows": False, "account": "work"}]]
    shown = component(mail_step(status, "attention", "credentials_left"), [], "")
    assert "Sealed mailbox credentials are still on this Mac." in shown["text"]
    assert "Connect mailbox" not in shown["buttons"]
    assert "Also delete every message imported under account of this mailbox" in shown["text"]


def test_an_unknown_account_after_remove_asks_for_the_label():
    answer = {"ok": True, "had_credentials": True, "deleted_messages": 0, "cursors_deleted": 0}
    answer["warnings"] = ["account_unknown"]
    result = component(mail_step(SET_UP, "done"), [answer], "await press(tree, 'Remove mailbox'); tree = view()\n")
    assert "hermes-mordred mail forget --account LABEL" in result["text"]
    assert field_value(result["tree"], "Account label to remove") == ""


# Canaries typed into masked inputs; none may survive in page state, the rendered
# tree, failure notes or host.notify calls once the step has moved on.
HASH = "deadbeefdeadbeefdeadbeefdeadbeef"
CODE = "97531"
PASSWORD = "pw-canary-2468"
KEY = "venice-canary-1357"
CANARIES = (HASH, CODE, PASSWORD, KEY)

# `answers` are rest() results in order: an object is returned, {"throw": x} is
# thrown, "HOLD" stays pending until the script calls release(answer).
SECRET_SCRIPT = """
const requests = []
const ANSWERS = ANSWER_LIST
let release = null
rest = async (path, init) => {
  requests.push(path)
  const answer = ANSWERS.shift()
  if (answer === 'HOLD') return new Promise(resolve => {release = resolve})
  if (answer && answer.throw) throw answer.throw
  return answer
}
const refresh = () => {}
let props = PROPS
const view = () => {cursor = 0; effects.length = 0; return COMPONENT({...props, refresh})}
const field = (tree, placeholder) => find(tree, n => n.type === 'input' && n.props.placeholder === placeholder)
const type = (tree, placeholder, value) => {
  const input = field(tree, placeholder)
  if (!input) throw new Error('no input ' + placeholder)
  input.props.onChange({target: {value}})
}
const press = (tree, label) => {
  const button = find(tree, n => n.type === 'button' && n.props.children === label)
  if (!button) throw new Error('no button ' + label)
  return button.props.onClick()
}
const runEffects = () => effects.splice(0).map(f => f()).filter(c => typeof c === 'function')
const unmount = () => runEffects().forEach(c => c())
let tree = view()
SCRIPT
console.log(JSON.stringify({tree, states, notifications, requests}))
"""

TG = ("TelegramStep", {"id": "telegram", "n": "2.3", "state": "next", "needsApi": True})
TG_DONE = ("TelegramStep", {"id": "telegram", "n": "2.3", "state": "done", "needsApi": True})
TG_WINDOWS = ("TelegramStep", {"n": 5, "done": False, "needsApi": True})
LLM = ("LlmStep", {"id": "question_model", "n": "2.2", "state": "next", "hermesKey": False})
LLM_DONE = ("LlmStep", {"id": "question_model", "n": "2.2", "state": "done", "hermesKey": False})
LLM_WINDOWS = ("LlmStep", {"n": 4, "done": False, "hermesKey": False})
FLOW = {"ok": True, "flow_id": "f1", "step": "code"}
REJECTED_422 = {
    "throw": {
        "status": 422,
        "body": {"detail": [{"type": "missing", "loc": ["body"], "input": {"api_hash": HASH, "api_key": KEY}}]},
        "message": f'422 {{"detail":[{{"input":"{HASH} {KEY} {CODE} {PASSWORD}"}}]}}',
    }
}


def secret(target: tuple[str, dict[str, Any]], answers: list[Any], script: str) -> Any:
    component, props = target
    return render_page(
        SECRET_SCRIPT.replace("COMPONENT", component)
        .replace("PROPS", json.dumps(props))
        .replace("ANSWER_LIST", json.dumps(answers))
        .replace("SCRIPT", script)
    )


TYPE_HASH = f"type(tree, 'api_hash', '{HASH}'); tree = view()"
TYPE_KEY = f"type(tree, 'Or paste a Venice API key', '{KEY}'); tree = view()"
SEND = "await press(tree, 'Send login code'); tree = view()"
TO_CODE = f"{SEND}\ntype(tree, 'Telegram login code', '{CODE}'); tree = view()"
TO_PASSWORD = (
    f"{SEND}\ntype(tree, 'Telegram login code', '{CODE}'); tree = view()\n"
    "await press(tree, 'Continue'); tree = view()\n"
    f"type(tree, 'Telegram password', '{PASSWORD}'); tree = view()"
)
CONTINUE = "await press(tree, 'Continue'); tree = view()"
USE_KEY = "await press(tree, 'Use this key'); tree = view()"
BLOCK_AND_BACK = (
    "props = {...props, state: 'blocked'}; tree = view(); runEffects()\n"
    "props = {...props, state: 'next'}; tree = view()"
)

SECRET_CASES = {
    # Telegram api_hash.
    "api_hash-success": (TG, [FLOW], f"{TYPE_HASH}\n{SEND}"),
    "api_hash-refused": (TG, [{"ok": False, "error": "invalid_api_credentials"}], f"{TYPE_HASH}\n{SEND}"),
    "api_hash-rejected-422": (TG, [REJECTED_422], f"{TYPE_HASH}\n{SEND}"),
    "api_hash-unmount": (TG, [], f"{TYPE_HASH}\nunmount(); tree = view()"),
    "api_hash-blocked": (TG, [], f"{TYPE_HASH}\n{BLOCK_AND_BACK}"),
    "api_hash-collapse": (
        TG_DONE,
        [],
        f"await press(tree, 'Details'); tree = view()\n{TYPE_HASH}\n"
        "await press(tree, 'Hide'); tree = view()\nawait press(tree, 'Details'); tree = view()",
    ),
    "api_hash-windows-422": (TG_WINDOWS, [REJECTED_422], f"{TYPE_HASH}\n{SEND}"),
    # Telegram login code.
    "code-refused": (TG, [FLOW, {"ok": False, "error": "login_code_invalid"}], f"{TO_CODE}\n{CONTINUE}"),
    "code-success": (TG, [FLOW, {"ok": True, "step": "done"}], f"{TO_CODE}\n{CONTINUE}"),
    "code-cancel": (TG, [FLOW, {"ok": True}], f"{TO_CODE}\npress(tree, 'Cancel'); tree = view()"),
    "code-unmount": (TG, [FLOW], f"{TO_CODE}\nunmount(); tree = view()"),
    "code-late-answer-after-cancel": (
        TG,
        [FLOW, "HOLD", {"ok": True}],
        f"{TO_CODE}\nconst pending = press(tree, 'Continue'); tree = view()\npress(tree, 'Cancel'); tree = view()\n"
        "release({ok: true, step: 'password'}); await pending; tree = view()",
    ),
    "code-windows-refused": (
        TG_WINDOWS,
        [FLOW, {"ok": False, "error": "login_code_invalid"}],
        f"{TO_CODE}\n{CONTINUE}",
    ),
    # Telegram two-step verification password.
    "password-refused": (
        TG,
        [FLOW, {"ok": True, "step": "password"}, {"ok": False, "error": "login_password_invalid"}],
        f"{TO_PASSWORD}\n{CONTINUE}",
    ),
    "password-success": (
        TG,
        [FLOW, {"ok": True, "step": "password"}, {"ok": True, "step": "done"}],
        f"{TO_PASSWORD}\n{CONTINUE}",
    ),
    "password-cancel": (
        TG,
        [FLOW, {"ok": True, "step": "password"}, {"ok": True}],
        f"{TO_PASSWORD}\npress(tree, 'Cancel'); tree = view()",
    ),
    "password-unmount": (TG, [FLOW, {"ok": True, "step": "password"}], f"{TO_PASSWORD}\nunmount(); tree = view()"),
    # Venice key.
    "venice-success": (LLM, [{"ok": True}], f"{TYPE_KEY}\n{USE_KEY}"),
    "venice-refused": (LLM, [{"ok": False, "error": "invalid_request"}], f"{TYPE_KEY}\n{USE_KEY}"),
    "venice-rejected-422": (LLM, [REJECTED_422], f"{TYPE_KEY}\n{USE_KEY}"),
    "venice-unmount": (LLM, [], f"{TYPE_KEY}\nunmount(); tree = view()"),
    "venice-blocked": (LLM, [], f"{TYPE_KEY}\n{BLOCK_AND_BACK}"),
    "venice-collapse": (
        LLM_DONE,
        [],
        f"await press(tree, 'Change'); tree = view()\n{TYPE_KEY}\n"
        "await press(tree, 'Hide'); tree = view()\nawait press(tree, 'Change'); tree = view()",
    ),
    "venice-windows-422": (LLM_WINDOWS, [REJECTED_422], f"{TYPE_KEY}\n{USE_KEY}"),
}


@pytest.mark.parametrize("case", list(SECRET_CASES))
def test_masked_inputs_leave_no_trace_after_success_failure_cancel_collapse_block_and_unmount(case):
    target, answers, script = SECRET_CASES[case]
    result = secret(target, answers, script)
    sinks = json.dumps({"state": result["states"], "tree": result["tree"], "notify": result["notifications"]})
    assert [canary for canary in CANARIES if canary in sinks] == []
    for note in result["notifications"]:
        assert set(note) <= {"error", "kind", "message"}


def test_a_late_answer_after_cancel_changes_nothing():
    target, answers, script = SECRET_CASES["code-late-answer-after-cancel"]
    result = secret(target, answers, script)
    text = json.dumps(result["tree"])
    assert "Telegram password" not in text and "Send login code" in text
    assert result["requests"][-1] == "/telegram/login/f1/cancel"
    assert result["notifications"] == []


def test_a_late_flow_after_collapse_is_cancelled():
    result = secret(
        TG_DONE,
        ["HOLD", {"ok": True}],
        f"await press(tree, 'Details'); tree = view()\n{TYPE_HASH}\n"
        "const pending = press(tree, 'Send login code'); tree = view()\n"
        "await press(tree, 'Hide'); tree = view()\n"
        "release({ok: true, flow_id: 'late', step: 'code'}); await pending; await Promise.resolve(); tree = view()",
    )
    assert result["requests"] == ["/telegram/login/start", "/telegram/login/late/cancel"]
    assert "Telegram login code" not in json.dumps(result["tree"])


def test_running_effects_alone_keeps_what_is_being_typed():
    """The harness runs every effect at once: clearing must come from the state change, not from that."""
    result = secret(LLM, [], f"{TYPE_KEY}\nrunEffects(); tree = view()")
    assert KEY in json.dumps(result["tree"])


def test_failures_are_inline_alerts_on_the_grouped_page_and_toasts_on_windows():
    framework = secret(LLM, [{"ok": False, "error": "invalid_request"}], f"{TYPE_KEY}\n{USE_KEY}")
    alert = json.dumps(framework["tree"])
    assert '"role": "alert"' in alert and "The request was not valid." in alert and framework["notifications"] == []
    legacy = secret(LLM_WINDOWS, [{"ok": False, "error": "invalid_request"}], f"{TYPE_KEY}\n{USE_KEY}")
    assert '"role": "alert"' not in json.dumps(legacy["tree"])
    assert legacy["notifications"] == [{"error": "The request was not valid."}]


def test_a_failed_change_of_a_done_step_shows_and_focuses_its_failure():
    result = secret(
        LLM_DONE,
        [{"ok": False, "error": "invalid_request"}],
        f"await press(tree, 'Change'); tree = view()\n{TYPE_KEY}\n{USE_KEY}",
    )
    tree = result["tree"]
    heading = json.dumps(tree["props"]["children"][0], ensure_ascii=False)
    assert "Done" in heading, "the step keeps its done badge"
    note = tree["props"]["children"][1]
    assert note["props"]["role"] == "alert" and note["props"]["tabIndex"] == -1
    assert "ref" in note["props"], "the note is the focus target"
    assert "The request was not valid." in json.dumps(note)
    effects = render_page(
        """
rest = async () => ({ok: false, error: 'invalid_request'})
const refresh = () => {}
const view = () => {cursor = 0; effects.length = 0; return LlmStep({id: 'q', n: '2.2', state: 'done', refresh})}
let tree = view()
await find(tree, n => n.type === 'button' && n.props.children === 'Change').props.onClick(); tree = view()
await find(tree, n => n.type === 'button' && n.props.children === 'Use local model').props.onClick()
tree = view()
const focused = []
const note = find(tree, n => n.props && n.props.role === 'alert')
note.props.ref.current = {focus: () => focused.push('note')}
effects.splice(0).forEach(f => f())
console.log(JSON.stringify(focused))
"""
    )
    assert effects == ["note"]


def test_import_status_attention_beats_a_stale_poll():
    result = render_page(
        """
const view = state => {
  cursor = 0
  const code = state === 'attention' ? 'no_key' : null
  return ImportStep({id: 'telegram_import', n: '2.4', state, code, refresh: () => {}})
}
// The import's own poll still says it is running.
states = [3, {syncing: true, progress: {dialogs_done: 1, dialogs_total: 3, messages_imported: 4}}]
const attention = view('attention')
const todo = view('todo')
const badge = tree => find(tree, n => n.type === 'h3').props.children[1].props.children[1].props.children
const note = JSON.stringify(find(attention, n => n.props && n.props.role === 'alert'))
console.log(JSON.stringify({attention: badge(attention), note,
  todo: badge(todo)}))
"""
    )
    assert result["attention"] == "Needs attention"
    assert "The database key is not available" in result["note"]
    assert result["todo"] == "Running"


def test_inputs_carry_accessible_names_on_the_grouped_page_only():
    script = """
const inputs = []
const visit = node => {
  if (!node || typeof node !== 'object') return
  if (Array.isArray(node)) { node.forEach(visit); return }
  if (node.type === 'input' && node.props.type !== 'radio') inputs.push(node.props['aria-label'] || null)
  const c = node.props && node.props.children
  ;(Array.isArray(c) ? c : [c]).forEach(visit)
}
const refresh = () => {}
visit(TelegramStep({STATE, n: '2.3', needsApi: true, refresh}))
visit(LlmStep({STATE, n: '2.2', hermesKey: true, refresh}))
visit(ImportStep({STATE, n: '2.4', ready: true, refresh}))
console.log(JSON.stringify(inputs))
"""
    grouped = render_page(script.replace("STATE", "id: 'x', state: 'next'"))
    assert grouped == [
        "api_id",
        "api_hash",
        "Phone number",
        "Venice API key",
        "Local endpoint",
        "Local model name",
        "Days of history to import",
    ]
    assert render_page(script.replace("STATE", "done: false")) == [None] * 7


def test_windows_rendering_matches_the_snapshot_taken_before_the_framework():
    """Windows and the shared steps in their old mode render as at f782f9cff (only the
    bare #b91c1c became var(--destructive, #b91c1c), as specified)."""
    snapshot = json.loads(WINDOWS_SNAPSHOT.read_text(encoding="utf-8"))
    current = render_page(WINDOWS_SCENARIOS.read_text(encoding="utf-8"))
    current = json.loads(json.dumps(current, ensure_ascii=False).replace("var(--destructive, #b91c1c)", "#b91c1c"))
    assert sorted(current) == sorted(snapshot)
    for name in snapshot:
        assert current[name] == snapshot[name], name


SKELETON = """
// The structure React reconciles by: element type, key, id and labelling, without text.
const skeleton = node => {
  if (Array.isArray(node)) return node.map(skeleton)
  if (!node || typeof node !== 'object' || !node.props) return null
  const {key, id} = node.props
  return [node.type, key ?? null, id ?? null, node.props['aria-labelledby'] ?? null, skeleton(node.props.children)]
}
"""


def test_a_jobs_refresh_keeps_the_page_structure_and_typed_values():
    """The harness cannot mount React: it checks that a refresh changing `jobs.length`
    renders the same element types, keys and ids in the same places (so React keeps
    every component mounted) and, through hook order, that a typed value survives."""
    status = mac(login=False)
    refreshed = copy.deepcopy(status)
    refreshed["jobs"] = [job("update"), job("uninstall", "j2")]
    result = render_page(
        SKELETON
        + """
const view = status => {cursor = 0; return PageBody({status, health: null, refresh: () => {}})}
const phone = tree => find(tree, n => n.type === 'input' && n.props['aria-label'] === 'Phone number')
let tree = view(FIRST)
const before = JSON.stringify(skeleton(tree))
phone(tree).props.onChange({target: {value: '+819012345678'}})
tree = view(SECOND)
const after = JSON.stringify(skeleton(tree))
console.log(JSON.stringify({same: before === after, kept: phone(tree).props.value, size: before.length}))
""".replace("FIRST", json.dumps(status)).replace("SECOND", json.dumps(refreshed))
    )
    assert result["same"] is True and result["size"] > 1000
    assert result["kept"] == "+819012345678"


# -- error text never reaches the page -------------------------------------------------------------

LEAK = "CANARY-7f3e-SECRET"


@pytest.mark.parametrize(
    "thrown,code",
    [
        (
            {
                "status": 422,
                "body": {"detail": [{"input": LEAK}]},
                "message": f'422 {{"detail":[{{"input":"{LEAK}"}}]}}',
            },
            "invalid_response",
        ),
        ({"message": f"TypeError: Failed to fetch {LEAK}"}, "transport_error"),
        ({"status": 404, "message": f"Not Found {LEAK}"}, "backend_unreachable"),
        ({"status": 502, "body": f"<html>{LEAK}</html>"}, "backend_unreachable"),
        ({"status": 500, "message": f"Internal Server Error {LEAK}"}, "invalid_response"),
        ({"status": 409, "body": {"ok": False, "error": "login_code_invalid", "detail": LEAK}}, "login_code_invalid"),
        ({"message": 'HTTP 409 {"ok":false,"error":"sync_in_progress","detail":"' + LEAK + '"}'}, "sync_in_progress"),
        ({"status": 400, "body": {"error": f"<b>{LEAK}</b>"}}, "invalid_response"),
    ],
    ids=["422-echo", "network", "404", "502-html", "500", "body-code", "message-code", "bad-code"],
)
def test_call_keeps_only_a_code_from_a_failed_request(thrown, code):
    result = render_page(
        """
rest = async () => { throw THROWN }
let error = null
try { await call('/llm/venice', {api_key: 'x'}) } catch (e) { error = e }
console.log(JSON.stringify({code: error.code, message: error.message, info: error.info, note: FailureNote({error}),
  step: StepFailure({error})}))
""".replace("THROWN", json.dumps(thrown))
    )
    assert result["code"] == code
    assert result["info"] == {}
    assert LEAK not in json.dumps(result)


@pytest.mark.parametrize(
    "answer",
    [
        {"ok": False, "error": "memory_encryption_failed", "detail": LEAK, "remedy": LEAK, "custody_notice": LEAK},
        {"ok": False, "error": "canary_unknown_code", "detail": LEAK},
        {"ok": False, "error": f"not a code {LEAK}"},
        {"ok": False, "error": "vault_anchor_stale", "remedy": f"rm -rf ~ # {LEAK}"},
        {
            "ok": False,
            "error": "vault_anchor_stale",
            "remedy": f"security delete-generic-password -s mordred-hermes.vault.anchor -a mordred-hermes.vault.{LEAK}",
        },
        f"{LEAK} plain text",
    ],
    ids=["macos-refusal-fields", "unknown-code", "invalid-code", "foreign-remedy", "malformed-remedy", "not-json"],
)
def test_no_response_text_reaches_the_grouped_page(answer):
    result = render_page(
        """
rest = async () => (ANSWER)
const props = {id: 'memory', n: '1.2', state: 'next', refresh: () => {}, hardwareKind: 'secure_enclave'}
const view = () => {cursor = 0; effects.length = 0; return MemoryStep(props)}
let tree = view()
await find(tree, n => n.type === 'button' && n.props.children === 'Turn on memory encryption').props.onClick()
tree = view()
console.log(JSON.stringify({tree, notifications}))
""".replace("ANSWER", json.dumps(answer))
    )
    text = json.dumps(result)
    assert LEAK not in text
    assert '"role": "alert"' in text


def test_the_stale_anchor_remedy_is_rendered_only_in_its_exact_form():
    remedy = "security delete-generic-password -s mordred-hermes.vault.anchor -a mordred-hermes.vault.0123456789abcdef"
    result = render_page(
        """
const error = new MordredError('vault_anchor_stale', {remedy: 'REMEDY'})
console.log(JSON.stringify(StepFailure({error})))
""".replace("REMEDY", remedy)
    )
    text = json.dumps(result)
    assert text.count(remedy) == 1 and "Copy command" in text
    assert "Keychain anchor remains" in text


def test_toasts_and_job_events_use_only_fixed_text():
    result = render_page(
        """
rest = async () => { throw {status: 422, body: {detail: [{input: 'LEAK'}]}, message: '422 LEAK'} }
const view = () => {cursor = 0; return LlmStep({done: false, hermesKey: false, refresh: () => {}})}
let tree = view()
const key = find(tree, n => n.type === 'input' && n.props.placeholder === 'Or paste a Venice API key')
key.props.onChange({target: {value: 'k'}})
tree = view()
await find(tree, n => n.type === 'button' && n.props.children === 'Use this key').props.onClick()
let handler = null
plugin.register({rest, register: () => {}, setTimeout: () => {}, onEvent: (name, fn) => {handler = fn}})
handler({payload: {state: 'failed', kind: 'enclave', error: 'LEAK not a code'}})
handler({payload: {state: 'failed', kind: 'enclave', error: 'constructor'}})
console.log(JSON.stringify(notifications))
""".replace("LEAK", LEAK)
    )
    assert LEAK not in json.dumps(result)
    generic = "The request failed. Check the Mordred page again or run hermes-mordred status in Terminal."
    assert result == [
        {
            "error": "Mordred\u2019s local API gave an answer this page does not understand. "
            "Check the Mordred page again or run hermes-mordred status in Terminal."
        },
        {"kind": "error", "message": f"Mordred: {generic}"},
        {"kind": "error", "message": f"Mordred: {generic}"},
    ]


def test_explain_never_interpolates_unknown_codes():
    result = render_page(
        "console.log(JSON.stringify(['__proto__', 'constructor', 'toString', null, undefined, 42, 'unknown_code']"
        ".map(code => explain(code))))"
    )
    assert result == ["The request failed. Check the Mordred page again or run hermes-mordred status in Terminal."] * 7


# -- copy ----------------------------------------------------------------------------------------


def ask_text(macos: bool) -> str:
    return render_page(
        """
const text = node => typeof node === 'string' ? node : !node || typeof node !== 'object' ? ''
  : Array.isArray(node) ? node.map(text).join('') : text(node.props && node.props.children)
console.log(JSON.stringify(text(AskHermes({macos: MACOS}))))
""".replace("MACOS", json.dumps(macos))
    )


def test_ask_hermes_copy_states_what_hermes_reads_and_reader_mode():
    text = ask_text(True)
    assert "After a history question the chat is in reader mode" in text
    assert (
        "cannot write files, run commands, send messages, schedule or delegate in that chat until you start a new chat"
        in text
    )
    assert "mordred_history_search" in text and "head line" in text
    assert "Fetch new mail in step 2.5 (reliable)" in text and "“sync my mail”" in text and "tools.tool_search" in text
    assert "never reach the chat, the model, the tools, storage or logs" in text
    assert "counts only" in text
    assert "hermes-mordred mail import" in text and "hermes-mordred telegram sync --days 0" in text
    # The privacy boundary is stated precisely: Hermes does read matching messages when asked.
    assert "never sees" not in text.lower() and "Hermes reads the matching messages" in text


def test_ask_hermes_copy_on_linux_has_no_mail():
    text = ask_text(False)
    assert "reader mode" in text and "mail" not in text.lower()


def test_why_blocks_are_native_details_with_the_design_copy():
    why = block("WHY")
    assert "never leaves this Mac\u2019s Secure Enclave" in why
    assert "Everything Hermes reads goes to its chat model" in why
    assert "its api_id and api_hash identify it, not you" in why
    assert "mordred.db" in why and "nothing is marked read, moved, deleted or sent" in why
    tree = render_page("console.log(JSON.stringify(Why({children: 'Because.'})))")
    assert tree["type"] == "details"
    assert tree["props"]["children"][0] == {
        "type": "summary",
        "props": {"style": {"cursor": "pointer"}, "children": "Why this step?"},
    }
