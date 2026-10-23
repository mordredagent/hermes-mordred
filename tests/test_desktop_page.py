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
from types import SimpleNamespace
from typing import Any

import pytest

from mordred_hermes.imports.mail.imap_sync import ERROR_CODES

from ._desktop_page import block, render_page, source

SDK_NAMES = {"host", "Button", "Checkbox", "Input", "ROUTES_AREA", "SIDEBAR_NAV_AREA", "PALETTE_AREA"}
IMPORT_SOURCES = {"@hermes/plugin-sdk", "react/jsx-runtime", "react"}
BLOCKER_CODES = (
    "needs_hermes_model",
    "needs_enclave",
    "needs_memory",
    "needs_databases",
    "needs_restart",
    "needs_login",
    "needs_question_model",
)
IMAP_HINT_CODES = ("authentication_failed", "server_alert", "login_disabled", "gmail_app_password_length")
STORE_GATE_CODES = (
    "not_armed",
    "conversion_pending",
    "unprotected_process",
    "no_key",
    "plaintext_store",
    "store_unavailable",
    "busy",
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
)
STEP_KEYS = ("enclave", "memory", "databases", "hermes_model", "question_model", "telegram", "telegram_import", "mail")
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


def v4(
    *,
    armed: bool = True,
    pending: bool = False,
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
    return {
        "databases": {
            "supported": supported,
            "armed": armed,
            "pending": pending,
            "journal": False,
            "databases": [{"relative": "state.db", "state": "encrypted" if armed else "plaintext"}],
            "plaintext_backups": 0,
        },
        "imports": {"available": available, "code": code, "sources": sources if available else {}},
        "mail": mail if mail is not None else {"configured": False},
    }


def job(kind: str, job_id: str = "j1") -> dict[str, Any]:
    return {"job_id": job_id, "kind": kind, "state": "running", "error": None, "progress": {"message": "…"}}


MAIL_SET_UP = {
    "configured": True,
    "account": "work",
    "gmail": True,
    "scope": ["all"],
    "touch_id": True,
    "last_fetch": {"at": NOW_MS // 1000 - 7200, "error": None, "partial": False},
}
MAIL_FAILED = {**MAIL_SET_UP, "last_fetch": {"at": NOW_MS // 1000 - 60, "error": "imap_auth_failed", "partial": False}}
SYNC_COUNTS = {"syncing": False, "progress": None, "last_error": None, "dialog_count": 3, "message_count": 25}
OLD = "mordred_update_required"

# (status, /sync answer, expected states): "state", "state:blocker" or "state:code"; None = no such step.
STATE_CASES = {
    "fresh mac, older API": (
        mac(hardware=False, memory=False, model=False, llm=False, login=False),
        None,
        {
            "enclave": "next",
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
        mac(**v4(armed=False, pending=True, available=False, code="conversion_pending")),
        None,
        {
            "enclave": "done",
            "memory": "done",
            "databases": "next",
            "hermes_model": "done",
            "question_model": "done",
            "telegram": "done",
            "telegram_import": "blocked:needs_restart",
            "mail": "blocked:needs_restart",
        },
    ),
    "v4, armed but Hermes not restarted": (
        mac(**v4(available=False, code="unprotected_process")),
        None,
        {
            "enclave": "done",
            "memory": "done",
            "databases": "done",
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


def compact(states: dict[str, Any]) -> dict[str, str | None]:
    result: dict[str, str | None] = {}
    for key in STEP_KEYS:
        entry = states.get(key)
        if entry is None:
            result[key] = None
            continue
        detail = entry.get("blocker") or entry.get("code")
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
def test_backend_answers_version_4_like_version_3(monkeypatch, platform):
    """The page may send 4 to this Mordred: `status` compares versions with >=, so 4 is treated as 3."""
    pytest.importorskip("fastapi")
    from mordred_hermes.desktop import api
    from mordred_hermes.wizard import telegram_setup_cli

    monkeypatch.setattr(api, "sys", SimpleNamespace(platform=platform))
    monkeypatch.setattr(telegram_setup_cli, "run_checks", lambda: [telegram_setup_cli.Check("hardware", True, "ok")])

    async def model():
        return {"ok": True}

    monkeypatch.setattr(api, "hermes_model_check", model)
    monkeypatch.setattr(api, "_store", lambda: SimpleNamespace(flags=lambda: {}))
    monkeypatch.setattr(api, "_hermes_venice_key", lambda: None)
    assert asyncio.run(api.status(client_version=4)) == asyncio.run(api.status(client_version=3))


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
    for code in sorted(set(PAGE_CODES) | set(ERROR_CODES) | set(STORE_GATE_CODES)):
        assert re.search(rf"^  {re.escape(code)}:", messages, re.M), code
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
                {"type": "h3", "props": {"style": {"margin": "0 0 8px"}, "children": "✓  Encrypt Hermes memory"}},
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
    assert result["protection"] == ("done", "Secure Enclave · memory encrypted · databases on")
    assert result["telegram"] == ("done", "connected · 3 chats · 25 messages")
    assert result["mail"] == ("done", "account work · 40 messages · last fetch 2 hours ago (complete)")
    failed = rows(mac(**v4(mail=MAIL_FAILED)))
    assert failed["mail"] == ("attention", "account work · 0 messages · last fetch 1 minute ago (imap_auth_failed)")
    pending = rows(mac(**v4(armed=False, pending=True, available=False, code="conversion_pending")))
    assert pending["protection"] == (
        "partial",
        "Secure Enclave · memory encrypted · databases: converting at next restart",
    )
    assert pending["telegram"] == ("partial", "connected · counts after a restart")
    assert rows(mac(**v4(telegram=(0, 0))))["telegram"] == ("partial", "connected · nothing imported yet")
    assert rows(mac(**v4()))["mail"] == ("not_started", "not set up")


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


def memory(response: dict[str, Any], setup: str = "", kind: str = "secure_enclave") -> Any:
    return render_page(
        MEMORY_SCRIPT.replace("RESPONSE", json.dumps(response))
        .replace("SETUP", setup)
        .replace("KIND", json.dumps(kind))
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


SECRET_SCRIPT = """
rest = async (path, init) => {requests.push(path); return RESPONSES.shift()}
const requests = []
const RESPONSES = ANSWERS
const view = () => {cursor = 0; effects.length = 0; return COMPONENT}
const input = (tree, label) => find(tree, n => n.type === 'input' && n.props['aria-label'] === label)
const press = (tree, label) => find(tree, n => n.type === 'button' && n.props.children === label).props.onClick()
const unmount = () => {
  const cleanups = effects.map(f => f()).filter(c => typeof c === 'function')
  cleanups.forEach(c => c())
}
let tree = view()
SCRIPT
console.log(JSON.stringify({value: VALUE, requests, notifications}))
"""


def secret(component: str, answers: list[Any], script: str, value: str) -> Any:
    return render_page(
        SECRET_SCRIPT.replace("COMPONENT", component)
        .replace("ANSWERS", json.dumps(answers))
        .replace("SCRIPT", script)
        .replace("VALUE", value)
    )


TELEGRAM = "TelegramStep({id: 'telegram', n: '2.3', state: 'next', needsApi: true, refresh: () => {}})"
TELEGRAM_LEGACY = "TelegramStep({n: 4, done: false, needsApi: true, refresh: () => {}})"
LLM = "LlmStep({id: 'question_model', n: '2.2', state: 'next', hermesKey: false, refresh: () => {}})"
LLM_LEGACY = "LlmStep({done: false, hermesKey: false, refresh: () => {}})"
TYPE_HASH = (
    "input(tree, 'api_hash').props.onChange({target: {value: '0123456789abcdef0123456789abcdef'}}); tree = view()"
)
TYPE_KEY = "input(tree, 'Venice API key').props.onChange({target: {value: 'venice-canary'}}); tree = view()"
TO_CODE = (
    "await press(tree, 'Send login code'); tree = view()\n"
    "input(tree, 'Telegram login code').props.onChange({target: {value: '12345'}}); tree = view()"
)


@pytest.mark.parametrize(
    "component,answers,script,value",
    [
        # api_hash: success, failure, unmount (framework and Windows modes).
        (
            TELEGRAM,
            [{"ok": True, "flow_id": "f1", "step": "code"}],
            TYPE_HASH + "\nawait press(tree, 'Send login code'); tree = view()",
            "states[1]",
        ),
        (
            TELEGRAM,
            [{"ok": False, "error": "invalid_api_credentials"}],
            TYPE_HASH + "\nawait press(tree, 'Send login code'); tree = view()",
            "input(tree, 'api_hash').props.value",
        ),
        (
            TELEGRAM_LEGACY,
            [{"ok": False, "error": "invalid_phone"}],
            TYPE_HASH + "\nawait press(tree, 'Send login code'); tree = view()",
            "input(tree, 'api_hash').props.value",
        ),
        (TELEGRAM, [], TYPE_HASH + "\nunmount(); tree = view()", "input(tree, 'api_hash').props.value"),
        # Login code: failure, cancel, unmount.
        (
            TELEGRAM,
            [{"ok": True, "flow_id": "f1", "step": "code"}, {"ok": False, "error": "login_code_invalid"}],
            TO_CODE + "\nawait press(tree, 'Continue'); tree = view()",
            "input(tree, 'Telegram login code').props.value",
        ),
        (
            TELEGRAM,
            [{"ok": True, "flow_id": "f1", "step": "code"}, {"ok": True}],
            TO_CODE + "\npress(tree, 'Cancel'); tree = view()",
            "states[3]",
        ),
        (
            TELEGRAM,
            [{"ok": True, "flow_id": "f1", "step": "code"}],
            TO_CODE + "\nunmount(); tree = view()",
            "input(tree, 'Telegram login code').props.value",
        ),
        (
            TELEGRAM,
            [{"ok": True, "flow_id": "f1", "step": "code"}, {"ok": True, "step": "done"}],
            TO_CODE + "\nawait press(tree, 'Continue'); tree = view()",
            "states[3]",
        ),
        # Venice key: success, failure (framework and Windows modes), unmount.
        (
            LLM,
            [{"ok": True}],
            TYPE_KEY + "\nawait press(tree, 'Use this key'); tree = view()",
            "input(tree, 'Venice API key').props.value",
        ),
        (
            LLM,
            [{"ok": False, "error": "invalid_request"}],
            TYPE_KEY + "\nawait press(tree, 'Use this key'); tree = view()",
            "input(tree, 'Venice API key').props.value",
        ),
        (
            LLM_LEGACY,
            [{"ok": False, "error": "invalid_request"}],
            TYPE_KEY + "\nawait press(tree, 'Use this key'); tree = view()",
            "input(tree, 'Venice API key').props.value",
        ),
        (LLM, [], TYPE_KEY + "\nunmount(); tree = view()", "input(tree, 'Venice API key').props.value"),
    ],
    ids=[
        "api_hash-success",
        "api_hash-failure",
        "api_hash-failure-windows",
        "api_hash-unmount",
        "code-failure",
        "code-cancel",
        "code-unmount",
        "code-success",
        "venice-success",
        "venice-failure",
        "venice-failure-windows",
        "venice-unmount",
    ],
)
def test_masked_inputs_are_cleared_after_success_failure_cancel_and_unmount(component, answers, script, value):
    result = secret(component, answers, script, value)
    assert result["value"] == ""
    assert "0123456789abcdef0123456789abcdef" not in json.dumps(result)
    assert "venice-canary" not in json.dumps(result) and "12345" not in json.dumps(result["value"])


def test_failures_are_inline_alerts_on_the_grouped_page_and_toasts_on_windows():
    framework = secret(
        LLM,
        [{"ok": False, "error": "invalid_request"}],
        TYPE_KEY + "\nawait press(tree, 'Use this key'); tree = view()",
        "tree",
    )
    assert '"role": "alert"' in json.dumps(framework["value"]) and framework["notifications"] == []
    legacy = secret(
        LLM_LEGACY,
        [{"ok": False, "error": "invalid_request"}],
        TYPE_KEY + "\nawait press(tree, 'Use this key'); tree = view()",
        "tree",
    )
    assert '"role": "alert"' not in json.dumps(legacy["value"])
    assert legacy["notifications"] == [{"error": "The request was not valid."}]


def test_inputs_carry_accessible_names():
    result = render_page("""
const inputs = []
const visit = node => {
  if (!node || typeof node !== 'object') return
  if (Array.isArray(node)) { node.forEach(visit); return }
  if (node.type === 'input' && node.props.type !== 'radio') inputs.push(node.props['aria-label'] || null)
  const c = node.props && node.props.children
  ;(Array.isArray(c) ? c : [c]).forEach(visit)
}
const refresh = () => {}
visit(TelegramStep({id: 'telegram', n: '2.3', state: 'next', needsApi: true, refresh}))
visit(LlmStep({id: 'question_model', n: '2.2', state: 'next', hermesKey: true, refresh}))
visit(ImportStep({id: 'telegram_import', n: '2.4', state: 'next', refresh}))
console.log(JSON.stringify(inputs))
""")
    assert result == [
        "api_id",
        "api_hash",
        "Phone number",
        "Venice API key",
        "Local endpoint",
        "Local model name",
        "Days of history to import",
    ]


def test_a_typed_value_survives_a_status_refresh():
    """Refreshes re-render the same components in the same places: nothing remounts or loses input."""
    status = mac(login=False)
    refreshed = copy.deepcopy(status)
    refreshed["jobs"] = [job("update")]
    result = render_page(
        """
const view = status => {cursor = 0; return PageBody({status, health: null, refresh: () => {}})}
const phone = tree => find(tree, n => n.type === 'input' && n.props['aria-label'] === 'Phone number')
let tree = view(FIRST)
phone(tree).props.onChange({target: {value: '+819012345678'}})
tree = view(SECOND)
const kept = phone(tree).props.value
tree = view(FIRST)
console.log(JSON.stringify({kept, again: phone(tree).props.value}))
""".replace("FIRST", json.dumps(status)).replace("SECOND", json.dumps(refreshed))
    )
    assert result == {"kept": "+819012345678", "again": "+819012345678"}


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
