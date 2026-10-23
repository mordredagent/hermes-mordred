"""``/mail/*``: setup start/finish/cancel, the ``mail_fetch`` job and forget, through the seams only."""

from __future__ import annotations

import datetime as dt
import json
import threading
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

pytest.importorskip("fastapi")

from mordred_hermes.desktop import _projections, api
from mordred_hermes.imports.mail.imap_sync import ERROR_CODES, FetchResult

from ._desktop_support import (
    ADDRESS,
    APP_PASSWORD,
    EXTRA,
    FOLDER,
    FakeFlow,
    FakeFolder,
    FakeMailSecrets,
    FakeRefused,
    FakeSetupError,
)

REAL_MAIL_AUDIT = api._mail_audit
SETUP_CODES = sorted(_projections.MAIL_SETUP_CODES - {"invalid_body", "mail_setup_failed"})


def _start_body(**extra: Any) -> dict[str, Any]:
    return {"address": ADDRESS, "extra_addresses": [EXTRA], "app_password": APP_PASSWORD, "account": "work", **extra}


def _memory_off(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "mordred_hermes.extension.telegram.memory_guard.memory_encryption_active", lambda home=None: False
    )


# -- setup ----------------------------------------------------------------------------------------


def test_start_passes_what_was_typed_and_answers_without_it(desktop: Any, capsys: Any) -> None:
    desktop.flows.start_result = FakeFlow(step="done", gmail=True, account="work")
    answer = desktop.post("/mail/setup/start", _start_body(touch_id=False))
    assert answer == {
        "ok": True,
        "flow_id": "flow_ABCDEFGH1234",
        "step": "done",
        "question": None,
        "gmail": True,
        "account": "work",
        "folders": [],
    }
    ((name, kwargs),) = desktop.flows.calls
    assert name == "start" and kwargs == {
        "address": ADDRESS,
        "imap_host": None,
        "account": "work",
        "extra_addresses": [EXTRA],
        "app_password": APP_PASSWORD,
        "presence": False,
    }
    assert not desktop.leaked(answer) and ADDRESS not in capsys.readouterr().out


def test_start_defaults(desktop: Any) -> None:
    desktop.post("/mail/setup/start", {"address": ADDRESS, "app_password": APP_PASSWORD, "imap_host": "imap.x.org"})
    ((_, kwargs),) = desktop.flows.calls
    assert kwargs["account"] == "mail" and kwargs["extra_addresses"] == [] and kwargs["presence"] is True
    assert kwargs["imap_host"] == "imap.x.org"


def test_folder_names_appear_only_in_the_folders_step(desktop: Any) -> None:
    desktop.flows.start_result = FakeFlow(
        step="folders", question="sent", folders=(FakeFolder(FOLDER, FOLDER + " " * 300 + "tail"), FakeFolder("b", 3))
    )
    started = desktop.post("/mail/setup/start", _start_body())
    assert started["step"] == "folders" and started["question"] == "sent"
    assert started["folders"] == [{"id": FOLDER, "display": (FOLDER + " " * 300)[:200]}]
    finished = desktop.post(f"/mail/setup/{started['flow_id']}/finish", {"selection": FOLDER})
    assert finished == {"ok": True, "step": "done"}
    assert desktop.flows.calls[-1] == ("finish", (started["flow_id"], FOLDER))
    assert FOLDER not in json.dumps(finished) and not desktop.leaked(finished)
    assert desktop.post(f"/mail/setup/{started['flow_id']}/finish", {"selection": None}) == {"ok": True, "step": "done"}
    assert desktop.flows.calls[-1] == ("finish", (started["flow_id"], None))


def test_a_done_flow_never_lists_folders(desktop: Any) -> None:
    desktop.flows.start_result = FakeFlow(step="done", question="sent", folders=(FakeFolder(FOLDER, FOLDER),))
    started = desktop.post("/mail/setup/start", _start_body())
    assert started["folders"] == [] and started["question"] is None


def test_odd_flow_fields_are_closed(desktop: Any) -> None:
    desktop.flows.start_result = FakeFlow(flow_id=ADDRESS, step="weird", question="who", account=ADDRESS)
    started = desktop.post("/mail/setup/start", _start_body())
    assert started["flow_id"] == "" and started["step"] == "done" and started["account"] is None
    assert not desktop.leaked(started)


@pytest.mark.parametrize("code", SETUP_CODES)
def test_every_setup_code_passes_through(desktop: Any, code: str) -> None:
    desktop.flows.start_result = FakeSetupError(code)
    assert desktop.post("/mail/setup/start", _start_body()) == {"ok": False, "error": code}


@pytest.mark.parametrize("hint", sorted(_projections.IMAP_HINTS))
def test_hints_pass_through(desktop: Any, hint: str) -> None:
    desktop.flows.start_result = FakeSetupError("imap_auth_failed", hint)
    assert desktop.post("/mail/setup/start", _start_body()) == {"ok": False, "error": "imap_auth_failed", "hint": hint}


def test_unknown_codes_hints_and_crashes_are_closed(desktop: Any) -> None:
    desktop.flows.start_result = FakeSetupError("imap_auth_failed", "[ALERT] " + ADDRESS)
    assert desktop.post("/mail/setup/start", _start_body()) == {"ok": False, "error": "imap_auth_failed"}
    desktop.flows.start_result = FakeSetupError("free text " + ADDRESS)
    assert desktop.post("/mail/setup/start", _start_body()) == {"ok": False, "error": "mail_setup_failed"}
    desktop.flows.start_result = RuntimeError(APP_PASSWORD)
    assert desktop.post("/mail/setup/start", _start_body()) == {"ok": False, "error": "mail_setup_failed"}
    assert not desktop.leaked()


@pytest.mark.parametrize(
    "code", ["mail_setup_stale", "invalid_selection", "mail_setup_flow_expired", "touch_id_policy_mismatch"]
)
def test_finish_refusals_pass_through(desktop: Any, code: str) -> None:
    desktop.flows.finish_error = FakeSetupError(code)
    assert desktop.post("/mail/setup/f/finish", {"selection": FOLDER}) == {"ok": False, "error": code}


@pytest.mark.parametrize(
    "body",
    [
        {"address": 1, "app_password": APP_PASSWORD},
        {"address": ADDRESS},
        {"address": ADDRESS, "app_password": APP_PASSWORD, "touch_id": "yes"},
        {"address": ADDRESS, "app_password": APP_PASSWORD, "extra_addresses": [EXTRA, 3]},
        {"address": ADDRESS, "app_password": APP_PASSWORD, "extra_addresses": EXTRA},
        {"address": ADDRESS, "app_password": APP_PASSWORD, "imap_host": 993},
        {"address": ADDRESS, "app_password": APP_PASSWORD, "account": None},
    ],
)
def test_start_type_errors_are_invalid_body(desktop: Any, body: dict[str, Any]) -> None:
    assert desktop.post("/mail/setup/start", body) == {"ok": False, "error": "invalid_body"}
    assert desktop.flows.calls == []


def test_finish_type_errors_are_invalid_body(desktop: Any) -> None:
    assert desktop.post("/mail/setup/f/finish", {"selection": 3}) == {"ok": False, "error": "invalid_body"}
    assert desktop.flows.calls == []


def test_setup_needs_macos_and_memory_but_cancel_does_not(desktop: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    _memory_off(monkeypatch)
    refused = {"ok": False, "error": "memory_encryption_required"}
    assert desktop.post("/mail/setup/start", _start_body()) == refused
    assert desktop.post("/mail/setup/f/finish", {"selection": None}) == refused
    assert desktop.post("/mail/setup/f/cancel") == {"ok": True}
    assert desktop.flows.calls == [("cancel", "f")]
    monkeypatch.setattr(api, "sys", SimpleNamespace(platform="linux"))
    assert desktop.post("/mail/setup/start", _start_body()) == {"ok": False, "error": "unsupported_platform"}


def test_cancel_is_idempotent_and_never_creates_the_flows(desktop: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(api, "_MAIL_FLOWS", None)
    monkeypatch.setattr(api, "_mail_flows", lambda: pytest.fail("cancel must not create the flows"))
    assert desktop.post("/mail/setup/x/cancel") == {"ok": True}

    def broken(flow_id: str) -> None:
        raise FakeSetupError("mail_setup_flow_expired")

    monkeypatch.setattr(api, "_MAIL_FLOWS", SimpleNamespace(cancel=broken))
    assert desktop.post("/mail/setup/x/cancel") == {"ok": True}


# -- fetch ----------------------------------------------------------------------------------------


@pytest.fixture
def fetch(desktop: Any, monkeypatch: pytest.MonkeyPatch) -> Any:
    seen: dict[str, Any] = {"calls": []}
    gate = threading.Event()
    gate.set()
    result = FetchResult(inserted=5, fetched=6, mailboxes=1, gmail=True)

    def run_fetch(options: Any, env: Any) -> Any:
        seen["calls"].append((options, env))
        gate.wait(5)
        print("fetching for", ADDRESS)  # nothing printed may reach a response
        if isinstance(seen.get("result"), BaseException):
            raise seen["result"]
        return seen.get("result", result)

    monkeypatch.setattr(api, "_run_fetch", run_fetch)
    monkeypatch.setattr(api, "_fetch_env", lambda home: SimpleNamespace(home=home, address=ADDRESS))
    return SimpleNamespace(desktop=desktop, seen=seen, gate=gate, result=result)


def test_fetch_runs_as_a_job_with_the_desktop_budget(fetch: Any, capsys: Any) -> None:
    started = fetch.desktop.post("/mail/fetch", {"max": 100, "since": "2026-10-01", "mailbox": "inbox"})
    assert started["ok"] is True and started["kind"] == "mail_fetch" and started["already_running"] is False
    job = fetch.desktop.wait_job(started["job_id"])
    assert job["state"] == "done" and job["error"] is None
    assert job["progress"] == {"result": fetch.result.as_dict()}
    ((options, env),) = fetch.seen["calls"]
    assert (options.max_messages, options.roles, options.since, options.dry_run) == (
        100,
        ("inbox",),
        dt.date(2026, 10, 1),
        False,
    )
    assert options.budget_s == 600.0 and options.via == "desktop" and env.home == fetch.desktop.home
    kinds = [event for event, _ in fetch.desktop.events]
    assert kinds == ["progress", "job"]
    assert fetch.desktop.events[0][1]["message"] == "Fetching new mail… up to 10 minutes"
    assert not fetch.desktop.leaked(started, job)
    assert ADDRESS in capsys.readouterr().out  # printed by the fake only, never in a response


def test_fetch_defaults(fetch: Any) -> None:
    started = fetch.desktop.post("/mail/fetch")
    fetch.desktop.wait_job(started["job_id"])
    ((options, _),) = fetch.seen["calls"]
    assert (options.max_messages, options.roles, options.since, options.dry_run) == (2000, None, None, False)
    started = fetch.desktop.post("/mail/fetch", {"mailbox": "all", "dry_run": True, "max": 1})
    fetch.desktop.wait_job(started["job_id"])
    options, _ = fetch.seen["calls"][-1]
    assert options.roles == ("all",) and options.dry_run is True and options.max_messages == 1


def test_a_result_error_fails_the_job_with_that_code(fetch: Any) -> None:
    fetch.seen["result"] = FetchResult(error="imap_auth_failed")
    started = fetch.desktop.post("/mail/fetch", {})
    job = fetch.desktop.wait_job(started["job_id"])
    assert job["state"] == "failed" and job["error"] == "imap_auth_failed"
    assert job["progress"]["result"]["error"] == "imap_auth_failed"
    assert fetch.desktop.events[-1] == (
        "job",
        {"job_id": started["job_id"], "kind": "mail_fetch", "state": "failed", "error": "imap_auth_failed"},
    )


def test_a_crashing_fetch_is_fetch_failed_without_text(fetch: Any) -> None:
    fetch.seen["result"] = RuntimeError(ADDRESS)
    job = fetch.desktop.wait_job(fetch.desktop.post("/mail/fetch", {})["job_id"])
    assert job["state"] == "failed" and job["error"] == "fetch_failed"
    assert not fetch.desktop.leaked(job)


def test_a_second_fetch_returns_the_running_job(fetch: Any) -> None:
    fetch.gate.clear()
    first = fetch.desktop.post("/mail/fetch", {})
    second = fetch.desktop.post("/mail/fetch", {"max": 5})
    assert second["already_running"] is True and second["job_id"] == first["job_id"]
    assert fetch.desktop.get("/status?client_version=4")["jobs"][0]["kind"] == "mail_fetch"
    fetch.gate.set()
    assert fetch.desktop.wait_job(first["job_id"])["state"] == "done"
    assert len(fetch.seen["calls"]) == 1


@pytest.mark.parametrize(
    "body",
    [
        {"max": 0},
        {"max": 2001},
        {"max": True},
        {"max": "5"},
        {"since": "2026-13-01"},
        {"since": "20261001"},
        {"since": 20261001},
        {"since": "2026-1-01"},
        {"mailbox": "spam"},
        {"dry_run": "yes"},
    ],
)
def test_fetch_validation(fetch: Any, body: dict[str, Any]) -> None:
    assert fetch.desktop.post("/mail/fetch", body) == {"ok": False, "error": "invalid_request"}
    assert fetch.seen["calls"] == []


def test_fetch_gates(fetch: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    _memory_off(monkeypatch)
    assert fetch.desktop.post("/mail/fetch", {}) == {"ok": False, "error": "memory_encryption_required"}
    monkeypatch.setattr(api, "sys", SimpleNamespace(platform="win32"))
    assert fetch.desktop.post("/mail/fetch", {}) == {"ok": False, "error": "unsupported_platform"}
    assert fetch.seen["calls"] == []


def test_fetch_job_busy_is_a_code(fetch: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    def busy(kind: str, work: Any) -> Any:
        raise api.JobBusy(kind)

    monkeypatch.setattr(api, "_start_job", busy)
    assert fetch.desktop.post("/mail/fetch", {}) == {"ok": False, "error": "mail_fetch_busy"}


def test_every_fetch_error_code_is_in_the_closed_set() -> None:
    assert ERROR_CODES <= _projections.MAIL_FETCH_CODES
    assert ERROR_CODES <= _projections.MAIL_CODES


# -- forget ---------------------------------------------------------------------------------------


@pytest.fixture
def forget(desktop: Any, monkeypatch: pytest.MonkeyPatch) -> Any:
    seen: dict[str, Any] = {"calls": [], "audit": []}
    done = SimpleNamespace(
        had_credentials=True, deleted_messages=12, cursors_deleted=2, warnings=("key_left",), address=ADDRESS
    )

    def run_forget(secret_store: Any, home: Path, *, account: str | None, rows: bool) -> Any:
        seen["calls"].append(
            {"account": account, "rows": rows, "home": home, "cancelled_first": desktop.flows.cancelled_all}
        )
        if isinstance(seen.get("result"), BaseException):
            raise seen["result"]
        return seen.get("result", done)

    monkeypatch.setattr(api, "_forget", run_forget)
    monkeypatch.setattr(api, "_mail_audit", lambda result, rows: seen["audit"].append((result, rows)))
    return SimpleNamespace(desktop=desktop, seen=seen, done=done)


def test_forget_with_rows_needs_the_phrase_before_anything_is_read(
    forget: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(api, "_mail_secret_store", lambda: pytest.fail("nothing may be read before the phrase"))
    for confirm in (None, "delete my data please", "DELETE MY DATA"):
        body = {"rows": True} if confirm is None else {"rows": True, "confirm": confirm}
        assert forget.desktop.post("/mail/forget", body) == {"ok": False, "error": "forget_confirm_mismatch"}
    assert forget.seen["calls"] == [] and forget.desktop.flows.calls == []


@pytest.mark.parametrize("body", [{}, {"rows": "true"}, {"rows": 1}, {"rows": None}, {"rows": False, "confirm": 5}])
def test_rows_must_be_a_json_boolean(forget: Any, body: dict[str, Any]) -> None:
    assert forget.desktop.post("/mail/forget", body) == {"ok": False, "error": "invalid_body"}
    assert forget.seen["calls"] == []


def test_forget_account_is_validated(forget: Any) -> None:
    assert forget.desktop.post("/mail/forget", {"rows": False, "account": "Work!"}) == {
        "ok": False,
        "error": "invalid_account",
    }
    assert forget.desktop.post("/mail/forget", {"rows": False, "account": 7}) == {"ok": False, "error": "invalid_body"}
    assert forget.desktop.post("/mail/forget", {"rows": False, "account": "work"})["ok"] is True
    assert forget.seen["calls"][-1]["account"] == "work"


def test_forget_cancels_flows_first_and_answers_counts_only(forget: Any) -> None:
    answer = forget.desktop.post("/mail/forget", {"rows": True, "confirm": " delete my data "})
    assert answer == {
        "ok": True,
        "had_credentials": True,
        "deleted_messages": 12,
        "cursors_deleted": 2,
        "warnings": ["key_left"],
    }
    (call,) = forget.seen["calls"]
    assert call["rows"] is True and call["account"] is None and call["cancelled_first"] == 1
    assert call["home"] == forget.desktop.home
    assert forget.seen["audit"] == [(forget.done, True)]
    assert not forget.desktop.leaked(answer)


def test_credential_only_forget_needs_no_memory_but_rows_do(forget: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    _memory_off(monkeypatch)
    assert forget.desktop.post("/mail/forget", {"rows": False})["ok"] is True
    assert forget.desktop.post("/mail/forget", {"rows": True, "confirm": "delete my data"}) == {
        "ok": False,
        "error": "memory_encryption_required",
    }
    monkeypatch.setattr(api, "sys", SimpleNamespace(platform="linux"))
    assert forget.desktop.post("/mail/forget", {"rows": False}) == {"ok": False, "error": "unsupported_platform"}


def test_forget_without_flows_does_not_create_them(forget: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(api, "_MAIL_FLOWS", None)
    monkeypatch.setattr(api, "_mail_flows", lambda: pytest.fail("forget must not create the flows"))
    assert forget.desktop.post("/mail/forget", {"rows": False})["ok"] is True


@pytest.mark.parametrize(
    "code",
    [
        "credentials_changed",
        "credentials_left",
        "account_mismatch",
        "sync_in_progress",
        "import_store_unavailable",
        "busy",
    ],
)
def test_forget_refusals_pass_through(forget: Any, code: str) -> None:
    forget.seen["result"] = FakeRefused(code)
    assert forget.desktop.post("/mail/forget", {"rows": False}) == {"ok": False, "error": code}
    assert forget.seen["audit"] == []


def test_forget_unknown_failures_and_warnings_are_closed(forget: Any) -> None:
    forget.seen["result"] = RuntimeError(ADDRESS)
    assert forget.desktop.post("/mail/forget", {"rows": False}) == {"ok": False, "error": "fetch_failed"}
    forget.seen["result"] = SimpleNamespace(
        had_credentials="yes", deleted_messages=-1, cursors_deleted=True, warnings=["account_unknown", ADDRESS, "busy"]
    )
    answer = forget.desktop.post("/mail/forget", {"rows": False})
    assert answer == {
        "ok": True,
        "had_credentials": False,
        "deleted_messages": 0,
        "cursors_deleted": 0,
        "warnings": ["account_unknown", "store_unavailable", "busy"],
    }
    assert not forget.desktop.leaked(answer)


# -- the seams' production bodies ---------------------------------------------------------------


def test_library_seams_resolve_lazily(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    calls: list[tuple[str, str]] = []

    class Flows:
        def __init__(self, secret_store: Any) -> None:
            self.secret_store = secret_store

    def library(module: str, name: str) -> Any:
        calls.append((module, name))
        return {
            "MailSetupFlows": Flows,
            "forget": lambda store, home, *, account, rows: ("forgot", home, account, rows),
            "open_import_store_readonly": lambda home: ("store", home),
        }[name]

    monkeypatch.setattr(api, "_library", library)
    monkeypatch.setattr(api, "_MAIL_FLOWS", None)
    monkeypatch.setattr(api, "_mail_secret_store", lambda: "secret-store")
    flows = api._mail_flows()
    assert isinstance(flows, Flows) and flows.secret_store == "secret-store" and api._mail_flows() is flows
    assert api._forget("s", tmp_path, account="work", rows=True) == ("forgot", tmp_path, "work", True)
    assert api._open_store_readonly(tmp_path) == ("store", tmp_path)
    assert calls == [
        ("..imports.mail.setup_flow", "MailSetupFlows"),
        ("..imports.mail.forget", "forget"),
        ("..imports.store", "open_import_store_readonly"),
    ]
    monkeypatch.setattr(api, "_MAIL_FLOWS", None)


def test_library_imports_relative_to_the_package() -> None:
    assert api._library("..imports.store", "ImportStore").__name__ == "ImportStore"


def test_fetch_and_status_seams_call_the_library(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    from mordred_hermes.imports.mail import imap_sync
    from mordred_hermes.wizard import mail_sync_cli

    monkeypatch.setattr(imap_sync, "run_fetch", lambda options, env: ("ran", options, env))
    monkeypatch.setattr(imap_sync, "default_env", lambda home: ("env", home))
    monkeypatch.setattr(mail_sync_cli, "imap_status", lambda store, flags: ("status", store, flags))
    assert api._run_fetch("o", "e") == ("ran", "o", "e")
    assert api._fetch_env(tmp_path) == ("env", tmp_path)
    assert api._imap_status("s", {"account": "a"}) == ("status", "s", {"account": "a"})
    assert type(api._mail_secret_store()).__name__ == "MailSecretStore"


def test_mail_audit_writes_the_shared_event(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    written: list[Any] = []
    monkeypatch.setattr(api, "_home", lambda: tmp_path)
    monkeypatch.setattr(
        api, "_library", lambda module, name: lambda done, *, rows: {"event": "mail.forget", "rows": rows}
    )
    monkeypatch.setattr("mordred_hermes._audit_support.build_audit_writer", lambda path: ("writer", path))
    monkeypatch.setattr(
        "mordred_hermes._audit_support.safe_audit_append", lambda writer, entry, logger: written.append((writer, entry))
    )
    REAL_MAIL_AUDIT(object(), rows=True)
    assert written == [(("writer", tmp_path / "mordred" / "audit.log"), {"event": "mail.forget", "rows": True})]


def test_mail_audit_failures_are_logged(monkeypatch: pytest.MonkeyPatch, caplog: Any) -> None:
    def missing(module: str, name: str) -> Any:
        raise ImportError(name)

    monkeypatch.setattr(api, "_library", missing)
    REAL_MAIL_AUDIT(object(), rows=False)
    assert "ImportError" in caplog.text


def test_fetch_mail_rejects_a_non_dict_result(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(api, "_fetch_env", lambda home: None)
    monkeypatch.setattr(api, "_run_fetch", lambda options, env: SimpleNamespace(as_dict=lambda: ["x"]))
    with pytest.raises(TypeError):
        api._fetch_mail(object(), tmp_path)


def test_flows_seam_in_status_is_untouched(desktop: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    """Status never touches the setup flows (and so never a pending password)."""
    monkeypatch.setattr(api, "_mail_flows", lambda: pytest.fail("status must not reach the flows"))
    monkeypatch.setattr(api, "_mail_secret_store", lambda: FakeMailSecrets(None))
    assert desktop.get("/status?client_version=4")["mail"] == {"configured": False}
