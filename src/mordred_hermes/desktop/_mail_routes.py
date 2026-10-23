"""``/mail/*`` and ``/imports/status``: Desktop step 2.5, mail over IMAP (macOS; a sub-router of ``api.router``).

Setup (start, finish, cancel), the ``mail_fetch`` job and forget, through the
mail library's seams in :mod:`._seams`; shared helpers (``sys``, ``_home``,
``_error``, ``_require_memory``, the job registry) come from :mod:`.api`. Both
are read at call time, so a test replaces each in one place. Every answer is a
closed projection (:mod:`._projections`): the address, the extra addresses,
the app password and folder names never leave the request that carried them,
except folder names in the ``folders`` step of ``/mail/setup/start``.
"""

from __future__ import annotations

import asyncio
import contextlib
import datetime as _dt
import logging
import re
from collections.abc import Callable
from pathlib import Path
from types import ModuleType
from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from . import _projections, _seams, _status_v4
from ._body import read_object
from ._jobs import JobBusy

router = APIRouter()
_log = logging.getLogger(__name__)

DESKTOP_BUDGET_S = 600.0
_ROLES = ("all", "inbox", "sent")
_ACCOUNT_RE = re.compile(r"[a-z][a-z0-9_]{0,31}")


def _api() -> ModuleType:
    from . import api

    return api


async def _call(work: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
    """Run a mail-library call in a thread; await it too if the library made it a coroutine."""
    result = await asyncio.to_thread(work, *args, **kwargs)
    if asyncio.iscoroutine(result):
        result = await result
    return result


def _mail_error(exc: BaseException, allowed: frozenset[str], fallback: str) -> JSONResponse:
    """A library refusal as ``{"ok": false, "error": code, "hint"?}``: closed codes and hints, no text."""
    code = getattr(exc, "code", None)
    if not (isinstance(code, str) and code in allowed):
        _log.warning("mordred desktop mail call failed (%s)", type(exc).__name__)
    answer: dict[str, Any] = {"ok": False, "error": _projections.closed(code, allowed, fallback)}
    hint = _projections.hint_of(exc)
    if hint is not None:
        answer["hint"] = hint
    return JSONResponse(answer, status_code=200)


async def _gate(*, memory: bool) -> JSONResponse | None:
    api = _api()
    if api.sys.platform != "darwin":
        refused: JSONResponse = api._error("unsupported_platform")
        return refused
    blocked: JSONResponse | None = await api._require_memory() if memory else None
    return blocked


def _strings(value: Any) -> list[str] | None:
    if value is None:
        return []
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return list(value)
    return None


@router.get("/imports/status")
async def imports_status() -> Any:
    """The ``imports``, ``mail`` and ``telegram_archive`` objects of ``/status`` (a light refresh)."""
    api = _api()
    return {"ok": True, **await asyncio.to_thread(_status_v4.imports_sections, api._home(), api.sys.platform)}


@router.post("/mail/setup/start")
async def mail_setup_start(request: Request) -> Any:
    """Body ``{"address", "imap_host"?, "account"?, "extra_addresses"?, "app_password", "touch_id"?}``.

    ``{"ok": true, "flow_id", "step": "done" | "folders", "question", "gmail",
    "account", "folders": [{"id", "display"}]}``; folder names appear only for
    the ``folders`` step. Refusals pass ``MailSetupError`` codes and hints through.
    """
    body = await read_object(request)
    if isinstance(body, JSONResponse):
        return body
    address, password = body.get("address"), body.get("app_password")
    host, account = body.get("imap_host"), body.get("account", "mail")
    extra, touch_id = _strings(body.get("extra_addresses")), body.get("touch_id", True)
    if (
        not isinstance(address, str)
        or not isinstance(password, str)
        or not (host is None or isinstance(host, str))
        or not isinstance(account, str)
        or extra is None
        or not isinstance(touch_id, bool)
    ):
        return _api()._error("invalid_body")
    blocked = await _gate(memory=True)
    if blocked is not None:
        return blocked
    try:
        flow = await _call(
            _seams.mail_flows().start,
            address=address,
            imap_host=host,
            account=account,
            extra_addresses=extra,
            app_password=password,
            presence=touch_id,
        )
    except Exception as exc:
        return _mail_error(exc, _projections.MAIL_SETUP_CODES, _projections.MAIL_SETUP_FALLBACK)
    finally:
        del password
    return _projections.setup_flow_view(flow)


@router.post("/mail/setup/{flow_id}/finish")
async def mail_setup_finish(flow_id: str, request: Request) -> Any:
    """Body ``{"selection": id | null}`` (the folder for the flow's ``question``). ``{"ok": true, "step": "done"}``."""
    body = await read_object(request)
    if isinstance(body, JSONResponse):
        return body
    selection = body.get("selection")
    if not (selection is None or isinstance(selection, str)):
        return _api()._error("invalid_body")
    blocked = await _gate(memory=True)
    if blocked is not None:
        return blocked
    try:
        await _call(_seams.mail_flows().finish, flow_id, selection=selection)
    except Exception as exc:
        return _mail_error(exc, _projections.MAIL_SETUP_CODES, _projections.MAIL_SETUP_FALLBACK)
    return {"ok": True, "step": "done"}


@router.post("/mail/setup/{flow_id}/cancel")
async def mail_setup_cancel(flow_id: str) -> Any:
    """Drop a pending flow and its password (idempotent; no gate, so cleanup always works)."""
    flows = _seams.MAIL_FLOWS
    if flows is not None:
        try:
            await _call(flows.cancel, flow_id)
        except Exception as exc:  # an unknown or expired flow is already gone
            _log.info("mordred desktop mail setup cancel (%s)", type(exc).__name__)
    return {"ok": True}


def _fetch_options(body: dict[str, Any]) -> Any:
    """``FetchOptions`` from a validated body, or ``None`` (``invalid_request``)."""
    from ..imports.mail.imap_sync import FetchOptions

    maximum, since = body.get("max", 2000), body.get("since")
    mailbox, dry_run = body.get("mailbox"), body.get("dry_run")
    if isinstance(maximum, bool) or not isinstance(maximum, int) or not 1 <= maximum <= 2000:
        return None
    if not (mailbox is None or mailbox in _ROLES) or not (dry_run is None or isinstance(dry_run, bool)):
        return None
    day: _dt.date | None = None
    if since is not None:
        if not isinstance(since, str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}", since):
            return None
        try:
            day = _dt.date.fromisoformat(since)
        except ValueError:
            return None
    return FetchOptions(
        max_messages=maximum,
        roles=None if mailbox is None else (mailbox,),
        since=day,
        dry_run=bool(dry_run),
        budget_s=DESKTOP_BUDGET_S,
        via="desktop",
    )


def fetch_mail(options: Any, home: Path) -> dict[str, Any]:
    """One fetch, as the closed ``FetchResult.as_dict()`` (``run_fetch`` never raises for a refusal)."""
    result = _seams.run_fetch(options, _seams.fetch_env(home))
    data = result.as_dict()
    if not isinstance(data, dict):
        raise TypeError("fetch result")
    return data


@router.post("/mail/fetch")
async def mail_fetch(request: Request) -> Any:
    """Body ``{"max"?: 1-2000, "since"?: "YYYY-MM-DD", "mailbox"?: "all"|"inbox"|"sent", "dry_run"?: bool}``.

    Runs as the job ``mail_fetch``; a second request while it runs returns that
    job with ``already_running: true``. On completion ``progress.result`` is
    ``FetchResult.as_dict()``; a ``result.error`` fails the job with that code.
    """
    api = _api()
    body = await read_object(request)
    if isinstance(body, JSONResponse):
        return body
    options = _fetch_options(body)
    if options is None:
        return api._error("invalid_request")
    blocked = await _gate(memory=True)
    if blocked is not None:
        return blocked
    for job in api._JOBS.running():
        if job.kind == "mail_fetch":
            return {"ok": True, **api._job_view(job), "already_running": True}
    home = api._home()

    async def work(job: Any) -> None:
        job.progress = {"message": "Fetching new mail… up to 10 minutes"}
        api._emit("progress", {"job_id": job.job_id, **job.progress})
        try:
            data = await job.run_sync(fetch_mail, options, home)
        except Exception as exc:
            _log.warning("mordred desktop mail fetch failed (%s)", type(exc).__name__)
            raise api._Fail(_projections.MAIL_FETCH_FALLBACK) from None
        job.progress = {"result": data}
        if data.get("error") is not None:
            raise api._Fail(_projections.closed(data["error"], _projections.MAIL_FETCH_CODES, "fetch_failed"))

    try:
        job = api._start_job("mail_fetch", work)
    except JobBusy as exc:
        return api._error(exc.code)
    return {"ok": True, **api._job_view(job), "already_running": False}


@router.post("/mail/forget")
async def mail_forget(request: Request) -> Any:
    """Body ``{"rows": bool, "account"?: label, "confirm"?: "delete my data"}``.

    Removes the sealed credentials, the flags and the Enclave key; ``rows``
    also deletes every message imported under the account (Takeout imports
    included) and needs the typed phrase, checked before anything is read.
    Pending setup flows are cancelled first. Answers ``{"ok": true,
    "had_credentials", "deleted_messages", "cursors_deleted", "warnings"}``.
    """
    from ..wizard.uninstall_cli import PURGE_PHRASE

    api = _api()
    body = await read_object(request)
    if isinstance(body, JSONResponse):
        return body
    rows, confirm, account = body.get("rows"), body.get("confirm"), body.get("account")
    if not isinstance(rows, bool) or not (confirm is None or isinstance(confirm, str)):
        return api._error("invalid_body")
    if rows and (confirm or "").strip() != PURGE_PHRASE:
        return api._error("forget_confirm_mismatch")
    if not (account is None or isinstance(account, str)):
        return api._error("invalid_body")
    if account is not None and not _ACCOUNT_RE.fullmatch(account):
        return api._error("invalid_account")
    blocked = await _gate(memory=rows)
    if blocked is not None:
        return blocked
    flows = _seams.MAIL_FLOWS
    if flows is not None:
        with contextlib.suppress(Exception):
            await _call(flows.cancel_all)
    home = api._home()
    try:
        done = await asyncio.to_thread(_seams.forget, _seams.mail_secret_store(), home, account=account, rows=rows)
    except Exception as exc:
        return _mail_error(exc, _projections.MAIL_FORGET_CODES, _projections.MAIL_FORGET_FALLBACK)
    await asyncio.to_thread(_seams.mail_audit, done, rows=rows, home=home)
    return _projections.forgotten_projection(done)
