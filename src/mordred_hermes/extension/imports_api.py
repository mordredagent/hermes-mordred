"""Imports over the extension gateway: the Desktop plugin's import screens, for the paired extension.

Two authed frame types (capability ``imports_v1``); both bodies cross the wire
sealed with K_extchat, because they carry phone numbers, login codes, mail
addresses, app passwords and account labels:

- ``imports_status`` → ``imports_status_result`` ``{content: sealed status}``.
  The status is read from this Hermes's own state (sealed credential flags,
  the import store's counts, the running jobs), so the extension shows exactly
  what the Desktop plugin shows and never keeps a copy of its own.
- ``imports_call`` ``{content: sealed {"op", ...}}`` → ``imports_call_result``
  ``{content: sealed result}`` or ``{error: code}``.

Ops: ``telegram_login_start`` / ``_code`` / ``_password`` / ``_cancel``,
``telegram_sync``, ``mail_setup_start`` / ``_finish`` / ``_cancel``,
``mail_fetch``, ``local_import`` and ``job``. They run the same libraries as
the Desktop routes behind the same gates, and nothing registers twice: a
logged-in Telegram refuses a new login (``telegram_already_logged_in``),
configured mail refuses a new setup (``mail_already_configured``), a fetch or
import that is already running is returned instead of started again, and the
import store keeps every message once (its idempotency rules). Errors are
content-free codes; page and activity sessions never reach these handlers.
"""

from __future__ import annotations

import asyncio
import datetime as _dt
import logging
import re
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any, Final

_log = logging.getLogger(__name__)

IMPORTS_CAPABILITY: Final = "imports_v1"

_LOCAL_SOURCES: Final = ("codex", "claude_code", "grok_bot")
_FLOW_ID_RE: Final = re.compile(r"[A-Za-z0-9_-]{8,64}")
_JOB_ID_RE: Final = re.compile(r"[A-Za-z0-9_-]{8,64}")
_MAX_FIELD: Final = 512
_MAIL_BUDGET_S: Final = 600.0


class ImportsRefusal(Exception):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _home() -> Path:
    from .._home import hermes_home

    return hermes_home()


def _text(body: dict[str, Any], key: str, *, required: bool = True) -> str | None:
    value = body.get(key)
    if value is None and not required:
        return None
    if not isinstance(value, str) or not value or len(value) > _MAX_FIELD:
        raise ImportsRefusal("invalid_request")
    return value


def _flow_id(body: dict[str, Any]) -> str:
    value = body.get("flow_id")
    if not isinstance(value, str) or not _FLOW_ID_RE.fullmatch(value):
        raise ImportsRefusal("invalid_request")
    return value


def _code_of(exc: BaseException, fallback: str) -> str:
    code = getattr(exc, "code", None)
    return code if isinstance(code, str) and code else fallback


async def _thread(work: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
    result = await asyncio.to_thread(work, *args, **kwargs)
    if asyncio.iscoroutine(result):
        result = await result
    return result


def _local_counts(home: Path) -> dict[str, dict[str, Any]]:
    """Per local source: committed conversations and messages, and when the last import was published.

    The Desktop's ``imports`` section keeps its two sources; this reads the same
    read-only store (never created, never unlocked) for the three local ones.
    """
    from ..imports.store import open_import_store_readonly

    try:
        store = open_import_store_readonly(home)
    except Exception:  # no store yet, or the gate refused: the Desktop section carries the code
        return {}
    try:
        status = store.status()
        with store.connection() as conn:
            finished = dict(
                conn.execute(
                    "SELECT source, max(finished_at) FROM import_runs WHERE state = 'committed' GROUP BY source"
                ).fetchall()
            )
    except Exception as exc:
        _log.warning("extension local import counts unreadable (%s)", type(exc).__name__)
        return {}
    finally:
        closer = getattr(store, "close", None)
        if callable(closer):
            closer()
    sources = status.get("sources") if isinstance(status, dict) else None
    result: dict[str, dict[str, Any]] = {}
    for source in _LOCAL_SOURCES:
        row = sources.get(source, {}) if isinstance(sources, dict) else {}
        at = finished.get(source)
        result[source] = {
            "conversations": int(row.get("conversations", 0)),
            "messages": int(row.get("messages", 0)),
            "last_import_at": int(at) if isinstance(at, int | float) else None,
        }
    return result


class ImportsApi:
    """One per gateway process: the login and setup flows and the job registry it owns."""

    def __init__(
        self,
        *,
        telegram_service: Callable[[], Any],
        home: Callable[[], Path] = _home,
        platform: str = sys.platform,
    ) -> None:
        from ..desktop._jobs import JobRegistry

        self._telegram_service = telegram_service
        self._home = home
        self._platform = platform
        self._jobs = JobRegistry(emit=lambda _event, _payload: None)
        self._telegram_flows: Any = None
        self._mail_flows: Any = None

    # -- gates (the Desktop routes' own) -----------------------------------------------

    def _require_darwin(self) -> None:
        if self._platform != "darwin":
            raise ImportsRefusal("unsupported_platform")

    async def _require_memory(self) -> None:
        from .telegram.memory_guard import memory_encryption_active

        if not await asyncio.to_thread(memory_encryption_active):
            raise ImportsRefusal("memory_encryption_required")

    async def _require_hermes_model(self) -> None:
        from ..desktop.api import hermes_model_check

        check = await hermes_model_check()
        if not check["ok"]:
            raise ImportsRefusal("hermes_model_not_private")

    # -- status -------------------------------------------------------------------------

    async def status(self) -> dict[str, Any]:
        """Flags and counts only, as the Desktop plugin reads them; nothing is unsealed."""
        from ..desktop import _status_v4
        from ..imports.local import local_status

        home = self._home()
        sections = await asyncio.to_thread(_status_v4.imports_sections, home, self._platform)
        try:
            telegram = await self._telegram_service().status()
        except Exception as exc:
            telegram = {"configured": False, "logged_in": False, "last_error": _code_of(exc, "telegram_unavailable")}
        local = await asyncio.to_thread(local_status)
        counts = await asyncio.to_thread(_local_counts, home) if self._platform == "darwin" else {}
        for source, entry in local.items():
            entry.update(counts.get(source, {"conversations": 0, "messages": 0, "last_import_at": None}))
        return {
            "imports": sections.get("imports"),
            "mail": sections.get("mail"),
            "telegram": telegram,
            "local": local,
            "jobs": [self._job_view(job) for job in self._jobs.running()],
        }

    # -- dispatch -----------------------------------------------------------------------

    async def call(self, body: dict[str, Any]) -> dict[str, Any]:
        """Run one op; a refusal raises :class:`ImportsRefusal` with its code."""
        op = body.get("op")
        handler = {
            "telegram_login_start": self._telegram_login_start,
            "telegram_login_code": self._telegram_login_code,
            "telegram_login_password": self._telegram_login_password,
            "telegram_login_cancel": self._telegram_login_cancel,
            "telegram_sync": self._telegram_sync,
            "mail_setup_start": self._mail_setup_start,
            "mail_setup_finish": self._mail_setup_finish,
            "mail_setup_cancel": self._mail_setup_cancel,
            "mail_fetch": self._mail_fetch,
            "local_import": self._local_import,
            "job": self._job,
        }.get(op if isinstance(op, str) else "")
        if handler is None:
            raise ImportsRefusal("invalid_request")
        return await handler(body)

    # -- Telegram -----------------------------------------------------------------------

    def _telegram(self) -> Any:
        if self._telegram_flows is None:
            from .telegram.login_flow import LoginFlows
            from .telegram.tee import default_secret_store

            self._telegram_flows = LoginFlows(default_secret_store())
        return self._telegram_flows

    async def _telegram_login_start(self, body: dict[str, Any]) -> dict[str, Any]:
        from .telegram.login_flow import LoginError

        phone = _text(body, "phone")
        api_id, api_hash = body.get("api_id"), body.get("api_hash")
        if not (api_id is None or isinstance(api_id, str | int)) or not (api_hash is None or isinstance(api_hash, str)):
            raise ImportsRefusal("invalid_request")
        if self._platform == "win32":
            raise ImportsRefusal("unsupported_platform")  # Windows custody needs the Desktop acknowledgement
        await self._require_memory()
        await self._require_hermes_model()
        try:
            flow = await self._telegram().start(api_id=api_id, api_hash=api_hash, phone=phone)
        except LoginError as exc:
            raise ImportsRefusal(exc.code) from None
        except Exception as exc:
            raise ImportsRefusal(_code_of(exc, "telegram_login_failed")) from None
        return {"flow_id": flow.flow_id, "step": flow.step}

    async def _telegram_login_code(self, body: dict[str, Any]) -> dict[str, Any]:
        return await self._telegram_step(body, "code")

    async def _telegram_login_password(self, body: dict[str, Any]) -> dict[str, Any]:
        return await self._telegram_step(body, "password")

    async def _telegram_step(self, body: dict[str, Any], field: str) -> dict[str, Any]:
        from .telegram.login_flow import LoginError

        flow_id, value = _flow_id(body), _text(body, field)
        flows = self._telegram()
        submit = flows.submit_code if field == "code" else flows.submit_password
        try:
            step = await submit(flow_id, value)
        except LoginError as exc:
            raise ImportsRefusal(exc.code) from None
        except Exception as exc:
            raise ImportsRefusal(_code_of(exc, "telegram_login_failed")) from None
        return {"step": step}

    async def _telegram_login_cancel(self, body: dict[str, Any]) -> dict[str, Any]:
        await self._telegram().cancel(_flow_id(body))
        return {}

    async def _telegram_sync(self, body: dict[str, Any]) -> dict[str, Any]:
        from .telegram.service import error_code

        days = body.get("days")
        if days is not None and (isinstance(days, bool) or not isinstance(days, int) or not 1 <= days <= 3650):
            raise ImportsRefusal("invalid_request")
        service = self._telegram_service()
        try:
            options = service.sync_options({"since_days": days, "include_archived": False})
            await service.start_sync(options)
        except Exception as exc:
            raise ImportsRefusal(error_code(exc, "telegram_sync_failed")) from None
        return {}

    # -- mail ---------------------------------------------------------------------------

    def _mail(self) -> Any:
        if self._mail_flows is None:
            from ..imports.mail.secrets import MailSecretStore
            from ..imports.mail.setup_flow import MailSetupFlows

            self._mail_flows = MailSetupFlows(MailSecretStore())
        return self._mail_flows

    async def _mail_setup_start(self, body: dict[str, Any]) -> dict[str, Any]:
        from ..desktop import _projections

        address, password = _text(body, "address"), _text(body, "app_password")
        host = _text(body, "imap_host", required=False)
        account = body.get("account", "mail")
        extra = body.get("extra_addresses", [])
        touch_id = body.get("touch_id", True)
        if (
            not isinstance(account, str)
            or not isinstance(extra, list)
            or not all(isinstance(item, str) and len(item) <= _MAX_FIELD for item in extra)
            or not isinstance(touch_id, bool)
        ):
            raise ImportsRefusal("invalid_request")
        self._require_darwin()
        await self._require_memory()
        try:
            flow = await _thread(
                self._mail().start,
                address=address,
                imap_host=host,
                account=account,
                extra_addresses=extra,
                app_password=password,
                presence=touch_id,
            )
        except Exception as exc:
            code = _projections.closed(
                getattr(exc, "code", None), _projections.MAIL_SETUP_CODES, _projections.MAIL_SETUP_FALLBACK
            )
            raise ImportsRefusal(code) from None
        finally:
            del password
        view = _projections.setup_flow_view(flow)
        view.pop("ok", None)
        return view

    async def _mail_setup_finish(self, body: dict[str, Any]) -> dict[str, Any]:
        from ..desktop import _projections

        flow_id = _flow_id(body)
        selection = body.get("selection")
        if not (selection is None or isinstance(selection, str)):
            raise ImportsRefusal("invalid_request")
        self._require_darwin()
        await self._require_memory()
        try:
            await _thread(self._mail().finish, flow_id, selection=selection)
        except Exception as exc:
            code = _projections.closed(
                getattr(exc, "code", None), _projections.MAIL_SETUP_CODES, _projections.MAIL_SETUP_FALLBACK
            )
            raise ImportsRefusal(code) from None
        return {"step": "done"}

    async def _mail_setup_cancel(self, body: dict[str, Any]) -> dict[str, Any]:
        flow_id = _flow_id(body)
        if self._mail_flows is not None:
            try:
                await _thread(self._mail_flows.cancel, flow_id)
            except Exception as exc:  # an unknown or expired flow is already gone
                _log.info("extension mail setup cancel (%s)", type(exc).__name__)
        return {}

    async def _mail_fetch(self, body: dict[str, Any]) -> dict[str, Any]:
        from ..desktop import _projections
        from ..imports.mail.imap_sync import FetchOptions, default_env, run_fetch

        maximum, since = body.get("max", 2000), body.get("since")
        if isinstance(maximum, bool) or not isinstance(maximum, int) or not 1 <= maximum <= 2000:
            raise ImportsRefusal("invalid_request")
        day: _dt.date | None = None
        if since is not None:
            if not isinstance(since, str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}", since):
                raise ImportsRefusal("invalid_request")
            try:
                day = _dt.date.fromisoformat(since)
            except ValueError:
                raise ImportsRefusal("invalid_request") from None
        self._require_darwin()
        await self._require_memory()
        options = FetchOptions(
            max_messages=maximum, roles=None, since=day, dry_run=False, budget_s=_MAIL_BUDGET_S, via="extension"
        )
        home = self._home()

        def fetch() -> dict[str, Any]:
            data = run_fetch(options, default_env(home)).as_dict()
            if not isinstance(data, dict):
                raise TypeError("fetch result")
            return data

        async def work(job: Any) -> None:
            job.progress = {"phase": "fetching"}
            try:
                data = await job.run_sync(fetch)
            except Exception as exc:
                _log.warning("extension mail fetch failed (%s)", type(exc).__name__)
                raise ImportsRefusal(_projections.MAIL_FETCH_FALLBACK) from None
            job.progress = {"result": data}
            if data.get("error") is not None:
                raise ImportsRefusal(_projections.closed(data["error"], _projections.MAIL_FETCH_CODES, "fetch_failed"))

        return self._start("mail_fetch", work)

    # -- local transcripts ----------------------------------------------------------------

    async def _local_import(self, body: dict[str, Any]) -> dict[str, Any]:
        from ..imports.local import LocalImportError, run_local_import

        source = body.get("source")
        if source not in _LOCAL_SOURCES:
            raise ImportsRefusal("invalid_request")
        self._require_darwin()
        await self._require_memory()
        home = self._home()

        async def work(job: Any) -> None:
            job.progress = {"phase": "scanning"}

            def report(progress: dict[str, int]) -> None:
                job.progress = {"phase": "importing", **progress}

            try:
                result = await job.run_sync(run_local_import, source, home=home, progress=report)
            except LocalImportError as exc:
                raise ImportsRefusal(exc.code) from None
            except Exception as exc:
                _log.warning("extension local import failed (%s)", type(exc).__name__)
                raise ImportsRefusal(_code_of(exc, "local_import_failed")) from None
            job.progress = {"phase": "done", "result": result.as_dict()}

        return self._start(f"local_import_{source}", work)

    # -- jobs -----------------------------------------------------------------------------

    @staticmethod
    def _job_view(job: Any) -> dict[str, Any]:
        return {
            "job_id": job.job_id,
            "kind": job.kind,
            "state": job.state,
            "error": job.error,
            "progress": job.progress,
        }

    def _start(self, kind: str, work: Callable[[Any], Any]) -> dict[str, Any]:
        running = self._jobs.is_running(kind)
        job = self._jobs.start(kind, work)
        return {**self._job_view(job), "already_running": running}

    async def _job(self, body: dict[str, Any]) -> dict[str, Any]:
        job_id = body.get("job_id")
        if not isinstance(job_id, str) or not _JOB_ID_RE.fullmatch(job_id):
            raise ImportsRefusal("invalid_request")
        job = self._jobs.get(job_id)
        if job is None:
            raise ImportsRefusal("job_not_found")
        return self._job_view(job)
