"""Package updates and uninstall from the Desktop page (a sub-router of ``api.router``).

``/update/check`` and ``/update/apply`` drive ``hermes-mordred update`` (never a
downgrade; refusals before any job starts); ``/uninstall/plan`` and
``/uninstall`` drive ``hermes-mordred uninstall`` with the page's answers. The
two jobs exclude each other. Shared helpers (``_home``, ``_error``, the job
registry) are read from :mod:`.api` at call time.
"""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from types import ModuleType
from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from ._body import read_object
from ._capture import captured_output
from ._jobs import JobBusy

router = APIRouter()
_log = logging.getLogger(__name__)


def _api() -> ModuleType:
    from . import api

    return api


class _FixedPassphrase:
    """PromptIO that answers every passphrase prompt with one generated value."""

    def __init__(self, passphrase: str) -> None:
        self._passphrase = passphrase
        self.used = False

    def ask_password(self, label: str, default: str = "", *, description: str | None = None) -> str:
        self.used = True
        return self._passphrase

    def ask_bool(self, label: str, default: bool, *, description: str | None = None) -> bool:
        return default

    def ask_text(self, label: str, default: str = "", *, description: str | None = None) -> str:
        return default

    def ask_choice(self, label: str, choices: Any, default: Any = None, **_: Any) -> Any:
        return default if default is not None else choices[0]

    def ask_multi(self, label: str, choices: Any, default: Any = ()) -> tuple[str, ...]:
        return tuple(default)


# -- package updates ----------------------------------------------------------------------

_REFUSAL_CODES = {
    "windows": "update_unsupported_windows",
    "source-install": "update_source_install",
    "no-uv": "update_no_uv",
    "not-a-venv": "update_not_a_venv",
    "foreign-source": "update_foreign_source",
    "bad-version": "update_bad_version",
    "hermes-too-old": "update_hermes_too_old",
}


def _running(kind: str) -> bool:
    return bool(_api()._JOBS.is_running(kind))


def _update_view(result: Any, *, current: Any | None, error: str | None = None) -> dict[str, Any]:
    """A :class:`.._self_update.CheckResult` for the page, plus whether an in-place update can run here.

    ``running`` is this process's version and ``installed`` the one on disk;
    they differ after an update until the gateway restarts
    (``restart_required``), whatever the page remembers. When the running
    package was imported from somewhere other than the installed distribution,
    ``foreign_source`` names that place and no restart is offered: the two
    versions will differ until that copy is removed. ``check_error`` is set
    when an explicit check failed while ``check`` still shows the last valid
    answer.
    """
    from .. import __version__
    from .. import _self_update as core

    view: dict[str, Any] = {"ok": True, "supported": True, "refusal": None, "running": __version__}
    try:
        if current is None:
            raise RuntimeError("installed metadata unreadable")
        view["installed"] = current.version
        core.refuse_if_unsupported(current, uv=core.find_uv(_api()._home()))
    except core.UpdateRefused as exc:
        view["supported"] = False
        view["refusal"] = {"code": _REFUSAL_CODES.get(exc.code, "update_refused"), "message": exc.message}
    except Exception as exc:  # metadata unreadable: say so instead of a 500
        view["supported"] = False
        view["refusal"] = {"code": "update_refused", "message": f"{type(exc).__name__}: {exc}"}
    foreign = current.foreign_source if current is not None else None
    view["foreign_source"] = foreign
    view["restart_required"] = foreign is None and view.get("installed") not in (None, __version__)
    view["check"] = result.to_json() if result is not None else None
    view["check_error"] = error
    return view


@router.get("/update/check")
async def update_check(refresh: int = 0) -> Any:
    """Is a newer Mordred release available?

    Without ``refresh`` this reuses Hermes's fresh plugin-check receipt or our
    own day-old answer and asks PyPI at most once a day (never when
    ``plugins.auto_update_check_hours`` is 0). ``refresh=1`` is the user's
    **Check now**: one request, cached on success only; when it fails the
    answer still shows the last valid one (``check``) and names the failure
    (``check_error``). ``check`` is ``null`` when nothing is known and nothing
    was asked.
    """
    from .. import _self_update as core

    def work() -> dict[str, Any]:
        home = _api()._home()
        try:
            current = core.installed(home)
        except Exception:
            _log.warning("mordred installed metadata unreadable", exc_info=True)
            current = None
        result: core.CheckResult | None
        error: str | None = None
        if refresh and current is not None:
            try:
                result = core.check(current=current)
                core.write_cache(result, home)
            except core.UpdateCheckFailed as exc:
                # Keep showing the last valid answer (no new request); name the failure.
                error = f"check failed: {exc}"
                result = core.hermes_receipt_check(home) or core.read_cache(home)
                if result is not None and (result.failed or result.installed != current.version):
                    result = None
        elif current is not None:
            result = core.cached_check(home, current=current)
        else:
            result = None
        return _update_view(result, current=current, error=error)

    try:
        return await asyncio.to_thread(work)
    except Exception as exc:
        _log.warning("mordred update check failed (%s)", type(exc).__name__)
        return _api()._error("update_check_failed")


def _prepare_update(target: str) -> tuple[Any, Any] | str:
    """The install source and uv for an update to *target*, or the refusal code."""
    from .. import _self_update as core

    try:
        current = core.installed(_api()._home())
        uv = core.find_uv(_api()._home())
        core.refuse_if_unsupported(current, uv=uv)
    except core.UpdateRefused as exc:
        return _REFUSAL_CODES.get(exc.code, "update_refused")
    except Exception as exc:
        _log.warning("mordred update refused (%s)", type(exc).__name__)
        return "update_refused"
    newer = core.is_newer(target, current.version)
    if newer is None:
        return "update_bad_version"
    if not newer:
        return "update_not_newer"
    return current, uv


@router.post("/update/apply")
async def update_apply(body: dict[str, Any] | None = None) -> Any:
    """Body: ``{"version": "<release>"}``. Runs ``hermes-mordred update --yes`` as a job.

    The version must parse and be newer than the one on disk: this route
    never downgrades (the CLI's ``--version`` is the explicit way). Refusals
    answer before any job starts; an uninstall in progress is a refusal too.
    ``progress.step`` / ``progress.output`` carry the failed step on error; on
    success ``progress.report`` is the update report and the page offers the
    gateway restart.
    """
    from .. import _self_update as core

    body = body or {}
    target = body.get("version")
    if not isinstance(target, str) or not target.strip():
        return _api()._error("invalid_request")
    target = target.strip()
    if _running("uninstall"):
        return _api()._error("update_busy")
    prepared = await asyncio.to_thread(_prepare_update, target)
    if isinstance(prepared, str):
        return _api()._error(prepared)
    current, uv = prepared
    if _running("uninstall"):  # an uninstall may have started during the await
        return _api()._error("update_busy")

    async def work(job: Any) -> None:
        job.progress = {"message": f"Installing hermes-mordred {target}…", "target": target}
        _api()._emit("progress", {"job_id": job.job_id, **job.progress})
        try:
            report = await job.run_sync(core.apply, target, current=current, uv=uv, home=_api()._home())
        except core.UpdateRefused as exc:
            job.progress = {"target": target, "refusal": exc.message, "rolled_back": exc.rolled_back}
            code = (
                "update_rollback_failed" if exc.rolled_back is False else _REFUSAL_CODES.get(exc.code, "update_refused")
            )
            raise _api()._Fail(code) from exc
        except core.UpdateFailed as exc:
            job.progress = {
                "target": target,
                "step": exc.step,
                "output": exc.output,
                "rolled_back": exc.rolled_back,
                "rollback_output": exc.rollback_output,
            }
            raise _api()._Fail("update_rollback_failed" if exc.rolled_back is False else "update_failed") from exc
        job.progress = {"target": target, "report": report.to_json()}

    try:
        job = _api()._start_job("update", work)
    except JobBusy as exc:
        return _api()._error(exc.code)
    return {"ok": True, **_api()._job_view(job)}


# -- uninstall ----------------------------------------------------------------------------


class _UninstallAnswers(_FixedPassphrase):
    """Answers ``hermes-mordred uninstall``'s prompts with what the page collected.

    The page's own confirmation replaces the yes/no question; the typed
    ``delete my data`` phrase (``--purge-data`` only) and the vault recovery
    passphrase (only if the device key cannot open the vault) come from the
    request body and are used once, in memory.
    """

    def __init__(self, recovery_passphrase: str, purge_phrase: str) -> None:
        super().__init__(recovery_passphrase)
        self._purge_phrase = purge_phrase

    def ask_bool(self, label: str, default: bool, *, description: str | None = None) -> bool:
        return True

    def ask_text(self, label: str, default: str = "", *, description: str | None = None) -> str:
        return self._purge_phrase


def _uninstall_context(prompt: Any = None) -> Any:
    from ..keyvault._identity import resolve_root
    from ..wizard.uninstall_cli import UninstallContext

    return UninstallContext(
        home=_api()._home(), vault_root=resolve_root(None), user_home=Path.home(), prompt_io=prompt, interactive=False
    )


@router.get("/uninstall/plan")
async def uninstall_plan() -> Any:
    """What uninstalling would do (the dry run), for the page to show before confirming."""
    from ..wizard.uninstall_cli import UninstallOptions, run_uninstall

    def plan(purge: bool, erase: bool = False) -> str:
        # The three dry runs share one process-wide capture lock, so they run one after another.
        with captured_output() as out:
            run_uninstall(_uninstall_context(), UninstallOptions(dry_run=True, purge_data=purge, erase_encrypted=erase))
        return out.getvalue()

    keep, purge, erase = await asyncio.gather(
        asyncio.to_thread(plan, False), asyncio.to_thread(plan, True), asyncio.to_thread(plan, True, True)
    )
    return {"ok": True, "plan": keep, "plan_purge": purge, "plan_erase": erase}


@router.post("/uninstall")
async def uninstall(request: Request) -> Any:
    """Body: ``{"mode": "decrypt" | "erase", "purge_data": bool, "confirm": str, "recovery_passphrase"?: str}``.

    ``decrypt`` (default) restores every encrypted target to plaintext, removes
    Mordred from Hermes and uninstalls the package; ``purge_data`` also
    deletes Mordred's data and keys. ``erase`` does not decrypt anything: the
    encrypted data is deleted as it is, together with all Mordred data.
    Deleting anything needs ``confirm`` = ``delete my data``. Runs as a job;
    ``progress.summary`` carries the report.
    """
    body = await read_object(request)
    if isinstance(body, JSONResponse):
        return body
    return await _uninstall(body)


async def _uninstall(body: dict[str, Any]) -> Any:
    """:func:`uninstall` after the body was read (the route's logic; tests drive it directly)."""
    from ..wizard.uninstall_cli import PURGE_PHRASE, UninstallOptions, run_uninstall

    erase = body.get("mode") == "erase"
    purge = erase or body.get("purge_data") is True
    phrase = str(body.get("confirm") or "")
    if purge and phrase.strip() != PURGE_PHRASE:
        return _api()._error("uninstall_confirm_mismatch")
    prompt = _UninstallAnswers(str(body.get("recovery_passphrase") or ""), phrase)
    if _running("update"):
        return _api()._error("uninstall_busy")

    async def work(job: Any) -> None:
        def run() -> tuple[int, str]:
            with captured_output() as out:
                rc = run_uninstall(
                    _uninstall_context(prompt), UninstallOptions(yes=True, purge_data=purge, erase_encrypted=erase)
                )
            return rc, out.getvalue()

        rc, summary = await job.run_sync(run)
        job.progress = {"summary": summary}
        if rc != 0:
            raise _api()._Fail("uninstall_failed")

    try:
        job = _api()._start_job("uninstall", work)
    except JobBusy as exc:
        return _api()._error(exc.code)
    return {"ok": True, **_api()._job_view(job)}
