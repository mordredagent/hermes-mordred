"""Mordred setup API for the Hermes Desktop plugin (``/api/plugins/mordred/...``).

The desktop half (``desktop/plugin.js``) collects secrets in masked dialogs
and sends them here with ``ctx.rest``: straight to this Python process, never
through the agent, the model, or the chat. This module:

- validates every body by hand (no pydantic models: a 422 would echo the
  secret back), never logs a body, and answers with stable error codes only;
- seals everything with the Secure Enclave (:mod:`..extension.telegram.tee`)
  or the Mordred file vault, and returns only non-secret status — with one
  deliberate exception: a freshly generated vault recovery passphrase is
  returned exactly once, to be shown to the user and written down;
- runs long work (building the Enclave helper, importing messages) as jobs
  and reports progress with plugin events plus a poll endpoint.

On Windows the Windows-specific decisions live in :mod:`._windows`: status for
``client_version >= 3`` (older clients keep the unsupported shape) with one row
per capability and no aggregate readiness answer, the helper state, the CNG
memory flow behind explicit acknowledgements, Telegram custody and
acknowledgement gating, logout/forget and the import service's memory guard.
Routes such as ``/sync`` and ``/jobs`` are shared. macOS and Linux never reach
that module. Every captured wizard output goes through :mod:`._capture` (one
capture per process at a time, only the capturing thread's text).

Secret-bearing routes take the raw ``Request`` and read the body with
:func:`._body.read_object` (``invalid_body``, never FastAPI's 422 echo). The
macOS sections added for ``client_version >= 4`` (vault, databases, imports,
mail) come from :mod:`._status_v4` and never unlock anything. The macOS
routes of the new steps are sub-routers included at the end of this module:
:mod:`._ceremony_routes` (``/vault/*``, ``/databases/*``) and
:mod:`._mail_routes` (``/mail/*``, ``/imports/status``); package updates and
uninstall are :mod:`._maintenance_routes`. The mail library, the
read-only import-store opener, the flow registries, the ceremony lock and the
router's lifespan (the flow reaper) live in :mod:`._seams`, read at call time.

Served by Hermes' dashboard server, which requires the per-process session
token on every ``/api`` request and binds to loopback only.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import secrets
import sys
import time
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from . import _seams, _status_v4, _vault
from ._body import read_object
from ._capture import captured_output
from ._jobs import Job as _Job
from ._jobs import JobRegistry, JobWork

_log = logging.getLogger(__name__)
PLUGIN_ID = "mordred"
router = APIRouter(lifespan=_seams.lifespan)


# -- helpers ------------------------------------------------------------------------


def _error(code: str, status: int = 200) -> JSONResponse:
    """Expected failures answer 200 + ``ok: false``: a non-2xx is logged by Desktop.

    The body is only ever a code, never an echo of what was sent.
    """
    del status
    return JSONResponse({"ok": False, "error": code}, status_code=200)


def _quiet(work: Any, *args: Any, **kwargs: Any) -> Any:
    """Run ``work`` with this thread's printed output captured and discarded (serialized, see ``_capture``)."""
    with captured_output():
        return work(*args, **kwargs)


def _code(exc: BaseException, fallback: str) -> str:
    code = getattr(exc, "code", None)
    return code if isinstance(code, str) and code else fallback


def _emit(event: str, payload: dict[str, Any]) -> None:
    with contextlib.suppress(Exception):
        from hermes_cli.plugin_events import broadcast_plugin_event

        broadcast_plugin_event(PLUGIN_ID, event, payload)


def _home() -> Path:
    from .._home import hermes_home

    return hermes_home()


def _store() -> Any:
    """The platform's Telegram credential store (``TeeSecretStore`` on macOS/Linux, C10b custody on Windows)."""
    from ..extension.telegram.tee import default_secret_store

    return default_secret_store()


def _writable_store() -> Any:
    """The store for writes after the route's checks; Windows verifies its role without per-use presence."""
    store = _store()
    if sys.platform == "win32":
        from ._windows import NoPresenceStore

        return NoPresenceStore(store)
    return store


_JOBS = JobRegistry(emit=lambda event, payload: _emit(event, payload))


def _start_job(kind: str, work: JobWork) -> _Job:
    return _JOBS.start(kind, work)


def _job_view(job: _Job) -> dict[str, Any]:
    return {"job_id": job.job_id, "kind": job.kind, "state": job.state, "error": job.error, "progress": job.progress}


# -- Hermes' own chat model ------------------------------------------------------------

_MODEL_CACHE: dict[str, Any] = {}
_MODEL_TTL = 600.0


async def hermes_model_check() -> dict[str, Any]:
    """Is the model Hermes chats with private (Venice ``private``) or local?

    Everything the agent reads goes to this model, so Telegram stays locked
    until it is. Venice privacy comes from its public model catalog (no key).
    """
    from ..extension.telegram import venice
    from ..extension.telegram.hermes_tools import _classify_endpoint, _configured_model

    model, base_url = await asyncio.to_thread(_configured_model)
    kind = _classify_endpoint(base_url)
    result: dict[str, Any] = {"model": model, "kind": kind or "other", "private": None, "ok": False}
    if kind == "local" and model:
        result.update(private=True, ok=True)
        return result
    if kind != "venice" or not model:
        return result
    cached = _MODEL_CACHE.get(model)
    if cached is not None and time.monotonic() - cached[0] < _MODEL_TTL:
        result.update(private=cached[1], ok=cached[1] is True)
        return result
    try:
        from ..extension.egress import resolve_route
        from ..extension.telegram.service import _default_http_session, _ProxiedSession

        route = await asyncio.to_thread(resolve_route, "api.venice.ai")
        raw = _default_http_session(route, 20.0)
        try:
            cfg = venice.VeniceConfig(api_key="", model=model)
            await venice.require_private_model(_ProxiedSession(raw, route.http_proxy_url), cfg)
            private: bool | None = True
        except venice.VeniceError as exc:
            private = False if exc.code in {"venice_model_not_private", "venice_model_unknown"} else None
        finally:
            await raw.close()
    except Exception:
        private = None  # could not verify (offline?): stay locked, let the UI retry
    if private is not None:
        _MODEL_CACHE[model] = (time.monotonic(), private)
    result.update(private=private, ok=private is True)
    return result


async def _require_hermes_model() -> JSONResponse | None:
    check = await hermes_model_check()
    return None if check["ok"] else _error("hermes_model_not_private")


# -- status -------------------------------------------------------------------------


@router.get("/status")
async def status(client_version: int = 1) -> dict[str, Any]:
    """Setup progress from metadata only (no Touch ID, no secrets, no content).

    ``client_version >= 4`` adds ``vault``, ``databases``, ``imports``, ``mail``
    and ``telegram_archive`` (:func:`_sections_v4`); older clients get exactly
    the keys they always got.
    """
    if sys.platform == "win32" and client_version >= 3:
        return await _windows_status(client_version)
    platform_status = {
        "platform": sys.platform,
        "telegram_supported": sys.platform == "darwin" or (sys.platform == "linux" and client_version >= 2),
        "telegram_platform_supported": sys.platform in ("darwin", "linux"),
        "hardware_kind": {"darwin": "secure_enclave", "linux": "tpm"}.get(sys.platform),
        "user_presence_supported": sys.platform == "darwin",
    }
    jobs = [_job_view(j) for j in _JOBS.running()]
    platform = sys.platform
    if not platform_status["telegram_supported"]:
        extra = await _status_v4.sections(platform, _home()) if client_version >= 4 else {}
        return {"ok": True, **platform_status, "checks": {}, "jobs": jobs, **extra}

    from ..wizard.telegram_setup_cli import run_checks

    async def sections() -> dict[str, Any]:
        return await _status_v4.sections(platform, _home()) if client_version >= 4 else {}

    checks, extra = await asyncio.gather(asyncio.to_thread(run_checks), sections())
    return {
        "ok": True,
        **platform_status,
        "hermes_model": await hermes_model_check(),
        "checks": {c.name: {"ok": c.ok, "detail": c.detail} for c in checks},
        "hermes_venice_key": _hermes_venice_key() is not None,
        "telegram_api": bool((await asyncio.to_thread(_store().flags) or {}).get("api_configured")),
        "jobs": jobs,
        **extra,
    }


async def _windows_status(client_version: int = 3) -> dict[str, Any]:
    """Windows status for a compatible client: capabilities, helper, memory, Telegram; no unwrap or launch."""
    from . import _windows

    jobs = [_job_view(j) for j in _JOBS.running()]
    payload = await asyncio.to_thread(_windows.status_payload, _home(), _store())
    result: dict[str, Any] = {"ok": True, **payload, "hermes_model": await hermes_model_check(), "jobs": jobs}
    if payload["telegram_supported"]:
        result["hermes_venice_key"] = await asyncio.to_thread(_hermes_venice_key) is not None
    if client_version >= 4:
        result.update(await _status_v4.sections("win32", _home()))
    return result


@router.get("/health")
async def health() -> dict[str, Any]:
    """Mordred is installed here: version, environment and package-manager member."""
    from .. import __version__
    from . import member
    from .install import plugin_dir

    return {
        "ok": True,
        "installed": True,
        "version": __version__,
        "environment": member.environment_info(),
        "member": member.member_status(plugin_dir()),
        "pm_managed": member.pm_managed(),
    }


@router.get("/jobs/{job_id}")
async def job_status(job_id: str) -> Any:
    job = _JOBS.get(job_id)
    return {"ok": True, **_job_view(job)} if job else _error("job_not_found", 404)


# -- step 1: Secure Enclave ---------------------------------------------------------------


@router.post("/hardware/build")
async def hardware_build() -> Any:
    if sys.platform == "darwin":
        return await enclave_build()
    if sys.platform == "win32":
        # The helper is installed by the native installer or the wizard
        # (`hermes-mordred keyvault enable-winkey`); the API only reports it.
        from . import _windows

        helper = await asyncio.to_thread(_windows.helper_report, _home())
        return {"ok": True, "built": False, "hardware_kind": _windows.HARDWARE_KIND, "helper": helper}
    if sys.platform != "linux":
        return _error("telegram_platform_unsupported")

    async def work(job: _Job) -> None:
        from ..wizard.keyvault_native_cli import enable_tpm

        job.progress = {"message": "Building and probing the TPM 2.0 helper…"}
        _emit("progress", {"job_id": job.job_id, **job.progress})
        rc = await job.run_sync(_quiet, enable_tpm)
        if rc != 0:
            raise _Fail("tpm_build_failed")

    return {"ok": True, **_job_view(_start_job("hardware", work))}


@router.post("/enclave/build")
async def enclave_build() -> Any:
    if sys.platform != "darwin":
        return _error("telegram_platform_unsupported")

    async def work(job: _Job) -> None:
        from ..wizard.keyvault_native_cli import enable_se

        job.progress = {"message": "Building the Secure Enclave helper (a few minutes)…"}
        _emit("progress", {"job_id": job.job_id, **job.progress})
        rc = await job.run_sync(_quiet, enable_se)
        if rc != 0:
            raise _Fail("enclave_build_failed")

    return {"ok": True, **_job_view(_start_job("enclave", work))}


class _Fail(RuntimeError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


# -- step 2: vault + memory encryption --------------------------------------------------


def generate_recovery_passphrase(words: int = 8) -> str:
    """Eight random words from the BIP-39 list (~88 bits)."""
    from ..keyvault._bip39 import _load_wordlist

    wordlist = _load_wordlist()
    return " ".join(secrets.choice(wordlist) for _ in range(words))


def _memory_active() -> bool:
    from ..extension.telegram.memory_guard import memory_encryption_active

    return memory_encryption_active()


@router.post("/memory/enable")
async def memory_enable(body: dict[str, Any] | None = None) -> Any:
    """Turn on sealed memory (macOS: memory only; the vault and ``.env`` come from ``/vault/*``).

    macOS answers ``vault_required`` without a vault and ``env_required`` until
    ``.env`` is enrolled and injecting; it never creates a vault or a
    passphrase, and it is idempotent (``already``). Linux and Windows keep
    their flows (TPM, CNG behind explicit acknowledgements).
    """
    if sys.platform == "win32":
        return await _windows_memory_enable(body)
    if sys.platform not in ("darwin", "linux"):
        return _error("telegram_platform_unsupported")

    if sys.platform == "linux" and (body or {}).get("acknowledge_tpm_no_recovery") is not True:
        return _error("telegram_platform_unsupported")

    if sys.platform == "linux":
        if await asyncio.to_thread(_memory_active):
            return {"ok": True, "already": True}
        return await _linux_memory_enable()
    # macOS: the vault and the env target are checked BEFORE the idempotent answer.
    home, root, platform = _home(), _seams.vault_root(), sys.platform
    return await _seams.run_ceremony(
        lambda: _vault.enable_memory(home=home, root=root, platform=platform, active=_memory_active)
    )


async def _linux_memory_enable() -> Any:
    from ..wizard import memory_cli

    home, root = _home(), _seams.vault_root()

    def enable_linux() -> dict[str, Any]:
        with captured_output():
            rc = memory_cli.enable(home=home, root=root, platform="linux")
        if rc != 0 or not _memory_active():
            return {"ok": False, "error": "memory_encryption_failed"}
        return {"ok": True, "restart_required": True}

    return await _seams.run_ceremony(enable_linux)


async def _windows_memory_enable(body: dict[str, Any] | None) -> Any:
    """CNG memory enable; both acknowledgements are sent only from below the displayed limitations."""
    from . import _windows

    if not _windows.acknowledged(body, _windows.MEMORY_ACKNOWLEDGEMENTS):
        return _error("telegram_platform_unsupported")
    executable = sys.executable
    return await asyncio.to_thread(lambda: _windows.enable_memory(_home(), executable=executable))


@router.post("/memory/disable")
async def memory_disable(body: dict[str, Any] | None = None) -> Any:
    """Windows only: decrypt memory back to plaintext and keep the CNG key (purge stays a CLI ceremony)."""
    del body
    if sys.platform != "win32":
        return _error("telegram_platform_unsupported")
    from . import _windows

    executable = sys.executable
    return await asyncio.to_thread(lambda: _windows.disable_memory(_home(), executable=executable))


@router.get("/memory/status")
async def memory_status() -> Any:
    """Windows only: the load-only memory state and the typed gateway inventory (unknown stays unknown)."""
    if sys.platform != "win32":
        return _error("telegram_platform_unsupported")
    from . import _windows

    home = _home()
    memory, gateways = await asyncio.gather(
        asyncio.to_thread(_windows.memory_summary, home), asyncio.to_thread(_windows.gateway_inventory, home)
    )
    return {"ok": True, "memory": memory, "gateways": gateways}


# -- step 3/4: Telegram API credentials and login -----------------------------------------------

_FLOWS: Any = None


def _flows() -> Any:
    global _FLOWS
    if _FLOWS is None:
        from ..extension.telegram.login_flow import LoginFlows

        _FLOWS = LoginFlows(_writable_store())
    return _FLOWS


async def _require_memory() -> JSONResponse | None:
    if sys.platform == "win32":
        from ._windows import memory_refusal

        refusal = await asyncio.to_thread(memory_refusal, _home())
        return None if refusal is None else JSONResponse(refusal)
    from ..extension.telegram.memory_guard import memory_encryption_active

    ok = await asyncio.to_thread(memory_encryption_active)
    return None if ok else _error("memory_encryption_required", 409)


async def _windows_telegram_refusal(body: Any) -> JSONResponse | None:
    """On Windows: an enrolled ``telegram`` role and the no-presence acknowledgement; ``None`` elsewhere."""
    if sys.platform != "win32":
        return None
    from ._windows import telegram_refusal

    refusal = await asyncio.to_thread(telegram_refusal, _home(), body)
    return None if refusal is None else JSONResponse(refusal)


@router.post("/telegram/login/start")
async def telegram_login_start(request: Request) -> Any:
    """Body: {"phone", and on first setup "api_id", "api_hash"}; on Windows also "acknowledge_no_presence"."""
    body = await read_object(request)
    if isinstance(body, JSONResponse):
        return body
    blocked = await _require_memory() or await _require_hermes_model() or await _windows_telegram_refusal(body)
    if blocked is not None:
        return blocked
    from ..extension.telegram.login_flow import LoginError

    try:
        flow = await _flows().start(api_id=body.get("api_id"), api_hash=body.get("api_hash"), phone=body.get("phone"))
    except LoginError as exc:
        return _error(exc.code)
    except Exception as exc:
        return _error(_code(exc, "telegram_login_failed"), 500)
    return {"ok": True, "flow_id": flow.flow_id, "step": flow.step}


@router.post("/telegram/login/{flow_id}/code")
async def telegram_login_code(flow_id: str, request: Request) -> Any:
    from ..extension.telegram.login_flow import LoginError

    body = await read_object(request)
    if isinstance(body, JSONResponse):
        return body
    try:
        step = await _flows().submit_code(flow_id, body.get("code"))
    except LoginError as exc:
        return _error(exc.code)
    except Exception as exc:
        return _error(_code(exc, "telegram_login_failed"), 500)
    return {"ok": True, "step": step}


@router.post("/telegram/login/{flow_id}/password")
async def telegram_login_password(flow_id: str, request: Request) -> Any:
    from ..extension.telegram.login_flow import LoginError

    body = await read_object(request)
    if isinstance(body, JSONResponse):
        return body
    try:
        step = await _flows().submit_password(flow_id, body.get("password"))
    except LoginError as exc:
        return _error(exc.code)
    except Exception as exc:
        return _error(_code(exc, "telegram_login_failed"), 500)
    return {"ok": True, "step": step}


@router.post("/telegram/login/{flow_id}/cancel")
async def telegram_login_cancel(flow_id: str) -> Any:
    await _flows().cancel(flow_id)
    return {"ok": True}


# -- step 5: privacy LLM --------------------------------------------------------------------------


def _hermes_venice_key() -> str | None:
    """The Venice key Hermes itself is configured with (never returned to the UI)."""
    import os

    from dotenv import dotenv_values

    from .._yaml_io import load_yaml_mapping

    config = load_yaml_mapping(_home() / "config.yaml")
    names: list[str] = []
    entries: list[Any] = [config.get("model")]
    providers = config.get("custom_providers")
    if isinstance(providers, list):
        entries.extend(providers)
    for entry in entries:
        if isinstance(entry, dict) and "api.venice.ai" in str(entry.get("base_url", "")):
            name = entry.get("key_env")
            if isinstance(name, str) and name:
                names.append(name)
    names.append("VENICE_API_KEY")
    file_values = dotenv_values(_home() / ".env") if (_home() / ".env").is_file() else {}
    for name in dict.fromkeys(names):
        value = os.environ.get(name) or file_values.get(name)
        if value and value.strip():
            return value.strip()
    return None


def _set_venice(api_key: str, model: str | None) -> None:
    from ..extension.telegram.llm_settings import with_venice_settings
    from ..extension.telegram.secrets import empty_secrets

    store = _writable_store()
    store.ensure_key()

    def mutate(old: Any) -> Any:
        base = old if old is not None else empty_secrets()
        return with_venice_settings(base, api_key=api_key, model=model)

    store.update(mutate)


@router.post("/llm/venice")
async def llm_venice(request: Request) -> Any:
    """Body: {"use_hermes_key": true} or {"api_key": "..."}; optional "model"; Windows: "acknowledge_no_presence"."""
    body = await read_object(request)
    if isinstance(body, JSONResponse):
        return body
    blocked = await _windows_telegram_refusal(body)
    if blocked is not None:
        return blocked
    model = body.get("model")
    if model is not None and (not isinstance(model, str) or not model.strip() or len(model) > 128):
        return _error("invalid_request")
    if body.get("use_hermes_key") is True:
        key = await asyncio.to_thread(_hermes_venice_key)
        if key is None:
            return _error("hermes_venice_key_missing", 404)
    else:
        raw = body.get("api_key")
        if not isinstance(raw, str) or not raw.strip() or len(raw) > 512:
            return _error("invalid_request")
        key = raw.strip()
    try:
        await asyncio.to_thread(_set_venice, key, model.strip() if isinstance(model, str) else None)
    except Exception as exc:
        return _error(_code(exc, "llm_config_failed"), 500)
    return {"ok": True}


@router.post("/llm/local")
async def llm_local(request: Request) -> Any:
    from ..extension.telegram.llm import LlmConfigError, normalize_local_endpoint

    body = await read_object(request)
    if isinstance(body, JSONResponse):
        return body
    blocked = await _windows_telegram_refusal(body)
    if blocked is not None:
        return blocked
    endpoint, model = body.get("endpoint"), body.get("model")
    if not isinstance(endpoint, str) or not isinstance(model, str) or not model.strip():
        return _error("invalid_request")
    try:
        canonical = normalize_local_endpoint(endpoint)
    except LlmConfigError as exc:
        return _error(exc.code)
    from ..extension.telegram.llm_settings import KEEP_KEY, with_local_settings
    from ..extension.telegram.secrets import empty_secrets

    def mutate(old: Any) -> Any:
        base = old if old is not None else empty_secrets()
        return with_local_settings(base, endpoint=canonical, model=model, api_key=KEEP_KEY)

    def save() -> None:
        store = _writable_store()
        store.ensure_key()
        store.update(mutate)

    try:
        await asyncio.to_thread(save)
    except Exception as exc:
        return _error(_code(exc, "llm_config_failed"), 500)
    return {"ok": True, "endpoint": canonical}


# -- step 6: import ------------------------------------------------------------------------------------

_SERVICE: Any = None


def _service() -> Any:
    global _SERVICE
    if _SERVICE is None:
        from ..extension.telegram.service import TelegramService

        if sys.platform == "win32":
            from ._windows import memory_guard

            # The C10b store comes from default_secret_store(); memory is checked load-only.
            _SERVICE = TelegramService(memory_guard=memory_guard(_home))
        else:
            _SERVICE = TelegramService()
    return _SERVICE


@router.post("/sync")
async def sync(body: dict[str, Any]) -> Any:
    """Body (all optional): days, include_archived, include_channels, include_large_groups."""
    days = body.get("days")
    if days is not None and (not isinstance(days, int) or isinstance(days, bool) or not 1 <= days <= 3650):
        return _error("invalid_request")
    overrides = {
        "since_days": days,
        "include_archived": body.get("include_archived") if isinstance(body.get("include_archived"), bool) else None,
        "include_channels": body.get("include_channels") if isinstance(body.get("include_channels"), bool) else None,
        "max_group_size": 0 if body.get("include_large_groups") is True else None,
    }
    svc = _service()
    try:
        options = svc.sync_options(overrides)
        await svc.start_sync(options)
    except Exception as exc:
        from ..extension.telegram.service import error_code

        return _error(error_code(exc, "telegram_sync_failed"), 409)
    return {"ok": True}


@router.get("/sync")
async def sync_status() -> Any:
    status = await _service().status()
    return {
        "ok": True,
        "syncing": status["syncing"],
        "progress": status["progress"],
        "last_error": status["last_error"],
        "dialog_count": status["dialog_count"],
        "message_count": status["message_count"],
    }


@router.post("/telegram/logout")
async def telegram_logout(body: dict[str, Any] | None = None) -> Any:
    """Windows only. Body ``{"forget": bool, "confirm"?: str}``.

    Logout drops the session and keeps the archive. ``forget`` runs the custody
    wipe (archive, sealed credentials, then the ``telegram`` role; never
    ``delete_key``) and, like ``/uninstall``, needs ``confirm`` = ``delete my
    data`` checked here, before anything is read, revoked or deleted.
    """
    if sys.platform != "win32":
        return _error("telegram_platform_unsupported")
    from ..wizard.uninstall_cli import PURGE_PHRASE
    from ._windows import telegram_logout as windows_logout

    body = body or {}
    forget = body.get("forget") is True
    if forget and str(body.get("confirm") or "").strip() != PURGE_PHRASE:
        return _error("forget_confirm_mismatch")
    return await windows_logout(_store(), forget=forget)


# -- the macOS steps' sub-routers (imported last: they read this module at call time) ------------

from . import _ceremony_routes, _mail_routes, _maintenance_routes  # noqa: E402

router.include_router(_ceremony_routes.router)
router.include_router(_mail_routes.router)
router.include_router(_maintenance_routes.router)
