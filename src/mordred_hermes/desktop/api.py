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
mail) are built by the closed projections of :mod:`._projections` and never
unlock anything; :mod:`._vault` holds the prepare/commit vault ceremony and
:mod:`._databases` the schedule-or-report database step. The mail library
(``imports.mail.setup_flow``, ``imports.mail.forget``) and the read-only
import-store opener are reached only through the seams ``_mail_flows``,
``_forget`` and ``_open_store_readonly``.

Served by Hermes' dashboard server, which requires the per-process session
token on every ``/api`` request and binds to loopback only.
"""

from __future__ import annotations

import asyncio
import contextlib
import contextvars
import datetime as _dt
import importlib
import logging
import re
import secrets
import sys
import threading
import time
from collections.abc import AsyncIterator, Callable
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from . import _databases, _projections, _vault
from ._body import read_object
from ._capture import captured_output
from ._jobs import Job as _Job
from ._jobs import JobBusy, JobRegistry, JobWork

_log = logging.getLogger(__name__)
PLUGIN_ID = "mordred"
#: How often the flow reaper drops expired mail setup and vault flows (and their passwords).
REAP_INTERVAL_S = 30.0


@contextlib.asynccontextmanager
async def _lifespan(_app: Any) -> AsyncIterator[None]:
    """Merged into the host app's lifespan by ``include_router``: the reaper runs while the app does."""
    task = asyncio.get_running_loop().create_task(_reaper())
    try:
        yield
    finally:
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task
        _cancel_all_flows()


router = APIRouter(lifespan=_lifespan)


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
        extra = await _sections_v4(platform) if client_version >= 4 else {}
        return {"ok": True, **platform_status, "checks": {}, "jobs": jobs, **extra}

    from ..wizard.telegram_setup_cli import run_checks

    async def sections() -> dict[str, Any]:
        return await _sections_v4(platform) if client_version >= 4 else {}

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
        result.update(await _sections_v4("win32"))
    return result


# -- status sections for client_version >= 4 (macOS facts; fixed shapes elsewhere) -----------------

#: ``telegram_archive`` on a cold status: the legacy ``index.enc`` (its version and dialogs) is
#: AES-GCM ciphertext under a subkey of the sealed Telegram ``store_key``, and no status poll unwraps it.
_TELEGRAM_ARCHIVE: dict[str, Any] = {"legacy": None}
_UNSUPPORTED_VAULT: dict[str, Any] = {
    "exists": False,
    "env_enrolled": False,
    "env_injecting": False,
    "optout": False,
    "unattended": None,
}


def _vault_root() -> Path:
    from ..wizard.vault_cli import _resolve_root

    return _resolve_root(None)


def _sqlcipher_available() -> bool:
    try:
        import sqlcipher3  # noqa: F401
    except ImportError:
        return False
    return True


async def _sections_v4(platform: str) -> dict[str, Any]:
    if platform != "darwin":
        return {
            "vault": dict(_UNSUPPORTED_VAULT),
            "databases": {"supported": False},
            "imports": _projections.imports_refused("unsupported_platform"),
            "mail": {"configured": False},
            "telegram_archive": dict(_TELEGRAM_ARCHIVE),
        }
    home = _home()
    vault, databases, imports = await asyncio.gather(
        asyncio.to_thread(_vault_facts_safe, home),
        asyncio.to_thread(_databases_safe, home, platform),
        asyncio.to_thread(_imports_sections, home, platform),
    )
    return {"vault": vault, "databases": databases, **imports}


def _vault_facts_safe(home: Path) -> dict[str, Any]:
    try:
        return _vault.facts(home, _vault_root(), platform="darwin")
    except Exception as exc:
        _log.warning("mordred desktop vault facts unreadable (%s)", type(exc).__name__)
        return dict(_UNSUPPORTED_VAULT)


def _databases_safe(home: Path, platform: str) -> dict[str, Any]:
    try:
        return _databases.status_object(home, platform=platform, sqlcipher=_sqlcipher_available())
    except Exception as exc:
        _log.warning("mordred desktop database status unreadable (%s)", type(exc).__name__)
        return {"supported": _sqlcipher_available(), "code": "databases_failed"}


def _imports_sections(home: Path, platform: str) -> dict[str, Any]:
    """``imports``, ``mail`` and ``telegram_archive``: read-only store, flags only, nothing unlocked."""
    if platform != "darwin":
        return {
            "imports": _projections.imports_refused("unsupported_platform"),
            "mail": {"configured": False},
            "telegram_archive": dict(_TELEGRAM_ARCHIVE),
        }
    store: Any = None
    try:
        store = _open_store_readonly(home)
        imports = _projections.imports_projection(store.status())
    except Exception as exc:  # a gate or store refusal is a state (ImportRefused carries the code)
        store = None
        imports = _projections.imports_refused(_store_refusal(exc))
    if not imports["available"]:
        store = None
    flags: Any = None
    residue = False
    try:
        secret_store = _mail_secret_store()
        flags = secret_store.flags()
        residue = bool(secret_store.residue())  # counts only when the flags do not name a valid setup
    except Exception as exc:  # flags() raises ``credentials_left`` for a sealed file without readable flags
        residue = getattr(exc, "code", None) == "credentials_left"
        if not residue:
            _log.warning("mordred desktop mail flags unreadable (%s)", type(exc).__name__)
    mail_status: Any = None
    if store is not None and flags:
        try:
            mail_status = _imap_status(store, flags)
        except Exception as exc:
            _log.warning("mordred desktop mail status unreadable (%s)", type(exc).__name__)
    return {
        "imports": imports,
        "mail": _projections.mail_projection(flags, mail_status, residue=residue),
        "telegram_archive": dict(_TELEGRAM_ARCHIVE),
    }


@router.get("/imports/status")
async def imports_status() -> Any:
    """The ``imports``, ``mail`` and ``telegram_archive`` objects of ``/status`` (a light refresh)."""
    sections = await asyncio.to_thread(_imports_sections, _home(), sys.platform)
    return {"ok": True, **sections}


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


# One vault or memory ceremony at a time in this process. A ``threading.Lock`` (not an
# asyncio one): the worker thread releases it when the ceremony really ends, so a
# cancelled HTTP request can neither cut the ceremony short nor let a second one start.
_CEREMONY_LOCK = threading.Lock()


async def _run_ceremony(work: Callable[[], dict[str, Any]]) -> Any:
    """Run ``work`` in a worker thread under the ceremony lock; never cancelled with the request."""
    if not _CEREMONY_LOCK.acquire(blocking=False):
        return _error("memory_operation_in_progress")

    def run() -> dict[str, Any]:
        try:
            return work()
        finally:
            _CEREMONY_LOCK.release()

    try:
        context = contextvars.copy_context()
        future = asyncio.get_running_loop().run_in_executor(None, context.run, run)
    except BaseException:
        _CEREMONY_LOCK.release()
        raise
    result = await asyncio.shield(future)
    return result if result.get("ok") else JSONResponse(result, status_code=200)


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

    if await asyncio.to_thread(_memory_active):
        return {"ok": True, "already": True}
    if sys.platform == "linux":
        return await _linux_memory_enable()
    home, root, platform = _home(), _vault_root(), sys.platform
    return await _run_ceremony(
        lambda: _vault.enable_memory(home=home, root=root, platform=platform, active=_memory_active)
    )


_VAULT_FLOWS: _vault.VaultFlows | None = None


def _vault_flows() -> _vault.VaultFlows:
    global _VAULT_FLOWS
    if _VAULT_FLOWS is None:
        _VAULT_FLOWS = _vault.VaultFlows(lambda: generate_recovery_passphrase())
    return _VAULT_FLOWS


@router.post("/vault/prepare")
async def vault_prepare(request: Request) -> Any:
    """Body ``{}``. Generate the recovery passphrase in memory and show it BEFORE anything is created.

    Answers ``{"ok": true, "flow_id", "passphrase": [8 words], "passphrase_reused": false}``;
    nothing on disk changes. An existing vault whose ``.env`` is not enrolled
    gets a flow without a passphrase (``passphrase: null, passphrase_reused:
    true``): its phrase is the one shown at its creation. ``vault_exists`` when
    there is nothing to do, ``env_optout`` when the owner restored a plaintext
    ``.env``. One flow at a time (a new one replaces it), TTL 600 s.
    """
    body = await read_object(request)
    if isinstance(body, JSONResponse):
        return body
    if sys.platform != "darwin":
        return _error("unsupported_platform")
    state = await asyncio.to_thread(_vault.facts, _home(), _vault_root(), platform="darwin")
    answer = _vault.prepare_answer(_vault_flows(), state)
    return answer if answer["ok"] else JSONResponse(answer, status_code=200)


@router.post("/vault/{flow_id}/commit")
async def vault_commit(flow_id: str, request: Request) -> Any:
    """Body ``{"unattended": bool}``. Create the vault with the prepared passphrase, enroll ``.env``.

    ``{"ok": true, "passphrase_reused": bool}``; ``vault_flow_expired`` (TTL,
    replaced, restart: nothing was created), ``vault_exists``, ``env_optout``,
    ``vault_anchor_stale`` (with ``anchor_store``, ``anchor_identity`` and,
    only for a legacy anchor over an empty vault directory, ``remedy``) or
    ``memory_encryption_failed``. ``unattended`` applies only to a device key
    created here (absent: the backend default, as ``setup``); an existing key
    keeps its policy.
    """
    body = await read_object(request)
    if isinstance(body, JSONResponse):
        return body
    unattended = body.get("unattended")
    if not (unattended is None or isinstance(unattended, bool)):
        return _error("invalid_body")
    if sys.platform != "darwin":
        return _error("unsupported_platform")
    flows = _vault_flows()
    flow = flows.get(flow_id)
    if flow is None:
        return _error("vault_flow_expired")
    home, root, platform = _home(), _vault_root(), sys.platform
    return await _run_ceremony(
        lambda: _vault.commit(home=home, root=root, platform=platform, flow=flow, flows=flows, unattended=unattended)
    )


async def _linux_memory_enable() -> Any:
    from ..wizard import memory_cli

    home, root = _home(), _vault_root()

    def enable_linux() -> dict[str, Any]:
        with captured_output():
            rc = memory_cli.enable(home=home, root=root, platform="linux")
        if rc != 0 or not _memory_active():
            return {"ok": False, "error": "memory_encryption_failed"}
        return {"ok": True, "restart_required": True}

    return await _run_ceremony(enable_linux)


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


# -- databases (macOS): schedule or report, never convert --------------------------------------


@router.get("/databases/status")
async def databases_status() -> Any:
    """The ``databases`` object of ``/status`` alone (after the restart control, when status is too heavy)."""
    return {"ok": True, **await asyncio.to_thread(_databases_safe, _home(), sys.platform)}


@router.post("/databases/encrypt")
async def databases_encrypt(request: Request) -> Any:
    """Body ``{"dry_run": bool}``. Schedules the conversion for the next start, or reports why not.

    ``{"ok": true, "action": "dry_run" | "scheduled" | "attention" | "needs_restart" | "done", …}``
    (``restart_required`` with ``scheduled`` / ``needs_restart``, ``code`` with
    ``attention``: ``journal``, ``decrypt_pending``, ``stale_pending``,
    ``plaintext_in_armed_home``); ``databases_unsupported`` off macOS or without
    SQLCipher; ``databases_failed`` when scheduling failed (re-read the status).
    No key is needed and none is unwrapped: the conversion runs at startup.
    """
    body = await read_object(request)
    if isinstance(body, JSONResponse):
        return body
    dry_run = body.get("dry_run", False)
    if not isinstance(dry_run, bool):
        return _error("invalid_body")
    if sys.platform != "darwin" or not await asyncio.to_thread(_sqlcipher_available):
        return _error("databases_unsupported")
    if dry_run:
        return {"ok": True, "action": "dry_run"}
    home = _home()

    def decide() -> dict[str, Any]:
        facts = _databases.status_object(home, platform="darwin", sqlcipher=True)
        return _databases.encrypt_answer(home, facts)

    try:
        return await asyncio.to_thread(decide)
    except Exception as exc:
        _log.warning("mordred desktop database encryption not scheduled (%s)", type(exc).__name__)
        return _error("databases_failed")


# -- mail over IMAP (macOS) -----------------------------------------------------------------------
#
# Seams (the only places that name the mail library and the read-only store opener;
# tests replace them with fakes): _mail_flows, _forget, _open_store_readonly,
# _mail_secret_store, _imap_status, _run_fetch, _fetch_env.

DESKTOP_BUDGET_S = 600.0
_MAIL_ROLES = ("all", "inbox", "sent")
_ACCOUNT_RE = re.compile(r"[a-z][a-z0-9_]{0,31}")
_MAIL_FLOWS: Any = None


def _library(module: str, name: str) -> Any:
    """``module.name`` of the mail library, imported when first used (this module imports without it)."""
    return getattr(importlib.import_module(module, __package__), name)


def _mail_flows() -> Any:
    """The process's ``MailSetupFlows`` (one pending flow; reaped every call and by the reaper)."""
    global _MAIL_FLOWS
    if _MAIL_FLOWS is None:
        _MAIL_FLOWS = _library("..imports.mail.setup_flow", "MailSetupFlows")(_mail_secret_store())
    return _MAIL_FLOWS


def _forget(secret_store: Any, home: Path, *, account: str | None, rows: bool) -> Any:
    return _library("..imports.mail.forget", "forget")(secret_store, home, account=account, rows=rows)


def _open_store_readonly(home: Path) -> Any:
    """The import store for counts: non-creating, non-unlocking, never initialised (raises ``ImportRefused``)."""
    return _library("..imports.store", "open_import_store_readonly")(home)


def _store_refusal(exc: BaseException) -> str:
    """``imports.store.refusal_code``: the store's closed code for a refusal (unknown: ``store_unavailable``)."""
    try:
        refusal_code = _library("..imports.store", "refusal_code")
    except (ImportError, AttributeError):  # an import store without the closed mapping: the code as it is
        code = getattr(exc, "code", None)
        return code if isinstance(code, str) else "store_unavailable"
    return str(refusal_code(exc))


def _mail_audit(done: Any, *, rows: bool) -> None:
    """The CLI's ``mail.forget`` audit event (``imports.mail.forget.audit_entry``), to the same audit log."""
    try:
        from .._audit_support import build_audit_writer, safe_audit_append

        entry = _library("..imports.mail.forget", "audit_entry")(done, rows=rows)
        safe_audit_append(build_audit_writer(_home() / "mordred" / "audit.log"), entry, logger=_log)
    except Exception as exc:
        _log.warning("mordred desktop mail audit append failed (%s)", type(exc).__name__)


def _mail_secret_store() -> Any:
    from ..imports.mail.secrets import MailSecretStore

    return MailSecretStore()


def _imap_status(store: Any, flags: Any) -> Any:
    from ..wizard.mail_sync_cli import imap_status

    return imap_status(store, flags)


def _run_fetch(options: Any, env: Any) -> Any:
    from ..imports.mail.imap_sync import run_fetch

    return run_fetch(options, env)


def _fetch_env(home: Path) -> Any:
    from ..imports.mail.imap_sync import default_env

    return default_env(home)


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


async def _mail_gate(*, memory: bool) -> JSONResponse | None:
    if sys.platform != "darwin":
        return _error("unsupported_platform")
    return await _require_memory() if memory else None


def _strings(value: Any) -> list[str] | None:
    if value is None:
        return []
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return list(value)
    return None


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
        return _error("invalid_body")
    blocked = await _mail_gate(memory=True)
    if blocked is not None:
        return blocked
    try:
        flow = await _call(
            _mail_flows().start,
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
        return _error("invalid_body")
    blocked = await _mail_gate(memory=True)
    if blocked is not None:
        return blocked
    try:
        await _call(_mail_flows().finish, flow_id, selection=selection)
    except Exception as exc:
        return _mail_error(exc, _projections.MAIL_SETUP_CODES, _projections.MAIL_SETUP_FALLBACK)
    return {"ok": True, "step": "done"}


@router.post("/mail/setup/{flow_id}/cancel")
async def mail_setup_cancel(flow_id: str) -> Any:
    """Drop a pending flow and its password (idempotent; no gate, so cleanup always works)."""
    if _MAIL_FLOWS is not None:
        try:
            await _call(_MAIL_FLOWS.cancel, flow_id)
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
    if not (mailbox is None or mailbox in _MAIL_ROLES) or not (dry_run is None or isinstance(dry_run, bool)):
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


def _fetch_mail(options: Any, home: Path) -> dict[str, Any]:
    """One fetch, as the closed ``FetchResult.as_dict()`` (``run_fetch`` never raises for a refusal)."""
    result = _run_fetch(options, _fetch_env(home))
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
    body = await read_object(request)
    if isinstance(body, JSONResponse):
        return body
    options = _fetch_options(body)
    if options is None:
        return _error("invalid_request")
    blocked = await _mail_gate(memory=True)
    if blocked is not None:
        return blocked
    for job in _JOBS.running():
        if job.kind == "mail_fetch":
            return {"ok": True, **_job_view(job), "already_running": True}
    home = _home()

    async def work(job: _Job) -> None:
        job.progress = {"message": "Fetching new mail… up to 10 minutes"}
        _emit("progress", {"job_id": job.job_id, **job.progress})
        try:
            data = await job.run_sync(_fetch_mail, options, home)
        except Exception as exc:
            _log.warning("mordred desktop mail fetch failed (%s)", type(exc).__name__)
            raise _Fail(_projections.MAIL_FETCH_FALLBACK) from None
        job.progress = {"result": data}
        if data.get("error") is not None:
            raise _Fail(_projections.closed(data["error"], _projections.MAIL_FETCH_CODES, "fetch_failed"))

    try:
        job = _start_job("mail_fetch", work)
    except JobBusy as exc:
        return _error(exc.code)
    return {"ok": True, **_job_view(job), "already_running": False}


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

    body = await read_object(request)
    if isinstance(body, JSONResponse):
        return body
    rows, confirm, account = body.get("rows"), body.get("confirm"), body.get("account")
    if not isinstance(rows, bool) or not (confirm is None or isinstance(confirm, str)):
        return _error("invalid_body")
    if rows and (confirm or "").strip() != PURGE_PHRASE:
        return _error("forget_confirm_mismatch")
    if not (account is None or isinstance(account, str)):
        return _error("invalid_body")
    if account is not None and not _ACCOUNT_RE.fullmatch(account):
        return _error("invalid_account")
    blocked = await _mail_gate(memory=rows)
    if blocked is not None:
        return blocked
    if _MAIL_FLOWS is not None:
        with contextlib.suppress(Exception):
            await _call(_MAIL_FLOWS.cancel_all)
    try:
        done = await asyncio.to_thread(_forget, _mail_secret_store(), _home(), account=account, rows=rows)
    except Exception as exc:
        return _mail_error(exc, _projections.MAIL_FORGET_CODES, _projections.MAIL_FORGET_FALLBACK)
    await asyncio.to_thread(_mail_audit, done, rows=rows)
    return _projections.forgotten_projection(done)


# -- flow lifetime ------------------------------------------------------------------------------


def _reap_once() -> None:
    """Drop expired mail setup and vault flows (with their passwords) while no request arrives."""
    for flows in (_MAIL_FLOWS, _VAULT_FLOWS):
        if flows is not None:
            try:
                flows.reap()
            except Exception as exc:
                _log.warning("mordred desktop flow reap failed (%s)", type(exc).__name__)


async def _reaper() -> None:
    while True:
        await asyncio.sleep(REAP_INTERVAL_S)
        _reap_once()


def _cancel_all_flows() -> None:
    """On shutdown: no prepared passphrase or app password outlives the backend."""
    for flows in (_MAIL_FLOWS, _VAULT_FLOWS):
        if flows is not None:
            try:
                flows.cancel_all()
            except Exception as exc:
                _log.warning("mordred desktop flow cancel failed (%s)", type(exc).__name__)


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
    return _JOBS.is_running(kind)


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
        core.refuse_if_unsupported(current, uv=core.find_uv(_home()))
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
        home = _home()
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
        return _error("update_check_failed")


def _prepare_update(target: str) -> tuple[Any, Any] | str:
    """The install source and uv for an update to *target*, or the refusal code."""
    from .. import _self_update as core

    try:
        current = core.installed(_home())
        uv = core.find_uv(_home())
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
        return _error("invalid_request")
    target = target.strip()
    if _running("uninstall"):
        return _error("update_busy")
    prepared = await asyncio.to_thread(_prepare_update, target)
    if isinstance(prepared, str):
        return _error(prepared)
    current, uv = prepared
    if _running("uninstall"):  # an uninstall may have started during the await
        return _error("update_busy")

    async def work(job: _Job) -> None:
        job.progress = {"message": f"Installing hermes-mordred {target}…", "target": target}
        _emit("progress", {"job_id": job.job_id, **job.progress})
        try:
            report = await job.run_sync(core.apply, target, current=current, uv=uv, home=_home())
        except core.UpdateRefused as exc:
            job.progress = {"target": target, "refusal": exc.message, "rolled_back": exc.rolled_back}
            code = (
                "update_rollback_failed" if exc.rolled_back is False else _REFUSAL_CODES.get(exc.code, "update_refused")
            )
            raise _Fail(code) from exc
        except core.UpdateFailed as exc:
            job.progress = {
                "target": target,
                "step": exc.step,
                "output": exc.output,
                "rolled_back": exc.rolled_back,
                "rollback_output": exc.rollback_output,
            }
            raise _Fail("update_rollback_failed" if exc.rolled_back is False else "update_failed") from exc
        job.progress = {"target": target, "report": report.to_json()}

    try:
        job = _start_job("update", work)
    except JobBusy as exc:
        return _error(exc.code)
    return {"ok": True, **_job_view(job)}


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
        home=_home(), vault_root=resolve_root(None), user_home=Path.home(), prompt_io=prompt, interactive=False
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
        return _error("uninstall_confirm_mismatch")
    prompt = _UninstallAnswers(str(body.get("recovery_passphrase") or ""), phrase)
    if _running("update"):
        return _error("uninstall_busy")

    async def work(job: _Job) -> None:
        def run() -> tuple[int, str]:
            with captured_output() as out:
                rc = run_uninstall(
                    _uninstall_context(prompt), UninstallOptions(yes=True, purge_data=purge, erase_encrypted=erase)
                )
            return rc, out.getvalue()

        rc, summary = await job.run_sync(run)
        job.progress = {"summary": summary}
        if rc != 0:
            raise _Fail("uninstall_failed")

    try:
        job = _start_job("uninstall", work)
    except JobBusy as exc:
        return _error(exc.code)
    return {"ok": True, **_job_view(job)}
