"""The Desktop API's seams, registries, ceremony lock and lifespan: one module, resolved at call time.

Every route module reaches the mail library, the read-only import-store opener,
the flow registries and the ceremony lock through THIS module's attributes at
call time (``_seams.mail_flows()``, never a ``from … import`` alias), so a
test replaces one attribute here and every route sees it.

- Library seams: :func:`mail_flows` (``imports.mail.setup_flow.MailSetupFlows``),
  :func:`forget` (``imports.mail.forget.forget``), :func:`mail_audit`
  (``imports.mail.forget.audit_entry``), :func:`open_store_readonly` and
  :func:`store_refusal` (``imports.store``), :func:`mail_secret_store`,
  :func:`imap_status`, :func:`run_fetch` and :func:`fetch_env`. The mail
  library is imported only when first used.
- Registries: ``MAIL_FLOWS`` (the process's ``MailSetupFlows``) and
  ``VAULT_FLOWS`` (:class:`._vault.VaultFlows`).
- ``CEREMONY_LOCK`` / :func:`run_ceremony`: one vault or memory ceremony at a
  time, in a worker thread that a cancelled request cannot cut short.
- :func:`lifespan`: ``api.router``'s lifespan, which ``include_router`` merges
  into the host app's (FastAPI 0.133 and 0.139 alike): a reaper drops expired
  flows every :data:`REAP_INTERVAL_S` seconds while no request arrives, and
  shutdown cancels every flow.
"""

from __future__ import annotations

import asyncio
import contextlib
import contextvars
import importlib
import logging
import threading
from collections.abc import AsyncIterator, Callable
from pathlib import Path
from typing import Any

from fastapi.responses import JSONResponse

from . import _vault

_log = logging.getLogger(__name__)

#: How often the reaper drops expired mail setup and vault flows (and their passwords).
REAP_INTERVAL_S = 30.0

MAIL_FLOWS: Any = None
VAULT_FLOWS: _vault.VaultFlows | None = None
# A ``threading.Lock`` (not an asyncio one): the worker thread releases it when the
# ceremony really ends, so a cancelled request can neither cut the ceremony short
# nor let a second one start.
CEREMONY_LOCK = threading.Lock()


# -- the mail library and the import store --------------------------------------------------------


def library(module: str, name: str) -> Any:
    """``module.name`` relative to this package, imported when first used."""
    return getattr(importlib.import_module(module, __package__), name)


def mail_secret_store() -> Any:
    from ..imports.mail.secrets import MailSecretStore

    return MailSecretStore()


def mail_flows() -> Any:
    """The process's ``MailSetupFlows`` (one pending flow; reaped every call and by the reaper)."""
    global MAIL_FLOWS
    if MAIL_FLOWS is None:
        MAIL_FLOWS = library("..imports.mail.setup_flow", "MailSetupFlows")(mail_secret_store())
    return MAIL_FLOWS


def forget(secret_store: Any, home: Path, *, account: str | None, rows: bool) -> Any:
    return library("..imports.mail.forget", "forget")(secret_store, home, account=account, rows=rows)


def mail_audit(done: Any, *, rows: bool, home: Path) -> None:
    """The CLI's ``mail.forget`` audit event (``imports.mail.forget.audit_entry``), to the same audit log."""
    try:
        from .._audit_support import build_audit_writer, safe_audit_append

        entry = library("..imports.mail.forget", "audit_entry")(done, rows=rows)
        safe_audit_append(build_audit_writer(home / "mordred" / "audit.log"), entry, logger=_log)
    except Exception as exc:
        _log.warning("mordred desktop mail audit append failed (%s)", type(exc).__name__)


def open_store_readonly(home: Path) -> Any:
    """The import store for counts: non-creating, non-unlocking, never initialised (raises ``ImportRefused``)."""
    return library("..imports.store", "open_import_store_readonly")(home)


def store_refusal(exc: BaseException) -> str:
    """``imports.store.refusal_code``: the store's closed code for a refusal (unknown: ``store_unavailable``)."""
    try:
        refusal_code = library("..imports.store", "refusal_code")
    except (ImportError, AttributeError):  # an import store without the closed mapping: the code as it is
        code = getattr(exc, "code", None)
        return code if isinstance(code, str) else "store_unavailable"
    return str(refusal_code(exc))


def imap_status(store: Any, flags: Any) -> Any:
    from ..wizard.mail_sync_cli import imap_status as status_of

    return status_of(store, flags)


def run_fetch(options: Any, env: Any) -> Any:
    from ..imports.mail.imap_sync import run_fetch as fetch

    return fetch(options, env)


def fetch_env(home: Path) -> Any:
    from ..imports.mail.imap_sync import default_env

    return default_env(home)


# -- vault and databases --------------------------------------------------------------------------


def vault_root() -> Path:
    from ..wizard.vault_cli import _resolve_root

    return _resolve_root(None)


def sqlcipher_available() -> bool:
    try:
        import sqlcipher3  # noqa: F401
    except ImportError:
        return False
    return True


def vault_flows() -> _vault.VaultFlows:
    global VAULT_FLOWS
    if VAULT_FLOWS is None:

        def generate() -> str:
            from . import api

            return api.generate_recovery_passphrase()

        VAULT_FLOWS = _vault.VaultFlows(generate)
    return VAULT_FLOWS


async def run_ceremony(work: Callable[[], dict[str, Any]]) -> Any:
    """Run ``work`` in a worker thread under the ceremony lock; never cancelled with the request."""
    lock = CEREMONY_LOCK
    if not lock.acquire(blocking=False):
        return JSONResponse({"ok": False, "error": "memory_operation_in_progress"}, status_code=200)

    def run() -> dict[str, Any]:
        try:
            return work()
        finally:
            lock.release()

    try:
        context = contextvars.copy_context()
        future = asyncio.get_running_loop().run_in_executor(None, context.run, run)
    except BaseException:
        lock.release()
        raise
    result = await asyncio.shield(future)
    return result if result.get("ok") else JSONResponse(result, status_code=200)


# -- flow lifetime --------------------------------------------------------------------------------


def reap_once() -> None:
    """Drop expired mail setup and vault flows (with their passwords) while no request arrives."""
    for flows in (MAIL_FLOWS, VAULT_FLOWS):
        if flows is not None:
            try:
                flows.reap()
            except Exception as exc:
                _log.warning("mordred desktop flow reap failed (%s)", type(exc).__name__)


async def reaper() -> None:
    while True:
        await asyncio.sleep(REAP_INTERVAL_S)
        reap_once()


def cancel_all_flows() -> None:
    """On shutdown: no prepared passphrase or app password outlives the backend."""
    for flows in (MAIL_FLOWS, VAULT_FLOWS):
        if flows is not None:
            try:
                flows.cancel_all()
            except Exception as exc:
                _log.warning("mordred desktop flow cancel failed (%s)", type(exc).__name__)


@contextlib.asynccontextmanager
async def lifespan(_app: Any) -> AsyncIterator[None]:
    """``api.router``'s lifespan, merged into the host app's: the reaper runs while the app does."""
    task = asyncio.get_running_loop().create_task(reaper())
    try:
        yield
    finally:
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task
        cancel_all_flows()
