"""Telegram importer service used by the extension WebSocket server and CLI.

One instance per ``extension serve`` process. It owns at most one running sync
task, exposes a status snapshot, the dialog list, and question answering. All
failures surface as stable codes (``TelegramServiceError.code``) so no message
text, name, or credential can reach a client or a log line through an
exception string.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import time
from collections.abc import AsyncIterator, Callable
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from ..egress import EgressError, EgressRoute, resolve_route
from . import venice
from .ask import (
    Aliases,
    AskError,
    AskRequest,
    budget_for,
    build_messages,
    dealias_stream,
    select_context,
    validate_question,
)
from .client import (
    SyncOptions,
    SyncProgress,
    TelegramClientError,
    build_client,
    sync_archive,
    telethon_available,
)
from .readonly import ReadOnlyViolation, RequestPolicy
from .secrets import TelegramSecrets, TelegramSecretsError, VaultSecretStore
from .store import ArchiveStore, StoreError

_log = logging.getLogger(__name__)

_VENICE_HOST = "api.venice.ai"
_ASK_TIMEOUT_SECONDS = 300.0
_MAX_DIALOGS_LISTED = 2000

# Telethon RPC error class names → wire codes. Matched by name so this module
# imports without Telethon installed.
_TELETHON_ERROR_CODES = {
    "FloodWaitError": "telegram_rate_limited",
    "FloodPremiumWaitError": "telegram_rate_limited",
    "AuthKeyUnregisteredError": "telegram_session_revoked",
    "SessionRevokedError": "telegram_session_revoked",
    "SessionExpiredError": "telegram_session_revoked",
    "UserDeactivatedError": "telegram_session_revoked",
    "UserDeactivatedBanError": "telegram_session_revoked",
    "AuthKeyDuplicatedError": "telegram_session_revoked",
}


class TelegramServiceError(RuntimeError):
    """Stable, content-free failure code."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def error_code(exc: BaseException, fallback: str) -> str:
    """Map any exception from this package to a reviewed wire code."""
    for kind in (
        TelegramServiceError,
        TelegramClientError,
        TelegramSecretsError,
        StoreError,
        AskError,
        venice.VeniceError,
        EgressError,
    ):
        if isinstance(exc, kind):
            return str(getattr(exc, "code", fallback))
    if isinstance(exc, ReadOnlyViolation):
        return "telegram_request_blocked"
    for cls in type(exc).__mro__:
        mapped = _TELETHON_ERROR_CODES.get(cls.__name__)
        if mapped is not None:
            return mapped
    if isinstance(exc, ConnectionError | OSError | asyncio.TimeoutError):
        return "telegram_unavailable"
    return fallback


@dataclass
class AskResult:
    model: str
    message_count: int
    dialog_count: int
    truncated: bool


def _audit(event: str, decision: str, **fields: Any) -> None:
    """Best-effort audit entry. Never includes content, names, or keys."""
    try:
        from ..._audit_support import build_audit_writer, safe_audit_append
        from ..._home import hermes_home

        writer = build_audit_writer(hermes_home() / "mordred" / "audit.log")
        safe_audit_append(writer, {"event": event, "decision": decision, "reason": None, **fields}, logger=_log)
    except Exception:
        _log.debug("telegram audit append failed", exc_info=True)


def check_llm_policy(base_url: str) -> None:
    """Apply the llm_guard strict-mode gate to the Venice endpoint.

    This client is not a Hermes provider adapter, so the ``pre_api_request``
    hook never sees it; run the same per-request check explicitly. Under
    strict mode Venice must be allow-listed (``cloud_provider_allowlist``
    contains ``"venice"`` and ``allow_cloud_llm`` is true). There is no
    interactive prompt here: ``prompt-once`` fails closed.
    """
    from ..._home import hermes_home
    from ..._policy_io import read_policy_mode_fail_closed
    from ...llm_guard import enforce
    from ...llm_guard._exceptions import MordredSessionRefused

    path = hermes_home() / "mordred" / "policy.json"
    mode = read_policy_mode_fail_closed(path, default="lenient", log=_log)
    try:
        from ..._audit_support import build_audit_writer

        writer = build_audit_writer(hermes_home() / "mordred" / "audit.log")
        enforce.check_runtime_provider(
            policy_mode=mode,
            policy_json_path=path,
            active_provider="venice",
            audit=writer,
            runtime_base_url=base_url,
            prompt_fn=lambda _provider: False,
        )
    except MordredSessionRefused as exc:
        raise TelegramServiceError("llm_policy_refused") from exc


def _default_http_session(route: EgressRoute, timeout: float) -> Any:
    import aiohttp

    connector = None
    if route.socks_proxy_url is not None:
        try:
            from aiohttp_socks import ProxyConnector

            connector = ProxyConnector.from_url(route.socks_proxy_url, rdns=True)
        except (ImportError, RuntimeError, ValueError) as exc:
            raise EgressError() from exc
    return aiohttp.ClientSession(
        connector=connector,
        timeout=aiohttp.ClientTimeout(total=timeout),
        trust_env=False,
    )


class _ProxiedSession:
    """Adds the explicit HTTP proxy (if any) to every request."""

    def __init__(self, session: Any, http_proxy: str | None) -> None:
        self._session = session
        self._proxy = http_proxy

    def get(self, url: str, **kwargs: Any) -> Any:
        if self._proxy is not None:
            kwargs["proxy"] = self._proxy
        return self._session.get(url, **kwargs)

    def post(self, url: str, **kwargs: Any) -> Any:
        if self._proxy is not None:
            kwargs["proxy"] = self._proxy
        return self._session.post(url, **kwargs)


class TelegramService:
    def __init__(
        self,
        *,
        secret_store: VaultSecretStore | None = None,
        archive_root: Path | None = None,
        client_factory: Callable[..., Any] = build_client,
        http_session_factory: Callable[[EgressRoute, float], Any] = _default_http_session,
        route_resolver: Callable[[str], EgressRoute] = resolve_route,
        policy_check: Callable[[str], None] = check_llm_policy,
        installed: Callable[[], bool] = telethon_available,
    ) -> None:
        self._secrets = secret_store or VaultSecretStore()
        self._archive_root = archive_root
        self._client_factory = client_factory
        self._http_session_factory = http_session_factory
        self._route_resolver = route_resolver
        self._policy_check = policy_check
        self._installed = installed
        self._sync_task: asyncio.Task[None] | None = None
        self._progress = SyncProgress()
        self._last_error: str | None = None

    # -- helpers --------------------------------------------------------------

    async def _load_secrets(self, *, fresh: bool = False) -> TelegramSecrets | None:
        return await asyncio.to_thread(self._secrets.load, fresh=fresh)

    def _archive(self, value: TelegramSecrets) -> ArchiveStore:
        return ArchiveStore(value.store_key, self._archive_root)

    @property
    def syncing(self) -> bool:
        return self._sync_task is not None and not self._sync_task.done()

    # -- status ---------------------------------------------------------------

    async def status(self) -> dict[str, Any]:
        """Snapshot for the popup. Counts and flags only, plus the account label."""
        result: dict[str, Any] = {
            "installed": self._installed(),
            "configured": False,
            "logged_in": False,
            "venice_configured": False,
            "venice_model": None,
            "syncing": self.syncing,
            "progress": asdict(self._progress),
            "last_error": self._last_error,
            "last_sync": 0,
            "dialog_count": 0,
            "message_count": 0,
            "account_label": "",
        }
        try:
            value = await self._load_secrets()
        except (TelegramSecretsError, StoreError) as exc:
            result["last_error"] = exc.code
            return result
        if value is None:
            return result
        result["configured"] = True
        result["logged_in"] = value.session is not None
        result["venice_configured"] = value.venice_api_key is not None
        result["venice_model"] = self._venice_model(value)
        try:
            index = await asyncio.to_thread(self._archive(value).load_index)
        except StoreError as exc:
            result["last_error"] = exc.code
            return result
        result["last_sync"] = index.last_sync
        result["dialog_count"] = len(index.dialogs)
        result["message_count"] = sum(d.message_count for d in index.dialogs.values())
        result["account_label"] = index.account_label
        return result

    async def dialogs(self) -> list[dict[str, Any]]:
        value = await self._load_secrets()
        if value is None:
            raise TelegramServiceError("telegram_not_configured")
        index = await asyncio.to_thread(self._archive(value).load_index)
        ordered = sorted(index.dialogs.values(), key=lambda d: d.last_date, reverse=True)
        return [
            {
                "id": str(d.dialog_id),
                "kind": d.kind,
                "title": d.title,
                "message_count": d.message_count,
                "last_date": d.last_date,
                "archived": d.archived,
            }
            for d in ordered[:_MAX_DIALOGS_LISTED]
        ]

    # -- sync -----------------------------------------------------------------

    async def start_sync(self, options: SyncOptions | None = None) -> None:
        """Start a background sync; raise ``sync_in_progress`` if one runs."""
        if self.syncing:
            raise TelegramServiceError("sync_in_progress")
        if not self._installed():
            raise TelegramServiceError("telegram_not_installed")
        value = await self._load_secrets(fresh=True)
        if value is None:
            raise TelegramServiceError("telegram_not_configured")
        if value.session is None:
            raise TelegramServiceError("telegram_not_logged_in")
        self._last_error = None
        self._progress = SyncProgress(started_at=int(time.time()))
        self._sync_task = asyncio.create_task(self._run_sync(value, options or SyncOptions()))

    async def wait_for_sync(self) -> None:
        if self._sync_task is not None:
            with contextlib.suppress(Exception):
                await self._sync_task

    async def _run_sync(self, value: TelegramSecrets, options: SyncOptions) -> None:
        store = self._archive(value)
        lock = store.locked()
        client: Any = None
        try:
            await asyncio.to_thread(lock.__enter__)
            try:
                # Built on the loop thread: Telethon binds a client to its loop.
                client = self._client_factory(value.api_id, value.api_hash, value.session, policy=RequestPolicy())
                await client.connect()
                if not await client.is_user_authorized():
                    raise TelegramServiceError("telegram_session_revoked")

                def on_progress(state: SyncProgress) -> None:
                    self._progress = state

                result = await sync_archive(client, store, options=options, progress=on_progress)
                self._progress = result
                _audit(
                    "telegram.sync",
                    "allow",
                    dialogs=result.dialogs_done,
                    messages=result.messages_imported,
                )
            finally:
                lock.__exit__(None, None, None)
        except asyncio.CancelledError:
            self._last_error = "sync_cancelled"
            raise
        except Exception as exc:
            code = error_code(exc, "telegram_sync_failed")
            self._last_error = code
            if code == "telegram_sync_failed":
                _log.warning("telegram sync failed", exc_info=True)
            _audit("telegram.sync", "raise", code=code)
        finally:
            if client is not None:
                with contextlib.suppress(Exception):
                    await client.disconnect()
            self._progress.finished_at = int(time.time())

    async def cancel_sync(self) -> None:
        task = self._sync_task
        if task is not None and not task.done():
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await task

    # -- questions --------------------------------------------------------------

    @staticmethod
    def _venice_model(value: TelegramSecrets) -> str:
        return value.venice_model or os.environ.get(venice.MODEL_ENV) or venice.DEFAULT_MODEL

    async def ask(self, request: AskRequest, on_meta: Callable[[AskResult], None]) -> AsyncIterator[str]:
        """Stream the answer; *on_meta* is called once before the first chunk."""
        question = validate_question(request.question)
        value = await self._load_secrets()
        if value is None:
            raise TelegramServiceError("telegram_not_configured")
        if value.venice_api_key is None:
            raise TelegramServiceError("venice_not_configured")
        cfg = venice.VeniceConfig(api_key=value.venice_api_key, model=self._venice_model(value))
        await asyncio.to_thread(self._policy_check, cfg.base_url)
        route = await asyncio.to_thread(self._route_resolver, _VENICE_HOST)
        raw_session = self._http_session_factory(route, _ASK_TIMEOUT_SECONDS)
        try:
            session = _ProxiedSession(raw_session, route.http_proxy_url)
            info = await venice.require_private_model(session, cfg)
            store = self._archive(value)
            index = await asyncio.to_thread(store.load_index)
            if not index.dialogs:
                raise TelegramServiceError("archive_empty")
            aliases = Aliases(enabled=request.pseudonymize)
            selection = await asyncio.to_thread(
                select_context, store, index, request, aliases, budget_chars=budget_for(info.context_tokens)
            )
            if selection.message_count == 0:
                raise TelegramServiceError("no_matching_messages")
            on_meta(
                AskResult(
                    model=cfg.model,
                    message_count=selection.message_count,
                    dialog_count=selection.dialog_count,
                    truncated=selection.truncated,
                )
            )
            _audit(
                "telegram.ask",
                "allow",
                model=cfg.model,
                messages=selection.message_count,
                dialogs=selection.dialog_count,
                pseudonymized=request.pseudonymize,
            )
            chunks = venice.stream_chat(session, cfg, build_messages(question, selection))
            async for text in dealias_stream(chunks, aliases):
                yield text
        finally:
            with contextlib.suppress(Exception):
                await raw_session.close()
