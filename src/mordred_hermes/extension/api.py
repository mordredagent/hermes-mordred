"""Mordred Extension WebSocket API (gateway side).

Serves ``ws://127.0.0.1:47711/ext`` for the browser extension. Localhost-only,
no TLS; an Origin check rejects connections from ordinary web pages (only
``chrome-extension://`` / ``moz-extension://`` / header-less clients pass).

Message protocol: ``Mordred-Extension/SPEC.ja.md`` §6 and the extension's
``src/lib/protocol.ts``. Handlers:

- ``auth2_hello``      → a browser's signed hello (pre-auth). An endorsed device key
  gets ``auth2_ok`` (signed by Hermes' identity key, with the endorsements and a
  fresh X25519 session); an unknown one gets ``auth2_unendorsed`` with the check
  code, and may then send ``device_enroll``, which asks the owner at the Mac
  (Touch ID or the login password) through :mod:`mordred_hermes.extension.trust`
- ``auth``             → the localhost page's process token, reply ``auth_ok``
- ``chat``             → injected ``chat_handler`` streamed as ``chat_chunk*`` + ``chat_end``
- ``encrypt``/``decrypt`` → :mod:`mordred_hermes.extension.crypto` with Hermes' master key
- ``accounts_request`` → keyvault address (``accounts_result``)
- ``sign_request`` → analyze + ``sign_prompt``; ``sign_approve`` → keyvault sign → ``sign_result``
- ``telegram_status`` / ``telegram_sync`` / ``telegram_dialogs`` → read-only Telegram importer
- ``telegram_ask`` → Venice private-model answer streamed as ``telegram_ask_meta`` +
  ``telegram_ask_chunk*`` + ``telegram_ask_end`` (or ``telegram_ask_error``); a request
  carrying ``"evidence": true`` also gets one sealed ``telegram_ask_evidence`` frame
  (validated source cards) right before ``telegram_ask_end``
- ``recall_query`` / ``recall_open`` / ``recall_dismiss`` → :mod:`mordred_hermes.recall` over
  ``mordred.db``'s import tables; the selection arrives sealed and the cards and context
  leave sealed with the socket's session key (``recall_result`` / ``recall_opened`` / ``recall_dismissed``)
- ``recall_recommend`` (``recall_recommend_v1``) → memories for the same search, picked and
  explained by a loopback local model (:mod:`mordred_hermes.recall.recommend`), streamed as
  sealed ``recall_recommend_item`` frames and one ``recall_recommend_end``;
  ``recall_recommend_cancel`` stops it (no reply)
- ``recall_translate`` (``recall_translate_v1``) → a page selection translated into the
  user's language by the same loopback local model (:mod:`mordred_hermes.recall.translate`),
  streamed as sealed ``recall_translate_piece`` frames and one ``recall_translate_end``;
  ``recall_translate_cancel`` stops it (no reply)
- ``recall_restore`` / ``recall_hidden`` → show a hidden conversation again, or list the
  hidden ones (sealed, with their source and title): ``recall_restored`` /
  ``recall_hidden_result`` (``recall_restore_v1``)
- ``recall_events`` (prototype) → :mod:`mordred_hermes.recall.events`: the typed words' hits
  grouped into events, headlined by a loopback-only local model when one is configured;
  sealed both ways (``recall_events_result``). ``mode: "selection"`` takes a page
  selection and searches its derived keywords instead (``recall_events_selection_v1``)
- ``activity_batch`` / ``activity_status`` → :mod:`mordred_hermes.extension.activity_api`;
  the paired extension may submit ``activity_batch``; the page principal never reaches them.

Server-initiated frames: ``ping`` (app-level keepalive, see
``_Connection.keepalive``) and ``error`` (malformed JSON / crashed handler).
Both are part of the extension's strict frame decoder contract.
"""

from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import json
import logging
import os
import re
import secrets
import threading
from collections.abc import AsyncIterator, Callable
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlsplit

from aiohttp import WSMsgType, web
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from . import activity_api, page_headers, pairing, trust
from ._windows_storage import ExtensionStorageError
from .crypto import (
    DecryptError,
    decrypt_message,
    encrypt_message,
    encrypt_message_v2,
    is_encrypted,
    key_id,
)
from .errors import wire_error_code
from .health import HEALTH_CAPABILITY
from .imports_api import IMPORTS_CAPABILITY, ImportsRefusal
from .vault_gate import LOCKED_REASON, VaultFatal, VaultGate, always_open
from .wallet import _do_sign, _get_account_snapshot, _prepare_sign, analyze_sign

# Slack tokens land verbatim in ~/.hermes/.env as ``KEY=value`` lines. A prefix
# check plus ``.strip()`` is not enough: ``.strip()`` only trims the *edges*, so
# "xoxb-x\nEVIL=secret" keeps its embedded newline and would inject a second
# dotenv entry that Hermes loads on its next restart. Pin both tokens to the
# exact charset Slack issues (``fullmatch`` — no newline is in the class).
_SLACK_BOT_TOKEN_RE = re.compile(r"xoxb-[A-Za-z0-9-]+")
_SLACK_APP_TOKEN_RE = re.compile(r"xapp-[A-Za-z0-9-]+")

# The localhost page is a LOWER-privilege principal than the paired extension,
# so its post-auth surface is an ALLOWLIST, not a denylist. Its bearer token is
# delivered out-of-band in the launch URL's fragment (never in an HTTP response)
# and removed from browser history by the page bootstrap. Any handler added to
# the `authed` table is refused for page sessions unless it is added here too.
#
# These are the page's *own* actions, not a read-only set: ``history_clear``
# deletes the encrypted store. It is allowed because the bundled page triggers
# it from an explicit, confirmed user action on data the page is already showing
# — never on the page's behalf and never automatically. What stays out is
# everything that acts beyond the page: credential/key writes, the K_master
# crypto oracle, and the wallet signer.
# ``test_page_allowlist_entries_are_all_used_by_the_shipped_page`` pins each
# entry to a call site in the shipped bundle.
_PAGE_ALLOWED = frozenset({"chat", "accounts_request", "history_get", "history_clear"})
_EXTENSION_CAPABILITIES = [
    "telegram_import_v1",
    activity_api.ACTIVITY_CAPABILITY,
    "recall_v1",
    # ``recall_query`` with ``mode: "words"``: every typed word, as typed (``RecallIndex.search_words``).
    "recall_words_v1",
    # ``recall_events``: the typed words' hits grouped into events, headlined by a local model (prototype).
    "recall_events_v1",
    # ``recall_events`` with ``mode: "selection"``: a page selection, searched by its derived keywords.
    "recall_events_selection_v1",
    # ``recall_restore`` / ``recall_hidden``: undo a dismissal, and list the hidden conversations.
    "recall_restore_v1",
    # ``recall_recommend``: memories for a search, picked and explained by a local model, streamed.
    "recall_recommend_v1",
    # ``recall_translate``: a selection translated into the user's language by a local model, streamed.
    "recall_translate_v1",
    # ``recall_conversation``: the whole conversation around a part, to read through.
    "recall_conversation_v1",
    IMPORTS_CAPABILITY,
    # ``health``: each feature's state (ok / off / down) and reason code (:mod:`.health`).
    HEALTH_CAPABILITY,
    # ``chat_model_call``: which model the chat runs, and upgrading it to a Venice-private model.
    "chat_model_v1",
]

# A sign_request entry leaves _pending_sign only on approve/reject (or when the
# socket dies), so an authed client that never approves would grow it without
# bound. Cap it and evict the oldest (dicts keep insertion order) — a stale
# prompt the user never answered is the right thing to drop.
_MAX_PENDING_SIGN = 32

# Part and conversation uids are opaque store ids (a mail one embeds the
# normalised Message-ID, so the alphabet is open); they only ever reach a bound
# SQL parameter. Bound the length and refuse control characters.
_RECALL_UID_RE = re.compile(r"[^\x00-\x1f\x7f]{1,512}")

_log = logging.getLogger(__name__)

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 47711

# Must match Mordred-Extension's protocol.ts. Outbound history is projected to
# the newest complete suffix that fits this raw text-frame ceiling.
MAX_WS_FRAME_CHARS = 4 * 1024 * 1024

# App-level keepalive period. Chrome kills an idle MV3 service worker after
# ~30s; receiving a WS message (any type) fires onmessage and resets that
# timer, while aiohttp's protocol-level ping/pong never reaches JS. Must stay
# below 30s with margin.
DEFAULT_KEEPALIVE_INTERVAL = 20.0

# A chat handler streams response chunks for a user message.
ChatHandler = Callable[[str, dict[str, Any]], AsyncIterator[str]]

# Telegram requests carry at most this many selected dialog ids.
_MAX_TELEGRAM_DIALOG_IDS = 50
# Questions run as their own tasks (a Venice answer can take minutes and must
# not stall the socket's other frames); cap how many one socket may run.
_MAX_TELEGRAM_ASKS_PER_SOCKET = 2
# One panel and one popup may each be recommending at once.
_MAX_RECALL_RECOMMENDS_PER_SOCKET = 2
# Likewise one translation each.
_MAX_RECALL_TRANSLATES_PER_SOCKET = 2
_TELEGRAM_DIALOG_ID_RE = re.compile(r"-?[0-9]{1,20}")


def _serialize_frame(payload: dict[str, Any]) -> str:
    """Serialize every outbound frame deterministically as ASCII.

    ASCII escaping makes Python's character count identical to both its wire
    byte count and the JavaScript client's raw-string count.
    """
    return json.dumps(payload, ensure_ascii=True, separators=(",", ":"))


def _bounded_history_result(
    request_id: Any,
    turns: list[dict[str, str]],
    *,
    max_chars: int = MAX_WS_FRAME_CHARS,
    status: str = "ok",  # history.STATUS_OK (kept a literal: history imports lazily)
) -> dict[str, Any]:
    """Return all projected turns or the longest complete newest suffix.

    The encrypted history itself is never modified. Per-turn serialization is
    reused to compute the exact compact JSON frame size without repeatedly
    serializing progressively smaller copies of a potentially large history.

    ``status`` is an ADDITIVE field (``ok`` / ``empty`` / ``unavailable`` /
    ``undecryptable``): ``turns`` stays a list of the same shape, so a client
    built against the older frame keeps working while a newer one can tell an
    empty conversation from one it can no longer decrypt.
    """
    full = {
        "id": request_id,
        "type": "history_result",
        "status": status,
        "turns": turns,
        "truncated": False,
    }
    encoded_turns = [_serialize_frame(turn) for turn in turns]
    empty_full = {**full, "turns": []}
    full_chars = len(_serialize_frame(empty_full))
    if encoded_turns:
        full_chars += sum(map(len, encoded_turns)) + len(encoded_turns) - 1
    if full_chars <= max_chars:
        return full

    truncated = {**full, "turns": [], "truncated": True}
    used = len(_serialize_frame(truncated))
    keep = 0
    # `truncated: true` must mean at least one turn was actually omitted. The
    # marker is one character shorter than `false`, so an exact boundary could
    # otherwise retain every turn merely by changing the marker's value.
    for encoded in reversed(encoded_turns[1:]):
        added = len(encoded) + (1 if keep else 0)
        if used + added > max_chars:
            break
        used += added
        keep += 1
    if keep:
        truncated["turns"] = turns[-keep:]
    return truncated


async def _default_chat_handler(content: str, _context: dict[str, Any]) -> AsyncIterator[str]:
    yield (f"⚠️ Hermes のエージェント接続が拡張 API に未接続です(chat_handler 未設定)。\n受信メッセージ: {content!r}")


# Directory holding the self-contained localhost web app (built from the
# extension's src/page; see scripts in the extension repo). Served at "/".
_WEB_DIR = Path(__file__).resolve().parent / "web"


def _is_extension_origin(origin: str | None) -> bool:
    """A well-formed extension origin and, once the installer named the Mordred
    extension's IDs (:mod:`.native_host`), one of those: no other extension."""
    if origin is None:
        return False
    if not _well_formed_extension_origin(origin):
        return False
    from .._core._home import hermes_home
    from . import native_host

    allowed = native_host.allowed_extension_ids(Path(hermes_home()))
    return allowed is None or native_host.extension_id_of(origin) in allowed


def _well_formed_extension_origin(origin: str) -> bool:
    try:
        parsed = urlsplit(origin)
        return bool(
            parsed.scheme in {"chrome-extension", "moz-extension"}
            and parsed.hostname
            and parsed.username is None
            and parsed.password is None
            and parsed.port is None
            and not parsed.path
            and not parsed.query
            and not parsed.fragment
        )
    except ValueError:
        return False


def _is_loopback_host(host: str) -> bool:
    """Return whether a bind/Host value names only the local machine."""
    normalized = host.strip().removeprefix("[").removesuffix("]")
    if normalized.casefold() == "localhost":
        return True
    try:
        return ipaddress.ip_address(normalized).is_loopback
    except ValueError:
        return False


def _request_is_loopback(request: web.Request) -> bool:
    """Validate both the TCP peer and HTTP Host against DNS-rebinding tricks."""
    remote = request.remote
    if remote is None or not _is_loopback_host(remote):
        return False
    try:
        hostname = urlsplit(f"//{request.host}").hostname
    except ValueError:
        return False
    return hostname is not None and _is_loopback_host(hostname)


def _enrollment_attested(origin: str, code: str, presented: object) -> bool:
    """Whether a new browser may be approved: always without a native host, else only with its ticket."""
    from .._core._home import hermes_home
    from . import native_host

    try:
        secret = native_host.read_secret(Path(hermes_home()))
    except (OSError, ValueError):
        return False
    if secret is None:
        return True
    extension_id = native_host.extension_id_of(origin)
    return extension_id is not None and native_host.ticket_valid(secret, extension_id, code, presented)


def _loopback_origin(host: str, port: int) -> str:
    """Return the canonical HTTP origin for an already-validated bind host."""
    normalized = host.strip().removeprefix("[").removesuffix("]")
    display_host = f"[{normalized}]" if ":" in normalized else normalized.casefold()
    return f"http://{display_host}:{port}"


class ExtensionAPIServer:
    def __init__(
        self,
        *,
        host: str = DEFAULT_HOST,
        port: int = DEFAULT_PORT,
        chat_handler: ChatHandler | None = None,
        telegram_service: Any = None,
        recall_service: Any = None,
        imports_api: Any = None,
        keepalive_interval: float = DEFAULT_KEEPALIVE_INTERVAL,
        activity_receiver: Any = None,
        activity_max_batch_bytes: int = activity_api.DEFAULT_MAX_BATCH_BYTES,
        vault_gate: VaultGate | None = None,
    ) -> None:
        if not _is_loopback_host(host):
            raise ValueError(f"extension API host must be loopback-only (got {host!r})")
        self.host = host
        self.port = port
        self.chat_handler: ChatHandler = chat_handler or _default_chat_handler
        # One importer per server process (it owns the single running sync).
        # Built lazily so a server without the Telegram extra never imports it.
        self._telegram_service = telegram_service
        self._recall_service = recall_service
        # One per process: it owns the login/setup flows and the import jobs.
        self._imports_api = imports_api
        self.keepalive_interval = keepalive_interval
        # ``None`` → every activity_batch answers ``activity_refused: store_unavailable``.
        self.activity_receiver = activity_receiver
        self.activity_max_batch_bytes = activity_max_batch_bytes
        # ``extension serve`` passes the gate it opens in the background; a
        # server hosted elsewhere got its secrets before it was built.
        self.vault_gate = vault_gate if vault_gate is not None else always_open()
        self._runner: web.AppRunner | None = None
        self._topics_updater: Any = None
        # Per-process page principal. It is printed only as a URL fragment by
        # the foreground launcher; fragments never cross the HTTP boundary.
        self._page_token = secrets.token_urlsafe(32)
        self._local_origins = {
            f"http://127.0.0.1:{port}",
            f"http://localhost:{port}",
            f"http://[::1]:{port}",
            _loopback_origin(host, port),
        }

    @property
    def telegram_service(self) -> Any:
        if self._telegram_service is None:
            from .telegram.service import TelegramService

            self._telegram_service = TelegramService()
        return self._telegram_service

    @property
    def recall_service(self) -> Any:
        if self._recall_service is None:
            from ..recall.service import RecallService

            self._recall_service = RecallService()
        return self._recall_service

    @property
    def imports_api(self) -> Any:
        if self._imports_api is None:
            from .imports_api import ImportsApi

            self._imports_api = ImportsApi(telegram_service=lambda: self.telegram_service)
        return self._imports_api

    @property
    def page_url(self) -> str:
        """Private launch URL carrying the page principal outside HTTP."""
        return f"{_loopback_origin(self.host, self.port)}/#token={quote(self._page_token, safe='')}"

    # -- lifecycle ----------------------------------------------------------

    async def start(self) -> None:
        app = web.Application()
        app.router.add_get("/ext", self._handle_ws)
        app.router.add_get("/", self._handle_page)
        app.router.add_get("/app", self._handle_page)
        self._runner = web.AppRunner(app)
        await self._runner.setup()
        site = web.TCPSite(self._runner, self.host, self.port)
        await site.start()
        _log.info(
            "Mordred extension API on ws://%s:%d/ext (page: http://%s:%d/)",
            self.host,
            self.port,
            self.host,
            self.port,
        )
        # The updater reads the store and the model settings from the vault's
        # environment, so it waits for the vault.
        self.vault_gate.on_open(self._start_topics_updater)

    def _start_topics_updater(self) -> None:
        """Keep recall's stored events and topics current (prototype; ``MORDRED_RECALL_TOPICS=0`` turns it off)."""
        if os.environ.get("MORDRED_RECALL_TOPICS", "1") == "0" or self._topics_updater is not None:
            return
        try:
            self._topics_updater = self.recall_service.topics_updater()
            self._topics_updater.start()
            _log.info("recall topics updater started")
        except Exception:
            _log.exception("recall topics updater not started")

    async def stop(self) -> None:
        if self._topics_updater is not None:
            self._topics_updater.stop()
            self._topics_updater = None
        if self._runner is not None:
            await self._runner.cleanup()
            self._runner = None

    # -- localhost web app --------------------------------------------------

    async def _handle_page(self, request: web.Request) -> web.Response:
        if not _request_is_loopback(request):
            return web.Response(status=403, text="loopback only", headers=page_headers.plain_response_headers())
        index = _WEB_DIR / "index.html"
        if not index.exists():
            return web.Response(
                status=503,
                text="Mordred web app not built. Run `npm run build:page` in the extension repo.",
                headers=page_headers.plain_response_headers(),
            )
        # The shared bundle retains the legacy placeholder so older Hermes
        # releases can inject their page token. This server launches with a
        # private URL fragment instead, so remove the placeholder without ever
        # placing the process token in an HTTP response.
        html = index.read_text("utf-8").replace("%%MORDRED_PAGE_TOKEN%%", "")
        return web.Response(
            text=html,
            content_type="text/html",
            # Derived from the bytes actually being served (see page_headers):
            # the bundle is built in the extension repo, so a refreshed bundle
            # must not be able to ship a page its own policy blocks.
            headers=page_headers.security_headers(
                html,
                connect_origins=page_headers.websocket_origins(self._local_origins),
            ),
        )

    # -- connection ---------------------------------------------------------

    def _origin_allowed(self, origin: str | None) -> bool:
        if not origin:
            return True  # header-less local clients (CLI tests, some WS stacks)
        return _is_extension_origin(origin) or origin in self._local_origins

    async def _handle_ws(self, request: web.Request) -> web.StreamResponse:
        origin = request.headers.get("Origin")
        if not _request_is_loopback(request) or not self._origin_allowed(origin):
            _log.warning("extension WS rejected: peer=%r host=%r origin=%r", request.remote, request.host, origin)
            return web.Response(status=403, text="forbidden origin")

        ws = web.WebSocketResponse(heartbeat=30)
        await ws.prepare(request)
        # The page authenticates with the page token (only valid from a local
        # origin); the extension authenticates with its paired ext_token.
        page_token = self._page_token if (origin in self._local_origins) else None
        conn = _Connection(
            ws,
            self.chat_handler,
            telegram_service=self.telegram_service,
            recall_service=self.recall_service,
            imports_api=self.imports_api,
            page_token=page_token,
            client_origin=origin,
            activity_receiver=self.activity_receiver,
            activity_max_batch_bytes=self.activity_max_batch_bytes,
            vault_gate=self.vault_gate,
        )
        await conn.send_challenge()
        keepalive = asyncio.create_task(conn.keepalive(self.keepalive_interval))
        try:
            async for msg in ws:
                if msg.type == WSMsgType.TEXT:
                    await conn.dispatch(msg.data)
                elif msg.type == WSMsgType.ERROR:
                    break
        finally:
            keepalive.cancel()
            conn.cancel_background_tasks()
        return ws


class _Connection:
    """Per-socket state machine."""

    def __init__(
        self,
        ws: web.WebSocketResponse,
        chat_handler: ChatHandler,
        *,
        telegram_service: Any = None,
        recall_service: Any = None,
        imports_api: Any = None,
        page_token: str | None = None,
        client_origin: str | None = None,
        activity_receiver: Any = None,
        activity_max_batch_bytes: int = activity_api.DEFAULT_MAX_BATCH_BYTES,
        vault_gate: VaultGate | None = None,
    ) -> None:
        self.ws = ws
        self.vault_gate = vault_gate if vault_gate is not None else always_open()
        self.chat_handler = chat_handler
        self.telegram_service = telegram_service
        self.recall_service = recall_service
        self.imports_api = imports_api
        self.page_token = page_token  # set only for local-origin (page) sockets
        self.client_origin = client_origin
        self._presence_connection = secrets.token_hex(16)
        self.authed = False
        # Extension sessions belong to one endorsed device key and to the exact
        # endorsement that admitted it; removing the device revokes its open
        # sockets. Their K_extchat is this socket's own session key.
        # Page sessions use the separate process-bound page principal.
        self._device_id: str | None = None
        self._device_generation: bytes | None = None
        self._session_key: bytes | None = None
        # A verified hello from an unknown device, kept for ``device_enroll``.
        self._hello: _Hello | None = None
        self._page_authenticated = False
        self.activity_receiver = activity_receiver
        self.activity_max_batch_bytes = activity_max_batch_bytes
        self._frame_bytes = 0
        self._nonce = b""
        self._pending_sign: dict[str, dict[str, Any]] = {}
        self._telegram_asks: dict[str, asyncio.Task[None]] = {}
        # Chat replies being streamed; held here so a running one is not collected.
        self._chats: set[asyncio.Task[None]] = set()
        self._recall_recommends: dict[str, tuple[asyncio.Task[None], threading.Event]] = {}
        self._recall_translates: dict[str, tuple[asyncio.Task[None], threading.Event]] = {}

    def cancel_background_tasks(self) -> None:
        """Stop work that would otherwise outlive this socket (and keep billing)."""
        from ..keyvault._presence import revoke

        revoke(principal=("extension", self._presence_connection))
        for task in list(self._telegram_asks.values()):
            task.cancel()
        self._telegram_asks.clear()
        for running in (self._recall_recommends, self._recall_translates):
            for task, stop in list(running.values()):
                stop.set()
                task.cancel()
            running.clear()

    async def _send(self, payload: dict[str, Any]) -> bool:
        # A client that disconnected mid-turn (e.g. during a slow local-LLM
        # response) must not crash the handler. Swallow write failures.
        if self.ws.closed:
            return False
        try:
            await self.ws.send_str(_serialize_frame(payload))
            return True
        except Exception as e:
            _log.debug("extension WS send dropped (client gone): %s", e)
            return False

    async def keepalive(self, interval: float) -> None:
        """Push an app-level ``ping`` every ``interval`` seconds.

        Keeps the browser extension's MV3 service worker alive: Chrome only
        extends the worker's ~30s idle deadline on WS *message* events, which
        protocol-level ping/pong (``heartbeat=30``) never produces. Clients
        accept and ignore this protocol frame. Ends itself once the socket
        closes."""
        if interval <= 0:
            return
        while True:
            await asyncio.sleep(interval)
            if not await self._send({"type": "ping"}):
                return

    async def send_challenge(self) -> None:
        self._nonce = os.urandom(32)
        # ``webauthn_required: False`` keeps localhost pages built before auth v2,
        # whose decoder requires the field, working with their page token.
        await self._send(
            {
                "type": "auth_challenge",
                "nonce": trust.b64u(self._nonce),
                "webauthn_required": False,
                "auth_versions": [trust.AUTH_VERSION],
            }
        )

    async def _parse_frame(self, raw: str) -> dict[str, Any] | None:
        try:
            msg = json.loads(raw)
        except ValueError:
            msg = None
        if not isinstance(msg, dict):
            _log.warning("extension WS: dropping malformed frame (%d bytes)", len(raw))
            await self._send({"type": "error", "reason": "bad_json"})
            return None
        return msg

    async def dispatch(self, raw: str) -> None:
        self._frame_bytes = len(raw.encode("utf-8", "surrogatepass"))
        msg = await self._parse_frame(raw)
        if msg is None:
            return
        mtype = msg.get("type")
        # Two dispatch tables keep the auth gate explicit: pre-auth messages are
        # always allowed; everything else requires a completed auth handshake.
        pre_auth = {
            "auth2_hello": self._on_auth2_hello,
            "device_enroll": self._on_device_enroll,
            "auth": self._on_auth,
        }
        authed = {
            "chat": self._on_chat,
            "encrypt": self._on_encrypt,
            "decrypt": self._on_decrypt,
            "slack_setup": self._on_slack_setup,
            "accounts_request": self._on_accounts,
            "sign_request": self._on_sign_request,
            "sign_approve": self._on_sign_approve,
            "history_get": self._on_history_get,
            "history_clear": self._on_history_clear,
            "telegram_status": self._on_telegram_status,
            "telegram_sync": self._on_telegram_sync,
            "telegram_dialogs": self._on_telegram_dialogs,
            "telegram_ask": self._on_telegram_ask,
            "telegram_ask_cancel": self._on_telegram_ask_cancel,
            "activity_batch": self._on_activity_batch,
            "activity_status": self._on_activity_status,
            "recall_query": self._on_recall_query,
            "recall_events": self._on_recall_events,
            "recall_open": self._on_recall_open,
            "recall_conversation": self._on_recall_conversation,
            "recall_dismiss": self._on_recall_dismiss,
            "recall_restore": self._on_recall_restore,
            "recall_hidden": self._on_recall_hidden,
            "recall_recommend": self._on_recall_recommend,
            "recall_recommend_cancel": self._on_recall_recommend_cancel,
            "recall_translate": self._on_recall_translate,
            "recall_translate_cancel": self._on_recall_translate_cancel,
            "imports_status": self._on_imports_status,
            "imports_call": self._on_imports_call,
            "chat_model_call": self._on_chat_model_call,
            "health": self._on_health,
        }
        try:
            if mtype in pre_auth:
                await pre_auth[mtype](msg)
            elif (refusal := self._authed_refusal(mtype, mtype in authed)) is not None:
                # Error refusals reply keyed by ``id`` so the caller never hangs.
                await self._send({"id": msg.get("id"), **refusal} if refusal["type"] == "error" else refusal)
            elif mtype in authed:
                if mtype in {"telegram_sync", "telegram_dialogs", "telegram_ask"}:
                    from .._core._home import hermes_home
                    from ..keyvault._presence import presence_scope
                    from ..keyvault._presence_hosts import profile_guard

                    home = hermes_home().resolve()
                    generation = (self._device_id, self._device_generation)
                    profile_current = profile_guard(home, self._authentication_is_current)

                    def current() -> bool:
                        return (
                            not self.ws.closed
                            and self.authed
                            and (self._device_id, self._device_generation) == generation
                            and profile_current()
                        )

                    with presence_scope(home, ("extension", self._presence_connection), "telegram", valid=current):
                        await authed[mtype](msg)
                else:
                    await authed[mtype](msg)
        except ExtensionStorageError as exc:
            await self._send_storage_refusal(msg, exc)
        except Exception:
            _log.exception("extension API handler error (type=%s)", mtype)
            # A client awaiting a reply keyed by ``id`` must not hang forever
            # on a crashed handler.
            err: dict[str, Any] = {"type": "error", "reason": "internal_error"}
            if msg.get("id") is not None:
                err["id"] = msg["id"]
            await self._send(err)

    def _authed_refusal(self, mtype: Any, known: bool) -> dict[str, Any] | None:
        """The refusal frame for a post-auth message, ``None`` when it may run."""
        if not self.authed:
            return {"type": "auth_fail", "reason": "not_authenticated"}
        if not known:
            return None
        if (failure := self._authentication_failure()) is not None:
            self._invalidate_authentication()
            return {"type": "auth_fail", "reason": failure}
        if self.page_token is not None and mtype not in _PAGE_ALLOWED:
            # Page session (local-origin socket): only the read-only /
            # conversational handlers in _PAGE_ALLOWED are permitted; every
            # other authed handler (credential/key writes, the K_master
            # crypto oracle, the wallet signer, activity submission) is refused.
            return {"type": "error", "reason": "page_session_forbidden"}
        return None

    # -- pairing / auth -----------------------------------------------------

    def _invalidate_authentication(self) -> None:
        from ..keyvault._presence import revoke

        revoke(principal=("extension", self._presence_connection))
        self.authed = False
        self._device_id = None
        self._device_generation = None
        self._session_key = None
        self._hello = None
        self._page_authenticated = False
        # An approval captured under a revoked principal must not survive a
        # re-authentication with a replacement pairing.
        self._pending_sign.clear()
        self.cancel_background_tasks()

    async def _send_storage_refusal(self, msg: dict[str, Any], exc: ExtensionStorageError) -> None:
        """Surface a checked Windows storage refusal instead of empty state.

        ``auth`` replies ``auth_fail``; every other request gets an ``error``
        frame keyed by its ``id`` with the classified, content-free code.
        """
        mtype = msg.get("type")
        self._log_storage_refusal(str(mtype), exc)
        if mtype == "auth":
            self._invalidate_authentication()
            await self._send({"type": "auth_fail", "reason": exc.wire_reason})
            return
        refusal: dict[str, Any] = {"type": "error", "reason": exc.wire_reason}
        if msg.get("id") is not None:
            refusal["id"] = msg["id"]
        await self._send(refusal)

    @staticmethod
    def _log_storage_refusal(what: str, exc: ExtensionStorageError) -> None:
        _log.warning(
            "extension %s refused by checked storage (%s, %s, native=%s)",
            what,
            exc.reason,
            exc.commit_state,
            exc.native_code,
        )

    def _authentication_failure(self) -> str | None:
        """``None`` while the principal is current, else the auth_fail reason."""
        try:
            return None if self._authentication_is_current() else "pairing_changed"
        except ExtensionStorageError as exc:
            self._log_storage_refusal("authentication check", exc)
            return exc.wire_reason

    def _authentication_is_current(self) -> bool:
        """Fail closed unless this socket still names the active principal.

        Checked Windows storage refusals propagate so the caller can report
        their classification; every other failure is plain revocation.
        """
        if not self.authed:
            return False
        if self._page_authenticated:
            return self.page_token is not None
        expected, device_id = self._device_generation, self._device_id
        if expected is None or device_id is None:
            return False
        try:
            state = trust.store().load()
            device = state.devices.get(device_id) if state is not None else None
            return device is not None and secrets.compare_digest(expected, device.generation)
        except Exception:
            # Missing/corrupt/unreadable trust state is revocation, not a
            # reason to retain a privileged session.
            return False

    async def _on_activity_batch(self, msg: dict[str, Any]) -> None:
        await activity_api.on_activity_batch(self, msg)

    async def _on_activity_status(self, msg: dict[str, Any]) -> None:
        await activity_api.on_activity_status(self, msg)

    async def _on_auth(self, msg: dict[str, Any]) -> None:
        """The localhost page's process token. Browsers use ``auth2_hello``."""
        token = msg.get("ext_token", "")
        self._invalidate_authentication()
        if not isinstance(token, str) or not self.page_token or not secrets.compare_digest(token, self.page_token):
            await self._send({"type": "auth_fail", "reason": "invalid_token"})
            return
        self.authed = True
        self._page_authenticated = True
        await self._send(
            {
                "type": "auth_ok",
                "hermes_version": _hermes_version(),
                "se_available": pairing.se_available(),
            }
        )

    async def _on_auth2_hello(self, msg: dict[str, Any]) -> None:
        self._invalidate_authentication()
        if not await self._vault_open(msg):
            await self._send({"type": "auth_fail", "reason": LOCKED_REASON})
            return
        try:
            hello = _Hello.parse(msg, self._nonce, self.client_origin)
            state = await _in_executor(trust.store().ensure_root)
        except trust.TrustError as exc:
            await self._send({"type": "auth_fail", "reason": exc.reason})
            return
        device = state.devices.get(hello.device_id)
        if device is not None and device.spki == hello.device_spki:
            await self._admit(state, device, hello)
            return
        self._hello = hello
        code = trust.sas(state.v_spki, state.hermes_spki, hello.device_spki, self._nonce, hello.nonce_c)
        hello.code = code
        body = trust.body_text(
            {
                "kind": "unendorsed",
                "hello_sha256": hello.digest,
                "hermes_spki": trust.b64u(state.hermes_spki),
                "v_spki": trust.b64u(state.v_spki),
                "sas": code,
            }
        )
        [sig] = await _in_executor(state.h.sign, [trust.SERVER_CONTEXT + body.encode()], "handshake")
        await self._send(
            {
                "type": "auth2_unendorsed",
                "body": body,
                "sig": trust.b64u(sig),
                "endorsements": [state.hermes_id] if state.hermes_id else [],
            }
        )

    async def _vault_open(self, msg: dict[str, Any]) -> bool:
        """Whether the vault is open, asking for Touch ID only when the hello asks to unlock.

        Only the extension's unlock button sets ``unlock``; an automatic
        reconnect is answered at once, so it never raises a prompt.
        """
        gate = self.vault_gate
        if gate.is_open():
            return True
        if msg.get("unlock") is not True or not self.client_origin or not _is_extension_origin(self.client_origin):
            return False
        try:
            state: str = await _in_executor(gate.unlock)
        except VaultFatal:
            # ``extension serve`` stops on this (``VaultGate.on_fatal``).
            return False
        return state == "open"

    async def _on_device_enroll(self, msg: dict[str, Any]) -> None:
        """Ask the owner at the Mac to approve the browser of the pending hello.

        Once the installer registered the native host, only a ticket from it
        (for this connection's check code) raises the approval: another program
        cannot ask the owner to approve itself.
        """
        hello = self._hello
        if hello is None or self.authed or hello.code is None:
            await self._send({"type": "auth_fail", "reason": "no_pending_hello"})
            return
        if not self.client_origin or not _is_extension_origin(self.client_origin):
            await self._send({"type": "auth_fail", "reason": "extension_origin_required"})
            return
        if not await _in_executor(_enrollment_attested, self.client_origin, hello.code, msg.get("ticket")):
            self._hello = None
            await self._send({"type": "auth_fail", "reason": "attestation_required"})
            return
        try:
            await _in_executor(pairing.ensure_master)
            state = await _in_executor(
                trust.store().approve, hello.device_spki, hello.label, self.client_origin, hello.code
            )
        except trust.TrustError as exc:
            self._hello = None
            await self._send({"type": "auth_fail", "reason": exc.reason})
            return
        if self._hello is not hello:
            return  # the socket re-authenticated while the owner was deciding
        device = state.devices.get(hello.device_id)
        if device is None:
            await self._send({"type": "auth_fail", "reason": "approval_denied"})
            return
        await self._admit(state, device, hello)

    async def _admit(self, state: trust.Trust, device: trust.Device, hello: _Hello) -> None:
        """``auth2_ok`` for an endorsed device: Hermes' signature, the endorsements, a session key."""
        if state.hermes_id is None:
            await self._send({"type": "auth_fail", "reason": "not_endorsed"})
            return
        eph = X25519PrivateKey.generate()
        body = trust.body_text(
            {
                "kind": "ok",
                "hello_sha256": hello.digest,
                "hermes_spki": trust.b64u(state.hermes_spki),
                "v_spki": trust.b64u(state.v_spki),
                "device_id": device.device_id,
                "eph_s": trust.b64u(eph.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)),
            }
        )
        try:
            [sig] = await _in_executor(state.h.sign, [trust.SERVER_CONTEXT + body.encode()], "handshake")
            key = trust.session_key(eph, hello.eph_c, hello.body, body)
        except trust.TrustError as exc:
            await self._send({"type": "auth_fail", "reason": exc.reason})
            return
        self._hello = None
        self.authed = True
        self._device_id = device.device_id
        self._device_generation = device.generation
        self._session_key = key
        await self._send(
            {
                "type": "auth2_ok",
                "body": body,
                "sig": trust.b64u(sig),
                "endorsements": [state.hermes_id, device.endorsement],
                "hermes_version": _hermes_version(),
                "se_available": pairing.se_available(),
                "capabilities": _EXTENSION_CAPABILITIES,
            }
        )

    # -- chat ---------------------------------------------------------------

    def _extchat_key(self) -> bytes | None:
        """K_extchat: this socket's session key (``None`` for the page, which sends plaintext)."""
        return self._session_key

    async def _on_chat(self, msg: dict[str, Any]) -> None:
        mid = msg.get("id")
        content = msg.get("content", "")
        context = msg.get("context") or {}

        # Chat E2E (reply-in-kind, SPEC-v2 §2): if the client encrypted the
        # message with K_extchat, decrypt it for the agent and encrypt each
        # reply chunk back. Plaintext in → plaintext out (e.g. the localhost web
        # app, which has no key yet).
        encrypted_input = isinstance(content, str) and is_encrypted(content)
        ek: bytes | None = None
        if encrypted_input:
            try:
                ek = self._extchat_key()
            except Exception:
                _log.exception("extension chat key could not be loaded")
            if ek is None:
                # Ciphertext is a security boundary, not just a serialization
                # format. If pairing disappeared or became unreadable, never
                # downgrade the still-encrypted input into an agent message.
                await self._send({"id": mid, "type": "chat_error", "reason": "encryption_key_unavailable"})
                return
            try:
                content = decrypt_message(ek, content)
            except DecryptError:
                # Stale K_extchat (e.g. the client re-paired): ``content`` is
                # still the raw 🔒ENC: blob. Do NOT fail open — forwarding it
                # would hand the agent ciphertext as the user's message. Tell
                # the client to re-key instead.
                await self._send({"id": mid, "type": "chat_error", "reason": "undecryptable"})
                return
        # The reply streams from its own task: a slow local model can write one
        # for minutes, and the socket must keep answering in the meantime (the
        # popup asks for the history whenever it opens and reads Hermes as
        # offline until it comes). The task is not cancelled with the socket: it
        # stops at the next chunk it cannot send, which closes the generator so
        # the turn finishes detached and is kept in the history.
        task = asyncio.create_task(self._stream_chat(mid, content, context, ek))
        self._chats.add(task)
        task.add_done_callback(self._chats.discard)

    async def _stream_chat(self, mid: Any, content: str, context: dict[str, Any], ek: bytes | None) -> None:
        kid = key_id(ek) if ek is not None else ""

        gen = self.chat_handler(content, context)
        try:
            async for chunk in gen:
                out = encrypt_message_v2(ek, chunk, kid) if ek is not None else chunk
                if not await self._send({"id": mid, "type": "chat_chunk", "content": out}):
                    # Client gone mid-stream: stop consuming. Closing ``gen``
                    # (finally below) lets the chat layer detach the running
                    # turn instead of streaming into the void.
                    return
            await self._send({"id": mid, "type": "chat_end"})
        except Exception as exc:
            # An injected chat handler's exception text is not ours to publish
            # (agent internals, provider URLs, file paths): reply with a code.
            reason = wire_error_code(exc, fallback="agent_error", context="chat")
            await self._send({"id": mid, "type": "chat_error", "reason": reason})
        finally:
            aclose = getattr(gen, "aclose", None)
            if aclose is not None:
                await aclose()

    async def _on_slack_setup(self, msg: dict[str, Any]) -> None:
        """Write Slack tokens the extension collected into ~/.hermes/.env so a
        new user doesn't have to hand-edit files (SPEC-v2 §6). We only persist
        config; the tokens take effect on the next Hermes restart.

        Auth (and the page-session refusal) is enforced in ``dispatch``."""
        mid = msg.get("id")

        async def _reply(ok: bool, note: str = "", error: str = "") -> None:
            await self._send({"id": mid, "type": "slack_setup_result", "ok": ok, "note": note, "error": error})

        bot = str(msg.get("bot_token", "")).strip()
        app = str(msg.get("app_token", "")).strip()
        # The extension E2E-encrypts the tokens with K_extchat (SPEC-v2 §6) so
        # credentials never cross the WS in plaintext. Unwrap before validating.
        ek = self._extchat_key()
        try:
            if ek is not None and is_encrypted(bot):
                bot = decrypt_message(ek, bot).strip()
            if ek is not None and is_encrypted(app):
                app = decrypt_message(ek, app).strip()
        except DecryptError:
            await _reply(False, error="token_decrypt_failed")
            return
        # Strict charset, not just a prefix — an embedded newline would inject an
        # extra dotenv line (see _SLACK_BOT_TOKEN_RE).
        if not _SLACK_BOT_TOKEN_RE.fullmatch(bot) or not _SLACK_APP_TOKEN_RE.fullmatch(app):
            await _reply(False, error="bad_token_format")
            return
        try:
            from .._core._home import hermes_home

            env_path = hermes_home() / ".env"
            updated = await asyncio.get_event_loop().run_in_executor(
                None,
                _update_slack_env,
                env_path,
                {"SLACK_BOT_TOKEN": bot, "SLACK_APP_TOKEN": app},
                msg.get("overwrite") is True,
            )
            if not updated:
                await _reply(False, error="slack_already_configured")
                return
            await _reply(True, note="tokens written to ~/.hermes/.env — restart Hermes to apply")
        except Exception as exc:
            # Typically an OSError naming ~/.hermes/.env — logged, not returned.
            await _reply(False, error=wire_error_code(exc, fallback="slack_setup_failed", context="slack_setup"))

    # -- Slack crypto (fallback path) --------------------------------------

    def _aes_key(self) -> bytes | None:
        p = pairing.load_pairing()
        return p.aes_key if p else None

    async def _on_encrypt(self, msg: dict[str, Any]) -> None:
        mid = msg.get("id")
        key = self._aes_key()
        if key is None:
            # ``encrypt_fail``, not ``decrypt_fail``: a client keying replies by
            # request type would never see this one.
            await self._send({"id": mid, "type": "encrypt_fail", "reason": "not_paired"})
            return
        ct = encrypt_message(key, msg.get("plaintext", ""))
        await self._send({"id": mid, "type": "encrypt_result", "ciphertext": ct})

    async def _on_decrypt(self, msg: dict[str, Any]) -> None:
        mid = msg.get("id")
        key = self._aes_key()
        if key is None:
            await self._send({"id": mid, "type": "decrypt_fail", "reason": "not_paired"})
            return
        try:
            pt = decrypt_message(key, msg.get("ciphertext", ""))
        except DecryptError as exc:
            await self._send({"id": mid, "type": "decrypt_fail", "reason": exc.reason})
            return
        await self._send({"id": mid, "type": "decrypt_result", "plaintext": pt})

    # -- Encrypted conversation history ------------------------------------

    async def _on_history_get(self, msg: dict[str, Any]) -> None:
        from . import history as extension_history

        projection = await asyncio.get_event_loop().run_in_executor(None, extension_history.projected_history)
        await self._send(
            _bounded_history_result(
                msg.get("id"),
                projection.turns,
                max_chars=MAX_WS_FRAME_CHARS,
                status=projection.status,
            )
        )

    async def _on_history_clear(self, msg: dict[str, Any]) -> None:
        from . import history as extension_history

        extension_history.clear()
        await self._send({"id": msg.get("id"), "type": "history_cleared", "ok": True})

    # -- Recall over the import store ----------------------------------------
    #
    # The selection and everything returned from the store is personal content,
    # so it crosses the wire sealed with K_extchat, like Telegram. A plaintext
    # selection is refused, not downgraded. Page sessions never reach these
    # handlers (not in _PAGE_ALLOWED). Errors are content-free codes.

    def _recall_ready(self) -> Any:
        if self.recall_service is None:
            from ..recall.service import RecallService

            self.recall_service = RecallService()
        return self.recall_service

    async def _recall_call(self, run: Callable[[Any], Any]) -> tuple[Any, str | None]:
        """Run ``run(service)`` off the loop: ``(result, None)`` or ``(None, error code)``."""
        from ..recall.service import RecallError

        service = self._recall_ready()
        try:
            return await asyncio.get_event_loop().run_in_executor(None, run, service), None
        except RecallError as exc:
            return None, exc.code
        except Exception:
            _log.exception("recall request failed")
            return None, "recall_unavailable"

    async def _on_recall_query(self, msg: dict[str, Any]) -> None:
        from ..recall.service import MAX_LIMIT

        mid = msg.get("id")
        ek = self._telegram_key()
        if ek is None:
            await self._send({"id": mid, "type": "recall_result", "ok": False, "error": "encryption_key_unavailable"})
            return
        sealed = msg.get("text")
        limit = msg.get("limit", 8)
        mode = msg.get("mode", "selection")
        if (
            not isinstance(sealed, str)
            or not is_encrypted(sealed)
            or not isinstance(limit, int)
            or isinstance(limit, bool)
            or not 1 <= limit <= MAX_LIMIT
            or mode not in ("selection", "words")
        ):
            await self._send({"id": mid, "type": "recall_result", "ok": False, "error": "invalid_request"})
            return
        try:
            text = decrypt_message(ek, sealed)
        except DecryptError:
            await self._send({"id": mid, "type": "recall_result", "ok": False, "error": "undecryptable"})
            return
        words = mode == "words"
        result, error = await self._recall_call(lambda svc: svc.query(text, limit=limit, words=words))
        if error is not None:
            await self._send({"id": mid, "type": "recall_result", "ok": False, "error": error})
        else:
            content = self._telegram_seal(ek, json.dumps(result, ensure_ascii=False))
            await self._send({"id": mid, "type": "recall_result", "ok": True, "content": content})

    async def _on_recall_events(self, msg: dict[str, Any]) -> None:
        from ..recall.service import MAX_EVENTS

        mid = msg.get("id")
        ek = self._telegram_key()
        if ek is None:
            await self._send(
                {"id": mid, "type": "recall_events_result", "ok": False, "error": "encryption_key_unavailable"}
            )
            return
        sealed = msg.get("text")
        limit = msg.get("limit", 5)
        headlines = msg.get("headlines", True)
        mode = msg.get("mode", "words")
        if (
            not isinstance(sealed, str)
            or not is_encrypted(sealed)
            or not isinstance(limit, int)
            or isinstance(limit, bool)
            or not 1 <= limit <= MAX_EVENTS
            or not isinstance(headlines, bool)
            or mode not in ("words", "selection")
        ):
            await self._send({"id": mid, "type": "recall_events_result", "ok": False, "error": "invalid_request"})
            return
        try:
            text = decrypt_message(ek, sealed)
        except DecryptError:
            await self._send({"id": mid, "type": "recall_events_result", "ok": False, "error": "undecryptable"})
            return
        selection = mode == "selection"
        result, error = await self._recall_call(
            lambda svc: svc.events(text, limit=limit, headlines=headlines, selection=selection)
        )
        if error is not None:
            await self._send({"id": mid, "type": "recall_events_result", "ok": False, "error": error})
        else:
            content = self._telegram_seal(ek, json.dumps(result, ensure_ascii=False))
            await self._send({"id": mid, "type": "recall_events_result", "ok": True, "content": content})

    async def _on_recall_open(self, msg: dict[str, Any]) -> None:
        from ..recall.service import MAX_CONTEXT

        mid = msg.get("id")
        ek = self._telegram_key()
        if ek is None:
            await self._send({"id": mid, "type": "recall_opened", "ok": False, "error": "encryption_key_unavailable"})
            return
        part_uid = msg.get("part_uid")
        before, after = msg.get("before", 2), msg.get("after", 2)
        bounds_ok = all(
            isinstance(n, int) and not isinstance(n, bool) and 0 <= n <= MAX_CONTEXT for n in (before, after)
        )
        if not isinstance(part_uid, str) or not _RECALL_UID_RE.fullmatch(part_uid) or not bounds_ok:
            await self._send({"id": mid, "type": "recall_opened", "ok": False, "error": "invalid_request"})
            return
        parts, error = await self._recall_call(lambda svc: svc.open(part_uid, before=before, after=after))
        if error is not None:
            await self._send({"id": mid, "type": "recall_opened", "ok": False, "error": error})
        else:
            content = self._telegram_seal(ek, json.dumps({"parts": parts}, ensure_ascii=False))
            await self._send({"id": mid, "type": "recall_opened", "ok": True, "content": content})

    async def _on_recall_conversation(self, msg: dict[str, Any]) -> None:
        mid = msg.get("id")
        ek = self._telegram_key()
        if ek is None:
            await self._send(
                {"id": mid, "type": "recall_conversation_result", "ok": False, "error": "encryption_key_unavailable"}
            )
            return
        part_uid = msg.get("part_uid")
        if not isinstance(part_uid, str) or not _RECALL_UID_RE.fullmatch(part_uid):
            await self._send({"id": mid, "type": "recall_conversation_result", "ok": False, "error": "invalid_request"})
            return
        found, error = await self._recall_call(lambda svc: svc.conversation(part_uid))
        if error is not None:
            await self._send({"id": mid, "type": "recall_conversation_result", "ok": False, "error": error})
        else:
            content = self._telegram_seal(ek, json.dumps(found, ensure_ascii=False))
            await self._send({"id": mid, "type": "recall_conversation_result", "ok": True, "content": content})

    async def _on_recall_dismiss(self, msg: dict[str, Any]) -> None:
        mid = msg.get("id")
        conv_uid = msg.get("conv_uid")
        if not isinstance(conv_uid, str) or not _RECALL_UID_RE.fullmatch(conv_uid):
            await self._send({"id": mid, "type": "recall_dismissed", "ok": False, "error": "invalid_request"})
            return
        _, error = await self._recall_call(lambda svc: svc.dismiss(conv_uid))
        if error is not None:
            await self._send({"id": mid, "type": "recall_dismissed", "ok": False, "error": error})
        else:
            await self._send({"id": mid, "type": "recall_dismissed", "ok": True})

    async def _on_recall_recommend(self, msg: dict[str, Any]) -> None:
        mid = msg.get("id")
        ek = self._telegram_key()
        if ek is None:
            await self._send(
                {"id": mid, "type": "recall_recommend_end", "ok": False, "error": "encryption_key_unavailable"}
            )
            return
        sealed = msg.get("text")
        mode = msg.get("mode", "words")
        if (
            not isinstance(mid, str)
            or not mid
            or mid in self._recall_recommends
            or not isinstance(sealed, str)
            or not is_encrypted(sealed)
            or mode not in ("words", "selection")
        ):
            await self._send({"id": mid, "type": "recall_recommend_end", "ok": False, "error": "invalid_request"})
            return
        if len(self._recall_recommends) >= _MAX_RECALL_RECOMMENDS_PER_SOCKET:
            await self._send({"id": mid, "type": "recall_recommend_end", "ok": False, "error": "too_many_requests"})
            return
        try:
            text = decrypt_message(ek, sealed)
        except DecryptError:
            await self._send({"id": mid, "type": "recall_recommend_end", "ok": False, "error": "undecryptable"})
            return
        stop = threading.Event()
        task = asyncio.create_task(self._run_recall_recommend(mid, text, mode == "selection", ek, stop))
        self._recall_recommends[mid] = (task, stop)
        task.add_done_callback(lambda _t: self._recall_recommends.pop(mid, None))

    async def _on_recall_recommend_cancel(self, msg: dict[str, Any]) -> None:
        """Stop a running recommendation (the panel closed or searched again). No reply."""
        mid = msg.get("id")
        running = self._recall_recommends.get(mid) if isinstance(mid, str) else None
        if running is not None:
            running[1].set()
            running[0].cancel()

    async def _run_recall_recommend(
        self, mid: str, text: str, selection: bool, ek: bytes, stop: threading.Event
    ) -> None:
        loop = asyncio.get_running_loop()
        found: asyncio.Queue[dict[str, Any]] = asyncio.Queue()

        def on_item(memory: dict[str, Any]) -> None:
            loop.call_soon_threadsafe(found.put_nowait, memory)

        work = asyncio.ensure_future(
            self._recall_call(
                lambda svc: svc.recommend(text, selection=selection, on_item=on_item, cancelled=stop.is_set)
            )
        )
        try:
            while True:
                getter = asyncio.ensure_future(found.get())
                done, _pending = await asyncio.wait({getter, work}, return_when=asyncio.FIRST_COMPLETED)
                if getter in done:
                    sealed = self._telegram_seal(ek, json.dumps(getter.result(), ensure_ascii=False))
                    if not await self._send({"id": mid, "type": "recall_recommend_item", "content": sealed}):
                        stop.set()
                        return
                    continue
                getter.cancel()
                while not found.empty():
                    sealed = self._telegram_seal(ek, json.dumps(found.get_nowait(), ensure_ascii=False))
                    if not await self._send({"id": mid, "type": "recall_recommend_item", "content": sealed}):
                        return
                _count, error = work.result()
                if error is not None:
                    await self._send({"id": mid, "type": "recall_recommend_end", "ok": False, "error": error})
                else:
                    await self._send({"id": mid, "type": "recall_recommend_end", "ok": True})
                return
        except asyncio.CancelledError:
            stop.set()
            raise

    async def _on_recall_translate(self, msg: dict[str, Any]) -> None:
        from ..recall.translate import valid_language

        mid = msg.get("id")
        ek = self._telegram_key()
        if ek is None:
            await self._send(
                {"id": mid, "type": "recall_translate_end", "ok": False, "error": "encryption_key_unavailable"}
            )
            return
        sealed = msg.get("text")
        language = msg.get("language")
        if (
            not isinstance(mid, str)
            or not mid
            or mid in self._recall_translates
            or not isinstance(sealed, str)
            or not is_encrypted(sealed)
            or not valid_language(language)
        ):
            await self._send({"id": mid, "type": "recall_translate_end", "ok": False, "error": "invalid_request"})
            return
        if len(self._recall_translates) >= _MAX_RECALL_TRANSLATES_PER_SOCKET:
            await self._send({"id": mid, "type": "recall_translate_end", "ok": False, "error": "too_many_requests"})
            return
        try:
            text = decrypt_message(ek, sealed)
        except DecryptError:
            await self._send({"id": mid, "type": "recall_translate_end", "ok": False, "error": "undecryptable"})
            return
        stop = threading.Event()
        task = asyncio.create_task(self._run_recall_translate(mid, text, str(language), ek, stop))
        self._recall_translates[mid] = (task, stop)
        task.add_done_callback(lambda _t: self._recall_translates.pop(mid, None))

    async def _on_recall_translate_cancel(self, msg: dict[str, Any]) -> None:
        """Stop a running translation (the panel closed or the selection changed). No reply."""
        mid = msg.get("id")
        running = self._recall_translates.get(mid) if isinstance(mid, str) else None
        if running is not None:
            running[1].set()
            running[0].cancel()

    async def _run_recall_translate(self, mid: str, text: str, language: str, ek: bytes, stop: threading.Event) -> None:
        loop = asyncio.get_running_loop()
        pieces: asyncio.Queue[object] = asyncio.Queue()
        finished = object()

        def on_piece(piece: str) -> None:
            loop.call_soon_threadsafe(pieces.put_nowait, piece)

        def run() -> str | None:
            from ..recall.translate import translate_selection

            try:
                return translate_selection(text, language, on_piece=on_piece, cancelled=stop.is_set)
            except Exception:
                _log.exception("recall translate failed")
                return "recall_unavailable"
            finally:
                loop.call_soon_threadsafe(pieces.put_nowait, finished)

        # The end marker goes through the same queue as the pieces, so every piece is read before it.
        # The executor future alone is not enough: it can be done while piece callbacks are still pending.
        work: asyncio.Future[str | None] = loop.run_in_executor(None, run)
        try:
            done = False
            while not done:
                item = await pieces.get()
                if item is finished:
                    break
                # Pieces that arrived together leave as one frame.
                piece = str(item)
                while not pieces.empty():
                    item = pieces.get_nowait()
                    if item is finished:
                        done = True
                        break
                    piece += str(item)
                sealed = self._telegram_seal(ek, json.dumps({"text": piece}, ensure_ascii=False))
                if not await self._send({"id": mid, "type": "recall_translate_piece", "content": sealed}):
                    stop.set()
                    return
            error = await work
            end: dict[str, Any] = {"id": mid, "type": "recall_translate_end", "ok": error is None}
            await self._send(end if error is None else {**end, "error": error})
        except asyncio.CancelledError:
            stop.set()
            raise

    async def _on_recall_restore(self, msg: dict[str, Any]) -> None:
        mid = msg.get("id")
        conv_uid = msg.get("conv_uid")
        if not isinstance(conv_uid, str) or not _RECALL_UID_RE.fullmatch(conv_uid):
            await self._send({"id": mid, "type": "recall_restored", "ok": False, "error": "invalid_request"})
            return
        _, error = await self._recall_call(lambda svc: svc.restore(conv_uid))
        if error is not None:
            await self._send({"id": mid, "type": "recall_restored", "ok": False, "error": error})
        else:
            await self._send({"id": mid, "type": "recall_restored", "ok": True})

    async def _on_recall_hidden(self, msg: dict[str, Any]) -> None:
        mid = msg.get("id")
        ek = self._telegram_key()
        if ek is None:
            await self._send(
                {"id": mid, "type": "recall_hidden_result", "ok": False, "error": "encryption_key_unavailable"}
            )
            return
        hidden, error = await self._recall_call(lambda svc: svc.hidden())
        if error is not None:
            await self._send({"id": mid, "type": "recall_hidden_result", "ok": False, "error": error})
        else:
            # Titles are chat names: they leave sealed like the rest of recall.
            content = self._telegram_seal(ek, json.dumps({"hidden": hidden}, ensure_ascii=False))
            await self._send({"id": mid, "type": "recall_hidden_result", "ok": True, "content": content})

    # -- Imports (the Desktop plugin's import screens) -------------------------
    #
    # Both directions are sealed with K_extchat: the requests carry phone
    # numbers, login codes, addresses and app passwords, the answers account
    # labels and folder names. A plaintext body is refused. Page sessions never
    # reach these handlers (not in _PAGE_ALLOWED). See :mod:`.imports_api`.

    async def _on_imports_status(self, msg: dict[str, Any]) -> None:
        mid = msg.get("id")
        ek = self._telegram_key()
        if ek is None:
            await self._send(
                {"id": mid, "type": "imports_status_result", "ok": False, "error": "encryption_key_unavailable"}
            )
            return
        if self.imports_api is None:
            await self._send({"id": mid, "type": "imports_status_result", "ok": False, "error": "imports_unavailable"})
            return
        try:
            status = await self.imports_api.status()
        except Exception:
            _log.exception("imports status failed")
            await self._send({"id": mid, "type": "imports_status_result", "ok": False, "error": "imports_unavailable"})
            return
        content = self._telegram_seal(ek, json.dumps(status, ensure_ascii=False))
        await self._send({"id": mid, "type": "imports_status_result", "ok": True, "content": content})

    async def _on_health(self, msg: dict[str, Any]) -> None:
        """Each feature's state and reason code; codes only, so the reply is not sealed."""
        from .._core._home import hermes_home
        from . import health

        items = await health.collect(
            home=Path(hermes_home()),
            chat_is_stub=self.chat_handler is _default_chat_handler,
            telegram_status=lambda: self._telegram_ready().status(),
        )
        await self._send({"id": msg.get("id"), "type": "health_result", "items": items})

    async def _on_imports_call(self, msg: dict[str, Any]) -> None:
        mid = msg.get("id")
        ek = self._telegram_key()
        if ek is None:
            await self._send(
                {"id": mid, "type": "imports_call_result", "ok": False, "error": "encryption_key_unavailable"}
            )
            return
        sealed = msg.get("content")
        if not isinstance(sealed, str) or not is_encrypted(sealed):
            await self._send({"id": mid, "type": "imports_call_result", "ok": False, "error": "invalid_request"})
            return
        try:
            body = json.loads(decrypt_message(ek, sealed))
        except (DecryptError, ValueError):
            await self._send({"id": mid, "type": "imports_call_result", "ok": False, "error": "undecryptable"})
            return
        if not isinstance(body, dict) or self.imports_api is None:
            await self._send({"id": mid, "type": "imports_call_result", "ok": False, "error": "invalid_request"})
            return
        try:
            result = await self.imports_api.call(body)
        except ImportsRefusal as exc:
            await self._send({"id": mid, "type": "imports_call_result", "ok": False, "error": exc.code})
            return
        except Exception:
            _log.exception("imports call failed (op=%s)", body.get("op") if isinstance(body.get("op"), str) else "?")
            await self._send({"id": mid, "type": "imports_call_result", "ok": False, "error": "imports_failed"})
            return
        finally:
            del body
        content = self._telegram_seal(ek, json.dumps(result, ensure_ascii=False))
        await self._send({"id": mid, "type": "imports_call_result", "ok": True, "content": content})

    # -- the chat's model ("upgrade the chat AI") -----------------------------
    #
    # The request and the reply are sealed with K_extchat like imports_call: the
    # request may carry a Venice API key, which is never accepted in plaintext.
    # Page sessions never reach this handler (not in _PAGE_ALLOWED).

    async def _on_chat_model_call(self, msg: dict[str, Any]) -> None:
        from . import chat_model

        mid = msg.get("id")
        ek = self._telegram_key()
        sealed = msg.get("content")
        if ek is None:
            await self._send(
                {"id": mid, "type": "chat_model_result", "ok": False, "error": "encryption_key_unavailable"}
            )
            return
        if not isinstance(sealed, str) or not is_encrypted(sealed):
            await self._send({"id": mid, "type": "chat_model_result", "ok": False, "error": "invalid_request"})
            return
        try:
            body = json.loads(decrypt_message(ek, sealed))
        except (DecryptError, ValueError):
            await self._send({"id": mid, "type": "chat_model_result", "ok": False, "error": "undecryptable"})
            return
        op = body.get("op") if isinstance(body, dict) else None
        try:
            if op == "status":
                result: dict[str, Any] = chat_model.status()
            elif op == "models":
                result = {"models": await chat_model.private_models()}
            elif op == "set_venice":
                await chat_model.set_venice(str(body.get("api_key") or ""), str(body.get("model") or ""))
                result = chat_model.status()
            elif op == "clear":
                await asyncio.to_thread(chat_model.clear)
                result = chat_model.status()
            else:
                await self._send({"id": mid, "type": "chat_model_result", "ok": False, "error": "invalid_request"})
                return
        except chat_model.ChatModelError as exc:
            await self._send({"id": mid, "type": "chat_model_result", "ok": False, "error": exc.code})
            return
        except Exception:
            _log.exception("chat model call failed (op=%s)", op if isinstance(op, str) else "?")
            await self._send({"id": mid, "type": "chat_model_result", "ok": False, "error": "chat_model_failed"})
            return
        finally:
            del body
        content = self._telegram_seal(ek, json.dumps(result, ensure_ascii=False))
        await self._send({"id": mid, "type": "chat_model_result", "ok": True, "content": content})

    # -- Telegram import (read-only) -----------------------------------------
    #
    # Personal content (account label, chat titles, answers) is sealed with
    # K_extchat on the wire, like chat. The question must arrive sealed too: a
    # plaintext question is refused rather than downgraded. Page sessions never
    # reach these handlers (not in _PAGE_ALLOWED).

    def _telegram_seal(self, ek: bytes, text: str) -> str:
        return encrypt_message_v2(ek, text, key_id(ek))

    def _telegram_key(self) -> bytes | None:
        try:
            return self._extchat_key()
        except Exception:
            _log.exception("extension telegram key could not be loaded")
            return None

    def _telegram_ready(self) -> Any:
        return self.telegram_service

    async def _on_telegram_status(self, msg: dict[str, Any]) -> None:
        from .telegram.service import error_code

        mid = msg.get("id")
        ek = self._telegram_key()
        if ek is None:
            await self._send(
                {"id": mid, "type": "telegram_status_result", "ok": False, "error": "encryption_key_unavailable"}
            )
            return
        try:
            status = await self._telegram_ready().status()
        except Exception as exc:
            code = error_code(exc, "telegram_unavailable")
            await self._send({"id": mid, "type": "telegram_status_result", "ok": False, "error": code})
            return
        status["account_label"] = self._telegram_seal(ek, status.get("account_label") or "")
        await self._send({"id": mid, "type": "telegram_status_result", "ok": True, "status": status})

    async def _on_telegram_sync(self, msg: dict[str, Any]) -> None:
        from .telegram.client import SyncOptions
        from .telegram.service import error_code

        mid = msg.get("id")
        raw = msg.get("options")
        options: SyncOptions | None = None
        if raw is not None:
            if not isinstance(raw, dict):
                await self._send({"id": mid, "type": "telegram_sync_result", "ok": False, "error": "invalid_request"})
                return
            limit = raw.get("limit_per_dialog")
            if limit is not None and (
                not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= 1_000_000
            ):
                await self._send({"id": mid, "type": "telegram_sync_result", "ok": False, "error": "invalid_request"})
                return
            # Fields the client sent override the scope saved at setup.
            overrides = {
                "include_channels": raw["include_channels"] if isinstance(raw.get("include_channels"), bool) else None,
                "include_archived": raw["include_archived"] if isinstance(raw.get("include_archived"), bool) else None,
                "limit_per_dialog": limit,
            }
            options = self._telegram_ready().sync_options(overrides)
        try:
            await self._telegram_ready().start_sync(options)
        except Exception as exc:
            code = error_code(exc, "telegram_sync_failed")
            await self._send({"id": mid, "type": "telegram_sync_result", "ok": False, "error": code})
            return
        await self._send({"id": mid, "type": "telegram_sync_result", "ok": True})

    async def _on_telegram_dialogs(self, msg: dict[str, Any]) -> None:
        from .telegram.service import error_code

        mid = msg.get("id")
        ek = self._telegram_key()
        if ek is None:
            await self._send(
                {"id": mid, "type": "telegram_dialogs_result", "ok": False, "error": "encryption_key_unavailable"}
            )
            return
        try:
            dialogs = await self._telegram_ready().dialogs()
        except Exception as exc:
            code = error_code(exc, "telegram_unavailable")
            await self._send({"id": mid, "type": "telegram_dialogs_result", "ok": False, "error": code})
            return
        for dialog in dialogs:
            dialog["title"] = self._telegram_seal(ek, dialog["title"])
        await self._send({"id": mid, "type": "telegram_dialogs_result", "ok": True, "dialogs": dialogs})

    def _parse_telegram_ask(self, msg: dict[str, Any], ek: bytes) -> Any:
        """Return an AskRequest, or a wire error code string."""
        from .telegram.ask import AskRequest

        question = msg.get("question")
        if not isinstance(question, str) or not is_encrypted(question):
            return "invalid_request"
        try:
            question = decrypt_message(ek, question)
        except DecryptError:
            return "undecryptable"
        raw_ids = msg.get("dialog_ids", [])
        if not isinstance(raw_ids, list) or len(raw_ids) > _MAX_TELEGRAM_DIALOG_IDS:
            return "invalid_request"
        if not all(isinstance(d, str) and _TELEGRAM_DIALOG_ID_RE.fullmatch(d) for d in raw_ids):
            return "invalid_request"
        since = msg.get("since")
        if since is not None and (not isinstance(since, int) or isinstance(since, bool) or since < 0):
            return "invalid_request"
        return AskRequest(
            question=question,
            dialog_ids=tuple(int(d) for d in raw_ids),
            since=since,
            pseudonymize=msg.get("pseudonymize") is not False,
        )

    async def _on_telegram_ask(self, msg: dict[str, Any]) -> None:
        mid = msg.get("id")
        ek = self._telegram_key()
        if ek is None:
            await self._send({"id": mid, "type": "telegram_ask_error", "reason": "encryption_key_unavailable"})
            return
        request = self._parse_telegram_ask(msg, ek)
        if isinstance(request, str):
            await self._send({"id": mid, "type": "telegram_ask_error", "reason": request})
            return
        if not isinstance(mid, str) or not mid or mid in self._telegram_asks:
            await self._send({"id": mid, "type": "telegram_ask_error", "reason": "invalid_request"})
            return
        if len(self._telegram_asks) >= _MAX_TELEGRAM_ASKS_PER_SOCKET:
            await self._send({"id": mid, "type": "telegram_ask_error", "reason": "too_many_requests"})
            return
        # Opt-in: clients whose strict frame decoder predates the frame never receive it.
        evidence = msg.get("evidence") is True
        task = asyncio.create_task(self._run_telegram_ask(mid, request, ek, evidence=evidence))
        self._telegram_asks[mid] = task
        task.add_done_callback(lambda _t: self._telegram_asks.pop(mid, None))

    async def _on_telegram_ask_cancel(self, msg: dict[str, Any]) -> None:
        """Stop a running question (the popup closed). No reply: the id is gone."""
        mid = msg.get("id")
        task = self._telegram_asks.get(mid) if isinstance(mid, str) else None
        if task is not None:
            from ..keyvault._presence import revoke

            revoke(principal=("extension", self._presence_connection))
            task.cancel()

    def _telegram_evidence_frame(self, mid: str, ek: bytes, report: Any) -> dict[str, Any]:
        """Source cards (stored facts plus the stored 160-character excerpt), sealed like the answer."""
        from .telegram.service import card_json

        payload = {
            "cards": [card_json(card) for card in report.cards],
            "unverified_ids": list(report.unverified_ids),
            "unsupported_quotes": len(report.unsupported_quotes),
        }
        sealed = self._telegram_seal(ek, json.dumps(payload, ensure_ascii=False))
        return {"id": mid, "type": "telegram_ask_evidence", "content": sealed}

    async def _run_telegram_ask(self, mid: str, request: Any, ek: bytes, *, evidence: bool = False) -> None:
        from .telegram.service import AskResult, error_code

        meta: list[AskResult] = []
        reports: list[Any] = []
        if evidence:
            gen = self._telegram_ready().ask(request, meta.append, on_evidence=reports.append)
        else:
            gen = self._telegram_ready().ask(request, meta.append)
        sent_meta = False
        try:
            async for chunk in gen:
                if not sent_meta and meta:
                    sent_meta = True
                    await self._send(
                        {
                            "id": mid,
                            "type": "telegram_ask_meta",
                            "model": meta[0].model,
                            "message_count": meta[0].message_count,
                            "dialog_count": meta[0].dialog_count,
                            "truncated": meta[0].truncated,
                        }
                    )
                sealed = self._telegram_seal(ek, chunk)
                if not await self._send({"id": mid, "type": "telegram_ask_chunk", "content": sealed}):
                    return
            if reports and not await self._send(self._telegram_evidence_frame(mid, ek, reports[-1])):
                return
            await self._send({"id": mid, "type": "telegram_ask_end"})
        except asyncio.CancelledError:
            from ..keyvault._presence import revoke

            revoke(principal=("extension", self._presence_connection))
            raise
        except Exception as exc:
            from ..keyvault._presence import revoke

            revoke(principal=("extension", self._presence_connection))
            await self._send(
                {"id": mid, "type": "telegram_ask_error", "reason": error_code(exc, "telegram_ask_failed")}
            )
        finally:
            await gen.aclose()

    # -- Web3 ---------------------------------------------------------------

    async def _on_accounts(self, msg: dict[str, Any]) -> None:
        mid = msg.get("id")
        try:
            address, chain_id = await asyncio.get_event_loop().run_in_executor(None, _get_account_snapshot)
        except Exception as exc:
            # This is an accounts RPC failure, not a chat stream failure. The
            # generic correlated error lets every client reject immediately
            # rather than waiting for its accounts_result timeout. The keyvault
            # detail (wallet paths, backend state) stays in the server log.
            reason = wire_error_code(exc, fallback="wallet_unavailable", context="accounts_request")
            await self._send({"id": mid, "type": "error", "reason": reason})
            return
        await self._send(
            {
                "id": mid,
                "type": "accounts_result",
                "accounts": [address] if address else [],
                "chainId": chain_id,
            }
        )

    async def _on_sign_request(self, msg: dict[str, Any]) -> None:
        mid = msg.get("id")
        request_id = str(msg.get("request_id") or "")
        if not request_id:
            # Every id-less request would collapse to "" and silently overwrite
            # the previous one's frozen params — the user could then approve a
            # prompt for one transaction and sign a different one.
            await self._send({"id": mid, "type": "sign_result", "request_id": "", "error": "missing_request_id"})
            return
        if request_id in self._pending_sign:
            # Reject a re-used request_id outright rather than replacing the
            # frozen params of an already-displayed prompt. Otherwise a dapp
            # could show the user a benign transaction, then re-send the same
            # request_id with a draining transaction before they click; the
            # pending entry would swap underneath the prompt and sign_approve
            # would sign what the user never saw.
            await self._send(
                {"id": mid, "type": "sign_result", "request_id": request_id, "error": "duplicate_request_id"}
            )
            return
        method = msg.get("method", "")
        params = msg.get("params", []) or []
        origin = msg.get("origin", "")
        try:
            prepared = await asyncio.get_event_loop().run_in_executor(
                None,
                _prepare_sign,
                method,
                params,
                msg.get("chain_id"),
                msg.get("rpc_url"),
            )
        except Exception as exc:
            detail = wire_error_code(exc, fallback="", context="sign_request")
            await self._send(
                {
                    "id": mid,
                    "type": "sign_result",
                    "request_id": request_id,
                    "error": f"transaction_prepare_failed: {detail}" if detail else "transaction_prepare_failed",
                }
            )
            return
        params = prepared.params
        chain_id = prepared.chain_id
        rpc_url = prepared.rpc_url
        rpc_endpoint = prepared.rpc_endpoint
        expected_signer = prepared.expected_signer
        # Bound the pending table (see _MAX_PENDING_SIGN); evict the oldest.
        while len(self._pending_sign) >= _MAX_PENDING_SIGN:
            self._pending_sign.pop(next(iter(self._pending_sign)))
        self._pending_sign[request_id] = {
            "method": method,
            "params": params,
            "origin": origin,
            "chain_id": chain_id,
            "rpc_url": rpc_url,
            "expected_signer": expected_signer,
        }
        analysis, decoded = analyze_sign(method, params)
        if method == "eth_sendTransaction" and params and isinstance(params[0], dict):
            decoded = {
                **decoded,
                "transaction": params[0],
                "chain_id": chain_id,
            }
        if expected_signer is not None:
            decoded = {**decoded, "signer": expected_signer}
        if rpc_endpoint is not None:
            analysis = {
                **analysis,
                "warnings": [*analysis.get("warnings", []), f"RPC 接続先: {rpc_endpoint}"],
            }
            decoded = {**decoded, "rpc_endpoint": rpc_endpoint}
        await self._send(
            {
                "id": mid,
                "type": "sign_prompt",
                "request_id": request_id,
                "analysis": analysis,
                "decoded": decoded,
                "params": params,
            }
        )

    async def _on_sign_approve(self, msg: dict[str, Any]) -> None:
        mid = msg.get("id")
        request_id = str(msg.get("request_id") or "")
        pend = self._pending_sign.pop(request_id, None)
        if pend is None:
            await self._send({"id": mid, "type": "sign_result", "request_id": request_id, "error": "unknown_request"})
            return
        # The wire contract is boolean. JSON strings such as ``"false"`` are
        # truthy in Python and must never cross the user-approval boundary.
        if msg.get("approved") is not True:
            await self._send({"id": mid, "type": "sign_result", "request_id": request_id, "error": "user_rejected"})
            return
        try:
            signature = await asyncio.get_event_loop().run_in_executor(
                None,
                _do_sign,
                pend["method"],
                pend["params"],
                pend.get("chain_id"),
                pend.get("rpc_url"),
                pend.get("expected_signer"),
            )
        except Exception as exc:
            error = wire_error_code(exc, fallback="sign_failed", context="sign_approve")
            await self._send({"id": mid, "type": "sign_result", "request_id": request_id, "error": error})
            return
        await self._send({"id": mid, "type": "sign_result", "request_id": request_id, "signature": signature})


def _hermes_version() -> str:
    try:
        from importlib.metadata import PackageNotFoundError, version
    except Exception:
        return "0.0.0"

    # The wire field predates the distribution rename and is retained for
    # protocol compatibility. Prefer the canonical project, while still
    # reporting the installed version on a pre-0.1.0a16 legacy environment.
    for distribution_name in ("hermes-mordred", "mordred-hermes"):
        try:
            return version(distribution_name)
        except PackageNotFoundError:
            continue
        except Exception:
            return "0.0.0"
    return "0.0.0"


def _dotenv_has_nonempty_key(existing: str, keys: set[str]) -> bool:
    """Whether dotenv text contains one of *keys* with a non-empty value."""
    from .._core._dotenv_text import has_nonempty_key

    return has_nonempty_key(existing, keys)


def _updated_env_text(existing: str, updates: dict[str, str]) -> str:
    """Return dotenv text with ``updates`` merged, preserving other lines."""
    from .._core._dotenv_text import merge_assignments

    return merge_assignments(existing, updates, mode="extension")


def _validate_env_updates(updates: dict[str, str]) -> None:
    from .._core._dotenv_text import contains_newline

    for key, val in updates.items():
        if contains_newline(key) or contains_newline(val):
            raise ValueError("refusing to write a dotenv entry containing a newline")


def _upsert_env_vars(env_path: Path, updates: dict[str, str]) -> None:
    """Lock and atomically upsert dotenv entries while preserving other lines.

    Raises ``ValueError`` on a key/value carrying CR or LF: entries are emitted
    as raw ``KEY=value`` lines joined by "\\n", so such a value would inject
    arbitrary extra dotenv entries. Callers validate their own inputs (see
    ``_SLACK_BOT_TOKEN_RE``); this is the last line of defence for future ones.

    The shared sibling lock is also used by ``DotEnvFileWriter`` so concurrent
    Slack and wizard updates cannot both read the same old file and lose one
    another's unrelated entries.
    """
    from .._core._dotenv_io import update_dotenv_file

    _validate_env_updates(updates)
    update_dotenv_file(env_path, lambda existing: _updated_env_text(existing, updates))


class _SlackAlreadyConfigured(Exception):
    """Internal transaction-abort signal; never includes credential text."""


def _update_slack_env(env_path: Path, updates: dict[str, str], overwrite: bool) -> bool:
    """Check-and-upsert Slack credentials in one locked dotenv transaction."""
    from .._core._dotenv_io import update_dotenv_file

    _validate_env_updates(updates)

    def transform(existing: str) -> str:
        if not overwrite and _dotenv_has_nonempty_key(
            existing,
            {"SLACK_BOT_TOKEN", "SLACK_APP_TOKEN"},
        ):
            raise _SlackAlreadyConfigured
        return _updated_env_text(existing, updates)

    try:
        update_dotenv_file(env_path, transform)
    except _SlackAlreadyConfigured:
        return False
    return True


async def _in_executor(func: Callable[..., Any], *args: Any) -> Any:
    # Vault I/O, Enclave signing and the owner's approval never run on the event loop.
    return await asyncio.get_running_loop().run_in_executor(None, func, *args)


class _Hello:
    """A browser's verified ``auth2_hello``: its signed body and the fields Hermes uses."""

    def __init__(self, body: str, fields: dict[str, Any]) -> None:
        self.body = body
        self.digest = trust.b64u(hashlib.sha256(body.encode()).digest())
        self.device_spki = trust.unb64u(fields["device_spki"])
        self.device_id = trust.device_id_of(self.device_spki)
        self.nonce_c = trust.unb64u(fields["nonce_c"])
        self.eph_c = trust.unb64u(fields["eph_c"])
        self.label = trust.clean_label(fields.get("label"))
        self.code: str | None = None

    @classmethod
    def parse(cls, msg: dict[str, Any], nonce: bytes, origin: str | None) -> _Hello:
        body = msg.get("body")
        if not isinstance(body, str) or len(body) > 8192:
            raise trust.TrustError("bad_hello")
        try:
            fields = json.loads(body)
        except ValueError as exc:
            raise trust.TrustError("bad_hello") from exc
        if (
            not isinstance(fields, dict)
            or fields.get("v") != trust.AUTH_VERSION
            or fields.get("nonce_s") != trust.b64u(nonce)
            or fields.get("origin") != (origin or "")
        ):
            raise trust.TrustError("bad_hello")
        try:
            hello = cls(body, fields)
        except KeyError as exc:
            raise trust.TrustError("bad_hello") from exc
        if len(hello.nonce_c) != 32 or len(hello.eph_c) != 32:
            raise trust.TrustError("bad_hello")
        if not trust.verify(hello.device_spki, trust.CLIENT_CONTEXT + body.encode(), trust.unb64u(msg.get("sig"))):
            raise trust.TrustError("bad_signature")
        return hello
