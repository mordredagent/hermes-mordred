"""Mordred Extension WebSocket API (gateway side).

Serves ``ws://127.0.0.1:7788/ext`` for the browser extension. Localhost-only,
no TLS; an Origin check rejects connections from ordinary web pages (only
``chrome-extension://`` / ``moz-extension://`` / header-less clients pass).

Message protocol: ``Mordred-Extension/SPEC.ja.md`` §6 and the extension's
``src/lib/protocol.ts``. Handlers:

- ``pair_init``        → :mod:`mordred_hermes.extension.pairing` (pre-auth)
- ``auth``             → validate ext_token, reply ``auth_ok`` (se_available)
- ``chat``             → injected ``chat_handler`` streamed as ``chat_chunk*`` + ``chat_end``
- ``encrypt``/``decrypt`` → :mod:`mordred_hermes.extension.crypto` with the shared key
- ``accounts_request`` → keyvault address (``accounts_result``)
- ``sign_request`` → analyze + ``sign_prompt``; ``sign_approve`` → keyvault sign → ``sign_result``

Server-initiated frames: ``ping`` (app-level keepalive, see
``_Connection.keepalive``) and ``error`` (malformed JSON / crashed handler).
Clients ignore unknown frame types (extension ``protocol.ts`` isServerMsg), so
both are backward-compatible.
"""

from __future__ import annotations

import asyncio
import contextlib
import ipaddress
import json
import logging
import re
import secrets
from collections.abc import AsyncIterator, Callable
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlsplit

from aiohttp import WSMsgType, web

from . import pairing
from .crypto import (
    DecryptError,
    decrypt_message,
    encrypt_message,
    encrypt_message_v2,
    hkdf_subkey,
    is_encrypted,
    key_id,
)
from .wallet import _do_sign, _get_address, _prepare_sign, _wallet_chain_id_hex, analyze_sign
from .webauthn import InvalidWebAuthnPublicKey

# K_extchat derivation label (SPEC-v2 §1.1) — must match the extension.
_EXTCHAT_SALT = "mordred-extchat-v1"
_EXTCHAT_INFO = "extchat"

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
_PAGE_ALLOWED = frozenset({"chat", "accounts_request", "history_get", "history_clear"})

# Reply frame type used when a page session is refused a non-allowed handler, so
# a client awaiting a reply keyed by `id` never hangs. Falls back to "error".
_PAGE_REFUSAL_TYPE = {
    "webauthn_register": "webauthn_registered",
    "slack_setup": "slack_setup_result",
    "channel_key_set": "channel_key_result",
    "encrypt": "encrypt_fail",
    "decrypt": "decrypt_fail",
    "sign_request": "sign_result",
    "sign_approve": "sign_result",
}

# A sign_request entry leaves _pending_sign only on approve/reject (or when the
# socket dies), so an authed client that never approves would grow it without
# bound. Cap it and evict the oldest (dicts keep insertion order) — a stale
# prompt the user never answered is the right thing to drop.
_MAX_PENDING_SIGN = 32

_log = logging.getLogger(__name__)

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 7788

# App-level keepalive period. Chrome kills an idle MV3 service worker after
# ~30s; receiving a WS message (any type) fires onmessage and resets that
# timer, while aiohttp's protocol-level ping/pong never reaches JS. Must stay
# below 30s with margin.
DEFAULT_KEEPALIVE_INTERVAL = 20.0

# A chat handler streams response chunks for a user message.
ChatHandler = Callable[[str, dict[str, Any]], AsyncIterator[str]]


async def _default_chat_handler(content: str, _context: dict[str, Any]) -> AsyncIterator[str]:
    yield (f"⚠️ Hermes のエージェント接続が拡張 API に未接続です(chat_handler 未設定)。\n受信メッセージ: {content!r}")


# Directory holding the self-contained localhost web app (built from the
# extension's src/page; see scripts in the extension repo). Served at "/".
_WEB_DIR = Path(__file__).resolve().parent / "web"


def _is_extension_origin(origin: str | None) -> bool:
    if origin is None:
        return False
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
        keepalive_interval: float = DEFAULT_KEEPALIVE_INTERVAL,
    ) -> None:
        if not _is_loopback_host(host):
            raise ValueError(f"extension API host must be loopback-only (got {host!r})")
        self.host = host
        self.port = port
        self.chat_handler: ChatHandler = chat_handler or _default_chat_handler
        self.keepalive_interval = keepalive_interval
        self._runner: web.AppRunner | None = None
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

    async def stop(self) -> None:
        if self._runner is not None:
            await self._runner.cleanup()
            self._runner = None

    # -- localhost web app --------------------------------------------------

    async def _handle_page(self, request: web.Request) -> web.Response:
        if not _request_is_loopback(request):
            return web.Response(status=403, text="loopback only")
        index = _WEB_DIR / "index.html"
        if not index.exists():
            return web.Response(
                status=503,
                text="Mordred web app not built. Run `npm run build:page` in the extension repo.",
            )
        html = index.read_text("utf-8")
        return web.Response(
            text=html,
            content_type="text/html",
            headers={
                # The fragment token is process-bound. Avoid retaining even the
                # token-free shell across restarts and keep security headers
                # deterministic for both "/" and "/app".
                "Cache-Control": "no-store",
                "X-Content-Type-Options": "nosniff",
                "Referrer-Policy": "no-referrer",
            },
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
        conn = _Connection(ws, self.chat_handler, page_token=page_token, client_origin=origin)
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
        return ws


class _Connection:
    """Per-socket state machine."""

    def __init__(
        self,
        ws: web.WebSocketResponse,
        chat_handler: ChatHandler,
        *,
        page_token: str | None = None,
        client_origin: str | None = None,
    ) -> None:
        self.ws = ws
        self.chat_handler = chat_handler
        self.page_token = page_token  # set only for local-origin (page) sockets
        self.client_origin = client_origin
        self.authed = False
        # Extension sessions are bound to the exact pairing token generation
        # that completed authentication. Re-pairing or clearing state must
        # revoke already-open sockets before they can touch replacement keys.
        # Page sessions use the separate process-bound page principal.
        self._authentication_generation: bytes | None = None
        self._page_authenticated = False
        self._nonce = b""
        self._pending_sign: dict[str, dict[str, Any]] = {}

    async def _send(self, payload: dict[str, Any]) -> bool:
        # A client that disconnected mid-turn (e.g. during a slow local-LLM
        # response) must not crash the handler. Swallow write failures.
        if self.ws.closed:
            return False
        try:
            await self.ws.send_str(json.dumps(payload))
            return True
        except Exception as e:
            _log.debug("extension WS send dropped (client gone): %s", e)
            return False

    async def keepalive(self, interval: float) -> None:
        """Push an app-level ``ping`` every ``interval`` seconds.

        Keeps the browser extension's MV3 service worker alive: Chrome only
        extends the worker's ~30s idle deadline on WS *message* events, which
        protocol-level ping/pong (``heartbeat=30``) never produces. Clients
        ignore the unknown frame type. Ends itself once the socket closes."""
        if interval <= 0:
            return
        while True:
            await asyncio.sleep(interval)
            if not await self._send({"type": "ping"}):
                return

    async def send_challenge(self) -> None:
        import os

        from .crypto import b64u_encode

        self._nonce = os.urandom(32)
        await self._send(
            {
                "type": "auth_challenge",
                "nonce": b64u_encode(self._nonce),
                "webauthn_required": pairing.has_webauthn_credential(),
            }
        )

    async def dispatch(self, raw: str) -> None:
        try:
            msg = json.loads(raw)
        except ValueError:
            msg = None
        if not isinstance(msg, dict):
            _log.warning("extension WS: dropping malformed frame (%d bytes)", len(raw))
            await self._send({"type": "error", "reason": "bad_json"})
            return
        mtype = msg.get("type")
        # Two dispatch tables keep the auth gate explicit: pre-auth messages are
        # always allowed; everything else requires a completed auth handshake.
        pre_auth = {"pair_init": self._on_pair_init, "auth": self._on_auth}
        authed = {
            "chat": self._on_chat,
            "encrypt": self._on_encrypt,
            "decrypt": self._on_decrypt,
            "channel_key_set": self._on_channel_key_set,
            "slack_setup": self._on_slack_setup,
            "accounts_request": self._on_accounts,
            "sign_request": self._on_sign_request,
            "sign_approve": self._on_sign_approve,
            "webauthn_register": self._on_webauthn_register,
            "history_get": self._on_history_get,
            "history_clear": self._on_history_clear,
        }
        try:
            if mtype in pre_auth:
                await pre_auth[mtype](msg)
            elif not self.authed:
                await self._send({"type": "auth_fail", "reason": "not_authenticated"})
            elif mtype in authed and not self._authentication_is_current():
                self._invalidate_authentication()
                await self._send({"type": "auth_fail", "reason": "pairing_changed"})
            elif self.page_token is not None and mtype in authed and mtype not in _PAGE_ALLOWED:
                # Page session (local-origin socket): only the read-only /
                # conversational handlers in _PAGE_ALLOWED are permitted; every
                # other authed handler (credential/key writes, the K_master
                # crypto oracle, the wallet signer) is refused. Reply rather than
                # ignore so the caller never hangs on its ``id``.
                await self._send(
                    {
                        "id": msg.get("id"),
                        "type": _PAGE_REFUSAL_TYPE.get(mtype, "error"),
                        "ok": False,
                        "error": "page_session_forbidden",
                    }
                )
            elif mtype in authed:
                await authed[mtype](msg)
        except Exception:
            _log.exception("extension API handler error (type=%s)", mtype)
            # A client awaiting a reply keyed by ``id`` must not hang forever
            # on a crashed handler.
            err: dict[str, Any] = {"type": "error", "reason": "internal_error"}
            if msg.get("id") is not None:
                err["id"] = msg["id"]
            await self._send(err)

    # -- pairing / auth -----------------------------------------------------

    def _invalidate_authentication(self) -> None:
        self.authed = False
        self._authentication_generation = None
        self._page_authenticated = False
        # An approval captured under a revoked principal must not survive a
        # re-authentication with a replacement pairing.
        self._pending_sign.clear()

    def _authentication_is_current(self) -> bool:
        """Fail closed unless this socket still names the active principal."""
        if not self.authed:
            return False
        if self._page_authenticated:
            return self.page_token is not None
        expected = self._authentication_generation
        if expected is None:
            return False
        try:
            current = pairing.authentication_generation_fingerprint()
            return current is not None and secrets.compare_digest(expected, current)
        except Exception:
            # Missing/corrupt/unreadable pairing state is revocation, not a
            # reason to retain a privileged session.
            return False

    async def _on_pair_init(self, msg: dict[str, Any]) -> None:
        mid = msg.get("id")
        try:
            # Executor: handle_pair_init does ECDH/signing plus flock-guarded
            # file I/O — neither belongs on the event loop.
            result = await asyncio.get_event_loop().run_in_executor(
                None, pairing.handle_pair_init, msg.get("code", ""), msg.get("ext_pubkey", ""), msg.get("challenge", "")
            )
        except pairing.PairError as exc:
            await self._send({"id": mid, "type": "pair_fail", "reason": exc.reason})
            return
        # handle_pair_init has replaced the active token. Invalidate any prior
        # principal on this same socket before returning the new credential.
        self._invalidate_authentication()
        await self._send({"id": mid, "type": "pair_complete", **result})

    async def _on_auth(self, msg: dict[str, Any]) -> None:
        token = msg.get("ext_token", "")
        self._invalidate_authentication()
        if not isinstance(token, str):
            await self._send({"type": "auth_fail", "reason": "invalid_token"})
            return
        # The localhost page authenticates with the per-process page token; the
        # extension with its paired ext_token. The page is exempt from WebAuthn
        # (it never holds the shared key and is served by Hermes itself).
        if self.page_token and secrets.compare_digest(token, self.page_token):
            self.authed = True
            self._page_authenticated = True
            await self._send(
                {
                    "type": "auth_ok",
                    "hermes_version": _hermes_version(),
                    "se_available": pairing.se_available(),
                }
            )
            return
        initial_generation = pairing.authentication_generation_fingerprint(token)
        if initial_generation is None:
            await self._send({"type": "auth_fail", "reason": "invalid_token"})
            return
        # WebAuthn hardening (§3.5): when a credential is registered, require a
        # valid assertion over this connection's nonce.
        webauthn_required = pairing.has_webauthn_credential()
        assertion = msg.get("webauthn_assertion")
        if webauthn_required and (
            not isinstance(assertion, dict)
            or not pairing.verify_webauthn_assertion(
                self._nonce,
                assertion,
                expected_origin=self.client_origin,
            )
        ):
            await self._send({"type": "auth_fail", "reason": "webauthn_required"})
            return
        final_generation = pairing.authentication_generation_fingerprint(token)
        if final_generation is None:
            await self._send({"type": "auth_fail", "reason": "pairing_changed"})
            return
        if not secrets.compare_digest(initial_generation, final_generation):
            # A valid legacy WebAuthn assertion may atomically add its missing
            # origin/RP-hash binding. Accept that one in-band migration only
            # after the same signed assertion verifies again against the new
            # stored binding and the resulting auth generation stays stable.
            if (
                not webauthn_required
                or not isinstance(assertion, dict)
                or not pairing.verify_webauthn_assertion(
                    self._nonce,
                    assertion,
                    expected_origin=self.client_origin,
                )
            ):
                await self._send({"type": "auth_fail", "reason": "pairing_changed"})
                return
            stable_generation = pairing.authentication_generation_fingerprint(token)
            if stable_generation is None or not secrets.compare_digest(
                final_generation,
                stable_generation,
            ):
                await self._send({"type": "auth_fail", "reason": "pairing_changed"})
                return
        self.authed = True
        self._authentication_generation = final_generation
        await self._send(
            {
                "type": "auth_ok",
                "hermes_version": _hermes_version(),
                "se_available": pairing.se_available(),
            }
        )

    async def _on_webauthn_register(self, msg: dict[str, Any]) -> None:
        mid = msg.get("id")
        cred_id = msg.get("credential_id") or ""
        pub = msg.get("public_key") or ""
        if cred_id and pub:
            if not self.client_origin or not _is_extension_origin(self.client_origin):
                await self._send(
                    {
                        "id": mid,
                        "type": "webauthn_registered",
                        "ok": False,
                        "error": "extension_origin_required",
                    }
                )
                return
            if not self.client_origin.startswith("chrome-extension://"):
                # Firefox's clientDataJSON uses a stable hashed extension
                # origin that is deliberately different from the random
                # moz-extension document/WebSocket origin.  The current wire
                # message does not carry that ceremony origin or its external
                # RP ID, so accepting registration would create a credential
                # that this server can never verify.
                await self._send(
                    {
                        "id": mid,
                        "type": "webauthn_registered",
                        "ok": False,
                        "error": "webauthn_browser_unsupported",
                    }
                )
                return
            try:
                pairing.save_webauthn_credential(cred_id, pub, origin=self.client_origin)
            except InvalidWebAuthnPublicKey:
                # The public wire error is deliberately stable and does not
                # expose parser/backend details from the rejected DER key.
                await self._send(
                    {
                        "id": mid,
                        "type": "webauthn_registered",
                        "ok": False,
                        "error": "invalid_public_key",
                    }
                )
                return
        else:
            pairing.clear_webauthn_credential()  # unregister
        await self._send({"id": mid, "type": "webauthn_registered", "ok": True})

    # -- chat ---------------------------------------------------------------

    def _extchat_key(self) -> bytes | None:
        """K_extchat = HKDF(master, extchat) — separate from Slack keys (SPEC-v2 §2)."""
        p = pairing.load_pairing()
        if p is None:
            return None
        return hkdf_subkey(p.aes_key, _EXTCHAT_SALT, _EXTCHAT_INFO)

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
            await self._send({"id": mid, "type": "chat_error", "reason": str(exc)})
        finally:
            aclose = getattr(gen, "aclose", None)
            if aclose is not None:
                await aclose()

    async def _on_channel_key_set(self, msg: dict[str, Any]) -> None:
        """Store a per-channel Slack key pushed by the extension (SPEC-v2 §4.4).
        key_ct is the raw K_chan (base64url), itself encrypted with K_extchat.

        Auth (and the page-session refusal) is enforced in ``dispatch``."""
        channel_id = msg.get("channel_id")
        key_ct = msg.get("key_ct", "")
        if not channel_id or not key_ct:
            return
        raw_b64 = key_ct
        ek = self._extchat_key()
        if ek is not None and is_encrypted(key_ct):
            try:
                raw_b64 = decrypt_message(ek, key_ct)
            except DecryptError:
                return  # can't unwrap the pushed key — ignore
        try:
            from .crypto import b64u_decode

            # Executor: the save is flock-guarded file I/O.
            await asyncio.get_event_loop().run_in_executor(
                None, pairing.save_channel_key, channel_id, b64u_decode(raw_b64)
            )
        except Exception:
            return

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
            from .._home import hermes_home

            env_path = hermes_home() / ".env"
            _upsert_env_vars(env_path, {"SLACK_BOT_TOKEN": bot, "SLACK_APP_TOKEN": app})
            await _reply(True, note="tokens written to ~/.hermes/.env — restart Hermes to apply")
        except Exception as exc:
            await _reply(False, error=str(exc))

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

        turns = await asyncio.get_event_loop().run_in_executor(None, extension_history.projected_turns)
        await self._send({"id": msg.get("id"), "type": "history_result", "turns": turns})

    async def _on_history_clear(self, msg: dict[str, Any]) -> None:
        from . import history as extension_history

        extension_history.clear()
        await self._send({"id": msg.get("id"), "type": "history_cleared", "ok": True})

    # -- Web3 ---------------------------------------------------------------

    async def _on_accounts(self, msg: dict[str, Any]) -> None:
        mid = msg.get("id")
        try:
            address = await asyncio.get_event_loop().run_in_executor(None, _get_address)
        except Exception as exc:
            # This is an accounts RPC failure, not a chat stream failure. The
            # generic correlated error lets every client reject immediately
            # rather than waiting for its accounts_result timeout.
            await self._send({"id": mid, "type": "error", "reason": f"wallet: {exc}"})
            return
        await self._send(
            {
                "id": mid,
                "type": "accounts_result",
                "accounts": [address] if address else [],
                "chainId": _wallet_chain_id_hex(),
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
            await self._send(
                {
                    "id": mid,
                    "type": "sign_result",
                    "request_id": request_id,
                    "error": f"transaction_prepare_failed: {exc}",
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
        if not msg.get("approved"):
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
            await self._send({"id": mid, "type": "sign_result", "request_id": request_id, "error": str(exc)})
            return
        await self._send({"id": mid, "type": "sign_result", "request_id": request_id, "signature": signature})


def _hermes_version() -> str:
    try:
        from importlib.metadata import version

        return version("mordred-hermes")
    except Exception:
        return "0.0.0"


def _upsert_env_vars(env_path: Path, updates: dict[str, str]) -> None:
    """Insert-or-replace ``KEY=value`` lines in a dotenv file, preserving the
    rest verbatim. Keys already present are overwritten in place; new keys are
    appended. The file is created if it doesn't exist.

    Raises ``ValueError`` on a key/value carrying CR or LF: entries are emitted
    as raw ``KEY=value`` lines joined by "\\n", so such a value would inject
    arbitrary extra dotenv entries. Callers validate their own inputs (see
    ``_SLACK_BOT_TOKEN_RE``); this is the last line of defence for future ones.

    The write is atomic (mkstemp + ``os.replace``) at mode 0o600: this file
    holds Slack bot/app tokens, so a plain ``write_text`` would (a) leave them
    world-readable at the umask default on first creation and (b) truncate-then-
    write, destroying every other var already in ``.env`` if the process died
    mid-write. ``os.replace`` also gives the resulting file the tmp's 0o600 mode,
    tightening an existing loosely-permissioned ``.env`` rather than preserving
    the leak. It is NOT ``keyvault._storage.atomic_write`` — that one refuses a
    pre-existing file whose mode isn't already 0o600, but a host-managed ``.env``
    may legitimately be 0o644."""
    import os
    import tempfile

    for key, val in updates.items():
        if any(c in key or c in val for c in ("\n", "\r")):
            raise ValueError("refusing to write a dotenv entry containing a newline")
    existing = env_path.read_text() if env_path.exists() else ""
    seen: set[str] = set()
    out: list[str] = []
    for ln in existing.splitlines():
        key = ln.split("=", 1)[0].strip() if "=" in ln else ""
        if key in updates:
            out.append(f"{key}={updates[key]}")
            seen.add(key)
        else:
            out.append(ln)
    out.extend(f"{key}={val}" for key, val in updates.items() if key not in seen)
    body = "\n".join(out) + "\n"

    env_path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(env_path.parent), prefix=".env.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(body)
        os.replace(tmp, env_path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise
