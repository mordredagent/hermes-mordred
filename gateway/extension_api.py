"""Mordred Extension WebSocket API (gateway side).

Serves ``ws://127.0.0.1:7788/ext`` for the browser extension. Localhost-only,
no TLS; an Origin check rejects connections from ordinary web pages (only
``chrome-extension://`` / ``moz-extension://`` / header-less clients pass).

Message protocol: ``Mordred-Extension/SPEC.ja.md`` §6 and the extension's
``src/lib/protocol.ts``. Handlers:

- ``pair_init``        → :mod:`gateway.extension_pairing` (pre-auth)
- ``auth``             → validate ext_token, reply ``auth_ok`` (se_available)
- ``chat``             → injected ``chat_handler`` streamed as ``chat_chunk*`` + ``chat_end``
- ``encrypt``/``decrypt`` → :mod:`gateway.extension_crypto` with the shared key
- ``accounts_request`` → keyvault address (``accounts_result``)
- ``sign_request`` → analyze + ``sign_prompt``; ``sign_approve`` → keyvault sign → ``sign_result``
"""

from __future__ import annotations

import asyncio
import json
import logging
import secrets
from pathlib import Path
from typing import Any, AsyncIterator, Awaitable, Callable, Optional

from aiohttp import WSMsgType, web

from . import extension_pairing as pairing
from .extension_crypto import (
    DecryptError,
    decrypt_message,
    encrypt_message,
    encrypt_message_v2,
    hkdf_subkey,
    is_encrypted,
    key_id,
)

# K_extchat derivation label (SPEC-v2 §1.1) — must match the extension.
_EXTCHAT_SALT = "mordred-extchat-v1"
_EXTCHAT_INFO = "extchat"

_log = logging.getLogger(__name__)

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 7788

# A chat handler streams response chunks for a user message.
ChatHandler = Callable[[str, dict[str, Any]], AsyncIterator[str]]


async def _default_chat_handler(content: str, _context: dict[str, Any]) -> AsyncIterator[str]:
    yield (
        "⚠️ Hermes のエージェント接続が拡張 API に未接続です（chat_handler 未設定）。"
        f"\n受信メッセージ: {content!r}"
    )


# Directory holding the self-contained localhost web app (built from the
# extension's src/page; see scripts in the extension repo). Served at "/".
_WEB_DIR = Path(__file__).resolve().parent / "extension_web"


def _is_extension_origin(origin: Optional[str]) -> bool:
    return bool(origin) and (
        origin.startswith("chrome-extension://") or origin.startswith("moz-extension://")
    )


class ExtensionAPIServer:
    def __init__(
        self,
        *,
        host: str = DEFAULT_HOST,
        port: int = DEFAULT_PORT,
        chat_handler: Optional[ChatHandler] = None,
    ) -> None:
        self.host = host
        self.port = port
        self.chat_handler: ChatHandler = chat_handler or _default_chat_handler
        self._runner: Optional[web.AppRunner] = None
        # Per-process token embedded in the served localhost page; only a client
        # that actually loaded Hermes' page (i.e. a real browser, not a random
        # local process guessing the port) can authenticate as the page (§ page).
        self._page_token = secrets.token_urlsafe(32)
        self._local_origins = {
            f"http://{h}:{port}" for h in ("127.0.0.1", "localhost")
        }

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
            self.host, self.port, self.host, self.port,
        )

    async def stop(self) -> None:
        if self._runner is not None:
            await self._runner.cleanup()
            self._runner = None

    # -- localhost web app --------------------------------------------------

    async def _handle_page(self, _request: web.Request) -> web.Response:
        index = _WEB_DIR / "index.html"
        if not index.exists():
            return web.Response(
                status=503,
                text="Mordred web app not built. Run `npm run build:page` in the extension repo.",
            )
        html = index.read_text("utf-8").replace("%%MORDRED_PAGE_TOKEN%%", self._page_token)
        return web.Response(text=html, content_type="text/html")

    # -- connection ---------------------------------------------------------

    def _origin_allowed(self, origin: Optional[str]) -> bool:
        if not origin:
            return True  # header-less local clients (CLI tests, some WS stacks)
        return _is_extension_origin(origin) or origin in self._local_origins

    async def _handle_ws(self, request: web.Request) -> web.WebSocketResponse:
        origin = request.headers.get("Origin")
        if not self._origin_allowed(origin):
            _log.warning("extension WS rejected: origin=%r", origin)
            return web.Response(status=403, text="forbidden origin")

        ws = web.WebSocketResponse(heartbeat=30)
        await ws.prepare(request)
        # The page authenticates with the page token (only valid from a local
        # origin); the extension authenticates with its paired ext_token.
        page_token = self._page_token if (origin in self._local_origins) else None
        conn = _Connection(ws, self.chat_handler, page_token=page_token)
        await conn.send_challenge()
        async for msg in ws:
            if msg.type == WSMsgType.TEXT:
                await conn.dispatch(msg.data)
            elif msg.type == WSMsgType.ERROR:
                break
        return ws


class _Connection:
    """Per-socket state machine."""

    def __init__(
        self,
        ws: web.WebSocketResponse,
        chat_handler: ChatHandler,
        *,
        page_token: Optional[str] = None,
    ) -> None:
        self.ws = ws
        self.chat_handler = chat_handler
        self.page_token = page_token  # set only for local-origin (page) sockets
        self.authed = False
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
        except Exception as e:  # noqa: BLE001 — client vanished mid-write; not fatal
            _log.debug("extension WS send dropped (client gone): %s", e)
            return False

    async def send_challenge(self) -> None:
        import os

        from .extension_crypto import b64u_encode

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
            return
        mtype = msg.get("type")
        try:
            if mtype == "pair_init":
                await self._on_pair_init(msg)
            elif mtype == "auth":
                await self._on_auth(msg)
            elif not self.authed:
                await self._send({"type": "auth_fail", "reason": "not_authenticated"})
            elif mtype == "chat":
                await self._on_chat(msg)
            elif mtype == "encrypt":
                await self._on_encrypt(msg)
            elif mtype == "decrypt":
                await self._on_decrypt(msg)
            elif mtype == "channel_key_set":
                await self._on_channel_key_set(msg)
            elif mtype == "slack_setup":
                await self._on_slack_setup(msg)
            elif mtype == "accounts_request":
                await self._on_accounts(msg)
            elif mtype == "sign_request":
                await self._on_sign_request(msg)
            elif mtype == "sign_approve":
                await self._on_sign_approve(msg)
            elif mtype == "webauthn_register":
                await self._on_webauthn_register(msg)
            elif mtype == "history_get":
                await self._on_history_get(msg)
            elif mtype == "history_clear":
                await self._on_history_clear(msg)
        except Exception:  # noqa: BLE001 — never let one frame kill the socket
            _log.exception("extension API handler error (type=%s)", mtype)

    # -- pairing / auth -----------------------------------------------------

    async def _on_pair_init(self, msg: dict[str, Any]) -> None:
        mid = msg.get("id")
        try:
            result = pairing.handle_pair_init(
                msg.get("code", ""), msg.get("ext_pubkey", ""), msg.get("challenge", "")
            )
        except pairing.PairError as exc:
            await self._send({"id": mid, "type": "pair_fail", "reason": exc.reason})
            return
        await self._send({"id": mid, "type": "pair_complete", **result})

    async def _on_auth(self, msg: dict[str, Any]) -> None:
        token = msg.get("ext_token", "")
        # The localhost page authenticates with the per-process page token; the
        # extension with its paired ext_token. The page is exempt from WebAuthn
        # (it never holds the shared key and is served by Hermes itself).
        if self.page_token and secrets.compare_digest(token, self.page_token):
            self.authed = True
            await self._send(
                {
                    "type": "auth_ok",
                    "hermes_version": _hermes_version(),
                    "se_available": pairing.se_available(),
                }
            )
            return
        if not pairing.validate_token(token):
            await self._send({"type": "auth_fail", "reason": "invalid_token"})
            return
        # WebAuthn hardening (§3.5): when a credential is registered, require a
        # valid assertion over this connection's nonce.
        if pairing.has_webauthn_credential():
            assertion = msg.get("webauthn_assertion")
            if not isinstance(assertion, dict) or not pairing.verify_webauthn_assertion(
                self._nonce, assertion
            ):
                await self._send({"type": "auth_fail", "reason": "webauthn_required"})
                return
        self.authed = True
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
            pairing.save_webauthn_credential(cred_id, pub)
        else:
            pairing.clear_webauthn_credential()  # unregister
        await self._send({"id": mid, "type": "webauthn_registered", "ok": True})

    # -- chat ---------------------------------------------------------------

    def _extchat_key(self) -> Optional[bytes]:
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
        # app, which has no key yet). Fail-open on decrypt.
        ek = self._extchat_key()
        encrypt_reply = bool(ek) and is_encrypted(content)
        if encrypt_reply:
            try:
                content = decrypt_message(ek, content)
            except DecryptError:
                encrypt_reply = False  # not our key — treat as plaintext, don't encrypt back
        kid = key_id(ek) if (encrypt_reply and ek) else ""

        try:
            async for chunk in self.chat_handler(content, context):
                out = encrypt_message_v2(ek, chunk, kid) if encrypt_reply else chunk
                await self._send({"id": mid, "type": "chat_chunk", "content": out})
            await self._send({"id": mid, "type": "chat_end"})
        except Exception as exc:  # noqa: BLE001
            await self._send({"id": mid, "type": "chat_error", "reason": str(exc)})

    async def _on_channel_key_set(self, msg: dict[str, Any]) -> None:
        """Store a per-channel Slack key pushed by the extension (SPEC-v2 §4.4).
        key_ct is the raw K_chan (base64url), itself encrypted with K_extchat."""
        if not self.authed:
            return
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
            from .extension_crypto import b64u_decode

            pairing.save_channel_key(channel_id, b64u_decode(raw_b64))
        except Exception:  # noqa: BLE001
            return

    async def _on_slack_setup(self, msg: dict[str, Any]) -> None:
        """Write Slack tokens the extension collected into ~/.hermes/.env so a
        new user doesn't have to hand-edit files (SPEC-v2 §6). We only persist
        config; the tokens take effect on the next Hermes restart."""
        mid = msg.get("id")

        async def _reply(ok: bool, note: str = "", error: str = "") -> None:
            await self._send(
                {"id": mid, "type": "slack_setup_result", "ok": ok, "note": note, "error": error}
            )

        if not self.authed:
            await _reply(False, error="not_authed")
            return
        bot = str(msg.get("bot_token", "")).strip()
        app = str(msg.get("app_token", "")).strip()
        if not bot.startswith("xoxb-") or not app.startswith("xapp-"):
            await _reply(False, error="bad_token_format")
            return
        try:
            from hermes_constants import get_hermes_home

            env_path = get_hermes_home() / ".env"
            existing = env_path.read_text() if env_path.exists() else ""
            lines = existing.splitlines()
            updates = {"SLACK_BOT_TOKEN": bot, "SLACK_APP_TOKEN": app}
            seen: set[str] = set()
            out: list[str] = []
            for ln in lines:
                key = ln.split("=", 1)[0].strip() if "=" in ln else ""
                if key in updates:
                    out.append(f"{key}={updates[key]}")
                    seen.add(key)
                else:
                    out.append(ln)
            for key, val in updates.items():
                if key not in seen:
                    out.append(f"{key}={val}")
            env_path.write_text("\n".join(out) + "\n")
            await _reply(True, note="tokens written to ~/.hermes/.env — restart Hermes to apply")
        except Exception as exc:  # noqa: BLE001
            await _reply(False, error=str(exc))

    # -- Slack crypto (fallback path) --------------------------------------

    def _aes_key(self) -> Optional[bytes]:
        p = pairing.load_pairing()
        return p.aes_key if p else None

    async def _on_encrypt(self, msg: dict[str, Any]) -> None:
        mid = msg.get("id")
        key = self._aes_key()
        if key is None:
            await self._send({"id": mid, "type": "decrypt_fail", "reason": "not_paired"})
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
        from gateway import extension_history

        turns = await asyncio.get_event_loop().run_in_executor(
            None, extension_history.projected_turns
        )
        await self._send({"id": msg.get("id"), "type": "history_result", "turns": turns})

    async def _on_history_clear(self, msg: dict[str, Any]) -> None:
        from gateway import extension_history

        extension_history.clear()
        await self._send({"id": msg.get("id"), "type": "history_cleared", "ok": True})

    # -- Web3 ---------------------------------------------------------------

    async def _on_accounts(self, msg: dict[str, Any]) -> None:
        mid = msg.get("id")
        try:
            address = await asyncio.get_event_loop().run_in_executor(None, _get_address)
        except Exception as exc:  # noqa: BLE001
            await self._send({"id": mid, "type": "chat_error", "reason": f"wallet: {exc}"})
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
        request_id = msg.get("request_id")
        method = msg.get("method", "")
        params = msg.get("params", []) or []
        origin = msg.get("origin", "")
        self._pending_sign[request_id] = {
            "method": method,
            "params": params,
            "origin": origin,
            "chain_id": msg.get("chain_id"),
            "rpc_url": msg.get("rpc_url"),
        }
        analysis, decoded = analyze_sign(method, params)
        await self._send(
            {
                "id": mid,
                "type": "sign_prompt",
                "request_id": request_id,
                "analysis": analysis,
                "decoded": decoded,
            }
        )

    async def _on_sign_approve(self, msg: dict[str, Any]) -> None:
        mid = msg.get("id")
        request_id = msg.get("request_id")
        pend = self._pending_sign.pop(request_id, None)
        if pend is None:
            await self._send({"id": mid, "type": "sign_result", "request_id": request_id, "error": "unknown_request"})
            return
        if not msg.get("approved"):
            await self._send({"id": mid, "type": "sign_result", "request_id": request_id, "error": "user_rejected"})
            return
        try:
            signature = await asyncio.get_event_loop().run_in_executor(
                None, _do_sign, pend["method"], pend["params"], pend.get("chain_id"), pend.get("rpc_url")
            )
        except Exception as exc:  # noqa: BLE001
            await self._send({"id": mid, "type": "sign_result", "request_id": request_id, "error": str(exc)})
            return
        await self._send({"id": mid, "type": "sign_result", "request_id": request_id, "signature": signature})


# --------------------------------------------------------------------------- #
# Sign helpers (run in executor — keyvault calls may block on Touch ID)
# --------------------------------------------------------------------------- #


def _get_address() -> str:
    from mordred_hermes.keyvault import extension_sign

    return extension_sign.get_address()


def _do_sign(
    method: str,
    params: list[Any],
    chain_id_hex: str | None = None,
    rpc_url: str | None = None,
) -> str:
    from mordred_hermes.keyvault import extension_sign

    if method == "personal_sign":
        return extension_sign.personal_sign(str(params[0]))
    if method == "eth_signTypedData_v4":
        return extension_sign.sign_typed_data_v4(params[1])
    if method == "eth_sendTransaction":
        return _send_transaction(params[0] if params else {}, chain_id_hex, rpc_url)
    raise ValueError(f"unsupported_method:{method}")


def _send_transaction(
    tx: dict[str, Any], chain_id_hex: str | None = None, rpc_url: str | None = None
) -> str:
    """Full eth_sendTransaction: fill missing fields via RPC, sign in the
    keyvault, broadcast, and return the transaction hash (SPEC §5.3).

    The active chain/RPC are taken from the extension request when present
    (custom RPC, §5.6), else from wallet.json. If no RPC is configured/reachable
    the flow falls back to returning the signed raw tx (still keyvault-signed)."""
    from mordred_hermes.keyvault import extension_sign
    from gateway import extension_rpc

    chain_id = int(chain_id_hex, 16) if chain_id_hex else extension_sign.chain_id_int()
    rpc_url = rpc_url or extension_sign.rpc_url_for(chain_id)

    if rpc_url:
        try:
            from_address = extension_sign.get_address()
            filled = extension_rpc.fill_transaction(rpc_url, tx, from_address, chain_id)
            raw = extension_sign.sign_transaction(filled, chain_id=chain_id)["raw"]
            return extension_rpc.send_raw_transaction(rpc_url, raw)
        except Exception as exc:  # noqa: BLE001
            raise RuntimeError(f"broadcast_failed: {exc}") from exc

    # No RPC configured — sign only (caller may broadcast the raw tx manually).
    out = extension_sign.sign_transaction(tx, chain_id=chain_id)
    return out["raw"]


def _wallet_chain_id_hex() -> str:
    try:
        from mordred_hermes.keyvault import extension_sign

        return hex(extension_sign.chain_id_int())
    except Exception:  # noqa: BLE001
        return "0x1"


def _hermes_version() -> str:
    try:
        from importlib.metadata import version

        return version("mordred-hermes")
    except Exception:  # noqa: BLE001
        return "0.0.0"


# --------------------------------------------------------------------------- #
# Deterministic sign-request analysis (risk + decode). An LLM pass can replace
# this later; keeping it deterministic makes it testable and offline-safe.
# --------------------------------------------------------------------------- #

_ERC20_TRANSFER = "a9059cbb"
_ERC20_APPROVE = "095ea7b3"
_MAX_UINT = (1 << 256) - 1


def analyze_sign(method: str, params: list[Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    if method == "personal_sign":
        return ({"risk": "low", "summary": "メッセージ署名（資産移動なし）", "warnings": []}, {})
    if method == "eth_signTypedData_v4":
        return (
            {"risk": "medium", "summary": "EIP-712 typed data 署名", "warnings": ["許可（permit）の可能性に注意"]},
            {"function": "eth_signTypedData_v4"},
        )
    if method == "eth_sendTransaction":
        return _analyze_tx(params[0] if params else {})
    return ({"risk": "medium", "summary": method, "warnings": []}, {})


def _analyze_tx(tx: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    data = str(tx.get("data") or "").removeprefix("0x")
    to = tx.get("to")
    value = _hex_to_int(tx.get("value"))
    warnings: list[str] = []
    decoded: dict[str, Any] = {}
    risk = "low"

    if data[:8] == _ERC20_TRANSFER and len(data) >= 8 + 128:
        recipient = "0x" + data[8 + 24 : 8 + 64]
        amount = int(data[8 + 64 : 8 + 128], 16)
        decoded = {"function": "transfer(address,uint256)", "args": {"to": recipient, "amount": str(amount)}}
        risk = "medium"
        summary = f"ERC-20 transfer: {amount} → {recipient}"
    elif data[:8] == _ERC20_APPROVE and len(data) >= 8 + 128:
        spender = "0x" + data[8 + 24 : 8 + 64]
        amount = int(data[8 + 64 : 8 + 128], 16)
        decoded = {"function": "approve(address,uint256)", "args": {"spender": spender, "amount": str(amount)}}
        if amount >= _MAX_UINT:
            risk = "high"
            warnings.append("無制限の approve（残高全額を引き出せる権限）です")
        else:
            risk = "medium"
        summary = f"ERC-20 approve: {spender}"
    elif value > 0:
        risk = "medium" if value >= 10**18 else "low"
        summary = f"ETH 送金: {value / 10**18:g} ETH → {to}"
    elif data:
        risk = "medium"
        summary = f"コントラクト呼び出し: {to}"
    else:
        summary = f"トランザクション → {to}"

    return ({"risk": risk, "summary": summary, "warnings": warnings}, decoded)


def _hex_to_int(v: Any) -> int:
    if v is None or v == "":
        return 0
    if isinstance(v, int):
        return v
    s = str(v)
    try:
        return int(s, 16) if s.startswith("0x") else int(s)
    except ValueError:
        return 0
