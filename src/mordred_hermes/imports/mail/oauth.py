"""Gmail signed in with Google: OAuth 2.0 for an installed app (loopback redirect, PKCE).

The browser extension's "Sign in with Google" asks Hermes for a sign-in
(:meth:`SignIns.start`). Hermes listens on ``127.0.0.1`` on a free port and
answers with Google's consent URL; the extension opens it in a tab. Google
sends the browser back to that loopback address with a one-time code, which
Hermes exchanges (with the PKCE verifier only it holds) for a refresh token and
the account's address, then seals the refresh token like an app password
(:mod:`.setup_flow`, :mod:`.secrets`). Every fetch turns the refresh token into a
short-lived access token and logs in with ``AUTHENTICATE XOAUTH2``
(:meth:`.imap.ImapSession.authenticate_xoauth2`).

The OAuth client is a Google Cloud "Desktop app" client the owner creates once:
``MORDRED_GMAIL_CLIENT_ID`` / ``MORDRED_GMAIL_CLIENT_SECRET``, else
``plugins.mordred_mail.gmail_client_id`` / ``gmail_client_secret`` in
``config.yaml``. Google treats an installed app's client secret as not
confidential; it is still never logged. Without a client a sign-in is refused
with ``gmail_oauth_unconfigured``.

Scopes: ``https://mail.google.com/`` (IMAP ``XOAUTH2`` accepts no narrower one;
Mordred only ever examines mailboxes read-only) and ``openid email`` (the
address is read from the ID token of the token response, which comes straight
from Google over TLS, so its signature need not be checked again).

Requests to Google follow the process's egress route (:func:`..extension.egress.resolve_route`):
direct or an HTTP proxy; a SOCKS-only route (Tor) is refused (``egress_unsupported``)
rather than sent around it.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import http.server
import json
import os
import secrets
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final

AUTH_URL: Final = "https://accounts.google.com/o/oauth2/v2/auth"
TOKEN_URL: Final = "https://oauth2.googleapis.com/token"
SCOPES: Final = "https://mail.google.com/ openid email"
CLIENT_ID_ENV: Final = "MORDRED_GMAIL_CLIENT_ID"
CLIENT_SECRET_ENV: Final = "MORDRED_GMAIL_CLIENT_SECRET"
CONFIG_SECTION: Final = "mordred_mail"
#: How long a sign-in waits for the owner to approve it in the browser.
SIGN_IN_TTL_SECONDS: Final = 600
_TIMEOUT: Final = 30.0
_MAX_SIGN_INS: Final = 2
_PAGE: Final = (
    "<!doctype html><meta charset=utf-8><title>Mordred</title>"
    "<body style='font:16px -apple-system,sans-serif;margin:40px'>"
    "<p>{message}</p><p style='color:#666'>{note}</p></body>"
)


class OAuthError(Exception):
    """A content-free failure code: ``gmail_oauth_unconfigured`` / ``_denied`` / ``_timeout`` / ``_failed`` ..."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class GoogleClient:
    client_id: str
    client_secret: str = field(repr=False)


@dataclass(frozen=True)
class Tokens:
    email: str = field(repr=False)
    access_token: str = field(repr=False)
    refresh_token: str = field(repr=False)


def client_from_config(environ: Mapping[str, str] | None = None, home: Path | None = None) -> GoogleClient | None:
    """The configured Desktop-app OAuth client (environment first, then ``config.yaml``), or ``None``."""
    env = os.environ if environ is None else environ
    client_id, secret = env.get(CLIENT_ID_ENV, "").strip(), env.get(CLIENT_SECRET_ENV, "").strip()
    if not (client_id and secret):
        section = _config_section(home)
        client_id = client_id or str(section.get("gmail_client_id") or "").strip()
        secret = secret or str(section.get("gmail_client_secret") or "").strip()
    return GoogleClient(client_id, secret) if client_id and secret else None


def _config_section(home: Path | None) -> dict[str, Any]:
    try:
        from ruamel.yaml import YAML

        from ..._home import hermes_home

        path = (home or Path(hermes_home())) / "config.yaml"
        data = YAML(typ="safe").load(path.read_text("utf-8")) if path.is_file() else None
        plugins = data.get("plugins") if isinstance(data, dict) else None
        section = plugins.get(CONFIG_SECTION) if isinstance(plugins, dict) else None
        return section if isinstance(section, dict) else {}
    except Exception:
        return {}


# --------------------------------------------------------------------------- #
# Google's token endpoint
# --------------------------------------------------------------------------- #

Post = Callable[[str, Mapping[str, str], float], dict[str, Any]]


def _post_form(url: str, fields: Mapping[str, str], timeout: float) -> dict[str, Any]:
    """POST a form to Google over the process's egress route; the JSON answer, else :class:`OAuthError`."""
    from ...extension.egress import EgressError, resolve_route

    host = urllib.parse.urlsplit(url).hostname or ""
    try:
        route = resolve_route(host)
    except EgressError:
        raise OAuthError("egress_unavailable") from None
    if route.socks_proxy_url and not route.http_proxy_url:
        raise OAuthError("egress_unsupported")
    proxies = {"https": route.http_proxy_url} if route.http_proxy_url else {}
    opener = urllib.request.build_opener(urllib.request.ProxyHandler(proxies))
    data = urllib.parse.urlencode(dict(fields)).encode()
    request = urllib.request.Request(url, data, {"content-type": "application/x-www-form-urlencoded"})
    try:
        with opener.open(request, timeout=timeout) as response:
            answer = json.load(response)
    except urllib.error.HTTPError as exc:
        code = "gmail_oauth_failed"
        try:
            reason = json.load(exc).get("error")
        except Exception:
            reason = None
        if reason == "invalid_grant":
            code = "gmail_oauth_expired"  # revoked, or a Testing-mode token past its 7 days: sign in again
        raise OAuthError(code) from None
    except (OSError, ValueError):
        raise OAuthError("gmail_oauth_unreachable") from None
    if not isinstance(answer, dict):
        raise OAuthError("gmail_oauth_failed")
    return answer


def _email_from_id_token(id_token: object) -> str:
    """The verified address in an ID token received directly from Google's token endpoint."""
    if not isinstance(id_token, str) or id_token.count(".") != 2:
        raise OAuthError("gmail_oauth_failed")
    payload = id_token.split(".")[1]
    try:
        claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    except (binascii.Error, ValueError):
        raise OAuthError("gmail_oauth_failed") from None
    email = claims.get("email") if isinstance(claims, dict) else None
    if not isinstance(email, str) or "@" not in email or claims.get("email_verified") is not True:
        raise OAuthError("gmail_oauth_failed")
    return email


def exchange_code(
    client: GoogleClient, code: str, verifier: str, redirect_uri: str, *, post: Post = _post_form
) -> Tokens:
    """The tokens for an authorization code (``offline`` access: a refresh token is required)."""
    answer = post(
        TOKEN_URL,
        {
            "code": code,
            "client_id": client.client_id,
            "client_secret": client.client_secret,
            "redirect_uri": redirect_uri,
            "grant_type": "authorization_code",
            "code_verifier": verifier,
        },
        _TIMEOUT,
    )
    access, refresh = answer.get("access_token"), answer.get("refresh_token")
    if not isinstance(access, str) or not access or not isinstance(refresh, str) or not refresh:
        raise OAuthError("gmail_oauth_failed")
    return Tokens(_email_from_id_token(answer.get("id_token")), access, refresh)


def refresh_access_token(client: GoogleClient, refresh_token: str, *, post: Post = _post_form) -> str:
    """A fresh access token for a sealed refresh token."""
    answer = post(
        TOKEN_URL,
        {
            "client_id": client.client_id,
            "client_secret": client.client_secret,
            "refresh_token": refresh_token,
            "grant_type": "refresh_token",
        },
        _TIMEOUT,
    )
    access = answer.get("access_token")
    if not isinstance(access, str) or not access:
        raise OAuthError("gmail_oauth_failed")
    return access


def access_token_for(refresh_token: str) -> str:
    """The access token a fetch logs in with (the configured client; ``gmail_oauth_unconfigured`` without one)."""
    client = client_from_config()
    if client is None:
        raise OAuthError("gmail_oauth_unconfigured")
    return refresh_access_token(client, refresh_token)


# --------------------------------------------------------------------------- #
# Sign-ins waiting for the browser
# --------------------------------------------------------------------------- #


def _pkce() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    return verifier, challenge


@dataclass
class SignIn:
    """One sign-in: waiting for the browser, then ``done`` or ``failed`` (a content-free ``error``)."""

    flow_id: str
    auth_url: str
    redirect_uri: str = field(repr=False)
    state: str = field(repr=False)
    verifier: str = field(repr=False)
    created: float
    status: str = "waiting"
    error: str | None = None
    #: What the completion returned (the fetch job's view), shown to the extension.
    outcome: dict[str, Any] | None = None
    _code: str | None = field(default=None, repr=False)
    _arrived: threading.Event = field(default_factory=threading.Event, repr=False)
    _server: http.server.HTTPServer | None = field(default=None, repr=False)


Complete = Callable[[Tokens], dict[str, Any] | None]


class SignIns:
    """The sign-ins of this process (at most :data:`_MAX_SIGN_INS`), each with its loopback listener."""

    def __init__(self, *, post: Post = _post_form, clock: Callable[[], float] = time.monotonic) -> None:
        self._post = post
        self._clock = clock
        self._flows: dict[str, SignIn] = {}
        self._guard = threading.Lock()

    def start(self, client: GoogleClient, complete: Complete, *, ttl: float = SIGN_IN_TTL_SECONDS) -> SignIn:
        """Listen on loopback, build Google's consent URL; once the code arrives, exchange it and ``complete``."""
        with self._guard:
            if sum(flow.status == "waiting" for flow in self._flows.values()) >= _MAX_SIGN_INS:
                raise OAuthError("gmail_oauth_busy")
        verifier, challenge = _pkce()
        state = secrets.token_urlsafe(24)
        flow_id = secrets.token_urlsafe(16)
        server = http.server.HTTPServer(("127.0.0.1", 0), _handler_for(self, flow_id))
        port = server.server_address[1]
        redirect_uri = f"http://127.0.0.1:{port}/"
        query = urllib.parse.urlencode(
            {
                "client_id": client.client_id,
                "redirect_uri": redirect_uri,
                "response_type": "code",
                "scope": SCOPES,
                "code_challenge": challenge,
                "code_challenge_method": "S256",
                "state": state,
                "access_type": "offline",
                "prompt": "consent",
            }
        )
        flow = SignIn(flow_id, f"{AUTH_URL}?{query}", redirect_uri, state, verifier, self._clock())
        flow._server = server
        with self._guard:
            self._flows[flow_id] = flow
        threading.Thread(target=server.serve_forever, name="mordred-gmail-oauth", daemon=True).start()
        threading.Thread(target=self._finish, args=(client, flow, complete, ttl), daemon=True).start()
        return flow

    def get(self, flow_id: str) -> SignIn:
        with self._guard:
            flow = self._flows.get(flow_id) if isinstance(flow_id, str) else None
        if flow is None:
            raise OAuthError("gmail_oauth_unknown")
        return flow

    def cancel(self, flow_id: str) -> None:
        with self._guard:
            flow = self._flows.get(flow_id) if isinstance(flow_id, str) else None
        if flow is not None and flow.status == "waiting":
            self._end(flow, "failed", "gmail_oauth_cancelled")
            flow._arrived.set()

    def _arrive(self, flow_id: str, query: Mapping[str, list[str]]) -> str:
        """The browser came back: ``"ok"``, ``"denied"`` or ``"ignored"`` (not this sign-in's state)."""
        with self._guard:
            flow = self._flows.get(flow_id)
        if flow is None or flow.status != "waiting" or flow._arrived.is_set():
            return "ignored"
        if query.get("state", [""])[0] != flow.state:
            return "ignored"
        code = query.get("code", [""])[0]
        if not code:
            self._end(flow, "failed", "gmail_oauth_denied")
            flow._arrived.set()
            return "denied"
        flow._code = code
        flow._arrived.set()
        return "ok"

    def _finish(self, client: GoogleClient, flow: SignIn, complete: Complete, ttl: float) -> None:
        arrived = flow._arrived.wait(ttl)
        server, flow._server = flow._server, None
        if server is not None:
            threading.Thread(target=server.shutdown, daemon=True).start()
        if not arrived:
            self._end(flow, "failed", "gmail_oauth_timeout")
            return
        code, flow._code = flow._code, None
        if flow.status != "waiting" or code is None:
            return
        try:
            tokens = exchange_code(client, code, flow.verifier, flow.redirect_uri, post=self._post)
            outcome = complete(tokens)
        except OAuthError as exc:
            self._end(flow, "failed", exc.code)
            return
        except Exception as exc:  # the setup's own code (content-free), else a generic one; nothing is logged
            code_attr = getattr(exc, "code", None)
            self._end(flow, "failed", code_attr if isinstance(code_attr, str) else "gmail_oauth_failed")
            return
        flow.outcome = outcome
        self._end(flow, "done", None)

    def _end(self, flow: SignIn, status: str, error: str | None) -> None:
        with self._guard:
            if flow.status != "waiting":
                return
            flow.status, flow.error = status, error
            flow.verifier = flow.state = ""
            # Finished sign-ins are kept a while for the extension to read, then dropped.
            now = self._clock()
            for flow_id, old in list(self._flows.items()):
                if old.status != "waiting" and now - old.created > SIGN_IN_TTL_SECONDS:
                    del self._flows[flow_id]


def _handler_for(sign_ins: SignIns, flow_id: str) -> type[http.server.BaseHTTPRequestHandler]:
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            parts = urllib.parse.urlsplit(self.path)
            if parts.path != "/":
                self.send_error(404)
                return
            outcome = sign_ins._arrive(flow_id, urllib.parse.parse_qs(parts.query))
            if outcome == "ignored":
                self.send_error(400)
                return
            message = (
                "Mordred: Google のログインを受け取りました。このタブを閉じてください。"
                if outcome == "ok"
                else "Mordred: ログインは許可されませんでした。"
            )
            body = (
                _PAGE.replace("{message}", message)
                .replace("{note}", "Hermes がメールを読み取り、暗号化して保存します。")
                .encode()
            )
            self.send_response(200)
            self.send_header("content-type", "text/html; charset=utf-8")
            self.send_header("cache-control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args: Any) -> None:
            return None  # the query holds the one-time code: never logged

    return Handler
