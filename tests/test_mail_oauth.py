"""Gmail signed in with Google (``imports/mail/oauth.py``): the client, the token exchange, the loopback
sign-in, the ``XOAUTH2`` login and the sealed refresh token. Google is faked; the IMAP side runs the real
imaplib client against ``tests/_fake_imap.py``."""

from __future__ import annotations

import base64
import json
import time
import urllib.error
import urllib.request
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import pytest

from mordred_hermes.imports.mail import oauth
from mordred_hermes.imports.mail.secrets import MailCredentials, MailSecretsError, decode, encode
from mordred_hermes.imports.mail.setup_flow import MailSetupError
from tests._mail_sync_helpers import ADDRESS, gmail_server
from tests.test_mail_setup_flow import Connector, make_flows

CLIENT = oauth.GoogleClient("client-1.apps.googleusercontent.com", "secret-1")


def _id_token(email: str = ADDRESS, verified: bool = True) -> str:
    claims = base64.urlsafe_b64encode(json.dumps({"email": email, "email_verified": verified}).encode()).decode()
    return f"header.{claims.rstrip('=')}.signature"


class _Google:
    """The token endpoint: records the forms and answers the next scripted reply."""

    def __init__(self, *answers: dict[str, Any]) -> None:
        self.answers = list(answers)
        self.forms: list[dict[str, str]] = []

    def __call__(self, url: str, fields: Mapping[str, str], timeout: float) -> dict[str, Any]:
        assert url == oauth.TOKEN_URL
        self.forms.append(dict(fields))
        return self.answers.pop(0)


def _wait(sign_in: oauth.SignIn, seconds: float = 5.0) -> None:
    deadline = time.monotonic() + seconds
    while sign_in.status == "waiting" and time.monotonic() < deadline:
        time.sleep(0.02)


def _visit(url: str) -> int:
    try:
        with urllib.request.urlopen(url, timeout=5) as response:
            return int(response.status)
    except urllib.error.HTTPError as exc:
        return exc.code


def test_the_client_comes_from_the_environment_else_config_yaml(tmp_path: Path) -> None:
    env = {oauth.CLIENT_ID_ENV: "id-env", oauth.CLIENT_SECRET_ENV: "secret-env"}
    assert oauth.client_from_config(env, tmp_path) == oauth.GoogleClient("id-env", "secret-env")
    assert oauth.client_from_config({}, tmp_path) is None
    (tmp_path / "config.yaml").write_text(
        "plugins:\n  mordred_mail:\n    gmail_client_id: id-yaml\n    gmail_client_secret: secret-yaml\n"
    )
    assert oauth.client_from_config({}, tmp_path) == oauth.GoogleClient("id-yaml", "secret-yaml")
    assert "secret" not in repr(oauth.client_from_config({}, tmp_path))


def test_a_code_is_exchanged_for_the_address_and_a_refresh_token() -> None:
    google = _Google({"access_token": "at-1", "refresh_token": "rt-1", "id_token": _id_token()})
    tokens = oauth.exchange_code(CLIENT, "code-1", "verifier-1", "http://127.0.0.1:5/", post=google)
    assert (tokens.email, tokens.access_token, tokens.refresh_token) == (ADDRESS, "at-1", "rt-1")
    assert google.forms[0]["code_verifier"] == "verifier-1" and google.forms[0]["grant_type"] == "authorization_code"
    assert "rt-1" not in repr(tokens) and ADDRESS not in repr(tokens)
    for answer in (
        {"access_token": "at", "id_token": _id_token()},  # no refresh token: offline access was not granted
        {"access_token": "at", "refresh_token": "rt", "id_token": _id_token(verified=False)},
        {"access_token": "at", "refresh_token": "rt", "id_token": "not-a-jwt"},
    ):
        with pytest.raises(oauth.OAuthError, match="gmail_oauth_failed"):
            oauth.exchange_code(CLIENT, "code", "v", "http://127.0.0.1:5/", post=_Google(answer))
    refreshed = _Google({"access_token": "at-2"})
    assert oauth.refresh_access_token(CLIENT, "rt-1", post=refreshed) == "at-2"
    assert refreshed.forms[0]["grant_type"] == "refresh_token"


def test_a_sign_in_waits_for_the_browser_on_loopback_then_completes() -> None:
    google = _Google({"access_token": "at-1", "refresh_token": "rt-1", "id_token": _id_token()})
    completed: list[oauth.Tokens] = []
    sign_ins = oauth.SignIns(post=google)
    sign_in = sign_ins.start(CLIENT, lambda tokens: completed.append(tokens) or {"job_id": "j1"})
    assert sign_in.auth_url.startswith("https://accounts.google.com/o/oauth2/v2/auth?")
    assert "code_challenge_method=S256" in sign_in.auth_url and "access_type=offline" in sign_in.auth_url
    assert sign_in.redirect_uri.startswith("http://127.0.0.1:")
    state = sign_in.state
    # Another page's visit (no or a wrong state) changes nothing.
    assert _visit(f"{sign_in.redirect_uri}?code=x&state=wrong") == 400
    assert sign_in.status == "waiting"
    assert _visit(f"{sign_in.redirect_uri}?code=code-1&state={state}") == 200
    _wait(sign_in)
    assert (sign_in.status, sign_in.error, sign_in.outcome) == ("done", None, {"job_id": "j1"})
    assert [t.refresh_token for t in completed] == ["rt-1"]
    assert google.forms[0]["code"] == "code-1" and google.forms[0]["redirect_uri"] == sign_in.redirect_uri
    assert sign_ins.get(sign_in.flow_id) is sign_in and sign_in.verifier == ""


def test_a_refusal_a_cancel_and_a_timeout_end_the_sign_in() -> None:
    sign_ins = oauth.SignIns(post=_Google())
    denied = sign_ins.start(CLIENT, lambda _tokens: None)
    assert _visit(f"{denied.redirect_uri}?error=access_denied&state={denied.state}") == 200
    _wait(denied)
    assert (denied.status, denied.error) == ("failed", "gmail_oauth_denied")

    cancelled = sign_ins.start(CLIENT, lambda _tokens: None)
    sign_ins.cancel(cancelled.flow_id)
    _wait(cancelled)
    assert (cancelled.status, cancelled.error) == ("failed", "gmail_oauth_cancelled")

    late = sign_ins.start(CLIENT, lambda _tokens: None, ttl=0.1)
    _wait(late)
    assert (late.status, late.error) == ("failed", "gmail_oauth_timeout")
    with pytest.raises(oauth.OAuthError, match="gmail_oauth_unknown"):
        sign_ins.get("nope")


def test_a_failing_setup_fails_the_sign_in_with_its_code() -> None:
    google = _Google({"access_token": "at-1", "refresh_token": "rt-1", "id_token": _id_token()})
    sign_ins = oauth.SignIns(post=google)

    def complete(_tokens: oauth.Tokens) -> None:
        raise MailSetupError("mail_already_configured")

    sign_in = sign_ins.start(CLIENT, complete)
    _visit(f"{sign_in.redirect_uri}?code=c&state={sign_in.state}")
    _wait(sign_in)
    assert (sign_in.status, sign_in.error) == ("failed", "mail_already_configured")


def test_setup_logs_in_with_xoauth2_and_seals_the_refresh_token(secrets: Any, home: Path) -> None:
    server = gmail_server(oauth_token="at-1")
    flows = make_flows(secrets, home, Connector(server))
    flow = flows.start_oauth(address=ADDRESS, access_token="at-1", refresh_token="rt-1")
    assert (flow.step, flow.gmail, flow.roles) == ("done", True, ("all",))
    assert "AUTHENTICATE" in server.verbs and "LOGIN" not in server.verbs
    creds = secrets.load()
    assert creds is not None
    assert (creds.app_password, creds.oauth_refresh_token, creds.imap_host) == ("", "rt-1", "imap.gmail.com")


def test_a_refused_token_is_an_auth_failure_and_seals_nothing(secrets: Any, home: Path) -> None:
    server = gmail_server(oauth_token="at-1")
    flows = make_flows(secrets, home, Connector(server))
    with pytest.raises(MailSetupError) as refused:
        flows.start_oauth(address=ADDRESS, access_token="stale", refresh_token="rt-1")
    assert refused.value.code == "imap_auth_failed"
    assert secrets.load() is None


def test_sealed_credentials_hold_exactly_one_way_to_log_in() -> None:
    base: dict[str, Any] = {
        "address": ADDRESS,
        "imap_host": "imap.gmail.com",
        "imap_port": 993,
        "own_addresses": (ADDRESS,),
        "account": "mail",
        "gmail": True,
        "mailboxes": {"all": "[Gmail]/All Mail"},
    }
    oauth_creds = MailCredentials(app_password="", oauth_refresh_token="rt-1", **base)
    assert decode(encode(oauth_creds)) == oauth_creds and "rt-1" not in repr(oauth_creds)
    password_creds = MailCredentials(app_password="pw", **base)
    assert (
        "oauth_refresh_token" not in json.loads(encode(password_creds))
        and decode(encode(password_creds)) == password_creds
    )
    for app_password, refresh in (("", ""), ("pw", "rt")):
        with pytest.raises(MailSecretsError):
            MailCredentials(app_password=app_password, oauth_refresh_token=refresh, **base)


@pytest.fixture
def home(tmp_path: Path) -> Path:
    path = tmp_path / "home"
    path.mkdir()
    return path


@pytest.fixture
def secrets(tmp_path: Path) -> Any:
    from tests._platform_test_helpers import require_posix_tee
    from tests.test_mail_secrets import FakeEnclave, sealed_store

    require_posix_tee()
    return sealed_store(tmp_path / "sealed", FakeEnclave())
