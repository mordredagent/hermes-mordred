from __future__ import annotations

import asyncio
import sys
from types import ModuleType, SimpleNamespace

import pytest

from mordred_hermes.keyvault import _presence as p
from mordred_hermes.keyvault import _presence_hosts as hosts


def test_hermes_framework_identity_and_profile_switch(tmp_path, monkeypatch):
    home = [tmp_path]
    monkeypatch.setattr(hosts, "_home", lambda: home[0])
    with hosts.hermes_presence(None):
        assert p._scope.get() is None
    with hosts.hermes_presence("framework-session"):
        scope = p._scope.get()
        assert scope.principal == ("hermes", "framework-session")
        assert scope.purpose == "telegram" and scope.valid()
        home[0] = tmp_path / "other"
        assert not scope.valid()
    assert p._scope.get() is None


def test_desktop_requires_real_host_auth_and_revokes_on_generation_change(tmp_path, monkeypatch):
    monkeypatch.setattr(hosts, "_home", lambda: tmp_path)
    host = ModuleType("hermes_cli.web_server")
    host.app = SimpleNamespace(state=SimpleNamespace(auth_required=False))
    host._SESSION_TOKEN = "test-host-generation"
    host._has_valid_session_token = lambda request: request.valid
    monkeypatch.setitem(sys.modules, "hermes_cli.web_server", host)
    for request in [SimpleNamespace(app=SimpleNamespace(), valid=True), SimpleNamespace(app=host.app, valid=False)]:
        with hosts.desktop_presence(request, "mail"):
            assert p._scope.get() is None
    with hosts.desktop_presence(SimpleNamespace(app=host.app, valid=True), "mail"):
        scope = p._scope.get()
        assert scope.principal[0] == "desktop" and scope.valid()
        assert "test-host-generation" not in repr(scope)
        host._SESSION_TOKEN = "replacement"
        assert not scope.valid()
    host.app.state.auth_required = True
    with hosts.desktop_presence(SimpleNamespace(app=host.app, valid=True), "mail"):
        assert p._scope.get() is None


def test_mail_raw_worker_propagates_context_and_ignores_argument_identity(tmp_path, monkeypatch):
    from mordred_hermes.extension.telegram import hermes_tools, mail_tool

    monkeypatch.setattr(hosts, "_home", lambda: tmp_path)

    async def allowed(parent):
        pass

    monkeypatch.setattr(hermes_tools, "_require_reader_allowed", allowed)
    seen = []

    def fetch(*args):
        scope = p._scope.get()
        seen.append((scope.principal, scope.purpose))
        return {"ok": True}

    monkeypatch.setattr(mail_tool, "_fetch", fetch)
    asyncio.run(mail_tool.mordred_mail_sync({}, session_id="framework-session"))
    assert seen == [(("hermes", "framework-session"), "mail")]
    answer = asyncio.run(mail_tool.mordred_mail_sync({"session_id": "spoofed"}, session_id="framework-session"))
    assert "invalid_request" in answer and len(seen) == 1


def test_scope_exception_revokes_only_matching_principal(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(p._pool, "revoke", lambda **kwargs: calls.append(kwargs))
    with pytest.raises(asyncio.CancelledError), p.presence_scope(tmp_path, ("hermes", "cancelled"), "telegram"):
        raise asyncio.CancelledError
    assert calls == [{"home": tmp_path.resolve(), "principal": ("hermes", "cancelled"), "purpose": "telegram"}]
    assert p._scope.get() is None
