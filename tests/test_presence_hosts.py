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


def test_cancelled_operation_cannot_start_a_helper_after_delayed_capability(tmp_path, monkeypatch):
    channels = []
    pool = p._PresencePool(factory=lambda *args: channels.append(args))
    monkeypatch.setattr(p, "_pool", pool)
    with p.presence_scope(tmp_path, ("hermes", "cancelled"), "mail"):
        scope = p._scope.get()
        p.revoke_current()  # cancellation before the worker reaches ECDH/admission
        with pytest.raises(p._OpsError):
            pool.exchange(scope, "helper", None, b"tag", b"peer", 300, "source")
    assert channels == []


def test_mail_cancellation_revokes_before_worker_cleanup(monkeypatch):
    from mordred_hermes.extension.telegram import mail_tool

    calls = []
    monkeypatch.setattr(p, "revoke_current", lambda: calls.append("revoke"))
    monkeypatch.setattr(mail_tool, "_fetch", lambda *args: {})

    async def cancelled(*args):
        raise asyncio.CancelledError

    async def drained(*args):
        assert calls == ["revoke"]
        calls.append("drain")
        return True

    monkeypatch.setattr(mail_tool, "_joined", cancelled)
    monkeypatch.setattr(mail_tool, "_joined_after_cancel", drained)
    with pytest.raises(asyncio.CancelledError):
        asyncio.run(mail_tool._run_worker(1))
    assert calls == ["revoke", "drain"]


def test_desktop_cancellation_revokes_while_worker_is_still_owned(tmp_path):
    import threading

    from mordred_hermes.desktop._jobs import Job

    entered, release = threading.Event(), threading.Event()

    def blocking():
        entered.set()
        assert release.wait(3)
        return "finished"

    async def run():
        with p.presence_scope(tmp_path, ("desktop", "generation"), "mail"):
            scope = p._scope.get()
            task = asyncio.create_task(Job("job", "mail_fetch").run_sync(blocking))
            try:
                assert await asyncio.to_thread(entered.wait, 1)
                task.cancel()
                await asyncio.sleep(0.01)
                assert scope.cancelled.is_set(), "cancel must revoke before the worker finishes"
                assert not task.done(), "keep the existing drain/ownership semantics"
            finally:
                release.set()
                assert await task == "finished"

    asyncio.run(run())


def test_cancelled_credential_operation_cannot_fall_back_when_setting_changes(tmp_path, monkeypatch):
    if sys.platform != "darwin":
        pytest.skip("macOS eligibility")
    from mordred_hermes.keyvault._seckey_errors import _application_tag

    monkeypatch.setattr(p, "configured_seconds", lambda home: 0)
    with p.presence_scope(tmp_path, ("hermes", "cancelled"), "mail"), p.credential_scope(tmp_path, "mail", "source"):
        p.revoke_current()
        with pytest.raises(p._OpsError):
            p.eligible(_application_tag("mordred-hermes.mail.credentials.v1"))


def test_profile_override_is_valid_in_the_independent_monitor_thread(tmp_path, monkeypatch):
    import contextvars
    from concurrent.futures import ThreadPoolExecutor

    selected = contextvars.ContextVar("test_profile", default=tmp_path)
    monkeypatch.setattr(hosts, "_home", selected.get)
    token = selected.set(tmp_path / "profile-a")
    try:
        with hosts.hermes_presence("framework-session"):
            scope = p._scope.get()
            with ThreadPoolExecutor(1) as executor:
                assert executor.submit(scope.active).result()
    finally:
        selected.reset(token)


def test_profile_switch_revokes_pending_scope_before_helper_admission(tmp_path, monkeypatch):
    import contextvars

    selected = contextvars.ContextVar("test_profile", default=tmp_path)
    monkeypatch.setattr(hosts, "_home", selected.get)
    pool = p._PresencePool()
    monkeypatch.setattr(p, "_pool", pool)
    selected.set(tmp_path / "profile-a")
    with hosts.hermes_presence("framework-session"):
        old = p._scope.get()
    selected.set(tmp_path / "profile-b")
    with hosts.hermes_presence("framework-session"):
        assert old.cancelled.is_set()
        assert p._scope.get().active()


def test_profile_specific_validation_binds_only_profile_context(tmp_path, monkeypatch):
    import contextvars
    from concurrent.futures import ThreadPoolExecutor

    selected = contextvars.ContextVar("test_selected_profile", default=tmp_path)
    unrelated = contextvars.ContextVar("test_request_secret", default=None)
    home = tmp_path / "profile-a"
    monkeypatch.setattr(hosts, "_home", selected.get)
    constants = ModuleType("hermes_constants")
    constants.set_hermes_home_override = lambda value: selected.set(type(home)(value))
    constants.reset_hermes_home_override = selected.reset
    monkeypatch.setitem(sys.modules, "hermes_constants", constants)
    token = selected.set(home)
    secret = unrelated.set("must-not-be-retained-by-validation")
    try:
        check = hosts.profile_guard(home, lambda: selected.get() == home and unrelated.get() is None)
        with ThreadPoolExecutor(1) as executor:
            assert executor.submit(check).result()
        assert selected.get() == home and unrelated.get() is not None
    finally:
        selected.reset(token)
        unrelated.reset(secret)
