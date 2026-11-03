"""Presence state contains no credential material and never slides its deadline."""

from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor

import pytest

from mordred_hermes.keyvault import _presence as p
from mordred_hermes.keyvault._seckey_errors import _OpsError


class Channel:
    def __init__(self, *args):
        self.calls = 0
        self.closed = False
        self.entered = threading.Event()
        self.release = threading.Event()
        self.release.set()
        self.fail = False

    def exchange(self, payload, timeout):
        self.calls += 1
        self.entered.set()
        assert self.release.wait(2)
        if self.fail:
            raise _OpsError(-25293, "OSStatus", "denied")
        return {"shared_hex": "ab" * 32}

    def close(self):
        self.closed = True
        self.release.set()

    def alive(self):
        return not self.closed


@pytest.fixture
def setup_pool(tmp_path):
    now = [0.0]
    channels = []

    def factory(*args):
        ch = Channel(*args)
        channels.append(ch)
        return ch

    pool = p._PresencePool(factory=factory, clock=lambda: now[0])
    scope = p._Scope(tmp_path, ("hermes", "session"), "telegram", lambda: True)
    yield pool, scope, channels, now
    pool.close()


def exchange(pool, scope, binding="source"):
    return pool.exchange(scope, "helper", None, b"tag", b"peer", 300, binding)


def test_decrypt_each_operation_and_non_sliding_expiry(setup_pool):
    pool, scope, channels, now = setup_pool
    exchange(pool, scope)
    now[0] = 299
    exchange(pool, scope)
    assert len(channels) == 1
    assert channels[0].calls == 2
    now[0] = 300
    exchange(pool, scope)
    assert channels[0].closed
    assert len(channels) == 2


def test_session_profile_purpose_and_source_isolation(setup_pool, tmp_path):
    pool, scope, channels, _ = setup_pool
    exchange(pool, scope)
    exchange(pool, scope, "replacement")
    assert channels[0].closed
    for s in [
        p._Scope(tmp_path / "other", scope.principal, "telegram", lambda: True),
        p._Scope(tmp_path, ("hermes", "other"), "telegram", lambda: True),
        p._Scope(tmp_path, scope.principal, "mail", lambda: True),
    ]:
        exchange(pool, s)
    assert len(channels) == 5


def test_parallel_initial_failure_is_shared(setup_pool):
    pool, scope, channels, _ = setup_pool
    exchange(pool, scope)
    ch = channels[0]
    ch.fail = True
    ch.release.clear()
    with ThreadPoolExecutor(3) as executor:
        first = executor.submit(exchange, pool, scope)
        assert ch.entered.wait(1)
        second = executor.submit(exchange, pool, scope)
        # reserve deterministically before releasing authentication
        for _ in range(1000):
            if pool.pending == 2:
                break
            threading.Event().wait(0.001)
        assert pool.pending == 2
        ch.release.set()
        for future in (first, second):
            with pytest.raises(_OpsError, match="denied"):
                future.result()
    assert ch.calls == 2  # successful setup plus a single failed request
    assert ch.closed


def test_revocation_does_not_wait_for_authentication(setup_pool):
    pool, scope, channels, _ = setup_pool
    exchange(pool, scope)
    ch = channels[0]
    ch.release.clear()
    with ThreadPoolExecutor(1) as executor:
        future = executor.submit(exchange, pool, scope)
        assert ch.entered.wait(1)
        pool.revoke(home=scope.home)
        assert ch.closed
        with pytest.raises(_OpsError):
            future.result()


def test_expiry_during_request_fails_without_retry(setup_pool):
    pool, scope, channels, now = setup_pool
    exchange(pool, scope)
    ch = channels[0]
    original = ch.exchange

    def delayed(*args):
        now[0] = 300
        return original(*args)

    ch.exchange = delayed
    with pytest.raises(_OpsError):
        exchange(pool, scope)
    assert len(channels) == 1
    assert ch.closed


@pytest.mark.parametrize(
    "value,expected", [(None, 0), (False, 0), ("300", 0), (-1, 0), (301, 0), (5.0, 0), (0, 0), (300, 300)]
)
def test_setting_fails_closed(value, expected):
    assert p._reuse_seconds(value) == expected


def test_helper_limit_and_waiter_limit(setup_pool, tmp_path):
    pool, scope, channels, _ = setup_pool
    for i in range(8):
        exchange(pool, p._Scope(tmp_path, ("hermes", str(i)), "telegram", lambda: True))
    with pytest.raises(_OpsError, match="capacity"):
        exchange(pool, scope)
    assert len(channels) == 8
    pool.close()
    exchange(pool, scope)
    entry = next(iter(pool._entries.values()))
    entry.pending = 17
    with pytest.raises(_OpsError, match="queue full"):
        exchange(pool, scope)
    assert channels[-1].calls == 1
    entry.pending = 0


def test_file_change_and_caller_revocation_are_monitored(setup_pool):
    pool, scope, channels, _ = setup_pool
    exchange(pool, scope)
    (scope.home / "config.yaml").write_text("changed")
    pool.reap()
    assert channels[0].closed
    current = [True]
    scope = p._Scope(scope.home, scope.principal, scope.purpose, lambda: current[0])
    exchange(pool, scope)
    current[0] = False
    pool.reap()
    assert channels[1].closed


def test_malformed_yaml_disables_reuse(tmp_path):
    (tmp_path / "config.yaml").write_text("plugins: [invalid")
    assert p.configured_seconds(tmp_path) == 0


def test_old_helper_capability_negotiation_is_prompt_free_and_falls_back(setup_pool, monkeypatch):
    from mordred_hermes.keyvault._seckey_helper import _HelperSecKeyOps

    _, scope, _, _ = setup_pool
    monkeypatch.setattr(p, "eligible", lambda tag: (scope, 300, "source"))
    calls = []

    def invoke(payload):
        calls.append(payload["cmd"])
        if payload["cmd"] == "capabilities":
            raise _OpsError(-1, "helper", "unknown cmd")
        return {"shared_hex": "ab" * 32}

    ops = _HelperSecKeyOps("helper")
    ops._invoke = invoke
    assert ops.key_exchange(b"tag", b"peer") == b"\xab" * 32
    assert ops.key_exchange(b"tag", b"peer") == b"\xab" * 32
    assert calls == ["capabilities", "ecdh", "ecdh"]


def test_no_fallback_after_session_authentication_started(setup_pool, monkeypatch):
    from mordred_hermes.keyvault._seckey_helper import _HelperSecKeyOps

    pool, scope, channels, _ = setup_pool
    monkeypatch.setattr(p, "_pool", pool)
    monkeypatch.setattr(p, "eligible", lambda tag: (scope, 300, "source"))
    calls = []
    ops = _HelperSecKeyOps("helper")
    ops._invoke = lambda payload: calls.append(payload["cmd"]) or {"presence_session": 1}
    ops.key_exchange(b"tag", b"peer")
    channels[0].fail = True
    with pytest.raises(_OpsError, match="denied"):
        ops.key_exchange(b"tag", b"peer")
    assert calls == ["capabilities"]
    assert channels[0].closed


def test_credential_scope_never_authorizes_another_key(tmp_path, monkeypatch):
    import sys

    if sys.platform != "darwin":
        pytest.skip("macOS eligibility")
    from mordred_hermes.keyvault._seckey_errors import _application_tag

    monkeypatch.setattr(p, "configured_seconds", lambda home: 300)
    monkeypatch.setattr(p, "_ensure_monitor", lambda: None)
    with (
        p.presence_scope(tmp_path, ("hermes", "session"), "telegram"),
        p.credential_scope(tmp_path, "telegram", "current-source"),
    ):
        assert p.eligible(_application_tag("wallet-key")) is None
        assert p.eligible(_application_tag("mordred-hermes.mail.credentials.v1")) is None
        assert p.eligible(_application_tag("mordred-hermes.telegram.credentials.v1")) is not None


def test_shared_failure_retains_no_traceback_or_decrypted_response(setup_pool):
    pool, scope, channels, now = setup_pool
    exchange(pool, scope)
    entry = next(iter(pool._entries.values()))
    response = {"shared_hex": "ab" * 32}

    def delayed(*args):
        now[0] = 300
        return response

    channels[0].exchange = delayed
    with pytest.raises(_OpsError):
        exchange(pool, scope)
    assert response == {}
    assert entry.failure.__traceback__ is None
    assert entry.failure.__context__ is None


def test_dead_helper_releases_capacity_without_waiting_for_parent_clock(setup_pool, tmp_path):
    pool, scope, channels, _ = setup_pool
    for i in range(8):
        exchange(pool, p._Scope(tmp_path, ("hermes", str(i)), "telegram", lambda: True))
    for channel in channels:
        channel.close()  # child uses a sleep-inclusive clock even if parent's clock stopped
    exchange(pool, scope)
    assert len(channels) == 9
    assert pool.pending == 0


def test_request_elapsed_budget_is_enforced_after_response(setup_pool):
    pool, scope, channels, now = setup_pool
    exchange(pool, scope)

    def delayed(*args):
        now[0] = 121
        return {"shared_hex": "ab" * 32}

    channels[0].exchange = delayed
    with pytest.raises(_OpsError, match="timed out"):
        exchange(pool, scope)
    assert channels[0].closed


def test_cancellation_is_confined_to_session_and_purpose(setup_pool, monkeypatch):
    pool, scope, channels, _ = setup_pool
    monkeypatch.setattr(p, "_pool", pool)
    exchange(pool, scope)
    mail = p._Scope(scope.home, scope.principal, "mail", lambda: True)
    other = p._Scope(scope.home, ("hermes", "other"), "telegram", lambda: True)
    exchange(pool, mail)
    exchange(pool, other)
    with pytest.raises(RuntimeError), p.presence_scope(scope.home, scope.principal, "telegram"):
        raise RuntimeError("cancelled")
    assert channels[0].closed
    assert not channels[1].closed and not channels[2].closed
