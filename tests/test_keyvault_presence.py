"""Presence state contains no credential material and never slides its deadline."""

from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor

import pytest

from mordred_hermes.keyvault import _presence as p
from mordred_hermes.keyvault._seckey_errors import _OpsError


class Channel:
    def __init__(self, *args):
        self.args = args
        self.payloads = []
        self.calls = 0
        self.closed = False
        self.entered = threading.Event()
        self.release = threading.Event()
        self.release.set()
        self.fail = False

    def exchange(self, payload, timeout):
        self.payloads.append(payload)
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


# --- operation windows: one prompt for an operation's own keys -----------------


def test_a_window_admits_the_operations_keys_but_never_credential_keys(tmp_path, monkeypatch):
    import sys

    if sys.platform != "darwin":
        pytest.skip("macOS eligibility")
    from mordred_hermes.keyvault._seckey_errors import _application_tag

    monkeypatch.setattr(p, "_ensure_monitor", lambda: None)
    vault, database = _application_tag("mordred-hermes.vault.0123"), _application_tag("default")
    assert p.window_for(vault) is None
    with p.operation_window(tmp_path, "setup"):
        window = p.window_for(vault)
        assert window is not None and window.seconds == 300 and window.scope.purpose == "setup"
        assert p.window_for(database) is window
        assert p.window_for(_application_tag("mordred-hermes.telegram.credentials.v1")) is None
        assert p.window_for(_application_tag("mordred-hermes.mail.credentials.v1")) is None
        with pytest.raises(_OpsError, match="already open"):
            p.open_window(tmp_path, "startup")
    assert p.window_for(vault) is None
    with pytest.raises(KeyError):
        p.open_window(tmp_path, "wallet")


def test_one_window_helper_serves_several_keys_and_closes_with_the_window(tmp_path, monkeypatch):
    import sys

    if sys.platform != "darwin":
        pytest.skip("macOS eligibility")
    from mordred_hermes.keyvault._seckey_helper import _HelperSecKeyOps

    made = []

    def factory(*args, **kwargs):
        channel = Channel(*args)
        made.append((channel, kwargs))
        return channel

    pool = p._PresencePool(factory=factory)
    monkeypatch.setattr(p, "_pool", pool)
    monkeypatch.setattr(p, "_ensure_monitor", lambda: None)
    calls = []
    ops = _HelperSecKeyOps("helper")
    capabilities = {"presence_session": 1, "presence_keys": 1, "presence_stores": 1}
    ops._invoke = lambda payload: calls.append(payload["cmd"]) or capabilities
    try:
        with p.operation_window(tmp_path, "startup"):
            for tag in (b"vault-key", b"database-key", b"vault-key"):
                assert ops.key_exchange(tag, b"peer") == b"\xab" * 32
            assert len(made) == 1
            channel, kwargs = made[0]
            assert kwargs == {"max_keys": p.WINDOW_KEYS, "purpose": "startup"}
            assert channel.calls == 3
            assert calls == ["capabilities"]
        assert channel.closed  # the window's end kills its helper
    finally:
        pool.close()


def test_one_window_helper_serves_keys_in_several_stores(tmp_path, monkeypatch):
    import sys

    if sys.platform != "darwin":
        pytest.skip("macOS eligibility")
    from mordred_hermes.keyvault._seckey_helper import _HelperSecKeyOps

    made = []

    def factory(*args, **kwargs):
        made.append(Channel(*args))
        return made[-1]

    pool = p._PresencePool(factory=factory)
    monkeypatch.setattr(p, "_pool", pool)
    monkeypatch.setattr(p, "_ensure_monitor", lambda: None)
    capabilities = {"presence_session": 1, "presence_keys": 1, "presence_stores": 1}
    keyvault = _HelperSecKeyOps("helper")
    keyvault._invoke = lambda payload: capabilities
    vault_store = tmp_path / "mordred" / "vault" / "sekey"
    vault = keyvault.with_store_override("MORDRED_SEKEY_STORE", vault_store)
    vault._invoke = lambda payload: capabilities
    linux = keyvault.with_store_override("MORDRED_TPMKEY_STORE", tmp_path / "tpm")
    linux._invoke = lambda payload: capabilities if payload["cmd"] == "capabilities" else {"shared_hex": "cd" * 32}
    try:
        with p.operation_window(tmp_path, "setup"):
            keyvault.key_exchange(b"keyvault-key", b"peer")
            vault.key_exchange(b"vault-key", b"peer")
            assert linux.key_exchange(b"tpm-key", b"peer") == b"\xcd" * 32  # not a Secure Enclave store: one-shot
            assert len(made) == 1  # one helper, so one Touch ID, for both stores
            (channel,) = made
            assert channel.args[1] is None  # spawned for the default store; requests name any other
            assert [payload.get("store") for payload in channel.payloads] == [None, str(vault_store)]
    finally:
        pool.close()


def test_only_a_window_names_a_store(tmp_path, monkeypatch):
    monkeypatch.setattr(p, "_ensure_monitor", lambda: None)
    pool = p._PresencePool(factory=Channel)
    credential = p._Scope(tmp_path, ("hermes", "session"), "telegram", lambda: True)
    with pytest.raises(_OpsError):
        pool.exchange(credential, "helper", None, b"telegram-key", b"peer", 300, "source", store="/elsewhere")
    pool.close()


def test_an_old_helper_keeps_one_prompt_per_key_inside_a_window(tmp_path, monkeypatch):
    import sys

    if sys.platform != "darwin":
        pytest.skip("macOS eligibility")
    from mordred_hermes.keyvault._seckey_helper import _HelperSecKeyOps

    monkeypatch.setattr(p, "_ensure_monitor", lambda: None)
    calls = []

    def invoke(payload):
        calls.append(payload["cmd"])
        if payload["cmd"] == "capabilities":
            return {"presence_session": 1}  # no presence_stores: no multi-key sessions
        return {"shared_hex": "ab" * 32}

    ops = _HelperSecKeyOps("helper")
    ops._invoke = invoke
    with p.operation_window(tmp_path, "setup"):
        ops.key_exchange(b"vault-key", b"peer")
        ops.key_exchange(b"database-key", b"peer")
    assert calls == ["capabilities", "ecdh", "ecdh"]


def test_operation_presence_is_opt_in(tmp_path):
    (tmp_path / "mordred").mkdir()
    assert not p.operation_presence_configured(tmp_path)
    (tmp_path / "mordred" / p.OPERATION_PRESENCE_MARKER).symlink_to(tmp_path / "elsewhere")
    assert not p.operation_presence_configured(tmp_path)  # a link is not the marker
    (tmp_path / "mordred" / p.OPERATION_PRESENCE_MARKER).unlink()
    p.enable_operation_presence(tmp_path)
    p.enable_operation_presence(tmp_path)  # idempotent
    assert p.operation_presence_configured(tmp_path)
    assert (tmp_path / "mordred" / p.OPERATION_PRESENCE_MARKER).stat().st_mode & 0o777 == 0o600


def test_creating_a_key_or_writing_config_keeps_a_window_but_ends_credential_sessions(tmp_path, monkeypatch):
    import sys

    if sys.platform != "darwin":
        pytest.skip("macOS eligibility")
    from mordred_hermes.keyvault._seckey_helper import _HelperSecKeyOps

    made = []

    def factory(*args, **kwargs):
        made.append(Channel(*args))
        return made[-1]

    pool = p._PresencePool(factory=factory)
    monkeypatch.setattr(p, "_pool", pool)
    monkeypatch.setattr(p, "_ensure_monitor", lambda: None)
    ops = _HelperSecKeyOps("helper")
    ops._invoke = lambda payload: (
        {"presence_session": 1, "presence_keys": 1, "presence_stores": 1}
        if payload["cmd"] == "capabilities"
        else {"public_key_hex": "04" + "ab" * 64}
    )
    credential = p._Scope(tmp_path, ("hermes", "session"), "telegram", lambda: True)
    try:
        with p.operation_window(tmp_path, "setup"):
            ops.key_exchange(b"vault-key", b"peer")
            pool.exchange(credential, "helper", None, b"telegram-key", b"peer", 300, "source")
            window_channel, credential_channel = made
            ops.create_keypair(b"new-key", "label")
            (tmp_path / "config.yaml").write_text("changed: true\n")
            pool.reap()
            assert credential_channel.closed
            assert not window_channel.closed
            ops.key_exchange(b"new-key", b"peer")
            assert len(made) == 2 and window_channel.calls == 2
        assert window_channel.closed
    finally:
        pool.close()


def _confirming_pool(monkeypatch, capabilities):
    from mordred_hermes.keyvault import _seckey_helper

    made = []

    def factory(*args, **kwargs):
        made.append(Channel(*args))
        return made[-1]

    pool = p._PresencePool(factory=factory)
    monkeypatch.setattr(p, "_pool", pool)
    monkeypatch.setattr(p, "_ensure_monitor", lambda: None)
    monkeypatch.setattr(_seckey_helper, "find_sekey_helper", lambda: "helper")
    monkeypatch.setattr(_seckey_helper, "_run_helper", lambda binary, payload, **kw: capabilities)
    return pool, made


def test_a_window_confirms_first_and_its_keys_reuse_that_touch_id(tmp_path, monkeypatch):
    import sys

    if sys.platform != "darwin":
        pytest.skip("macOS eligibility")
    from mordred_hermes.keyvault._seckey_helper import _HelperSecKeyOps

    capabilities = {"presence_session": 1, "presence_keys": 1, "presence_stores": 1, "presence_confirm": 1}
    pool, made = _confirming_pool(monkeypatch, capabilities)
    ops = _HelperSecKeyOps("helper")
    ops._invoke = lambda payload: capabilities
    try:
        with p.operation_window(tmp_path, "setup"):
            made_before = list(made)
            # The stand-in channel answers ``shared_hex``; a real helper answers ``ok``.
            with pytest.raises(_OpsError):
                p.confirm_window()
            assert made_before == [] and len(made) == 1
            assert made[0].payloads == [{"cmd": "authenticate"}]
    finally:
        pool.close()


def test_a_confirmed_window_serves_the_keys_without_another_helper(tmp_path, monkeypatch):
    import sys

    if sys.platform != "darwin":
        pytest.skip("macOS eligibility")
    from mordred_hermes.keyvault._seckey_helper import _HelperSecKeyOps

    capabilities = {"presence_session": 1, "presence_keys": 1, "presence_stores": 1, "presence_confirm": 1}
    pool, made = _confirming_pool(monkeypatch, capabilities)
    original = Channel.exchange

    def exchange(self, payload, timeout):
        reply = original(self, payload, timeout)
        return {"ok": True} if payload["cmd"] == "authenticate" else reply

    monkeypatch.setattr(Channel, "exchange", exchange)
    ops = _HelperSecKeyOps("helper")
    ops._invoke = lambda payload: capabilities
    try:
        with p.operation_window(tmp_path, "setup"):
            p.confirm_window()
            ops.key_exchange(b"keyvault-key", b"peer")
            assert len(made) == 1
            assert [payload["cmd"] for payload in made[0].payloads] == ["authenticate", "ecdh"]
    finally:
        pool.close()


@pytest.mark.parametrize(
    "capabilities",
    [{"presence_session": 1, "presence_keys": 1, "presence_stores": 1}, {"presence_session": 1}],
)
def test_a_helper_that_cannot_confirm_ahead_asks_at_first_use(tmp_path, monkeypatch, capabilities):
    import sys

    if sys.platform != "darwin":
        pytest.skip("macOS eligibility")
    pool, made = _confirming_pool(monkeypatch, capabilities)
    try:
        with p.operation_window(tmp_path, "setup"):
            p.confirm_window()
        assert made == []
    finally:
        pool.close()


def test_confirming_needs_an_open_window(monkeypatch):
    pool, made = _confirming_pool(monkeypatch, {"presence_confirm": 1, "presence_stores": 1})
    p.confirm_window()
    assert made == []
    pool.close()


def test_only_a_window_confirms_ahead(tmp_path, monkeypatch):
    monkeypatch.setattr(p, "_ensure_monitor", lambda: None)
    pool = p._PresencePool(factory=Channel)
    credential = p._Scope(tmp_path, ("hermes", "session"), "telegram", lambda: True)
    with pytest.raises(_OpsError):
        pool.exchange(credential, "helper", None, b"telegram-key", b"peer", 300, "source", confirm=True)
    pool.close()
