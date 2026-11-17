"""Drive Hermes's real tool and cron delivery, mocking only destination I/O."""

from __future__ import annotations

import asyncio
import importlib
import json
import os
import secrets
import subprocess
import sys
from contextlib import contextmanager
from threading import Thread
from types import SimpleNamespace

import pytest

from mordred_hermes.extension import crypto, e2e, gateway_plugin, pairing

SLACK = "C12345678"
DISCORD = "123456789012345678"
THREAD = "223456789012345678"
PARENT = "323456789012345678"
BODY = "private report **keep exact** 🦉"
TOKEN = "synthetic-bot-credential"


class Destination:
    def __init__(self):
        self.channels = {DISCORD: {"id": DISCORD, "type": 0}}
        self.posts = []
        self.legacy = []
        self.requests = []
        self.session_options = []
        self.fail_at = None
        self.reject = False
        self.lookup_error = False
        self.cancel = False

    def request(self, method, url, **kwargs):
        self.requests.append((method, url, kwargs))
        dest = self

        class Response:
            status = 200

            async def __aenter__(self):
                if dest.cancel:
                    raise asyncio.CancelledError
                if method == "GET" and dest.lookup_error:
                    raise RuntimeError(BODY + TOKEN)
                if method == "POST" and not url.endswith("conversations.open"):
                    dest.posts.append((url, kwargs["json"]))
                    if len(dest.posts) == dest.fail_at:
                        raise RuntimeError(BODY + TOKEN)
                return self

            async def __aexit__(self, *args):
                pass

            async def json(self, **kwargs):
                if method == "GET":
                    return dest.channels.get(url.rsplit("/", 1)[-1], {})
                if url.endswith("conversations.open"):
                    return {"ok": True, "channel": {"id": "D12345678"}}
                if dest.reject:
                    self.status = 403
                    return {"ok": False, "error": BODY + TOKEN, "message": BODY + TOKEN}
                return {"ok": True, "ts": "1785000000.000100", "id": str(len(dest.posts))}

        return Response()

    def session(self, **kwargs):
        self.session_options.append(kwargs)
        dest = self

        class Session:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *args):
                pass

            def request(self, method, url, **kw):
                return dest.request(method, url, **kw)

            def get(self, url, **kw):
                return self.request("GET", url, **kw)

            def post(self, url, **kw):
                return self.request("POST", url, **kw)

        return Session()

    async def legacy_send(self, name, config, chat_id, message, thread_id=None, media_files=None, **kwargs):
        self.legacy.append((name, chat_id, message, thread_id, media_files))
        return {"success": True, "platform": name, "chat_id": chat_id, "message_id": "legacy"}


@pytest.fixture
def delivery(monkeypatch):
    before = set(sys.modules)
    import aiohttp
    from cron import scheduler
    from gateway import config
    from gateway.platform_registry import platform_registry
    from gateway.platforms import base

    # Other suites deliberately evict modules; use the canonical module rather
    # than a stale parent-package attribute left by such an eviction.
    send = importlib.import_module("tools.send_message_tool")

    dest = Destination()
    original = send._send_to_platform
    # Restore the seam after plugin registration, which assigns it directly.
    monkeypatch.setattr(send, "_send_to_platform", original)
    monkeypatch.setattr(aiohttp, "ClientSession", dest.session)
    from mordred_hermes.network import api as network_api

    monkeypatch.setattr(network_api, "status", lambda: SimpleNamespace(active_path="clearnet", ready=True))
    real_resolve_proxy_url = base.resolve_proxy_url
    monkeypatch.setattr(base, "resolve_proxy_url", lambda **kw: None)
    monkeypatch.setattr(scheduler, "load_config", lambda: {"cron": {"wrap_response": False}})
    configs = {config.Platform(n): config.PlatformConfig(enabled=True, token=TOKEN) for n in ("slack", "discord")}
    monkeypatch.setattr(config, "load_gateway_config", lambda: config.GatewayConfig(platforms=configs))
    registry_get = platform_registry.get

    def get_entry(name):
        if name not in {"slack", "discord"}:
            return registry_get(name)

        async def sender(pconfig, chat_id, message, **kwargs):
            return await dest.legacy_send(name, pconfig, chat_id, message, **kwargs)

        return SimpleNamespace(standalone_sender_fn=sender, max_message_length=2000 if name == "discord" else 39000)

    monkeypatch.setattr(platform_registry, "get", get_entry)
    # Hermes 0.13 uses named HTTP senders instead of registry senders.
    for name in ("slack", "discord"):
        if hasattr(send, "_send_" + name):

            async def legacy(token, chat_id, message, _name=name, **kwargs):
                return await dest.legacy_send(_name, None, chat_id, message, **kwargs)

            monkeypatch.setattr(send, "_send_" + name, legacy)
    from mordred_hermes.extension.telegram import hermes_tools

    monkeypatch.setattr(hermes_tools, "register_tools", lambda ctx: None)
    ctx = SimpleNamespace(register_hook=lambda *args: None)
    gateway_plugin.register(ctx)
    e2e._ENC_THREADS.clear()
    yield SimpleNamespace(
        dest=dest,
        send=send,
        scheduler=scheduler,
        config=config,
        configs=configs,
        ctx=ctx,
        real_resolve_proxy_url=real_resolve_proxy_url,
    )
    e2e._ENC_THREADS.clear()
    for name in set(sys.modules) - before:
        if name.split(".")[0] in {"gateway", "cron", "tools", "model_tools"}:
            sys.modules.pop(name, None)


def bind(platform, channel):
    key = secrets.token_bytes(32)
    pairing.save_channel_key(f"{platform}:scope:{channel}", key)
    return key


def tool(delivery, platform, chat, body=BODY, thread=None):
    target = f"{platform}:{chat}" + (f":{thread}" if thread else "")
    return json.loads(delivery.send.send_message_tool({"target": target, "message": body}))


def decrypt_posts(dest, key, platform, chat, thread=None):
    wires = []
    for url, payload in dest.posts:
        if platform == "slack":
            assert url == "https://slack.com/api/chat.postMessage"
            assert payload["channel"] == chat
            assert payload.get("thread_ts") == thread
            assert payload["mrkdwn"] is False
            wires.append(payload["text"])
        else:
            assert url == f"https://discord.com/api/v10/channels/{chat}/messages"
            wires.append(payload["content"])
    assert wires
    assert all(len(wire) <= (2000 if platform == "discord" else 39000) for wire in wires)
    return "".join(
        crypto.decrypt_message_v3(key, wire, direction="reply", platform=platform, chat_id=chat, thread_root=thread)
        for wire in wires
    )


@pytest.mark.parametrize("platform,chat", [("slack", SLACK), ("discord", DISCORD)])
@pytest.mark.parametrize("thread", [None, THREAD])
def test_real_tool_encrypts_bound_destination(delivery, platform, chat, thread):
    if platform == "slack" and thread and not delivery.send._parse_target_ref("slack", f"{chat}:{thread}")[2]:
        pytest.skip("Hermes 0.13 tool does not accept Slack thread targets; cron/seam tests cover threads")
    key = bind(platform, chat)
    if platform == "discord" and thread:
        delivery.dest.channels[THREAD] = {"id": THREAD, "type": 11, "parent_id": chat}
    result = tool(delivery, platform, chat, thread=thread)
    assert result.get("success"), result
    assert delivery.dest.legacy == []
    assert (
        decrypt_posts(delivery.dest, key, platform, thread if platform == "discord" and thread else chat, thread)
        == BODY
    )


@pytest.mark.parametrize("platform,chat", [("slack", SLACK), ("discord", DISCORD)])
def test_real_tool_preserves_unbound_delivery(delivery, platform, chat):
    assert tool(delivery, platform, chat)["success"]
    assert delivery.dest.posts == []
    expected = (
        "private report *keep exact* 🦉" if platform == "slack" and hasattr(delivery.send, "_send_slack") else BODY
    )
    assert delivery.dest.legacy[0][1:4] == (chat, expected, None)


@contextmanager
def running_loop():
    loop = asyncio.new_event_loop()
    thread = Thread(target=loop.run_forever)
    thread.start()
    try:
        yield loop
    finally:
        loop.call_soon_threadsafe(loop.stop)
        thread.join()
        loop.close()


@pytest.mark.parametrize("platform,chat", [("slack", SLACK), ("discord", DISCORD)])
@pytest.mark.parametrize("fallback", [False, True])
def test_real_cron_encrypts_standalone_and_adapter_failure_fallback(delivery, platform, chat, fallback):
    key = bind(platform, chat)
    platform_id = delivery.config.Platform(platform)
    failures = []

    class RefusingAdapter:
        async def send(self, *args, **kwargs):
            failures.append(True)
            return SimpleNamespace(success=False, error="mordred_encrypt_unavailable")

    with running_loop() as loop:
        error = delivery.scheduler._deliver_result(
            {"id": "test", "name": "test", "deliver": f"{platform}:{chat}"},
            BODY,
            adapters={platform_id: RefusingAdapter()} if fallback else None,
            loop=loop if fallback else None,
        )
    assert error is None, error
    assert bool(failures) == fallback
    assert delivery.dest.legacy == []
    assert decrypt_posts(delivery.dest, key, platform, chat) == BODY


@pytest.mark.parametrize("thread", [None, THREAD])
def test_discord_inherits_actual_parent_without_changing_aad(delivery, thread):
    key = bind("discord", PARENT)
    delivery.dest.channels[DISCORD] = {"id": DISCORD, "type": 11, "parent_id": PARENT}
    delivery.dest.channels[THREAD] = {"id": THREAD, "type": 11, "parent_id": DISCORD}
    # Direct thread destinations have no supplied thread root; metadata threads
    # preserve that root even when the inherited key belongs to another ID.
    chat = PARENT if thread else DISCORD
    if thread:
        delivery.dest.channels[THREAD]["parent_id"] = PARENT
    assert tool(delivery, "discord", chat, thread=thread)["success"]
    assert decrypt_posts(delivery.dest, key, "discord", thread or DISCORD, thread) == BODY
    assert delivery.dest.legacy == []


def test_discord_destination_key_precedes_parent(delivery):
    key = bind("discord", DISCORD)
    bind("discord", PARENT)
    delivery.dest.channels[DISCORD] = {"id": DISCORD, "type": 11, "parent_id": PARENT}
    assert tool(delivery, "discord", DISCORD)["success"]
    assert decrypt_posts(delivery.dest, key, "discord", DISCORD) == BODY


@pytest.mark.parametrize("platform,chat", [("slack", SLACK), ("discord", DISCORD)])
@pytest.mark.parametrize("failure", ["missing_key", "conflicting_keys", "keyring_error"])
def test_key_failures_refuse_without_plaintext(delivery, monkeypatch, platform, chat, failure, caplog):
    if failure == "missing_key":
        assert e2e.mark_encrypted_thread(platform, chat, None, "unknown0")
    else:
        bind(platform, chat)
        if failure == "conflicting_keys":
            pairing.save_channel_key(f"{platform}:other:{chat}", secrets.token_bytes(32))
        else:

            def broken_keys():
                raise RuntimeError(BODY + TOKEN)

            monkeypatch.setattr(pairing, "load_channel_keys", broken_keys)
    result = tool(delivery, platform, chat)
    assert "error" in result
    assert delivery.dest.legacy == delivery.dest.posts == []
    assert BODY not in json.dumps(result) + caplog.text
    assert TOKEN not in json.dumps(result) + caplog.text


def test_ambiguous_discord_destination_never_inherits_parent(delivery):
    bind("discord", DISCORD)
    bind("discord", PARENT)
    pairing.save_channel_key(f"discord:other:{DISCORD}", secrets.token_bytes(32))
    delivery.dest.channels[DISCORD] = {"id": DISCORD, "type": 11, "parent_id": PARENT}
    assert "error" in tool(delivery, "discord", DISCORD)
    assert delivery.dest.legacy == delivery.dest.posts == []


@pytest.mark.parametrize("failure", ["lookup", "empty", "wrong_id", "missing_parent", "wrong_parent", "invalid_type"])
def test_discord_unknown_context_refuses_even_if_no_binding_known(delivery, failure):
    info = {"id": DISCORD, "type": 0}
    chat, thread = DISCORD, None
    if failure == "lookup":
        delivery.dest.lookup_error = True
    elif failure == "empty":
        info = {}
    elif failure == "wrong_id":
        info["id"] = PARENT
    elif failure == "missing_parent":
        info["type"] = 11
    elif failure == "wrong_parent":
        chat, thread = PARENT, DISCORD
        info.update(type=11, parent_id=THREAD)
    else:
        info["type"] = "0"
    delivery.dest.channels[DISCORD] = info
    result = tool(delivery, "discord", chat, thread=thread)
    assert "error" in result
    assert delivery.dest.legacy == delivery.dest.posts == []
    assert BODY not in json.dumps(result)
    assert TOKEN not in json.dumps(result)


@pytest.mark.parametrize("platform,chat", [("slack", SLACK), ("discord", DISCORD)])
@pytest.mark.parametrize("failure", ["rejected", "first_chunk", "second_chunk"])
def test_send_failure_never_delegates_and_redacts_errors(delivery, platform, chat, failure, caplog):
    key = bind(platform, chat)
    body = BODY * 2000
    delivery.dest.reject = failure == "rejected"
    delivery.dest.fail_at = {"first_chunk": 1, "second_chunk": 2}.get(failure)
    result = tool(delivery, platform, chat, body=body)
    assert "error" in result
    assert delivery.dest.legacy == []
    assert delivery.dest.posts
    # Even the failed request carried only authenticated ciphertext.
    decrypted = decrypt_posts(delivery.dest, key, platform, chat)
    assert body.startswith(decrypted)
    assert BODY not in json.dumps(result) + caplog.text
    assert TOKEN not in json.dumps(result) + caplog.text


@pytest.mark.parametrize("platform,chat", [("slack", SLACK), ("discord", DISCORD)])
def test_encrypted_multibyte_chunks_roundtrip(delivery, platform, chat):
    key = bind(platform, chat)
    body = BODY * 2000
    assert tool(delivery, platform, chat, body=body)["success"]
    assert len(delivery.dest.posts) > 1
    assert delivery.dest.legacy == []
    assert decrypt_posts(delivery.dest, key, platform, chat) == body


@pytest.mark.parametrize("platform,chat", [("slack", SLACK), ("discord", DISCORD)])
@pytest.mark.parametrize("route", ["tool", "cron"])
def test_protected_media_rejects_entire_request(delivery, tmp_path, platform, chat, route):
    bind(platform, chat)
    attachment = tmp_path / "private.txt"
    attachment.write_text("private attachment")
    body = f"{BODY}\nMEDIA:{attachment}"
    if route == "tool":
        result = tool(delivery, platform, chat, body=body)
        assert "error" in result
    else:
        error = delivery.scheduler._deliver_result({"id": "test", "deliver": f"{platform}:{chat}"}, body)
        assert error and "mordred_encrypt_attachments_unsupported" in error
    assert delivery.dest.legacy == delivery.dest.posts == []


@pytest.mark.parametrize("kind", [15, 16])
def test_protected_forum_creation_refused_before_any_post(delivery, kind):
    bind("discord", DISCORD)
    delivery.dest.channels[DISCORD]["type"] = kind
    assert "error" in tool(delivery, "discord", DISCORD)
    assert delivery.dest.legacy == delivery.dest.posts == []


def test_existing_forum_thread_can_use_parent_binding(delivery):
    key = bind("discord", DISCORD)
    delivery.dest.channels[DISCORD]["type"] = 15
    delivery.dest.channels[THREAD] = {"id": THREAD, "type": 11, "parent_id": DISCORD}
    assert tool(delivery, "discord", DISCORD, thread=THREAD)["success"]
    assert decrypt_posts(delivery.dest, key, "discord", THREAD, THREAD) == BODY


@pytest.mark.parametrize("platform,chat", [("slack", SLACK), ("discord", DISCORD)])
def test_cron_fallback_failure_never_sends_plaintext(delivery, platform, chat):
    key = bind(platform, chat)
    delivery.dest.fail_at = 2

    class RefusingAdapter:
        async def send(self, *args, **kwargs):
            return SimpleNamespace(success=False, error="mordred_encrypt_send_failed")

    with running_loop() as loop:
        error = delivery.scheduler._deliver_result(
            {"id": "test", "deliver": f"{platform}:{chat}"},
            BODY * 2000,
            adapters={delivery.config.Platform(platform): RefusingAdapter()},
            loop=loop,
        )
    assert error and "mordred_encrypt_send_failed" in error
    assert delivery.dest.legacy == []
    assert decrypt_posts(delivery.dest, key, platform, chat)


def test_guard_registration_is_idempotent(delivery):
    before = delivery.send._send_to_platform
    gateway_plugin.register(delivery.ctx)
    assert delivery.send._send_to_platform is before
    key = bind("slack", SLACK)
    assert tool(delivery, "slack", SLACK)["success"]
    assert decrypt_posts(delivery.dest, key, "slack", SLACK) == BODY
    assert len(delivery.dest.posts) == 1


@pytest.mark.parametrize("failure", ["missing", "sync", "signature", "import"])
def test_registration_refuses_unprotectable_send_seam(delivery, monkeypatch, failure):
    from mordred_hermes.extension import standalone_outbound

    if failure == "missing":
        monkeypatch.delattr(delivery.send, "_send_to_platform")
    elif failure == "import":
        real_import = standalone_outbound.importlib.import_module

        def unavailable(name, *args, **kwargs):
            if name == "tools.send_message_tool":
                raise ImportError(BODY + TOKEN)
            return real_import(name, *args, **kwargs)

        monkeypatch.setattr(standalone_outbound.importlib, "import_module", unavailable)
    elif failure == "sync":
        monkeypatch.setattr(delivery.send, "_send_to_platform", lambda *args, **kwargs: None)
    else:

        async def incompatible(platform, config, chat_id, message):
            pass

        monkeypatch.setattr(delivery.send, "_send_to_platform", incompatible)
    with pytest.raises(standalone_outbound.StandaloneGuardRefused) as caught:
        gateway_plugin.register(delivery.ctx)
    assert not isinstance(caught.value, Exception)
    assert BODY not in str(caught.value)
    assert TOKEN not in str(caught.value)


def test_other_platform_preserves_all_arguments_and_result(delivery, monkeypatch):
    from mordred_hermes.extension import standalone_outbound

    calls = []
    result = {"success": True, "warnings": ["original"]}

    async def original(platform, pconfig, chat_id, message, thread_id=None, media_files=None, force_document=False):
        calls.append((platform, pconfig, chat_id, message, thread_id, media_files, force_document))
        return result

    monkeypatch.setattr(delivery.send, "_send_to_platform", original)
    standalone_outbound.install_standalone_guard()
    config, media = object(), [("file", False)]
    actual = asyncio.run(delivery.send._send_to_platform("other", config, "chat", BODY, "thread", media, True))
    assert actual is result
    assert calls == [("other", config, "chat", BODY, "thread", media, True)]
    assert delivery.dest.requests == []


@pytest.mark.parametrize("platform,chat", [("slack", SLACK), ("discord", DISCORD)])
def test_routing_failure_refuses_before_destination_io(delivery, monkeypatch, platform, chat):
    from mordred_hermes.extension import egress

    bind(platform, chat)

    def unavailable(host, **kwargs):
        raise egress.EgressError()

    monkeypatch.setattr(egress, "resolve_route", unavailable)
    assert "error" in tool(delivery, platform, chat)
    assert delivery.dest.requests == delivery.dest.posts == delivery.dest.legacy == []


def test_tor_route_uses_remote_dns_without_ambient_proxy(delivery, monkeypatch):
    from aiohttp_socks import ProxyConnector
    from gateway.platforms import base

    from mordred_hermes.network import api as network_api

    bind("slack", SLACK)
    monkeypatch.setattr(network_api, "status", lambda: SimpleNamespace(active_path="tor", ready=True))
    monkeypatch.setattr(network_api, "is_dropped", lambda: False)
    monkeypatch.setattr(base, "resolve_proxy_url", lambda **kw: "socks5h://user:password@127.0.0.1:9050")
    connector = object()
    calls = []

    def build(url, **kwargs):
        calls.append((url, kwargs))
        return connector

    monkeypatch.setattr(ProxyConnector, "from_url", build)
    assert tool(delivery, "slack", SLACK)["success"]
    assert calls == [("socks5://user:password@127.0.0.1:9050", {"rdns": True})]
    assert delivery.dest.session_options[0]["connector"] is connector
    assert delivery.dest.session_options[0]["trust_env"] is False
    assert delivery.dest.requests[0][2]["allow_redirects"] is False


@pytest.mark.parametrize("platform,chat", [("slack", SLACK), ("discord", DISCORD)])
def test_cancellation_does_not_become_success_or_plaintext(delivery, platform, chat):
    bind(platform, chat)
    delivery.dest.cancel = True
    with pytest.raises(asyncio.CancelledError):
        asyncio.run(
            delivery.send._send_to_platform(
                delivery.config.Platform(platform), delivery.configs[delivery.config.Platform(platform)], chat, BODY
            )
        )
    assert delivery.dest.legacy == []


@pytest.mark.parametrize("platform,chat", [("slack", SLACK), ("discord", DISCORD)])
def test_real_cron_thread_preserves_context(delivery, platform, chat):
    key = bind(platform, chat)
    if platform == "discord":
        delivery.dest.channels[THREAD] = {"id": THREAD, "type": 11, "parent_id": chat}
    error = delivery.scheduler._deliver_result(
        {"id": "test", "deliver": "origin", "origin": {"platform": platform, "chat_id": chat, "thread_id": THREAD}},
        BODY,
    )
    assert error is None, error
    assert delivery.dest.legacy == []
    assert decrypt_posts(delivery.dest, key, platform, THREAD if platform == "discord" else chat, THREAD) == BODY


@pytest.mark.parametrize("imports_first", [False, True])
def test_registration_protects_both_sender_module_import_orders(tmp_path, imports_first):
    script = """
import asyncio
from types import SimpleNamespace
from mordred_hermes.extension import gateway_plugin, pairing
from mordred_hermes.extension.telegram import hermes_tools
hermes_tools.register_tools = lambda ctx: None
if IMPORTS_FIRST:
    from tools import send_message_tool
    from cron import scheduler
gateway_plugin.register(SimpleNamespace(register_hook=lambda *args: None))
from tools import send_message_tool
from cron import scheduler
from gateway.config import Platform, PlatformConfig
assert send_message_tool._send_to_platform.__mordred_standalone_guard__
pairing.save_channel_key("slack:scope:C12345678", b"k" * 32)
result = asyncio.run(send_message_tool._send_to_platform(
    Platform.SLACK, PlatformConfig(enabled=True, token="synthetic"),
    "C12345678", "secret", media_files=[("private.txt", False)]))
assert result == {"error": "mordred_encrypt_attachments_unsupported"}, result
""".replace("IMPORTS_FIRST", str(imports_first))
    result = subprocess.run(
        [sys.executable, "-c", script],
        env={**os.environ, "HERMES_HOME": str(tmp_path)},
        capture_output=True,
        text=True,
        timeout=45,
    )
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize(
    "path,ready,proxy",
    [
        ("tor", True, None),
        ("tor", True, "socks5://remote.invalid:9050"),
        ("tor", True, "http://127.0.0.1:8080"),
        ("tor", False, "socks5://127.0.0.1:9050"),
        ("vpn", False, None),
    ],
)
def test_unverified_protected_network_never_opens_session(delivery, monkeypatch, path, ready, proxy):
    from gateway.platforms import base

    from mordred_hermes.network import api as network_api

    bind("discord", DISCORD)
    monkeypatch.setattr(network_api, "status", lambda: SimpleNamespace(active_path=path, ready=ready))
    monkeypatch.setattr(network_api, "is_dropped", lambda: False)
    monkeypatch.setattr(base, "resolve_proxy_url", lambda **kw: proxy)
    assert "error" in tool(delivery, "discord", DISCORD)
    assert delivery.dest.session_options == delivery.dest.legacy == []


def test_cron_slack_user_checks_resolved_dm_binding(delivery):
    key = bind("slack", "D12345678")
    platform = delivery.config.Platform.SLACK
    result = asyncio.run(delivery.send._send_to_platform(platform, delivery.configs[platform], "U12345678", BODY))
    assert result.get("success"), result
    assert decrypt_posts(delivery.dest, key, "slack", "D12345678") == BODY
    assert delivery.dest.legacy == []


@pytest.mark.parametrize("protected", [False, True])
def test_discord_preserves_platform_proxy_for_lookup_and_ciphertext(delivery, monkeypatch, protected):
    from gateway.platforms import base

    proxy = "http://synthetic-user:synthetic-password@127.0.0.1:18080"
    for name in (
        "HTTPS_PROXY",
        "HTTP_PROXY",
        "ALL_PROXY",
        "NO_PROXY",
        "https_proxy",
        "http_proxy",
        "all_proxy",
        "no_proxy",
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("DISCORD_PROXY", proxy)
    monkeypatch.setattr(base, "resolve_proxy_url", delivery.real_resolve_proxy_url)
    monkeypatch.setattr(base, "_detect_macos_system_proxy", lambda: None)
    if protected:
        bind("discord", DISCORD)
    assert tool(delivery, "discord", DISCORD)["success"]
    assert delivery.dest.requests
    assert all(kwargs.get("proxy") == proxy for _method, _url, kwargs in delivery.dest.requests)
    assert len(delivery.dest.posts) == int(protected)
