"""First automated coverage for :mod:`mordred_hermes.extension.outbound`
(reply-in-kind E2E encryption on the *send* path, SPEC-v2 §4).

Exercises the real ``e2e``/``pairing``/``crypto`` keyring machinery (an
isolated ``HERMES_HOME``, no crypto mocking) against fake Slack/Discord
adapter objects that only expose the attributes ``_wrap_slack`` /
``_wrap_discord`` / ``_slack_encrypted_send`` / ``_discord_encrypted_send``
actually touch -- mirroring ``scripts/poc_outbound_roundtrip.py``. No network,
no ``slack_sdk``/``discord.py`` import: ``install_outbound_patches()`` locates
the real platform adapter classes via ``importlib.import_module`` against
``gateway.platforms.*`` / ``plugins.platforms.*``, which may or may not be
installed depending on which hermes-agent extras are present (CI installs
fewer extras than ``--all-extras``); wrapping a fake class directly, exactly
like the PoC, keeps these tests deterministic regardless of that.

Uses ``asyncio.run`` rather than pytest-asyncio (not a project dependency),
matching ``tests/extension/test_extension_api_server.py``.
"""

from __future__ import annotations

import asyncio
import secrets
import sys
from enum import Enum
from types import SimpleNamespace

import pytest

from mordred_hermes.extension import crypto, e2e, gateway_plugin, outbound, pairing


@pytest.fixture(autouse=True)
def _isolated_home(tmp_path, monkeypatch):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))


@pytest.fixture(autouse=True)
def _no_gateway_import_leak():
    """``outbound._SendResult()`` does a real ``from gateway.platforms.base
    import SendResult`` (the only part of ``gateway.*`` these tests actually
    need), which permanently caches ``gateway``/``gateway.platforms``/
    ``gateway.platforms.base`` in ``sys.modules`` for the rest of the pytest
    process. That breaks ``tests/extension/test_extension_rpc.py``, which
    relies on ``monkeypatch.setitem(sys.modules, "gateway", None)`` to
    *simulate* gateway being unimportable -- Python's import fast path
    returns an already-cached ``gateway.platforms.base`` without ever
    re-checking the (monkeypatched-None) ``gateway`` entry, silently
    defeating that test. Snapshot sys.modules before each test here and
    remove only the ``gateway*`` keys THIS test added, so later test files
    see a clean slate."""
    before = {k for k in sys.modules if k == "gateway" or k.startswith("gateway.")}
    yield
    for k in [k for k in sys.modules if (k == "gateway" or k.startswith("gateway.")) and k not in before]:
        del sys.modules[k]


def _seed_master_key() -> bytes:
    key = secrets.token_bytes(32)
    pairing._save_pairing(
        pairing.Pairing(aes_key=key, ext_token="t", ext_pubkey_b64="", hermes_pubkey_b64="", paired_at=0.0)
    )
    return key


# --------------------------------------------------------------------------- #
# Slack fakes (mirrors scripts/poc_outbound_roundtrip.py's FakeSlackAdapter)
# --------------------------------------------------------------------------- #


class FakeSlackClient:
    def __init__(self) -> None:
        self.posts: list[dict] = []

    async def chat_postMessage(self, **kw):
        self.posts.append(kw)
        return {"ts": f"ts{len(self.posts)}"}


class FakeSlackAdapter:
    """Minimal stand-in exposing the attributes ``_wrap_slack`` /
    ``_slack_encrypted_send`` touch."""

    MAX_MESSAGE_LENGTH = 3000

    def __init__(self) -> None:
        self._app = object()
        self._client = FakeSlackClient()
        self._bot_message_ts: set[str] = set()

    def _get_client(self, chat_id):
        return self._client

    def _resolve_thread_ts(self, reply_to, metadata):
        return (metadata or {}).get("thread_ts")

    async def stop_typing(self, chat_id):
        return None

    # The ORIGINAL plaintext send. The wrapper must NOT call this for an
    # encrypted thread -- if it does, the fake records the leak so the
    # assertion can detect it.
    async def send(self, chat_id, content, reply_to=None, metadata=None):
        self._client.posts.append({"channel": chat_id, "text": content, "PLAINTEXT_LEAK": True})
        return SimpleNamespace(success=True)


outbound._wrap_slack(FakeSlackAdapter)


def test_slack_reply_into_encrypted_thread_is_ciphertext():
    """Reply into a known-encrypted thread: wire text is ciphertext (starts
    with the v2 ENC marker), plaintext never appears in the fake's sent
    payloads, and thread_ts propagates onto every posted message."""
    _seed_master_key()
    chan_key = secrets.token_bytes(32)
    pairing.save_channel_key("C-outbound-1", chan_key)
    kid = crypto.key_id(chan_key)
    chat_id, thread_ts = "C-outbound-1", "1710000001.0001"
    e2e.mark_encrypted_thread("slack", chat_id, thread_ts, kid)

    adapter = FakeSlackAdapter()
    reply = "roger — deploying now"
    res = asyncio.run(adapter.send(chat_id, reply, metadata={"thread_ts": thread_ts}))

    posts = adapter._client.posts
    assert posts, "expected at least one chat_postMessage call"
    assert not any(p.get("PLAINTEXT_LEAK") for p in posts)  # never fell back to the plaintext send
    for p in posts:
        assert reply not in p["text"]
        assert p["text"].startswith(crypto.ENC_PREFIX_V2)
        assert p["thread_ts"] == thread_ts
        assert p["mrkdwn"] is False  # ciphertext must never be rendered as markdown

    # Round-trips back via the real inbound decrypt path.
    joined = " ".join(p["text"] for p in posts)
    back, _ = e2e.decrypt_inbound_keyed(joined)
    assert back is not None
    assert reply in back
    assert res.success is True


def test_slack_reply_into_encrypted_thread_without_a_key_sends_locked_notice():
    """Thread is known-encrypted but no key can be found (no channel key, no
    master pairing): the fail-closed path posts the locked notice instead of
    ever calling the plaintext send."""
    chat_id, thread_ts = "C-outbound-2", "1710000002.0002"
    e2e.mark_encrypted_thread("slack", chat_id, thread_ts)  # marked encrypted; no pairing/keys seeded

    adapter = FakeSlackAdapter()
    secret = "do not leak this"
    res = asyncio.run(adapter.send(chat_id, secret, metadata={"thread_ts": thread_ts}))

    posts = adapter._client.posts
    assert not any(p.get("PLAINTEXT_LEAK") for p in posts)  # never fell back to the plaintext send
    assert len(posts) == 1
    assert posts[0]["text"] == outbound._LOCKED_NOTICE
    assert posts[0]["thread_ts"] == thread_ts
    assert secret not in posts[0]["text"]
    assert res.success is False
    assert res.error == "mordred_encrypt_unavailable"


def test_slack_reply_into_unmarked_thread_passes_through_plaintext():
    """A thread never marked encrypted must go through the ORIGINAL send
    unmodified, even when a pairing/master key exists."""
    _seed_master_key()
    adapter = FakeSlackAdapter()
    reply = "plain reply, no encryption needed"
    res = asyncio.run(adapter.send("C-outbound-3", reply, metadata={"thread_ts": "1710000003.0003"}))

    posts = adapter._client.posts
    assert len(posts) == 1
    assert posts[0]["PLAINTEXT_LEAK"] is True  # went through the unmodified original send
    assert posts[0]["text"] == reply
    assert res.success is True


# --------------------------------------------------------------------------- #
# Discord fakes
# --------------------------------------------------------------------------- #


class FakeDiscordChannel:
    def __init__(self, cid: int, parent_id: int | None = None) -> None:
        self.id = cid
        self.parent_id = parent_id
        self.sent: list[str] = []

    async def send(self, content: str):
        self.sent.append(content)
        return SimpleNamespace(id=len(self.sent))


class FakeDiscordClient:
    def __init__(self) -> None:
        self.channels: dict[int, FakeDiscordChannel] = {}

    def add_channel(self, chat_id: str, parent_id: str | None = None) -> FakeDiscordChannel:
        ch = FakeDiscordChannel(int(chat_id), int(parent_id) if parent_id else None)
        self.channels[ch.id] = ch
        return ch

    def get_channel(self, cid: int):
        return self.channels.get(cid)

    async def fetch_channel(self, cid: int):
        return self.channels.get(cid)


class FakeDiscordAdapter:
    """Minimal stand-in exposing the attributes ``_wrap_discord`` /
    ``_discord_encrypted_send`` touch."""

    MAX_MESSAGE_LENGTH = 2000

    def __init__(self, client: FakeDiscordClient) -> None:
        self._client = client

    # The ORIGINAL plaintext send. The wrapper must NOT call this for an
    # encrypted channel/thread -- if it does, the fake records the leak.
    async def send(self, chat_id, content, reply_to=None, metadata=None):
        channel = self._client.channels[int(chat_id)]
        channel.sent.append(f"PLAINTEXT_LEAK:{content}")
        return SimpleNamespace(success=True)


outbound._wrap_discord(FakeDiscordAdapter)


def test_discord_reply_into_encrypted_channel_is_ciphertext():
    """Reply into a known-encrypted channel: wire text is ciphertext, and
    plaintext never appears in the fake channel's sent payloads."""
    _seed_master_key()
    chan_key = secrets.token_bytes(32)
    chat_id = "911001"
    pairing.save_channel_key(chat_id, chan_key)
    kid = crypto.key_id(chan_key)
    e2e.mark_encrypted_thread("discord", chat_id, None, kid)

    client = FakeDiscordClient()
    client.add_channel(chat_id)
    adapter = FakeDiscordAdapter(client)
    reply = "shipped"
    res = asyncio.run(adapter.send(chat_id, reply, metadata={}))

    channel = client.channels[int(chat_id)]
    assert channel.sent
    assert not any(m.startswith("PLAINTEXT_LEAK:") for m in channel.sent)
    for m in channel.sent:
        assert reply not in m
        assert crypto.is_encrypted(m)

    joined = " ".join(channel.sent)
    back, _ = e2e.decrypt_inbound_keyed(joined)
    assert back is not None
    assert reply in back
    assert res.success is True


def test_discord_reply_into_encrypted_channel_without_a_key_fails_closed():
    """Channel is known-encrypted but no key exists at all: Discord has no
    locked-notice message (unlike Slack) -- fail-closed means NOTHING is
    sent, plaintext included."""
    chat_id = "911002"
    e2e.mark_encrypted_thread("discord", chat_id, None)  # marked encrypted; no pairing/keys seeded

    client = FakeDiscordClient()
    client.add_channel(chat_id)
    adapter = FakeDiscordAdapter(client)
    res = asyncio.run(adapter.send(chat_id, "do not leak this", metadata={}))

    channel = client.channels[int(chat_id)]
    assert channel.sent == []  # nothing posted at all
    assert res.success is False
    assert res.error == "mordred_encrypt_unavailable"


def test_discord_reply_into_unmarked_channel_passes_through_plaintext():
    """A channel never marked encrypted must go through the ORIGINAL send
    unmodified, even when a pairing/master key exists."""
    _seed_master_key()
    chat_id = "911003"
    client = FakeDiscordClient()
    client.add_channel(chat_id)
    adapter = FakeDiscordAdapter(client)
    reply = "plain discord reply"
    res = asyncio.run(adapter.send(chat_id, reply, metadata={}))

    channel = client.channels[int(chat_id)]
    assert channel.sent == [f"PLAINTEXT_LEAK:{reply}"]
    assert res.success is True


def test_discord_reply_in_thread_finds_key_via_parent_channel_lookup():
    """Multi-id key lookup path: a message replied straight into a Discord
    *thread* whose own encrypted-mark carries no key id -- the real
    per-channel key lives under the PARENT channel's id instead (threads
    inherit the parent's key, per ``_discord_encrypted_send``'s comment).
    Proves the lookup tries more than just the direct id."""
    thread_id, parent_id = "911004", "911005"
    # A pairing must exist for decrypt_inbound_keyed's round-trip check below
    # (it bails out early with no pairing at all) -- but its key must differ
    # from the channel key, so the assertions below can tell "found the real
    # per-channel key via the parent lookup" apart from any accidental use of
    # the master key.
    master_key = _seed_master_key()
    chan_key = secrets.token_bytes(32)
    pairing.save_channel_key(parent_id, chan_key)
    kid = crypto.key_id(chan_key)
    assert kid != crypto.key_id(master_key)
    e2e.mark_encrypted_thread("discord", thread_id, None)  # gate passes; no kid of its own
    e2e.mark_encrypted_thread("discord", parent_id, None, kid)  # real key lives here

    client = FakeDiscordClient()
    client.add_channel(thread_id, parent_id=parent_id)
    adapter = FakeDiscordAdapter(client)
    reply = "resolved in the thread"
    res = asyncio.run(adapter.send(thread_id, reply, metadata={}))

    channel = client.channels[int(thread_id)]
    assert channel.sent
    assert not any(m.startswith("PLAINTEXT_LEAK:") for m in channel.sent)
    for m in channel.sent:
        assert reply not in m
        assert crypto.is_encrypted(m)
        # The wire token must be keyed by the CHANNEL key's fingerprint, not
        # the master key's -- proves the parent-id lookup actually found the
        # per-channel key rather than reply_key() falling back to the master.
        _ver, wire_kid, _nonce, _ct = crypto.parse_token(m)
        assert wire_kid == kid

    joined = " ".join(channel.sent)
    back, _ = e2e.decrypt_inbound_keyed(joined)
    assert back is not None
    assert reply in back
    assert res.success is True


# --------------------------------------------------------------------------- #
# Full inbound-hook -> live-adapter regressions
# --------------------------------------------------------------------------- #


class FakePlatform(Enum):
    """Match Hermes' ``Platform`` enum string/value behaviour."""

    SLACK = "slack"
    DISCORD = "discord"


def test_slack_enum_inbound_then_thread_reply_stays_encrypted():
    """Reproduce the live Slack path end to end.

    The inbound hook receives ``Platform.SLACK`` (whose ``str()`` is not
    ``"slack"``), wraps the gateway's live adapter, decrypts a top-level
    message, and the gateway replies in a newly-created Slack thread. The
    reply must still take the ciphertext path.
    """
    _seed_master_key()
    chan_key = secrets.token_bytes(32)
    chat_id, reply_thread = "C-live-slack", "1710000099.0001"
    pairing.save_channel_key(chat_id, chan_key)
    kid = crypto.key_id(chan_key)

    class LiveSlackAdapter:
        MAX_MESSAGE_LENGTH = 3000

        def __init__(self) -> None:
            self._app = object()
            self._client = FakeSlackClient()
            self._bot_message_ts: set[str] = set()

        def _get_client(self, _chat_id):
            return self._client

        def _resolve_thread_ts(self, _reply_to, metadata):
            return (metadata or {}).get("thread_ts")

        async def stop_typing(self, _chat_id):
            return None

        async def send(self, target, content, reply_to=None, metadata=None):
            self._client.posts.append({"channel": target, "text": content, "PLAINTEXT_LEAK": True})
            return SimpleNamespace(success=True)

    adapter = LiveSlackAdapter()
    gateway = SimpleNamespace(adapters={FakePlatform.SLACK: adapter})
    request = "private slack question"
    event = SimpleNamespace(
        text=crypto.encrypt_message_v2(chan_key, request, kid),
        source=SimpleNamespace(platform=FakePlatform.SLACK, chat_id=chat_id, thread_id=None),
    )

    hook_result = gateway_plugin.pre_gateway_dispatch(event=event, gateway=gateway)
    assert hook_result == {"action": "rewrite", "text": request}

    answer = "private slack answer"
    result = asyncio.run(adapter.send(chat_id, answer, metadata={"thread_ts": reply_thread}))

    posts = adapter._client.posts
    assert posts
    assert not any(post.get("PLAINTEXT_LEAK") for post in posts)
    assert all(answer not in post["text"] and crypto.is_encrypted(post["text"]) for post in posts)
    decrypted, _ = e2e.decrypt_inbound_keyed(" ".join(post["text"] for post in posts))
    assert decrypted == answer
    assert result.success is True


def test_discord_thread_inbound_then_reply_stays_encrypted():
    """Reproduce Hermes' live Discord auto-thread shape end to end.

    Discord represents an auto-threaded inbound event with ``chat_id`` and
    ``thread_id`` both set to the thread snowflake. The outbound adapter gets
    the same thread in ``metadata``. The registry lookup must retain that
    thread root instead of replacing it with ``None``.
    """
    _seed_master_key()
    chan_key = secrets.token_bytes(32)
    thread_id, parent_id = "922001", "922000"
    pairing.save_channel_key(parent_id, chan_key)
    kid = crypto.key_id(chan_key)

    class LiveDiscordAdapter:
        MAX_MESSAGE_LENGTH = 2000

        def __init__(self, client) -> None:
            self._client = client

        async def send(self, chat_id, content, reply_to=None, metadata=None):
            target = str((metadata or {}).get("thread_id") or chat_id)
            self._client.channels[int(target)].sent.append(f"PLAINTEXT_LEAK:{content}")
            return SimpleNamespace(success=True)

    client = FakeDiscordClient()
    channel = client.add_channel(thread_id, parent_id=parent_id)
    adapter = LiveDiscordAdapter(client)
    gateway = SimpleNamespace(adapters={FakePlatform.DISCORD: adapter})
    request = "private discord question"
    event = SimpleNamespace(
        text=crypto.encrypt_message_v2(chan_key, request, kid),
        source=SimpleNamespace(
            platform=FakePlatform.DISCORD,
            chat_id=thread_id,
            thread_id=thread_id,
            parent_chat_id=parent_id,
        ),
    )

    hook_result = gateway_plugin.pre_gateway_dispatch(event=event, gateway=gateway)
    assert hook_result == {"action": "rewrite", "text": request}

    answer = "private discord answer"
    result = asyncio.run(adapter.send(thread_id, answer, metadata={"thread_id": thread_id}))

    assert channel.sent
    assert not any(message.startswith("PLAINTEXT_LEAK:") for message in channel.sent)
    assert all(answer not in message and crypto.is_encrypted(message) for message in channel.sent)
    decrypted, _ = e2e.decrypt_inbound_keyed(" ".join(channel.sent))
    assert decrypted == answer
    assert result.success is True
