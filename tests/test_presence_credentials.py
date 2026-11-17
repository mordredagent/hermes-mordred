"""Exercise real custody, wrapping and AES decryption with only native IPC faked."""

from __future__ import annotations

import sys

import pytest

from mordred_hermes.keyvault import _presence as p
from tests.test_posix_telegram_custody import native_store, value

pytestmark = pytest.mark.skipif(sys.platform != "darwin", reason="macOS presence adapter")


@pytest.mark.parametrize("purpose", ["telegram", "mail"])
def test_presence_only_is_reused_and_replacement_requires_new_authentication(tmp_path, monkeypatch, purpose):
    if purpose == "telegram":
        store, native = native_store(tmp_path)
        credentials = value()
    else:
        from tests._mail_sync_helpers import generic_creds
        from tests.test_mail_cross_platform_storage import native_store as mail_store

        store, native = mail_store(tmp_path)
        credentials = generic_creds()
    store.ensure_key()
    store.store(credentials)
    (tmp_path / "config.yaml").write_text("plugins:\n  mordred_keyvault:\n    presence_reuse_seconds: 300\n")
    prompts, channels, now = [], [], [0.0]
    log = []
    store._audit_sink = log.append
    original = native.invoke

    def invoke(payload):
        if payload["cmd"] == "capabilities":
            return {"presence_session": 1}
        return original(payload)

    native.ops._invoke = invoke

    class Channel:
        def __init__(self, *args):
            self.closed = False
            prompts.append(1)
            channels.append(self)

        def exchange(self, payload, timeout):
            return original(payload)

        def close(self):
            self.closed = True

        def alive(self):
            return not self.closed

    pool = p._PresencePool(factory=Channel, clock=lambda: now[0])
    monkeypatch.setattr(p, "_pool", pool)
    try:
        for moment in (0, 10, 299):
            now[0] = moment
            with p.presence_scope(tmp_path, ("hermes", "framework-session"), purpose):
                assert store.load() == credentials
        assert len(prompts) == 1
        assert native.ecdh_calls == 3
        assert sum(e["reason"] == "keyvault.unwrap_authorized" for e in log) == 3
        # Even identical bytes installed with a new source identity revoke reuse.
        source = store.sealed_path
        replacement = source.with_suffix(".replacement")
        replacement.write_bytes(source.read_bytes())
        replacement.chmod(0o600)
        replacement.replace(source)
        with p.presence_scope(tmp_path, ("hermes", "framework-session"), purpose):
            assert store.load() == credentials
        assert channels[0].closed and len(prompts) == 2
        # Plain CLI/administrative calls still perform their own one-shot ECDH.
        assert store.load() == credentials
        assert native.ecdh_calls == 5
    finally:
        pool.close()
