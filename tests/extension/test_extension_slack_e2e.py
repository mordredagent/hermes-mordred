"""Tests for Hermes-side Slack E2E outbound encryption (reply-in-kind).

See Mordred-Extension/SPEC.ja.md §4 and mordred-docs/dev/SLACK_E2E.md.
Covers the module-level helpers; the SlackAdapter.send wiring is exercised
indirectly via these (the network call is out of scope for a unit test).
"""

from __future__ import annotations

import importlib

import pytest

from gateway.extension_crypto import decrypt_message, is_encrypted

slack = importlib.import_module("gateway.platforms.slack")

KEY = bytes(range(32))
MAX = 39000


@pytest.fixture(autouse=True)
def _clear_registry():
    slack._MORDRED_ENC_THREADS.clear()
    yield
    slack._MORDRED_ENC_THREADS.clear()


# --- reply encryption (body-only, leading mentions plaintext) ----------------

def test_encrypt_reply_keeps_leading_mention_plaintext():
    out = slack._mordred_encrypt_reply(KEY, "<@U0BA5N3QFR9> 了解、テスト", MAX)
    assert len(out) == 1
    assert out[0].startswith("<@U0BA5N3QFR9> ")
    token = out[0].split(" ", 1)[1]
    assert is_encrypted(token)
    assert decrypt_message(KEY, token) == "了解、テスト"


def test_encrypt_reply_no_mention_encrypts_whole_body():
    out = slack._mordred_encrypt_reply(KEY, "ただの返信", MAX)
    assert len(out) == 1
    assert is_encrypted(out[0])
    assert decrypt_message(KEY, out[0]) == "ただの返信"


def test_encrypt_reply_only_mention_stays_plaintext():
    # No secret body → nothing to encrypt.
    assert slack._mordred_encrypt_reply(KEY, "<@U1>", MAX) == ["<@U1>"]


def test_encrypt_reply_long_body_splits_into_decryptable_chunks():
    body = "あ" * 60000
    out = slack._mordred_encrypt_reply(KEY, body, MAX)
    assert len(out) > 1
    joined = "".join(decrypt_message(KEY, c) for c in out)
    assert joined == body
    # Every chunk is an independent ciphertext blob.
    assert all(is_encrypted(c) for c in out)


# --- reply-in-kind registry --------------------------------------------------

def test_registry_marks_and_matches_thread():
    slack._mordred_mark_encrypted_thread("C1", "1700000000.0001")
    assert slack._mordred_is_encrypted_thread("C1", "1700000000.0001") is True
    assert slack._mordred_is_encrypted_thread("C1", "other") is False
    assert slack._mordred_is_encrypted_thread("C2", "1700000000.0001") is False


def test_registry_none_thread_matches_top_level():
    slack._mordred_mark_encrypted_thread("D1", None)
    assert slack._mordred_is_encrypted_thread("D1", None) is True


def test_registry_expires():
    slack._mordred_mark_encrypted_thread("C9", "t")
    slack._MORDRED_ENC_THREADS[("C9", "t")] = 1.0  # force-expire (epoch past)
    assert slack._mordred_is_encrypted_thread("C9", "t") is False


# --- inbound decryption (token anywhere; mention-exclusion aware) -------------

def _patch_pairing(monkeypatch):
    from types import SimpleNamespace

    import gateway.extension_pairing as ep

    monkeypatch.setattr(ep, "load_pairing", lambda: SimpleNamespace(aes_key=KEY))


def test_inbound_decrypts_token_after_leading_mention(monkeypatch):
    _patch_pairing(monkeypatch)
    from gateway.extension_crypto import encrypt_message

    ct = encrypt_message(KEY, "今動いてる？")
    # Slack delivers "<@U…> 🔒ENC:v1:…" once the extension keeps the mention plaintext.
    assert slack._extension_decrypt_inbound(f"<@U1> {ct}") == "<@U1> 今動いてる？"


def test_inbound_decrypts_whole_message(monkeypatch):
    _patch_pairing(monkeypatch)
    from gateway.extension_crypto import encrypt_message

    ct = encrypt_message(KEY, "本文だけ")
    assert slack._extension_decrypt_inbound(ct) == "本文だけ"


def test_inbound_plaintext_returns_none(monkeypatch):
    _patch_pairing(monkeypatch)
    assert slack._extension_decrypt_inbound("ただの平文") is None


def test_inbound_fail_open_without_pairing(monkeypatch):
    import gateway.extension_pairing as ep

    monkeypatch.setattr(ep, "load_pairing", lambda: None)
    from gateway.extension_crypto import encrypt_message

    ct = encrypt_message(KEY, "x")
    assert slack._extension_decrypt_inbound(f"<@U1> {ct}") is None
