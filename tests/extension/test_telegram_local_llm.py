"""Saved local LLM configuration exercised through the real Telegram service and HTTP."""

from __future__ import annotations

import asyncio
import errno
import json
import logging
import socket
import time
from dataclasses import replace
from types import SimpleNamespace

import aiohttp
import pytest

from mordred_hermes.extension.telegram import hermes_tools, secrets, service, store
from tests.extension.local_llm_server import LocalLlmServer


class MemorySecrets:
    """Only custody is substituted; serialization, archive and transport remain real."""

    def __init__(self, endpoint: str) -> None:
        self.value = secrets.TelegramSecrets(
            api_id=1,
            api_hash="ab" * 16,
            store_key=b"\x05" * 32,
            backend="local",
            local_endpoint=endpoint,
            local_model="synthetic-model",
        )

    def load(self, *, fresh: bool = True):
        assert fresh
        return secrets.decode(secrets.encode(self.value))

    def update(self, mutate):
        self.value = secrets.decode(secrets.encode(mutate(self.value)))
        return self.value


@pytest.fixture
def ask_local(tmp_path, monkeypatch):
    archive = store.ArchiveStore(b"\x05" * 32, tmp_path / "archive")
    archive.append_messages(
        -5, [store.StoredMessage(id=1, date=1, sender="Carol", text="PRIVATE-MESSAGE budget moved")]
    )
    archive.save_index(store.ArchiveIndex(dialogs={-5: store.DialogInfo(-5, "group", "Finance", message_count=1)}))
    events = []
    original_audit = service._audit
    monkeypatch.setattr(
        service,
        "_audit",
        lambda event, decision, **fields: events.append({"event": event, "decision": decision, **fields}),
    )

    def run(endpoint, *, timeout=2, credentials=None, real_audit=False):
        if real_audit:
            monkeypatch.setattr(service, "_audit", original_audit)
        vault = credentials or MemorySecrets(endpoint)
        svc = service.TelegramService(
            secret_store=vault,
            archive_root=tmp_path / "archive",
            policy_check=lambda _b, _u: None,
            http_session_factory=lambda route, _timeout: service._default_http_session(route, timeout),
        )
        monkeypatch.setattr(hermes_tools, "_service", lambda: svc)
        result = asyncio.run(
            hermes_tools.telegram_ask(
                {"question": "budget?", "chat_ids": [-5]},
                parent_agent=SimpleNamespace(model="reader", base_url="http://127.0.0.1:1234/v1"),
            )
        )
        return json.loads(result), events

    return run


def test_failed_audit_does_not_log_transport_exception_secrets(ask_local, monkeypatch, caplog):
    from mordred_hermes import _audit_support

    def broken_writer(_path):
        raise OSError("AUDIT-SECRET")

    monkeypatch.setattr(_audit_support, "build_audit_writer", broken_writer)
    with (
        caplog.at_level(logging.DEBUG, logger=service._log.name),
        LocalLlmServer(chunked=True, response=b"BODY-SECRET\r\n") as peer,
    ):
        endpoint = peer.origin + "/PATH-SECRET/v1"
        vault = MemorySecrets(endpoint)
        vault.value = replace(vault.value, local_api_key="KEY-SECRET")
        result, _ = ask_local(endpoint, credentials=vault, real_audit=True)
        assert result["error"] == "local_llm_unavailable"
        assert result["detail"]["endpoint"] == peer.origin
        assert len(peer.requests) == 1
    records = [record for record in caplog.records if record.name == service._log.name]
    assert records  # A failed audit remains observable without exposing the active exception chain.
    exposed = caplog.text + json.dumps(result)
    for secret in ("BODY-SECRET", "PATH-SECRET", "KEY-SECRET", "AUDIT-SECRET", "PRIVATE-MESSAGE"):
        assert secret not in exposed
    assert all(record.exc_info is None for record in records)


@pytest.mark.parametrize(
    ("status", "code"),
    [
        (401, "local_llm_unauthorized"),
        (404, "local_llm_unavailable"),
        (500, "local_llm_unavailable"),
        (307, "local_llm_unavailable"),
    ],
)
def test_http_failure_reaches_tool_and_audit_without_secrets(status, code, ask_local):
    with LocalLlmServer(status=status) as peer:
        result, events = ask_local(peer.origin + "/URL-SECRET/v1")
        assert result["error"] == code
        assert result["detail"]["endpoint"] == peer.origin
        assert result["detail"]["http_status"] == status
        assert result["detail"]["failure"] == "http_error"
        assert result["detail"]["hint"]
        failed = [event for event in events if event["event"] == "telegram.ask.failed"]
        assert len(failed) == 1 and failed[0]["error"] == code
        assert failed[0]["detail"] == result["detail"]
        assert len(peer.requests) == 1  # including redirects: never follow the Location
    exposed = json.dumps([result, events])
    for secret in ("URL-SECRET", "SERVER-SECRET", "PRIVATE-MESSAGE"):
        assert secret not in exposed


def test_connector_error_reports_connection_failure(ask_local, monkeypatch):
    calls = 0

    def refused(_session, _url, **_kwargs):
        nonlocal calls
        calls += 1
        key = SimpleNamespace(host="127.0.0.1", port=1, ssl=False)
        raise aiohttp.ClientConnectorError(key, ConnectionRefusedError(errno.ECONNREFUSED, "synthetic refusal"))

    monkeypatch.setattr(aiohttp.ClientSession, "post", refused)
    result, _ = ask_local("http://127.0.0.1:1/v1")
    assert result["error"] == "local_llm_unavailable"
    assert result["detail"]["failure"] == "connection_failed"
    assert result["detail"]["endpoint"] == "http://127.0.0.1:1"
    assert "http_status" not in result["detail"]
    assert calls == 1


def test_closed_port_reports_connection_failure(ask_local):
    # Keep ownership until the request completes: no other peer can reuse this port.
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as refused:
        refused.bind(("127.0.0.1", 0))
        origin = f"http://127.0.0.1:{refused.getsockname()[1]}"
        started = time.monotonic()
        result, _ = ask_local(origin + "/v1", timeout=10)
        elapsed = time.monotonic() - started
    assert result["error"] == "local_llm_unavailable"
    assert result["detail"]["failure"] == "connection_failed", (
        f"failure={result['detail']['failure']}, elapsed={elapsed:.3f}s"
    )
    assert result["detail"]["endpoint"] == origin
    assert "http_status" not in result["detail"]


def test_slow_server_reports_timeout(ask_local):
    with LocalLlmServer(delay=1) as peer:
        result, _ = ask_local(peer.endpoint, timeout=0.03)
    assert result["error"] == "local_llm_unavailable"
    assert result["detail"]["failure"] == "timeout"


def test_success_still_returns_the_local_answer(ask_local):
    with LocalLlmServer() as peer:
        result, events = ask_local(peer.endpoint)
        assert result["answer"] == "The budget moved."
        assert result["model"] == "synthetic-model"
        assert peer.requests[0]["path"] == "/v1/chat/completions"
        assert peer.requests[0]["body"]["stream"] is True
        assert "venice_parameters" not in peer.requests[0]["body"]
        assert peer.requests[0]["authorization"] is None
    assert not any(event["event"] == "telegram.ask.failed" for event in events)
    assert (result["evidence"], result["unverified_ids"]) == ([], [])  # nothing cited


def _cite_first_head(body):
    """A model that cites the first evidence id it was shown, plus one it was not."""
    prompt = body["messages"][1]["content"]
    first = prompt.split("[Telegram ", 1)[1].split("]", 1)[0]
    answer = f"The budget moved ({first}); also (tg:-9:9#a)."
    return f"data: {json.dumps({'choices': [{'delta': {'content': answer}}]})}\n\ndata: [DONE]\n\n".encode()


def test_local_answer_returns_validated_evidence(ask_local):
    with LocalLlmServer(response=_cite_first_head) as peer:
        result, _ = ask_local(peer.endpoint)
        prompt = peer.requests[0]["body"]["messages"][1]["content"]
    assert "[Telegram tg:-5:1#a] speaker: ⟦P1⟧ (legacy: forwards not distinguished) → chat: ⟦C1⟧ /" in prompt
    assert '"from"' not in prompt and "Carol" not in prompt
    assert result["answer"] == "The budget moved (tg:-5:1#a); also (tg:-9:9#a)."
    [card] = result["evidence"]
    assert (card["id"], card["speaker"], card["chat"], card["provenance_quality"]) == (
        "tg:-5:1#a",
        "Carol",
        "Finance",
        "legacy",
    )
    assert card["excerpt"] == "PRIVATE-MESSAGE budget moved"
    assert result["unverified_ids"] == ["tg:-9:9#a"]


@pytest.mark.parametrize("windows_custody", [False, True])
def test_authenticated_server_answers_after_cli_key_configuration(ask_local, monkeypatch, capsys, windows_custody):
    import argparse

    from mordred_hermes.wizard import _cli_parsers, telegram_cli

    with LocalLlmServer(api_key="LOCAL-SECRET") as peer:
        vault = MemorySecrets(peer.endpoint)
        result, _ = ask_local(peer.endpoint, credentials=vault)
        assert result["error"] == "local_llm_unauthorized"
        monkeypatch.setenv("TEST_LOCAL_KEY", "LOCAL-SECRET")
        monkeypatch.setattr(telegram_cli, "_secret_store", lambda: vault)
        monkeypatch.setattr(telegram_cli._windows_telegram, "routed", lambda: windows_custody)
        if windows_custody:
            # The in-memory custody substitute includes admission, independent of
            # this host's real helper/profile. Real refusal is tested separately.
            monkeypatch.setattr(telegram_cli._windows_telegram, "custody_code", lambda: None)
        parser = argparse.ArgumentParser()
        _cli_parsers._add_telegram(parser.add_subparsers())
        args = parser.parse_args(
            [
                "telegram",
                "local-llm",
                "--endpoint",
                peer.endpoint,
                "--model",
                "synthetic-model",
                "--api-key-env",
                "TEST_LOCAL_KEY",
            ]
        )
        assert args.func(args) == 0
        monkeypatch.delenv("TEST_LOCAL_KEY")  # runtime must use the saved key, never the environment
        result, events = ask_local(peer.endpoint, credentials=vault)
        assert result["answer"] == "The budget moved."
        assert peer.requests[-1]["authorization"] == "Bearer LOCAL-SECRET"
    assert "LOCAL-SECRET" not in json.dumps([result, events]) + capsys.readouterr().out


@pytest.mark.parametrize(
    ("reason", "diagnostic"), [("helper-missing", "tee_unavailable"), ("custody-unsafe", "custody-unsafe")]
)
def test_cli_custody_denial_does_not_update_synthetic_store(monkeypatch, capsys, reason, diagnostic):
    from mordred_hermes.wizard import telegram_cli

    vault = MemorySecrets("http://127.0.0.1:1/v1")
    before = vault.value

    def no_update(_mutate):
        pytest.fail("custody refusal must precede credential updates")

    monkeypatch.setattr(vault, "update", no_update)
    monkeypatch.setattr(telegram_cli, "_secret_store", lambda: vault)
    monkeypatch.setattr(telegram_cli._windows_telegram, "routed", lambda: True)
    monkeypatch.setattr(telegram_cli._windows_telegram, "telegram_capability", lambda home=None: reason)
    assert telegram_cli.telegram_local_llm(endpoint="http://127.0.0.1:2/v1", model="changed") == 1
    assert vault.value is before
    captured = capsys.readouterr()
    assert diagnostic in captured.err
    assert "Questions now go" not in captured.out
