"""Saved local LLM configuration exercised through the real Telegram service and HTTP."""

from __future__ import annotations

import asyncio
import json
from types import SimpleNamespace

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
    monkeypatch.setattr(
        service,
        "_audit",
        lambda event, decision, **fields: events.append({"event": event, "decision": decision, **fields}),
    )

    def run(endpoint, *, timeout=2, credentials=None):
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


def test_closed_port_reports_connection_failure(ask_local):
    with LocalLlmServer() as peer:
        endpoint, origin = peer.endpoint, peer.origin
    result, _ = ask_local(endpoint)
    assert result["error"] == "local_llm_unavailable"
    assert result["detail"]["failure"] == "connection_failed"
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


def test_authenticated_server_answers_after_cli_key_configuration(ask_local, monkeypatch, capsys):
    import argparse

    from mordred_hermes.wizard import _cli_parsers, telegram_cli

    with LocalLlmServer(api_key="LOCAL-SECRET") as peer:
        vault = MemorySecrets(peer.endpoint)
        result, _ = ask_local(peer.endpoint, credentials=vault)
        assert result["error"] == "local_llm_unauthorized"
        monkeypatch.setenv("TEST_LOCAL_KEY", "LOCAL-SECRET")
        monkeypatch.setattr(telegram_cli, "_secret_store", lambda: vault)
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
