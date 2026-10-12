"""Explicit local-model health checks through the public Telegram CLI."""

from __future__ import annotations

import argparse
import json
from dataclasses import replace

import pytest

from mordred_hermes.extension.telegram import secrets, service, store, tee
from mordred_hermes.wizard import _cli_parsers, telegram_setup_cli
from tests.extension.local_llm_server import LocalLlmServer
from tests.extension.test_telegram_local_llm import MemorySecrets


@pytest.fixture
def doctor(monkeypatch, capsys):
    def archive_forbidden(*_args, **_kwargs):
        raise AssertionError("the probe must not open the archive")

    monkeypatch.setattr(store.ArchiveStore, "__init__", archive_forbidden)

    def run(vault, *, probe=True):
        monkeypatch.setattr(tee, "default_secret_store", lambda: vault)
        monkeypatch.setattr(
            telegram_setup_cli,
            "run_checks",
            lambda: telegram_setup_cli._check_credentials(
                {"logged_in": True, "llm_backend": "local", "llm_model": "metadata-model"}
            ),
        )
        parser = argparse.ArgumentParser()
        _cli_parsers._add_telegram(parser.add_subparsers())
        args = parser.parse_args(["telegram", "doctor", "--json", *(["--probe-llm"] if probe else [])])
        rc = args.func(args)
        output = capsys.readouterr()
        report = json.loads(output.out)
        return rc, next(row for row in report if row["name"] == "privacy_llm")

    return run


def test_ordinary_doctor_reports_configuration_without_unsealing(doctor):
    class Sealed:
        def load(self, **_kwargs):
            pytest.fail("ordinary doctor must not unseal")

    rc, check = doctor(Sealed(), probe=False)
    assert rc == 0 and check["ok"] is True
    assert "not checked" in check["detail"]
    assert "--probe-llm" in check["fix"]


def test_probe_uses_saved_endpoint_model_and_key_without_archive(doctor):
    with LocalLlmServer(api_key="SEALED-SECRET") as peer:
        vault = MemorySecrets(peer.endpoint)
        vault.value = replace(vault.value, local_api_key="SEALED-SECRET")
        rc, check = doctor(vault)
        assert rc == 0 and check["ok"] is True
        assert peer.origin in check["detail"] and "synthetic-model" in check["detail"]
        assert "metadata-model" not in check["detail"]
        request = peer.requests[0]
        assert request["authorization"] == "Bearer SEALED-SECRET"
        assert request["path"] == "/v1/chat/completions"
        assert request["body"]["model"] == "synthetic-model"
        assert request["body"]["stream"] is True
        assert request["body"]["max_tokens"] == 64
        assert len(request["body"]["messages"]) == 1
        assert "PRIVATE-MESSAGE" not in json.dumps(request)
        assert "SEALED-SECRET" not in json.dumps(check)


@pytest.mark.parametrize("status", [401, 404, 500, 307])
def test_probe_failure_is_degraded_with_status_and_fix(doctor, status):
    with LocalLlmServer(status=status) as peer:
        rc, check = doctor(MemorySecrets(peer.origin + "/URL-SECRET/v1"))
        assert rc == 1 and check["ok"] is False
        assert str(status) in check["detail"] and peer.origin in check["detail"]
        assert check["fix"]
        assert len(peer.requests) == 1
    assert "URL-SECRET" not in json.dumps(check) and "SERVER-SECRET" not in json.dumps(check)


@pytest.mark.parametrize(
    ("response", "code"),
    [
        (b"data: [DONE]\n\n", "llm_empty_answer"),
        (
            b'data: {"choices":[{"delta":{"content":"<think>private reasoning</think>"}}]}\n\ndata: [DONE]\n\n',
            "llm_empty_answer",
        ),
        (b'{"choices":[{"message":{"content":"non-streaming"}}]}', "local_llm_bad_response"),
    ],
)
def test_probe_requires_visible_streamed_text(doctor, response, code):
    with LocalLlmServer(response=response) as peer:
        rc, check = doctor(MemorySecrets(peer.endpoint))
    assert rc == 1 and check["ok"] is False
    assert code in check["detail"]


def test_truncated_response_cannot_pass_probe(doctor):
    with LocalLlmServer(truncate=True) as peer:
        rc, check = doctor(MemorySecrets(peer.endpoint))
    assert rc == 1 and "transport_error" in check["detail"]


@pytest.mark.parametrize("suffix", [b"", b"data: {broken"])
def test_clean_http_eof_without_completed_sse_is_not_healthy(doctor, suffix):
    response = b'data: {"choices":[{"delta":{"content":"partial"}}]}\n\n' + suffix
    with LocalLlmServer(response=response) as peer:
        rc, check = doctor(MemorySecrets(peer.endpoint))
    assert rc == 1 and check["ok"] is False
    assert "local_llm_bad_response" in check["detail"]
    assert "invalid_response" in check["detail"]


def test_explicit_finish_reason_completes_the_probe(doctor):
    response = b'data: {"choices":[{"delta":{"content":"OK"},"finish_reason":"stop"}]}\n\n'
    with LocalLlmServer(response=response) as peer:
        rc, check = doctor(MemorySecrets(peer.endpoint))
    assert rc == 0 and check["ok"] is True


def test_probe_closed_port_and_timeout_are_distinguishable(doctor, monkeypatch):
    with LocalLlmServer() as peer:
        endpoint = peer.endpoint
    rc, check = doctor(MemorySecrets(endpoint))
    assert rc == 1 and "connection_failed" in check["detail"]
    original_session = service._default_http_session
    monkeypatch.setattr(service, "_default_http_session", lambda route, _timeout: original_session(route, 0.03))
    with LocalLlmServer(delay=1) as peer:
        rc, check = doctor(MemorySecrets(peer.endpoint))
    assert rc == 1 and "timeout" in check["detail"]


@pytest.mark.parametrize("case", ["missing", "cloud", "custody"])
def test_probe_refuses_unconfigured_cloud_or_unavailable_custody(doctor, monkeypatch, case):
    class Unavailable:
        def load(self, *, fresh=True):
            assert fresh
            if case == "custody":
                raise secrets.TelegramSecretsError("tee_auth_cancelled")
            if case == "missing":
                return None
            return replace(
                MemorySecrets("http://127.0.0.1:1/v1").value, backend="venice", venice_api_key="CLOUD-SECRET"
            )

    def forbidden(*_args, **_kwargs):
        pytest.fail("no HTTP session is allowed for this configuration")

    monkeypatch.setattr(service, "_default_http_session", forbidden)
    rc, check = doctor(Unavailable())
    assert rc == 1 and check["ok"] is False and check["fix"]
    assert "CLOUD-SECRET" not in json.dumps(check)
