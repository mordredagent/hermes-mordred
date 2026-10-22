"""Synthetic Telegram archive -> real local model; explicit gate, no account or native keys.

Set MORDRED_TELEGRAM_LIVE_TEST=1, MORDRED_TELEGRAM_LIVE_ENDPOINT and
MORDRED_TELEGRAM_LIVE_MODEL. Optionally set MORDRED_TELEGRAM_LIVE_API_KEY
for a server that requires authentication. No real Telegram content is used.
"""

from __future__ import annotations

import asyncio
import json
import os
from types import SimpleNamespace

import pytest

from mordred_hermes.extension.telegram import hermes_tools, service, store, tee
from mordred_hermes.wizard import telegram_cli, telegram_setup_cli
from tests.extension.test_telegram_tee import _tee_store, _value

pytestmark = pytest.mark.integration


def test_live_saved_local_model_probe_and_telegram_ask(tmp_path, monkeypatch, capsys):
    if os.environ.get("MORDRED_TELEGRAM_LIVE_TEST") != "1":
        pytest.skip("set MORDRED_TELEGRAM_LIVE_TEST=1 with endpoint/model to run real local inference")
    endpoint = os.environ["MORDRED_TELEGRAM_LIVE_ENDPOINT"]
    model = os.environ["MORDRED_TELEGRAM_LIVE_MODEL"]
    keyed = bool(os.environ.get("MORDRED_TELEGRAM_LIVE_API_KEY"))
    monkeypatch.setenv("HERMES_HOME", str(tmp_path / "home"))
    vault, _ = _tee_store(tmp_path)
    vault.ensure_key()
    vault.store(_value(venice_api_key=None))
    archive = store.ArchiveStore(b"\x05" * 32, tmp_path / "archive")
    archive.append_messages(
        -5, [store.StoredMessage(id=1, date=1, sender="Carol", text="The budget meeting moved to Monday.")]
    )
    archive.save_index(store.ArchiveIndex(dialogs={-5: store.DialogInfo(-5, "group", "Synthetic", message_count=1)}))
    assert telegram_cli.telegram_local_llm(endpoint=endpoint, model=model, store=vault) == 0
    svc = service.TelegramService(
        secret_store=vault,
        archive_root=tmp_path / "archive",
        policy_check=lambda _b, _u: None,
        memory_guard=lambda: None,
    )
    monkeypatch.setattr(hermes_tools, "_service", lambda: svc)
    monkeypatch.setattr(hermes_tools, "_reader_mode_ready", lambda _session_id: True)

    def ask():
        return json.loads(
            asyncio.run(
                hermes_tools.telegram_ask(
                    {"question": "When is the budget meeting? Answer in one short sentence.", "chat_ids": [-5]},
                    parent_agent=SimpleNamespace(model=model, base_url=endpoint),
                )
            )
        )

    if keyed:
        refused = ask()
        assert refused["error"] == "local_llm_unauthorized"
        assert refused["detail"]["http_status"] == 401
        assert (
            telegram_cli.telegram_local_llm(
                endpoint=endpoint, model=model, store=vault, api_key_env="MORDRED_TELEGRAM_LIVE_API_KEY"
            )
            == 0
        )
    monkeypatch.setattr(tee, "default_secret_store", lambda: vault)
    monkeypatch.setattr(telegram_setup_cli, "run_checks", lambda: telegram_setup_cli._check_credentials(vault.flags()))
    capsys.readouterr()
    assert telegram_setup_cli.telegram_doctor(as_json=True, probe_llm=True) == 0
    report = json.loads(capsys.readouterr().out)
    assert next(row for row in report if row["name"] == "privacy_llm")["ok"] is True
    result = ask()
    assert "error" not in result and result["answer"].strip()
    assert result["model"] == model
    assert result["search"]["messages_sent_to_privacy_llm"] == 1
    # Soft: a real model may or may not cite; any card it earns is the one part it was shown.
    assert isinstance(result["evidence"], list) and isinstance(result["unverified_ids"], list)
    assert {card["id"] for card in result["evidence"]} <= {"tg:-5:1#a"}
