"""Shared persistent-provider resolution used by network and LLM guards."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import Mock

from mordred_hermes._provider_resolution import (
    read_auth_active_provider,
    read_config_model_provider,
    resolve_disk_provider,
)


def test_concrete_config_provider_wins_over_stale_auth(tmp_path: Path) -> None:
    config = tmp_path / "config.yaml"
    auth = tmp_path / "auth.json"
    config.write_text("model:\n  provider: OpenAI\n", encoding="utf-8")
    auth.write_text(json.dumps({"active_provider": "anthropic"}), encoding="utf-8")

    assert resolve_disk_provider(config_path=config, auth_json_path=auth) == "openai"


def test_auto_config_falls_back_to_auth(tmp_path: Path) -> None:
    config = tmp_path / "config.yaml"
    auth = tmp_path / "auth.json"
    config.write_text("model:\n  provider: auto\n", encoding="utf-8")
    auth.write_text(json.dumps({"active_provider": " Gemini "}), encoding="utf-8")

    assert resolve_disk_provider(config_path=config, auth_json_path=auth) == "gemini"


def test_missing_or_invalid_values_return_none(tmp_path: Path) -> None:
    config = tmp_path / "config.yaml"
    auth = tmp_path / "auth.json"
    config.write_text("model:\n  provider: []\n", encoding="utf-8")
    auth.write_text(json.dumps({"active_provider": []}), encoding="utf-8")

    assert read_config_model_provider(config) is None
    assert read_auth_active_provider(auth) is None
    assert resolve_disk_provider(config_path=config, auth_json_path=None) is None


def test_resolution_short_circuits_auth_for_concrete_config(tmp_path: Path) -> None:
    config_reader = Mock(return_value="openai")
    auth_reader = Mock(side_effect=AssertionError("auth fallback must not run"))

    assert (
        resolve_disk_provider(
            config_path=tmp_path / "config.yaml",
            auth_json_path=tmp_path / "auth.json",
            config_reader=config_reader,
            auth_reader=auth_reader,
        )
        == "openai"
    )
    config_reader.assert_called_once_with(tmp_path / "config.yaml")
    auth_reader.assert_not_called()


def test_injected_empty_config_value_still_uses_auth_fallback(tmp_path: Path) -> None:
    assert (
        resolve_disk_provider(
            config_path=tmp_path / "config.yaml",
            auth_json_path=tmp_path / "auth.json",
            config_reader=Mock(return_value=""),
            auth_reader=Mock(return_value="anthropic"),
        )
        == "anthropic"
    )
