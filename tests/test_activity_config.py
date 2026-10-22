"""``plugins.mordred_activity`` parsing: site exclusions, raw-event retention and unknown keys."""

from __future__ import annotations

from typing import Any

import pytest

from mordred_hermes.activity.config import ActivityConfig
from mordred_hermes.activity.contracts import DEFAULT_EXCLUDED_SITES, site_excluded


def test_site_keys_default_to_the_built_in_exclusions() -> None:
    assert not DEFAULT_EXCLUDED_SITES
    assert ActivityConfig().excluded_sites == DEFAULT_EXCLUDED_SITES
    assert ActivityConfig.from_mapping({}).excluded_sites == DEFAULT_EXCLUDED_SITES


def test_configured_exclusions_extend_the_empty_default_and_cover_subdomains() -> None:
    config = ActivityConfig.from_mapping({"excluded_sites": [" Mail.Example ", "bank.example"]})
    assert config.excluded_sites == DEFAULT_EXCLUDED_SITES | {"mail.example", "bank.example"}
    assert config.warnings == ()
    assert site_excluded("mail.example", config.excluded_sites)
    assert site_excluded("eu.mail.example", config.excluded_sites)
    assert not site_excluded("example", config.excluded_sites)
    assert not site_excluded("notmail.example", config.excluded_sites)


def test_unknown_site_keys_are_ignored_with_a_warning() -> None:
    config = ActivityConfig.from_mapping({"excluded_sites": ["mail.example"], "allowed_sites": ["mail.example"]})
    assert config.excluded_sites == frozenset({"mail.example"})
    assert config.warnings == ("unknown key allowed_sites",)


@pytest.mark.parametrize("raw", ["mail.example", [1], [" "], None])
def test_invalid_excluded_sites_fall_back_with_a_warning(raw: Any) -> None:
    config = ActivityConfig.from_mapping({"excluded_sites": raw})
    assert config.excluded_sites == DEFAULT_EXCLUDED_SITES
    assert config.warnings == ("invalid value for excluded_sites",)


def test_raw_retention_defaults_to_a_year() -> None:
    assert ActivityConfig().retention_raw_days == ActivityConfig.from_mapping({}).retention_raw_days == 365


def test_raw_retention_zero_means_keep_forever() -> None:
    config = ActivityConfig.from_mapping({"retention_raw_days": 0})
    assert (config.retention_raw_days, config.warnings) == (0, ())


@pytest.mark.parametrize("raw", [-1, True, 1.5, "30", None])
def test_invalid_raw_retention_falls_back_with_a_warning(raw: Any) -> None:
    config = ActivityConfig.from_mapping({"retention_raw_days": raw})
    assert config.retention_raw_days == 365
    assert config.warnings == ("invalid value for retention_raw_days",)


@pytest.mark.parametrize(
    "key", ["review_mode", "recall_enabled", "review_provider", "recall_max_bytes", "retention_candidate_days"]
)
def test_keys_of_the_removed_lesson_pipeline_are_unknown(key: str) -> None:
    config = ActivityConfig.from_mapping({"enabled": True, key: 1})
    assert config.enabled is True
    assert config.warnings == (f"unknown key {key}",)
    assert not hasattr(config, key)


# --- history_* keys ---------------------------------------------------------------------------------------

HISTORY_DEFAULTS = {
    "history_enabled": True,
    "history_on_navigate": True,
    "history_turn_context": True,
    "history_capture_hermes": True,
    "history_chat_corrections": True,
    "history_max_chars": 1500,
    "history_max_episodes": 3,
    "history_lookback_days": 90,
    "history_session_budget_chars": 8000,
    "history_max_tool_bytes": 4096,
}


def test_history_keys_default_to_on_but_the_feature_stays_off() -> None:
    config = ActivityConfig.from_mapping({})
    assert {key: getattr(config, key) for key in HISTORY_DEFAULTS} == HISTORY_DEFAULTS
    assert config.enabled is False
    assert config.history_active is False
    assert ActivityConfig.from_mapping({"enabled": True}).history_active is True
    assert ActivityConfig.from_mapping({"enabled": True, "history_enabled": False}).history_active is False


def test_history_keys_parse_valid_values_without_warnings() -> None:
    section = {
        "history_enabled": False,
        "history_on_navigate": False,
        "history_turn_context": False,
        "history_capture_hermes": False,
        "history_chat_corrections": False,
        "history_max_chars": 800,
        "history_max_episodes": 10,
        "history_lookback_days": 7,
        "history_session_budget_chars": 0,
        "history_max_tool_bytes": 65536,
    }
    config = ActivityConfig.from_mapping(section)
    assert {key: getattr(config, key) for key in section} == section
    assert config.warnings == ()


@pytest.mark.parametrize(
    ("key", "raw"),
    [
        ("history_enabled", "yes"),
        ("history_turn_context", 1),
        ("history_max_chars", 199),
        ("history_max_chars", 8001),
        ("history_max_episodes", 0),
        ("history_max_episodes", 11),
        ("history_lookback_days", 0),
        ("history_session_budget_chars", -1),
        ("history_max_tool_bytes", 1023),
        ("history_max_tool_bytes", True),
        ("history_max_tool_bytes", 4096.0),
    ],
)
def test_invalid_history_values_fall_back_with_a_warning(key: str, raw: Any) -> None:
    config = ActivityConfig.from_mapping({key: raw})
    assert getattr(config, key) == HISTORY_DEFAULTS[key]
    assert config.warnings == (f"invalid value for {key}",)


def test_excluded_sites_are_normalized_to_bare_hosts() -> None:
    raw = ["https://Bank.example.com/login", "*.mail.example", "shop.example.", "pay.example:443", "bücher.example"]
    config = ActivityConfig.from_mapping({"enabled": True, "excluded_sites": raw})
    assert config.excluded_sites == {
        "bank.example.com",
        "mail.example",
        "shop.example",
        "pay.example",
        "xn--bcher-kva.example",
    }
    assert config.warnings == ()
    assert config.history_active is True


@pytest.mark.parametrize("raw", ["bank.example", ["ok.example", ""], ["ok.example", "not a host"], [None]])
def test_an_invalid_exclusion_list_switches_the_history_off(raw: Any) -> None:
    config = ActivityConfig.from_mapping({"enabled": True, "excluded_sites": raw})
    assert config.excluded_sites_valid is False
    assert config.history_active is False
