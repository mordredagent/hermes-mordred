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
