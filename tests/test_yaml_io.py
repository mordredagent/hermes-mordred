"""Unit tests for the shared YAML mapping loader.

Covers every branch of :func:`mordred_hermes._yaml_io.load_yaml_mapping`,
including the two failure-handling knobs the migration relies on: the
parametrized ``catch`` set and the optional ``log`` — plus every branch of
the :func:`mordred_hermes._yaml_io.load_plugin_section` extraction built on
top of it.
"""

from __future__ import annotations

import logging
from pathlib import Path

import pytest

from mordred_hermes._yaml_io import load_plugin_section, load_yaml_mapping


def test_missing_file_returns_empty(tmp_path: Path) -> None:
    assert load_yaml_mapping(tmp_path / "absent.yaml") == {}


def test_loads_top_level_mapping(tmp_path: Path) -> None:
    path = tmp_path / "config.yaml"
    path.write_text(
        "plugins:\n  mordred_network:\n    default_path: tor\n",
        encoding="utf-8",
    )
    assert load_yaml_mapping(path) == {"plugins": {"mordred_network": {"default_path": "tor"}}}


def test_non_mapping_top_level_returns_empty(tmp_path: Path) -> None:
    path = tmp_path / "list.yaml"
    path.write_text("- one\n- two\n", encoding="utf-8")
    assert load_yaml_mapping(path) == {}


def test_malformed_yaml_is_swallowed_and_logged(tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    path = tmp_path / "bad.yaml"
    path.write_text("plugins: [unterminated\n", encoding="utf-8")
    logger = logging.getLogger("test.yaml_io")
    with caplog.at_level(logging.WARNING, logger="test.yaml_io"):
        assert load_yaml_mapping(path, log=logger) == {}
    assert "could not read" in caplog.text


def test_default_catch_lets_non_yaml_errors_escape(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / "config.yaml"
    path.write_text("ok: 1\n", encoding="utf-8")
    from ruamel.yaml import YAML

    def _boom(self: YAML, stream: object) -> object:
        raise RuntimeError("boom")

    monkeypatch.setattr(YAML, "load", _boom)
    # The default narrow catch is (OSError, YAMLError); a RuntimeError must propagate.
    with pytest.raises(RuntimeError):
        load_yaml_mapping(path)


def test_broad_catch_swallows_any_exception(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / "config.yaml"
    path.write_text("ok: 1\n", encoding="utf-8")
    from ruamel.yaml import YAML

    def _boom(self: YAML, stream: object) -> object:
        raise RuntimeError("boom")

    monkeypatch.setattr(YAML, "load", _boom)
    # catch=(Exception,) widens the net (and log=None exercises the no-logger path).
    assert load_yaml_mapping(path, catch=(Exception,)) == {}


def test_plugin_section_returns_mapping(tmp_path: Path) -> None:
    path = tmp_path / "config.yaml"
    path.write_text(
        "plugins:\n  mordred_network:\n    default_path: tor\n",
        encoding="utf-8",
    )
    assert load_plugin_section(path, "mordred_network") == {"default_path": "tor"}


def test_plugin_section_missing_file_returns_none(tmp_path: Path) -> None:
    assert load_plugin_section(tmp_path / "absent.yaml", "mordred_network") is None


@pytest.mark.parametrize(
    "content",
    [
        "other_key: 1\n",  # no `plugins` key at all
        "plugins: [not, a, mapping]\n",  # `plugins` is not a mapping
        "plugins:\n  other_plugin:\n    x: 1\n",  # section absent
        "plugins:\n  mordred_network: just-a-string\n",  # section not a mapping
    ],
)
def test_plugin_section_absent_or_malformed_returns_none(tmp_path: Path, content: str) -> None:
    path = tmp_path / "config.yaml"
    path.write_text(content, encoding="utf-8")
    assert load_plugin_section(path, "mordred_network") is None


def test_plugin_section_present_but_empty_is_distinguishable(tmp_path: Path) -> None:
    # `{}` (present-but-empty) vs `None` (absent) is part of the contract:
    # the wizard's upgrade path compares sections and must see the difference.
    path = tmp_path / "config.yaml"
    path.write_text("plugins:\n  mordred_network: {}\n", encoding="utf-8")
    assert load_plugin_section(path, "mordred_network") == {}


def test_plugin_section_forwards_catch_and_log(tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    path = tmp_path / "bad.yaml"
    path.write_text("plugins: [unterminated\n", encoding="utf-8")
    logger = logging.getLogger("test.yaml_io.section")
    with caplog.at_level(logging.WARNING, logger="test.yaml_io.section"):
        assert load_plugin_section(path, "mordred_network", log=logger) is None
    assert "could not read" in caplog.text


def test_round_trip_loads_custom_tags_that_safe_mode_rejects(tmp_path: Path) -> None:
    # The rt loader must carry documents with custom tags so section-comparison
    # callers (wizard upgrade / OpenClaw migration) see an unequal value and
    # reach their conflict handling; the safe loader raises and the degraded
    # path would report the section absent.
    path = tmp_path / "config.yaml"
    path.write_text(
        "plugins:\n  mordred_privacy_check:\n    policy: !keep strict\n",
        encoding="utf-8",
    )
    assert load_plugin_section(path, "mordred_privacy_check") is None  # safe mode: swallowed parse error
    section = load_plugin_section(path, "mordred_privacy_check", round_trip=True)
    assert section is not None
    assert section["policy"] != "strict"  # TaggedScalar compares unequal -> conflict path
