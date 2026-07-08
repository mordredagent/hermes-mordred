"""Unit tests for the shared policy.json mapping loader.

Covers every branch of :func:`mordred_hermes._policy_io.load_policy_mapping`:
missing file, a valid top-level object, a non-object root, a JSON parse
error (logged), and an ``OSError`` on open (the no-logger path).
"""

from __future__ import annotations

import logging
from pathlib import Path

import pytest

from mordred_hermes._policy_io import load_policy_mapping, read_policy_mode_fail_closed


def test_missing_file_returns_empty(tmp_path: Path) -> None:
    assert load_policy_mapping(tmp_path / "absent.json") == {}


def test_loads_top_level_mapping(tmp_path: Path) -> None:
    path = tmp_path / "policy.json"
    path.write_text('{"policy": "strict", "allow_cloud_llm": false}', encoding="utf-8")
    assert load_policy_mapping(path) == {"policy": "strict", "allow_cloud_llm": False}


def test_non_mapping_top_level_returns_empty(tmp_path: Path) -> None:
    path = tmp_path / "list.json"
    path.write_text('["strict", "off"]', encoding="utf-8")
    assert load_policy_mapping(path) == {}


def test_malformed_json_is_swallowed_and_logged(tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    path = tmp_path / "bad.json"
    path.write_text('{"policy": unquoted}', encoding="utf-8")
    logger = logging.getLogger("test.policy_io")
    with caplog.at_level(logging.WARNING, logger="test.policy_io"):
        assert load_policy_mapping(path, log=logger) == {}
    assert "could not read" in caplog.text


def test_oserror_is_swallowed_without_logger(tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    # A directory ``exists()`` but opening it raises IsADirectoryError (an
    # OSError); with ``log=None`` the error is swallowed silently to ``{}``.
    a_dir = tmp_path / "policy.json"
    a_dir.mkdir()
    with caplog.at_level(logging.WARNING):
        assert load_policy_mapping(a_dir) == {}
    assert caplog.text == ""


# --------------------------------------------------------------------------- #
# read_policy_mode_fail_closed — the M1 open-first, fail-closed reader        #
# --------------------------------------------------------------------------- #

_FC_LOG = logging.getLogger("test.policy_io.fail_closed")


def test_fail_closed_absent_file_keeps_default(tmp_path: Path) -> None:
    assert read_policy_mode_fail_closed(tmp_path / "absent.json", default="lenient", log=_FC_LOG) == "lenient"
    assert read_policy_mode_fail_closed(tmp_path / "absent.json", default="off", log=_FC_LOG) == "off"


def test_fail_closed_dangling_symlink_keeps_default(tmp_path: Path) -> None:
    # Equivalent to deletion — the one non-strict failure mode besides absence.
    link = tmp_path / "policy.json"
    link.symlink_to(tmp_path / "gone.json")
    assert read_policy_mode_fail_closed(link, default="lenient", log=_FC_LOG) == "lenient"


def test_fail_closed_unreadable_file_is_strict(tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    # A directory exists() but open() raises IsADirectoryError (an OSError
    # that is NOT FileNotFoundError) — must fail closed, not read as absent.
    a_dir = tmp_path / "policy.json"
    a_dir.mkdir()
    with caplog.at_level(logging.ERROR, logger=_FC_LOG.name):
        assert read_policy_mode_fail_closed(a_dir, default="lenient", log=_FC_LOG) == "strict"
    assert "failing closed to strict" in caplog.text


def test_fail_closed_malformed_json_is_strict(tmp_path: Path) -> None:
    p = tmp_path / "policy.json"
    p.write_text("{not json", encoding="utf-8")
    assert read_policy_mode_fail_closed(p, default="lenient", log=_FC_LOG) == "strict"


def test_fail_closed_non_dict_root_is_strict(tmp_path: Path) -> None:
    p = tmp_path / "policy.json"
    p.write_text('["a", "list"]', encoding="utf-8")
    assert read_policy_mode_fail_closed(p, default="lenient", log=_FC_LOG) == "strict"


@pytest.mark.parametrize("bad", ['"garbage"', "42", "[]", "{}"])
def test_fail_closed_invalid_mode_value_is_strict(tmp_path: Path, bad: str) -> None:
    # Unhashable values ([]/{}) must hit the False branch, not TypeError.
    p = tmp_path / "policy.json"
    p.write_text(f'{{"policy": {bad}}}', encoding="utf-8")
    assert read_policy_mode_fail_closed(p, default="lenient", log=_FC_LOG) == "strict"


def test_fail_closed_missing_policy_key_keeps_default(tmp_path: Path) -> None:
    p = tmp_path / "policy.json"
    p.write_text('{"other": 1}', encoding="utf-8")
    assert read_policy_mode_fail_closed(p, default="lenient", log=_FC_LOG) == "lenient"


@pytest.mark.parametrize("mode", ["strict", "lenient", "off"])
def test_fail_closed_valid_modes_pass_through(tmp_path: Path, mode: str) -> None:
    p = tmp_path / "policy.json"
    p.write_text(f'{{"policy": "{mode}"}}', encoding="utf-8")
    assert read_policy_mode_fail_closed(p, default="lenient", log=_FC_LOG) == mode
