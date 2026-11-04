"""Unit tests for the shared YAML mapping loader.

Covers every branch of :func:`mordred_hermes._core._yaml_io.load_yaml_mapping`,
including the two failure-handling knobs the migration relies on: the
parametrized ``catch`` set and the optional ``log`` — plus every branch of
the :func:`mordred_hermes._core._yaml_io.load_plugin_section` extraction built on
top of it.
"""

from __future__ import annotations

import logging
import warnings
from pathlib import Path

import pytest
from ruamel.yaml.error import YAMLError, YAMLWarning

from mordred_hermes._core._yaml_io import load_plugin_section, load_yaml_mapping


@pytest.fixture(params=["generic-file", "checked-snapshot"])
def yaml_path(request: pytest.FixtureRequest, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    from mordred_hermes._core import _config_io, _yaml_io
    from mordred_hermes._private_fs import FileIdentity, FileMetadata

    path = tmp_path / "config.yaml"
    monkeypatch.setattr(_yaml_io, "_platform", "nt" if request.param == "checked-snapshot" else "posix")
    if request.param == "checked-snapshot":
        # Supply checked bytes at the filesystem boundary while exercising the real parser.
        def read_snapshot(paths: _config_io.CanonicalPaths) -> _config_io.CanonicalSnapshot:
            data = (paths.home / paths.config_name).read_bytes()
            contents = _config_io.CheckedContents(data, FileMetadata(FileIdentity(1, b"yaml-test"), len(data), 1))
            return _config_io.CanonicalSnapshot(contents, None)

        monkeypatch.setattr(_config_io, "read_canonical_snapshot", read_snapshot)
    return path


@pytest.mark.parametrize("round_trip", [False, True], ids=["safe-pure", "round-trip"])
@pytest.mark.parametrize("content_kind", ["duplicate-anchor", "malformed-scalar", "custom-tag"])
def test_yaml_diagnostics_exclude_content_and_preserve_values(
    yaml_path: Path,
    round_trip: bool,
    content_kind: str,
    caplog: pytest.LogCaptureFixture,
    capsys: pytest.CaptureFixture[str],
) -> None:
    token = "synthetic_secret_yaml_token"
    contents = {
        "duplicate-anchor": f"first: &{token} one\nsecond: &{token} two\nref: *{token}\n",
        "malformed-scalar": f'value: "{token}\\q"\n',
        "custom-tag": f"value: !{token} strict\n",
    }
    yaml_path.write_text(contents[content_kind], encoding="utf-8")
    logger = logging.getLogger("test.yaml_io.diagnostics")
    with warnings.catch_warnings(record=True) as captured, caplog.at_level(logging.WARNING):
        warnings.simplefilter("always")
        result = load_yaml_mapping(yaml_path, round_trip=round_trip, log=logger)
        # The parse scope must restore filters even when parsing raises.
        warnings.warn("outside parse scope", UserWarning, stacklevel=1)
        warnings.warn("outside YAML parse scope", YAMLWarning, stacklevel=1)

    if content_kind == "duplicate-anchor":
        assert result == {"first": "one", "second": "two", "ref": "two"}
    elif content_kind == "custom-tag" and round_trip:
        assert str(result["value"]) == "strict"
        assert result["value"] != "strict"
        assert str(result["value"].tag) == f"!{token}"
    else:
        assert result == {}
        assert ("ScannerError" if content_kind == "malformed-scalar" else "ConstructorError") in caplog.text

    stdio = capsys.readouterr()
    diagnostics = caplog.text + stdio.out + stdio.err + "".join(str(item.message) for item in captured)
    assert token not in diagnostics
    assert [str(item.message) for item in captured] == ["outside parse scope", "outside YAML parse scope"]
    assert all(record.exc_info is None and record.stack_info is None for record in caplog.records)


@pytest.mark.parametrize("round_trip", [False, True], ids=["safe-pure", "round-trip"])
@pytest.mark.parametrize("exception_type", [OSError, YAMLError, ValueError, RuntimeError])
@pytest.mark.parametrize("catch", [None, (ValueError,), (Exception,)])
def test_yaml_catch_selection_is_preserved(
    yaml_path: Path,
    round_trip: bool,
    exception_type: type[Exception],
    catch: tuple[type[BaseException], ...] | None,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    from ruamel.yaml import YAML

    from mordred_hermes._core import _yaml_io

    yaml_path.write_text("ok: 1\n", encoding="utf-8")
    error = exception_type("synthetic_secret_exception_token")

    def fail_parse(self: YAML, stream: object) -> object:
        warnings.warn("unrelated parser warning", UserWarning, stacklevel=1)
        raise error

    monkeypatch.setattr(YAML, "load", fail_parse)
    selected = (
        catch
        if catch is not None
        else ((OSError, ValueError, YAMLError) if _yaml_io._platform == "nt" else (OSError, YAMLError))
    )
    logger = logging.getLogger("test.yaml_io.catch")
    with warnings.catch_warnings(record=True) as captured, caplog.at_level(logging.WARNING):
        warnings.simplefilter("always")
        if isinstance(error, selected):
            assert load_yaml_mapping(yaml_path, catch=catch, round_trip=round_trip, log=logger) == {}
            assert exception_type.__name__ in caplog.text
        else:
            with pytest.raises(exception_type) as raised:
                load_yaml_mapping(yaml_path, catch=catch, round_trip=round_trip, log=logger)
            assert raised.value is error
        warnings.warn("after parser failure", YAMLWarning, stacklevel=1)
    assert "synthetic_secret_exception_token" not in caplog.text
    assert [str(item.message) for item in captured] == ["unrelated parser warning", "after parser failure"]


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
