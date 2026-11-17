"""Unit tests for the shared YAML mapping loader.

Covers every branch of :func:`mordred_hermes._core._yaml_io.load_yaml_mapping`,
including the two failure-handling knobs the migration relies on: the
parametrized ``catch`` set and the optional ``log`` — plus every branch of
the :func:`mordred_hermes._core._yaml_io.load_plugin_section` extraction built on
top of it.
"""

from __future__ import annotations

import logging
import os
import select
import signal
import sys
import threading
import warnings
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
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
    assert captured[0].filename == __file__
    assert captured[0].lineno == fail_parse.__code__.co_firstlineno + 1


@pytest.mark.parametrize("round_trip", [False, True], ids=["safe-pure", "round-trip"])
@pytest.mark.parametrize("finish_order", [(0, 1), (1, 0)], ids=["overlapping-exit", "nested-exit"])
@pytest.mark.parametrize("warning_kind", ["duplicate-anchor", "yaml-1.1-mantissa"])
@pytest.mark.parametrize("warning_as_error", [False, True], ids=["record-policy", "error-policy"])
def test_concurrent_parses_keep_diagnostics_private_and_warning_policy_unchanged(
    yaml_path: Path,
    round_trip: bool,
    finish_order: tuple[int, int],
    warning_kind: str,
    warning_as_error: bool,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from ruamel.yaml import YAML

    if warning_kind == "duplicate-anchor":
        token = "synthetic_secret_concurrent_anchor"
        content = f"first: &{token} one\nsecond: &{token} two\nref: *{token}\n"
        expected = {"first": "one", "second": "two", "ref": "two"}
    else:
        token = "13371337"
        content = f"%YAML 1.1\n---\nvalue: {token}e+04\n"
        expected = {"value": 133713370000.0}
    yaml_path.write_text(content, encoding="utf-8")
    entered = [threading.Event(), threading.Event()]
    proceed = [threading.Event(), threading.Event()]
    worker = threading.local()
    original_load = YAML.load

    def paused_load(self: YAML, stream: object) -> object:
        index = worker.index
        entered[index].set()
        assert proceed[index].wait(5), "parse release was not signaled"
        return original_load(self, stream)

    def parse(index: int) -> dict[str, object]:
        worker.index = index
        return load_yaml_mapping(yaml_path, round_trip=round_trip)

    monkeypatch.setattr(YAML, "load", paused_load)
    with warnings.catch_warnings(record=True) as captured:
        warnings.simplefilter("always")
        warnings.simplefilter("error" if warning_as_error else "always", YAMLWarning)
        warnings.simplefilter("error", RuntimeWarning)
        filters_before = warnings.filters[:]
        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = []
            try:
                for index in range(2):
                    futures.append(pool.submit(parse, index))
                    assert entered[index].wait(5), "parse did not reach the real loader"
                # A warning from another thread must retain the caller's policy.
                with pytest.raises(RuntimeWarning, match="unrelated error policy"):
                    warnings.warn("unrelated error policy", RuntimeWarning, stacklevel=1)
                if warning_as_error:
                    with pytest.raises(YAMLWarning, match="unrelated concurrent YAML warning"):
                        warnings.warn("unrelated concurrent YAML warning", YAMLWarning, stacklevel=1)
                else:
                    warnings.warn("unrelated concurrent YAML warning", YAMLWarning, stacklevel=1)
                for index in finish_order:
                    proceed[index].set()
                    assert futures[index].result(timeout=5) == expected
            finally:
                for event in proceed:
                    event.set()
        filters_after = warnings.filters[:]

    assert token not in "".join(str(item.message) for item in captured)
    assert [str(item.message) for item in captured] == (
        [] if warning_as_error else ["unrelated concurrent YAML warning"]
    )
    assert filters_after == filters_before


def test_nested_yaml_warning_scopes_restore_hook_filters_and_source() -> None:
    from mordred_hermes._core._yaml_warnings import quiet_yaml_warnings

    with warnings.catch_warnings(record=True) as captured:
        warnings.simplefilter("always")
        original_warn = warnings.warn
        original_filters = warnings.filters[:]
        delegated_message = UserWarning("delegated warning instance")
        delegated_source = object()
        with quiet_yaml_warnings():
            outer_warn = warnings.warn
            with pytest.raises(RuntimeError, match="leave nested scope"), quiet_yaml_warnings():
                assert warnings.warn is outer_warn
                assert warnings.filters == original_filters
                warnings.warn(YAMLWarning("synthetic_nested_instance_secret"), stacklevel=1)
                warnings.warn("synthetic_nested_secret", YAMLWarning, stacklevel=1)
                raise RuntimeError("leave nested scope")
            warnings.warn("synthetic_outer_secret", YAMLWarning, stacklevel=1)

            def emit() -> None:
                warnings.warn("delegated caller warning", UserWarning, stacklevel=2)

            expected_line = sys._getframe().f_lineno + 1
            emit()
            # Warning instances choose their own category, overriding the argument.
            warnings.warn(delegated_message, YAMLWarning, source=delegated_source, stacklevel=0)
        assert warnings.warn is original_warn
        assert warnings.filters == original_filters
        warnings.warn("outside restored YAML warning", YAMLWarning, stacklevel=1)
    assert [str(item.message) for item in captured] == [
        "delegated caller warning",
        "delegated warning instance",
        "outside restored YAML warning",
    ]
    assert captured[0].filename == __file__
    assert captured[0].lineno == expected_line
    assert captured[1].message is delegated_message
    assert captured[1].source is delegated_source


@pytest.mark.parametrize("stacklevel", [None, 1, 2, 3, 0, -1, -20])
def test_yaml_warning_dispatch_preserves_stdlib_source(stacklevel: int | None) -> None:
    from mordred_hermes._core._yaml_warnings import quiet_yaml_warnings

    def emit(warn: Callable[..., None]) -> None:
        if stacklevel is None:
            warn("forwarded source", UserWarning)
        else:
            warn("forwarded source", UserWarning, stacklevel=stacklevel)

    with warnings.catch_warnings(record=True) as captured:
        warnings.simplefilter("always")
        original_warn = warnings.warn
        with quiet_yaml_warnings():
            for warn in (original_warn, warnings.warn):
                emit(warn)
    assert len(captured) == 2
    assert (captured[0].filename, captured[0].lineno) == (captured[1].filename, captured[1].lineno)


@pytest.mark.parametrize(
    "invalid",
    [{"stacklevel": "bad"}, {"stacklevel": None}, {"stacklevel": 1.5}, {"category": "bad"}, {"category": ValueError}],
)
def test_yaml_warning_dispatch_preserves_stdlib_argument_errors(invalid: dict[str, object]) -> None:
    from mordred_hermes._core._yaml_warnings import quiet_yaml_warnings

    arguments = {"message": "synthetic_invalid_warning_secret", "category": YAMLWarning, **invalid}
    original_warn = warnings.warn
    with pytest.raises(TypeError) as original_error:
        original_warn(**arguments)
    with quiet_yaml_warnings(), pytest.raises(TypeError) as dispatched_error:
        warnings.warn(**arguments)
    assert str(dispatched_error.value) == str(original_error.value)


@pytest.mark.parametrize("wizard_warns", [False, True], ids=["clean-wizard", "strict-wizard"])
def test_yaml_parse_overlaps_wizard_warning_capture(
    yaml_path: Path, wizard_warns: bool, monkeypatch: pytest.MonkeyPatch
) -> None:
    from ruamel.yaml import YAML

    from mordred_hermes.wizard._direct_tools_yaml import answer

    token = "synthetic_secret_wizard_overlap"
    content = f"first: &{token} one\nsecond: &{token} two\nref: *{token}\n"
    yaml_path.write_text(content, encoding="utf-8")
    entered = [threading.Event(), threading.Event()]
    proceed = [threading.Event(), threading.Event()]
    worker = threading.local()
    original_load = YAML.load

    def paused_load(self: YAML, stream: object) -> object:
        index = worker.index
        entered[index].set()
        assert proceed[index].wait(5)
        return original_load(self, stream)

    def parse(index: int) -> object:
        worker.index = index
        return load_yaml_mapping(yaml_path) if index == 0 else answer(content if wizard_warns else "tools: {}\n")

    monkeypatch.setattr(YAML, "load", paused_load)
    with warnings.catch_warnings(record=True) as captured:
        warnings.simplefilter("always")
        original_warn = warnings.warn
        original_filters = warnings.filters[:]
        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = []
            try:
                for index in range(2):
                    futures.append(pool.submit(parse, index))
                    assert entered[index].wait(5)
                proceed[0].set()
                assert futures[0].result(timeout=5) == {"first": "one", "second": "two", "ref": "two"}
                proceed[1].set()
                assert futures[1].result(timeout=5) == (
                    {"code": "config_unreadable"}
                    if wizard_warns
                    else {"direct": False, "source": "default", "existing": "absent"}
                )
            finally:
                for event in proceed:
                    event.set()
        assert warnings.warn is original_warn
        assert warnings.filters == original_filters
    assert not captured


@pytest.mark.skipif(not hasattr(os, "fork"), reason="requires fork")
def test_yaml_warning_scope_fork_resets_other_thread_lock_and_hook() -> None:
    from mordred_hermes._core import _yaml_warnings

    ready, release = threading.Event(), threading.Event()
    original_warn = warnings.warn

    def hold_scope_lock() -> None:
        with _yaml_warnings.quiet_yaml_warnings(), _yaml_warnings._lock:
            ready.set()
            assert release.wait(5)

    read_fd, write_fd = os.pipe()
    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(hold_scope_lock)
        pid = None
        try:
            assert ready.wait(5)
            pid = os.fork()
            if pid == 0:
                os.close(read_fd)
                try:
                    assert warnings.warn is original_warn
                    with warnings.catch_warnings(record=True) as captured:
                        warnings.simplefilter("always")
                        with _yaml_warnings.quiet_yaml_warnings():
                            warnings.warn("synthetic_child_secret", YAMLWarning, stacklevel=1)
                        warnings.warn("outside child scope", YAMLWarning, stacklevel=1)
                    assert [str(item.message) for item in captured] == ["outside child scope"]
                    assert warnings.warn is original_warn
                    os.write(write_fd, b"ok")
                finally:
                    os._exit(0)
            os.close(write_fd)
            assert select.select([read_fd], [], [], 5)[0], "forked warning scope hung on inherited lock"
            assert os.read(read_fd, 32) == b"ok"
        finally:
            release.set()
            future.result(timeout=5)
            os.close(read_fd)
            if pid and os.waitpid(pid, os.WNOHANG)[0] == 0:
                os.kill(pid, signal.SIGKILL)
                os.waitpid(pid, 0)
    assert warnings.warn is original_warn


@pytest.mark.skipif(not hasattr(os, "fork"), reason="requires fork")
def test_yaml_warning_scope_fork_preserves_surviving_nested_scopes() -> None:
    from mordred_hermes._core._yaml_warnings import quiet_yaml_warnings

    read_fd, write_fd = os.pipe()
    original_warn = warnings.warn
    pid = None
    try:
        with warnings.catch_warnings(record=True) as captured:
            warnings.simplefilter("always")
            with quiet_yaml_warnings():
                with quiet_yaml_warnings():
                    pid = os.fork()
                    if pid == 0:
                        os.close(read_fd)
                        warnings.warn("synthetic_nested_fork_secret", YAMLWarning, stacklevel=1)
                if pid == 0:
                    warnings.warn("synthetic_outer_fork_secret", YAMLWarning, stacklevel=1)
            if pid == 0:
                assert not captured
        if pid == 0:
            assert warnings.warn is original_warn
            os.write(write_fd, b"ok")
            os._exit(0)
        os.close(write_fd)
        assert select.select([read_fd], [], [], 5)[0], "surviving fork scope did not unwind"
        assert os.read(read_fd, 32) == b"ok"
    finally:
        if pid == 0:
            os._exit(0)
        os.close(read_fd)
        if pid and os.waitpid(pid, os.WNOHANG)[0] == 0:
            os.kill(pid, signal.SIGKILL)
            os.waitpid(pid, 0)


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
