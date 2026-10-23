"""Hermes's direct tool calls (``wizard.direct_tools``): read like Hermes, written by Hermes.

``read_mode`` reads config.yaml with Hermes's loader setup and rule (the 26-case
parity table below). ``set_direct`` never edits the file: it runs Hermes's own
``hermes config set|unset tools.tool_search.enabled`` and checks the result with
``hermes config get``. A fake ``hermes`` console script (a Python script in a
venv-like ``bin/``) records its argv and environment, prints canaries, and
applies or skips the change as each test asks.
"""

from __future__ import annotations

import json
import os
import sys
import traceback
from pathlib import Path
from typing import Any

import pytest

from mordred_hermes import _config_text_io
from mordred_hermes.wizard import direct_tools
from mordred_hermes.wizard import policy_writer as pw
from mordred_hermes.wizard.direct_tools import (
    ERROR_CODES,
    KEY,
    SNIPPET,
    DirectToolsError,
    read_mode,
    set_direct,
)
from tests.test_config_io import fs as fs

posix_only = pytest.mark.skipif(sys.platform == "win32", reason="POSIX paths and a shebang fake")

CANARY = "canary-model-7c1e"
CONFIG = f"# Hermes configuration\nmodel:\n  default: {CANARY}\n"


@pytest.fixture
def home(tmp_path: Path) -> Path:
    path = tmp_path / "hermes-home"
    (path / "mordred").mkdir(parents=True, mode=0o700)
    return path


def write(home: Path, text: str, mode: int = 0o600) -> Path:
    config = home / "config.yaml"
    config.write_text(text, encoding="utf-8")
    os.chmod(config, mode)
    return config


def _manage(home: Path) -> None:
    from mordred_hermes.keyvault._config_bootstrap import _marker_path

    marker = _marker_path(home)
    marker.parent.mkdir(parents=True, exist_ok=True)
    marker.write_text("vault-managed\n", encoding="utf-8")


# -- read: parity with Hermes ---------------------------------------------------------------------
#
# Hermes 0.21.5 (``~/.hermes/hermes-agent``), re-implemented here independently of the module under
# test: ``hermes_yaml.safe_load`` is ruamel ``YAML(typ="safe")`` with ``version = (1, 1)`` (plain
# ``off``/``no``/``n``/``false`` are booleans, ``y``/``yes``/``on``/``true`` too); ``_deep_merge``
# puts the user's file over ``DEFAULT_CONFIG`` (``tools.tool_search.enabled: "auto"``), ignoring a
# ``None`` over a default mapping; ``ToolSearchConfig.from_raw`` turns a non-mapping into
# ``{"enabled": "off" if raw is False else "auto"}`` and reads ``enabled`` with ``_tri_state``:
# ``str(v).strip().lower()``, aliases true/1/yes -> on and false/0/no -> off, else auto/on/off or auto.


def hermes_rule(text: str) -> bool:
    """Is Hermes direct (``enabled == "off"``) for this config.yaml text?"""
    from ruamel.yaml import YAML
    from ruamel.yaml.error import YAMLError

    def load(pure: bool) -> Any:
        yaml = YAML(typ="safe", pure=pure)
        yaml.version = (1, 1)
        return yaml.load(text)

    try:
        user = load(False) or {}  # hermes_yaml.safe_load: the C parser first, then the pure one
    except YAMLError:
        user = load(True) or {}
    tools = user.get("tools")
    tools = tools if isinstance(tools, dict) else {}
    raw = tools.get("tool_search")
    raw = {"enabled": "auto"} if raw is None else raw  # None over the default mapping is ignored
    if not isinstance(raw, dict):
        raw = {"enabled": "off" if raw is False else "auto"}
    value = raw.get("enabled")
    value = "auto" if value is None else value  # the default's "auto" survives a None
    aliases = {"true": "on", "1": "on", "yes": "on", "false": "off", "0": "off", "no": "off"}
    word = str(value).strip().lower()
    return aliases.get(word, word if word in ("auto", "on", "off") else "auto") == "off"


ENABLED = "tools:\n  tool_search:\n    enabled: {}\n"
LEGACY = "tools:\n  tool_search: {}\n"
#: (YAML value, direct for Hermes): 20 values of ``enabled`` and 6 of the legacy scalar.
PARITY = [
    (ENABLED.format("off"), True),
    (ENABLED.format("Off"), True),
    (ENABLED.format("OFF"), True),
    (ENABLED.format('"off"'), True),
    (ENABLED.format("'OFF'"), True),
    (ENABLED.format("no"), True),
    (ENABLED.format("n"), True),  # YAML 1.1 boolean
    (ENABLED.format("N"), True),
    (ENABLED.format("false"), True),
    (ENABLED.format('"false"'), True),
    (ENABLED.format("0"), True),
    (ENABLED.format('"no"'), True),
    (ENABLED.format('"n"'), False),  # a string "n" is not one of _tri_state's spellings
    (ENABLED.format("auto"), False),
    (ENABLED.format("on"), False),  # YAML 1.1 true
    (ENABLED.format("yes"), False),
    (ENABLED.format("y"), False),
    (ENABLED.format("1"), False),
    (ENABLED.format('""'), False),
    (ENABLED.format(""), False),  # null: the default "auto"
    (LEGACY.format("false"), True),
    (LEGACY.format("off"), True),  # YAML 1.1 false
    (LEGACY.format("n"), True),
    (LEGACY.format('"off"'), False),  # a string is not ``False``: Hermes reads "auto"
    (LEGACY.format("0"), False),  # neither is the integer 0
    (LEGACY.format("true"), False),
]


def test_the_parity_table_has_26_cases() -> None:
    assert len(PARITY) == 26 and len({text for text, _ in PARITY}) == 26


@posix_only
@pytest.mark.parametrize("text,direct", PARITY)
def test_read_mode_reads_like_hermes(home: Path, text: str, direct: bool) -> None:
    write(home, text)
    assert hermes_rule(text) is direct  # the table itself follows Hermes's rule
    mode = read_mode(home)
    assert mode["direct"] is direct and mode["source"] in ("config", "default")


DIRECTIVE = "%YAML 1.2\n---\n"


@posix_only
@pytest.mark.parametrize(
    "text",
    [DIRECTIVE + ENABLED.format("n"), DIRECTIVE + LEGACY.format("off"), DIRECTIVE + ENABLED.format("auto")],
    ids=["enabled-n", "legacy-off", "auto"],
)
def test_a_yaml_directive_reads_like_hermes(home: Path, text: str) -> None:
    """Hermes's C-first loader keeps YAML 1.1 under ``%YAML 1.2`` (the pure parser alone would not)."""
    write(home, text)
    assert read_mode(home)["direct"] is hermes_rule(text)


@posix_only
def test_no_config_reads_as_the_default_deferred_mode(home: Path) -> None:
    assert read_mode(home) == {"direct": False, "source": "default"}
    assert sorted(p.name for p in home.iterdir()) == ["mordred"]  # nothing created by a read


@posix_only
@pytest.mark.parametrize(
    "text,expected",
    [
        ('tools:\n  tool_search:\n    enabled: "off"\n', {"direct": True, "source": "config"}),
        ("tools:\n  tool_search:\n    enabled: 'off'\n", {"direct": True, "source": "config"}),  # hermes config set
        ("tools:\n  tool_search: false\n", {"direct": True, "source": "config"}),
        ("tools:\n  tool_search:\n    enabled: on\n", {"direct": False, "source": "config"}),
        ("tools:\n  tool_search:\n    listing: auto\n", {"direct": False, "source": "default"}),
        ("tools: [a, b]\n", {"direct": False, "source": "default"}),
        ("tools:\n", {"direct": False, "source": "default"}),
        ("", {"direct": False, "source": "default"}),
    ],
)
def test_source_and_no_raw_value(home: Path, text: str, expected: dict[str, object]) -> None:
    write(home, text)
    assert read_mode(home) == expected


@posix_only
@pytest.mark.parametrize("text", [f"model: [{CANARY}\n", f"- {CANARY}\n", f"{CANARY}\n", f"a: 1\na: {CANARY}\n"])
def test_unreadable_config_reads_as_unknown_without_any_value(home: Path, text: str) -> None:
    write(home, text)
    assert read_mode(home) == {"direct": None, "source": "unreadable", "code": "config_unreadable"}


DUPLICATE_ANCHOR = f"model: &m {CANARY}\nother: &m second-{CANARY}\ntools:\n  tool_search:\n    enabled: auto\n"


@posix_only
def test_a_yaml_warning_is_unreadable_and_nothing_reaches_any_output(
    home: Path, capfd: pytest.CaptureFixture[str], caplog: pytest.LogCaptureFixture
) -> None:
    """ruamel's ReusedAnchorWarning quotes both source lines: it is captured, never shown."""
    write(home, DUPLICATE_ANCHOR)
    assert read_mode(home) == {"direct": None, "source": "unreadable", "code": "config_unreadable"}
    with pytest.raises(DirectToolsError) as error:
        set_direct(home, True)
    assert error.value.code == "config_unreadable"
    assert CANARY not in "".join(traceback.format_exception(error.value))
    out, err = capfd.readouterr()
    assert CANARY not in out + err + caplog.text


def test_warnings_are_captured_without_changing_the_process_filters() -> None:
    import warnings

    from mordred_hermes.wizard._direct_tools_yaml import hermes_data

    before = list(warnings.filters)
    with pytest.raises(DirectToolsError):
        hermes_data(DUPLICATE_ANCHOR)
    assert warnings.filters == before


# -- the fake ``hermes`` ------------------------------------------------------------------------------

FAKE_HERMES = r"""#!PYTHON
import json, os, sys, time
from pathlib import Path

here = Path(__file__).resolve().parent
plan_file = here / "plan.json"
plan = json.loads(plan_file.read_text()) if plan_file.exists() else {}
args = sys.argv[1:]
with (here / "calls.jsonl").open("a", encoding="utf-8") as log:
    log.write(json.dumps({
        "argv": args, "home": os.environ.get("HERMES_HOME"), "cwd": os.getcwd(),
        "pythonpath": "PYTHONPATH" in os.environ, "pythonhome": "PYTHONHOME" in os.environ,
        "decrypt": os.environ.get("MORDRED_CONFIG_DECRYPT"),
    }) + "\n")
print("CANARY-stdout")
print("CANARY-stderr", file=sys.stderr)
time.sleep(plan.get("sleep", 0))
verb, key = args[1], args[2]
config = Path(os.environ["HERMES_HOME"]) / "config.yaml"
from ruamel.yaml import YAML
yaml = YAML(typ="safe", pure=True)
yaml.version = (1, 1)
data = (yaml.load(config.read_text(encoding="utf-8")) if config.exists() else None) or {}
parts = key.split(".")
if verb == "get":
    node = data
    for part in parts:
        node = node.get(part) if isinstance(node, dict) else None
    value = plan.get("get", node if node is not None else "auto")
    print("false" if value is False else value)
elif plan.get("apply", True):
    if verb == "set":
        node = data
        for part in parts[:-1]:
            node = node.setdefault(part, {})
        node[parts[-1]] = args[3]  # Hermes keeps a string-typed setting a string
    else:
        chain = [data]
        for part in parts[:-1]:
            chain.append(chain[-1].get(part, {}))
        if parts[-1] not in chain[-1]:
            print("Config key not set", file=sys.stderr)
            sys.exit(1)
        del chain[-1][parts[-1]]
        for index in range(len(parts) - 1, 0, -1):
            if not chain[index]:
                del chain[index - 1][parts[index - 1]]
    out = YAML(typ="safe", pure=True)
    out.default_flow_style = False
    with config.open("w", encoding="utf-8") as handle:
        out.dump(data, handle) if data else handle.write("")
if plan.get("managed") and os.environ.get("MORDRED_CONFIG_DECRYPT") != "0" and config.exists():
    config.unlink()  # the lifecycle hook's reseal at exit removes the plaintext working copy
sys.exit(plan.get("exit_" + verb, 0))
"""


class FakeHermes:
    def __init__(self, bin_dir: Path) -> None:
        self.bin = bin_dir

    def plan(self, **plan: Any) -> None:
        (self.bin / "plan.json").write_text(json.dumps(plan), encoding="utf-8")

    def calls(self) -> list[dict[str, Any]]:
        log = self.bin / "calls.jsonl"
        return [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()] if log.exists() else []

    def argv(self) -> list[list[str]]:
        return [call["argv"] for call in self.calls()]


@pytest.fixture
def hermes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> FakeHermes:
    """A venv-like ``bin/`` with this interpreter's ``python`` path and a fake ``hermes`` next to it."""
    bin_dir = tmp_path / "venv" / "bin"
    bin_dir.mkdir(parents=True)
    for name in ("hermes", "hermes.exe"):
        script = bin_dir / name
        script.write_text(FAKE_HERMES.replace("PYTHON", sys.executable).replace("CANARY", CANARY), encoding="utf-8")
        script.chmod(0o755)
    monkeypatch.setattr(direct_tools, "_python", lambda: str(bin_dir / "python"))
    monkeypatch.setenv("PYTHONPATH", "/nonexistent-pythonpath")
    monkeypatch.setenv("MORDRED_CONFIG_DECRYPT", "1")  # the child must get 0 whatever the parent exports
    return FakeHermes(bin_dir)


SET = ["config", "set", KEY, "off"]
UNSET = ["config", "unset", KEY]
GET = ["config", "get", KEY]


@posix_only
def test_on_runs_hermes_config_set_then_checks_with_get(home: Path, hermes: FakeHermes) -> None:
    write(home, CONFIG)
    set_direct(home, True)
    assert hermes.argv() == [SET, GET]
    assert read_mode(home) == {"direct": True, "source": "config"}
    for call in hermes.calls():
        assert call["home"] == str(home) and Path(call["cwd"]).resolve() == home.resolve()
        assert call["pythonpath"] is False and call["pythonhome"] is False
        assert call["decrypt"] == "0"  # the child never materializes or reseals a vault-managed config.yaml


@posix_only
def test_off_runs_hermes_config_unset_then_checks_with_get(home: Path, hermes: FakeHermes) -> None:
    write(home, CONFIG + "tools:\n  tool_search:\n    enabled: 'off'\n")
    set_direct(home, False)
    assert hermes.argv() == [UNSET, GET]
    assert read_mode(home) == {"direct": False, "source": "default"}


@posix_only
def test_off_unsets_the_legacy_boolean_itself(home: Path, hermes: FakeHermes) -> None:
    write(home, "tools:\n  tool_search: false\n  other: 1\n")
    set_direct(home, False)
    assert hermes.argv() == [["config", "unset", "tools.tool_search"], GET]
    assert read_mode(home)["direct"] is False


@posix_only
@pytest.mark.parametrize("text,enabled", [("model: x\n", False), ("tools:\n  tool_search:\n    enabled: off\n", True)])
def test_nothing_runs_when_the_setting_is_already_as_asked(
    home: Path, hermes: FakeHermes, text: str, enabled: bool
) -> None:
    write(home, text)
    set_direct(home, enabled)
    assert hermes.calls() == []


@posix_only
@pytest.mark.parametrize(
    "value", ["auto", '"auto"', "on", "true", "yes", "y", "1", "Auto", ""], ids=lambda v: v or "null"
)
def test_on_replaces_an_absent_value_or_an_explicit_deferral(home: Path, hermes: FakeHermes, value: str) -> None:
    write(home, f"tools:\n  tool_search:\n    enabled: {value}\n")
    set_direct(home, True)
    assert hermes.argv() == [SET, GET]


@posix_only
@pytest.mark.parametrize(
    "text",
    [
        "tools:\n  tool_search:\n    enabled: maybe\n",
        "tools:\n  tool_search:\n    enabled: 2\n",
        "tools:\n  tool_search:\n    enabled: [off]\n",
        'tools:\n  tool_search: "auto"\n',
        "tools:\n  tool_search: true\n",
        "tools:\n  tool_search: 0\n",
    ],
)
def test_on_refuses_a_value_it_does_not_replace_and_runs_nothing(home: Path, hermes: FakeHermes, text: str) -> None:
    config = write(home, text)
    with pytest.raises(DirectToolsError) as error:
        set_direct(home, True)
    assert error.value.code == "config_has_setting"
    assert hermes.calls() == [] and config.read_text(encoding="utf-8") == text


@posix_only
@pytest.mark.parametrize("enabled", [True, False])
def test_a_missing_hermes_command_is_refused(
    home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, enabled: bool
) -> None:
    empty = tmp_path / "empty-venv" / "bin"
    empty.mkdir(parents=True)
    monkeypatch.setattr(direct_tools, "_python", lambda: str(empty / "python"))
    write(home, "tools:\n  tool_search:\n    enabled: 'off'\n" if not enabled else CONFIG)
    with pytest.raises(DirectToolsError) as error:
        set_direct(home, enabled)
    assert error.value.code == "hermes_cli_missing"
    assert SNIPPET == 'tools:\n  tool_search:\n    enabled: "off"\n'


@posix_only
def test_the_runtime_venv_and_desktop_launcher_are_found_under_the_home(
    home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(direct_tools, "_python", lambda: str(tmp_path / "nowhere" / "python"))
    assert direct_tools.hermes_command(home) is None
    launcher = home / "hermes-agent" / ".hermes" / "bin" / "hermes"
    launcher.parent.mkdir(parents=True)
    launcher.write_text("#!/bin/sh\n", encoding="utf-8")
    launcher.chmod(0o755)
    assert direct_tools.hermes_command(home) == launcher
    runtime = home / "hermes-agent" / "venv" / "bin" / "hermes"
    runtime.parent.mkdir(parents=True)
    runtime.write_text("#!/bin/sh\n", encoding="utf-8")
    runtime.chmod(0o755)
    assert direct_tools.hermes_command(home) == runtime


@posix_only
@pytest.mark.parametrize("verb", ["set", "get"])
def test_a_non_zero_exit_is_config_write_failed(home: Path, hermes: FakeHermes, verb: str) -> None:
    write(home, CONFIG)
    hermes.plan(**{f"exit_{verb}": 3})
    with pytest.raises(DirectToolsError) as error:
        set_direct(home, True)
    assert error.value.code == "config_write_failed"


@posix_only
@pytest.mark.parametrize("enabled,plan", [(True, {"apply": False}), (True, {"get": "auto"}), (False, {"get": "off"})])
def test_a_result_hermes_does_not_read_as_asked_is_config_write_failed(
    home: Path, hermes: FakeHermes, enabled: bool, plan: dict[str, Any]
) -> None:
    write(home, CONFIG if enabled else "tools:\n  tool_search:\n    enabled: 'off'\n")
    hermes.plan(**plan)
    with pytest.raises(DirectToolsError) as error:
        set_direct(home, enabled)
    assert error.value.code == "config_write_failed"


@posix_only
def test_a_hermes_that_hangs_is_stopped_at_the_timeout(
    home: Path, hermes: FakeHermes, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(direct_tools, "HERMES_TIMEOUT_S", 0.5)
    write(home, CONFIG)
    hermes.plan(sleep=5)
    with pytest.raises(DirectToolsError) as error:
        set_direct(home, True)
    assert error.value.code == "config_write_failed"


@posix_only
def test_hermes_output_is_never_shown(
    home: Path, hermes: FakeHermes, capfd: pytest.CaptureFixture[str], caplog: pytest.LogCaptureFixture
) -> None:
    write(home, CONFIG)
    set_direct(home, True)
    set_direct(home, False)
    hermes.plan(exit_set=1)
    with pytest.raises(DirectToolsError):
        set_direct(home, True)
    out, err = capfd.readouterr()
    assert CANARY not in out + err + caplog.text


@posix_only
@pytest.mark.parametrize("enabled", [True, False])
def test_a_sealed_away_config_is_refused_before_hermes_runs(home: Path, hermes: FakeHermes, enabled: bool) -> None:
    _manage(home)
    assert read_mode(home) == {"direct": None, "source": "unreadable", "code": "config_vault_managed"}
    with pytest.raises(DirectToolsError) as error:
        set_direct(home, enabled)
    assert error.value.code == "config_vault_managed"
    assert hermes.calls() == [] and not (home / "config.yaml").exists()


@posix_only
def test_a_vault_managed_config_on_disk_is_changed_through_hermes(
    home: Path, hermes: FakeHermes, monkeypatch: pytest.MonkeyPatch
) -> None:
    # This test home has a marker but no vault: Mordred's start-up hook in the fake's venv would
    # (rightly) refuse to start; with a real vault it opens and reseals config.yaml around the command.
    monkeypatch.setenv("MORDRED_CONFIG_DECRYPT", "0")
    _manage(home)
    write(home, CONFIG)
    set_direct(home, True)
    assert hermes.argv() == [SET, GET]


@posix_only
@pytest.mark.parametrize("enabled", [True, False])
def test_an_unreadable_config_is_refused_before_hermes_runs(home: Path, hermes: FakeHermes, enabled: bool) -> None:
    config = write(home, f"model: [{CANARY}\n")
    with pytest.raises(DirectToolsError) as error:
        set_direct(home, enabled)
    assert error.value.code == "config_unreadable"
    assert CANARY not in "".join(traceback.format_exception(error.value))
    assert hermes.calls() == [] and config.read_text(encoding="utf-8") == f"model: [{CANARY}\n"


def test_error_codes_are_closed() -> None:
    assert ERROR_CODES == (
        "config_unreadable",
        "config_vault_managed",
        "config_write_failed",
        "config_has_setting",
        "hermes_cli_missing",
        "config_unsupported_shape",
    )


def test_mordred_never_writes_config_yaml_itself() -> None:
    """The writer modules are gone from the delegating code: no round-trip dump, no atomic write."""
    source = Path(direct_tools.__file__).read_text(encoding="utf-8")
    yaml_side = (Path(direct_tools.__file__).parent / "_direct_tools_yaml.py").read_text(encoding="utf-8")
    for text in (source, yaml_side):
        assert "_atomic_write_text" not in text and "PolicyWriter" not in text and ".dump(" not in text
        assert "write_text" not in text and "_round_trip_yaml" not in text


# -- Windows: the same delegation; the read goes through the checked snapshot ------------------------


@pytest.fixture
def windows(fs, monkeypatch: pytest.MonkeyPatch):
    backend, paths = fs
    monkeypatch.setattr(_config_text_io, "_windows", lambda: True)
    monkeypatch.setattr(pw, "_windows", lambda: True, raising=False)
    return backend, paths


def put(directory: Any, name: str, data: bytes) -> None:
    directory.files[name] = data, directory.backend.identity()


def test_windows_reads_through_the_checked_snapshot(windows) -> None:
    b, paths = windows
    put(b.home, "config.yaml", b"tools:\n  tool_search:\n    enabled: off\n")
    assert read_mode(paths.home) == {"direct": True, "source": "config"}
    put(b.home, "config.yaml", b"# only a comment\n")
    assert read_mode(paths.home)["code"] == "config_unreadable"  # as for the checked writer


@posix_only
def test_windows_delegates_to_hermes_exe_and_never_publishes_itself(windows, hermes: FakeHermes) -> None:
    b, paths = windows
    put(b.home, "config.yaml", CONFIG.encode())
    paths.home.mkdir(parents=True, exist_ok=True)
    before = b.home.files.copy(), b.policy.files.copy()
    set_direct(paths.home, True)
    assert hermes.argv() == [SET, GET]
    assert (b.home.files, b.policy.files) == before  # no PolicyWriter transaction
    assert direct_tools.hermes_command(paths.home) == hermes.bin / "hermes.exe"


# -- the real Hermes CLI of the repo venv -------------------------------------------------------------


def _repo_hermes() -> Path | None:
    candidate = Path(sys.executable).parent / ("hermes.exe" if sys.platform == "win32" else "hermes")
    try:
        import hermes_cli.config  # noqa: F401
    except ImportError:
        return None
    return candidate if candidate.is_file() else None


@posix_only
@pytest.mark.skipif(_repo_hermes() is None, reason="no hermes-agent (hermes console script) in this venv")
def test_the_real_hermes_config_set_unset_get(home: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """hermes-agent 0.19 (the repo venv) has ``config set/unset/get``; 0.21 keeps the same commands."""
    monkeypatch.setenv("MORDRED_CONFIG_DECRYPT", "0")  # never the developer's vault, whatever the home
    config = write(home, "model:\n  default: x\n")
    set_direct(home, True)
    assert read_mode(home) == {"direct": True, "source": "config"}
    assert "enabled: 'off'" in config.read_text(encoding="utf-8")  # Hermes stores the string 'off'
    set_direct(home, False)
    assert read_mode(home) == {"direct": False, "source": "default"}


@posix_only
@pytest.mark.skipif(_repo_hermes() is None, reason="no hermes-agent (hermes console script) in this venv")
def test_the_real_hermes_never_runs_for_a_shared_mapping(home: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Hermes's setter would change ``other.enabled`` too: Mordred refuses before running it."""
    monkeypatch.setenv("MORDRED_CONFIG_DECRYPT", "0")
    config = write(home, SHARED.format("auto"))
    with pytest.raises(DirectToolsError) as error:
        set_direct(home, True)
    assert error.value.code == "config_unsupported_shape"
    assert config.read_text(encoding="utf-8") == SHARED.format("auto")
    from ruamel.yaml import YAML

    assert YAML(typ="safe", pure=True).load(config.read_text(encoding="utf-8"))["other"]["enabled"] == "auto"


# -- pass 3: the reader child, the lifecycle hook, shared mappings, relative homes, concurrency -------

SHARED = "other: &shared\n  enabled: {}\ntools:\n  tool_search: *shared\n"
WARNING_DOCS = {
    "reused-anchor": f"model: &m {CANARY}\nother: &m second-{CANARY}\n",
    "mantissa-no-dot": f"model:\n  default: {CANARY}\n  temperature: 1e3\n",
}


@pytest.fixture
def fresh_reader():
    """No cached reader answers (each read below spawns the child)."""
    direct_tools._ANSWERS.clear()
    yield
    direct_tools._ANSWERS.clear()


@pytest.mark.parametrize("name", list(WARNING_DOCS))
def test_the_reader_raises_these_warnings_and_refuses(name: str) -> None:
    """In the child the YAML warning is raised, recorded and turned into config_unreadable."""
    from mordred_hermes.wizard._direct_tools_yaml import answer

    assert answer(WARNING_DOCS[name]) == {"code": "config_unreadable"}


@posix_only
@pytest.mark.parametrize("name", list(WARNING_DOCS))
def test_yaml_warnings_never_reach_this_process_even_with_other_warning_contexts(
    home: Path,
    fresh_reader: None,
    capfd: pytest.CaptureFixture[str],
    caplog: pytest.LogCaptureFixture,
    name: str,
) -> None:
    """Another thread keeps entering and leaving warnings.catch_warnings() while config.yaml is read:
    the parse runs in the child, whose stderr is dropped, so nothing of the document gets out."""
    import threading
    import warnings

    write(home, WARNING_DOCS[name])
    stop = threading.Event()

    def churn() -> None:
        while not stop.is_set():
            with warnings.catch_warnings():
                warnings.simplefilter("default")

    thread = threading.Thread(target=churn, daemon=True)
    thread.start()
    try:
        for _ in range(5):
            direct_tools._ANSWERS.clear()
            assert read_mode(home) == {"direct": None, "source": "unreadable", "code": "config_unreadable"}
    finally:
        stop.set()
        thread.join(timeout=5)
    out, err = capfd.readouterr()
    assert CANARY not in out + err + caplog.text
    assert "Warning" not in out + err


@posix_only
def test_the_reader_child_gets_the_text_on_stdin_and_answers_one_json_line(
    home: Path, fresh_reader: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    import subprocess

    seen: list[dict[str, Any]] = []
    real = subprocess.run

    def spy(argv: list[str], **kwargs: Any) -> Any:
        seen.append({"argv": argv, **kwargs})
        return real(argv, **kwargs)

    monkeypatch.setenv("PYTHONPATH", "/nonexistent-pythonpath")
    monkeypatch.setattr(direct_tools.subprocess, "run", spy)
    write(home, "tools:\n  tool_search:\n    enabled: off\n")
    assert read_mode(home) == {"direct": True, "source": "config"}
    (call,) = seen
    assert call["argv"][:3] == [sys.executable, "-I", "-c"] and call["cwd"] is None
    assert call["input"] == b"tools:\n  tool_search:\n    enabled: off\n"  # the text, never a path
    assert str(home) not in " ".join(call["argv"])
    assert "PYTHONPATH" not in call["env"] and "PYTHONHOME" not in call["env"]
    assert call["env"]["MORDRED_CONFIG_DECRYPT"] == "0"  # the reader never materializes or reseals config.yaml
    assert call["timeout"] == direct_tools.READER_TIMEOUT_S


@posix_only
def test_an_unchanged_file_is_answered_from_the_cache(
    home: Path, fresh_reader: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[str] = []
    real = direct_tools._spawn_reader

    def counted(text: str, strict_empty: bool) -> Any:
        calls.append(text)
        return real(text, strict_empty)

    monkeypatch.setattr(direct_tools, "_spawn_reader", counted)
    write(home, CONFIG)
    for _ in range(3):
        assert read_mode(home) == {"direct": False, "source": "default"}
    write(home, CONFIG + "tools:\n  tool_search:\n    enabled: off\n")
    assert read_mode(home)["direct"] is True
    assert len(calls) == 2
    for index in range(10):
        write(home, f"model: m{index}\n")
        read_mode(home)
    assert len(direct_tools._ANSWERS) == 8


@posix_only
@pytest.mark.parametrize(
    "stdout,code",
    [
        (b"", 0),
        (b"not json\n", 0),
        (b'{"direct": "yes", "source": "config", "existing": "absent"}\n', 0),
        (b'{"direct": true, "source": "config", "existing": "absent", "raw": "x"}\n', 0),
        (b'{"code": "something_else"}\n', 0),
        (b'{"direct": true, "source": "config", "existing": "absent"}\n', 1),
    ],
)
def test_a_reader_answer_that_does_not_conform_is_unreadable(
    home: Path, fresh_reader: None, monkeypatch: pytest.MonkeyPatch, stdout: bytes, code: int
) -> None:
    import subprocess

    monkeypatch.setattr(
        direct_tools.subprocess, "run", lambda argv, **kwargs: subprocess.CompletedProcess(argv, code, stdout, b"")
    )
    write(home, CONFIG)
    assert read_mode(home) == {"direct": None, "source": "unreadable", "code": "config_unreadable"}
    assert direct_tools._ANSWERS == {}  # a failed answer is never cached


@posix_only
def test_a_reader_that_hangs_is_unreadable(home: Path, fresh_reader: None, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(direct_tools, "READER_TIMEOUT_S", 0.5)
    monkeypatch.setattr(direct_tools, "_READER_BOOT", "import time; time.sleep(5)")
    write(home, CONFIG)
    assert read_mode(home)["code"] == "config_unreadable"


@posix_only
def test_the_child_hermes_never_reseals_the_running_processs_config(
    home: Path, hermes: FakeHermes, monkeypatch: pytest.MonkeyPatch
) -> None:
    """With the lifecycle hook, each child hermes would remove the working copy at exit."""
    monkeypatch.setenv("MORDRED_CONFIG_DECRYPT", "1")
    _manage(home)
    write(home, CONFIG)
    hermes.plan(managed=True)
    set_direct(home, True)
    assert (home / "config.yaml").exists()
    assert read_mode(home) == {"direct": True, "source": "config"}


@posix_only
@pytest.mark.parametrize("enabled,value", [(True, "auto"), (False, "'off'")])
def test_a_shared_tools_or_tool_search_mapping_is_refused_before_hermes_runs(
    home: Path, hermes: FakeHermes, enabled: bool, value: str
) -> None:
    config = write(home, SHARED.format(value))
    with pytest.raises(DirectToolsError) as error:
        set_direct(home, enabled)
    assert error.value.code == "config_unsupported_shape"
    assert hermes.calls() == [] and config.read_text(encoding="utf-8") == SHARED.format(value)


@posix_only
@pytest.mark.parametrize(
    "text",
    [
        "base: &t\n  tool_search:\n    enabled: auto\ntools: *t\n",
        "base: &t\n  tool_search:\n    enabled: auto\ntools:\n  <<: *t\n  other: 1\n",
        "shared: &s\n  enabled: auto\nlist:\n  - *s\ntools:\n  tool_search: *s\n",
    ],
    ids=["tools-alias", "tool-search-through-a-merge", "alias-in-a-list"],
)
def test_every_shared_shape_is_refused(home: Path, hermes: FakeHermes, text: str) -> None:
    write(home, text)
    with pytest.raises(DirectToolsError) as error:
        set_direct(home, True)
    assert error.value.code == "config_unsupported_shape" and hermes.calls() == []


@posix_only
def test_a_relative_home_is_made_absolute_for_the_child(
    tmp_path: Path, hermes: FakeHermes, monkeypatch: pytest.MonkeyPatch
) -> None:
    profile = tmp_path / "profile"
    (profile / "mordred").mkdir(parents=True)
    (profile / "config.yaml").write_text(CONFIG, encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    set_direct(Path("profile"), True)
    absolute = str(Path.cwd() / "profile")
    assert [call["home"] for call in hermes.calls()] == [absolute, absolute]
    assert all(Path(call["cwd"]).resolve() == profile.resolve() for call in hermes.calls())
    assert read_mode(Path("profile")) == {"direct": True, "source": "config"}
    assert not (profile / "profile").exists()
    assert direct_tools.hermes_command(Path("profile")) == hermes.bin / "hermes"


@posix_only
def test_two_simultaneous_off_requests_both_succeed_with_one_unset(home: Path, hermes: FakeHermes) -> None:
    import threading

    write(home, CONFIG + "tools:\n  tool_search:\n    enabled: 'off'\n")
    hermes.plan(sleep=0.3)  # widen the window in which the second request arrives
    barrier = threading.Barrier(2)
    errors: list[BaseException] = []

    def off() -> None:
        barrier.wait()
        try:
            set_direct(home, False)
        except BaseException as exc:  # recorded for the assertion below
            errors.append(exc)

    threads = [threading.Thread(target=off) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30)
    assert errors == []
    assert [call["argv"][1] for call in hermes.calls()].count("unset") == 1
    assert read_mode(home) == {"direct": False, "source": "default"}
