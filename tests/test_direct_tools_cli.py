"""``hermes-mordred direct-tools on | off | status``: output, exit codes and no other config value."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import pytest

from mordred_hermes.wizard import direct_tools_cli
from mordred_hermes.wizard._cli_parsers import _setup_subparser
from mordred_hermes.wizard.direct_tools import DirectToolsError

# The real Hermes home here is a POSIX temporary directory; the Windows writer path is covered
# on the fake canonical coordinator in test_direct_tools.py.
pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="the POSIX writer path")

CANARIES = ("canary-model-5d2b", "canary-key-env-91f0", "https://canary.example.invalid/v1")
CONFIG = f"""# kept
model:
  default: {CANARIES[0]}
  key_env: {CANARIES[1]}
  base_url: {CANARIES[2]}
tools:
  tool_search:
    listing: auto
"""
RESTART = "Restart Hermes (or Hermes Desktop) for this to take effect."


@pytest.fixture
def home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    path = tmp_path / "hermes-home"
    (path / "mordred").mkdir(parents=True, mode=0o700)
    (path / "config.yaml").write_text(CONFIG, encoding="utf-8")
    (path / "config.yaml").chmod(0o600)
    monkeypatch.setattr(direct_tools_cli, "_home", lambda: path)
    return path


def run(*argv: str) -> int:
    parser = argparse.ArgumentParser()
    _setup_subparser(parser)
    args = parser.parse_args(["direct-tools", *argv])
    return int(args.func(args))


def no_canary(*texts: str) -> bool:
    return not any(canary in text for canary in CANARIES for text in texts)


def test_the_parser_offers_on_off_and_status() -> None:
    parser = argparse.ArgumentParser()
    _setup_subparser(parser)
    for command in ("on", "off", "status"):
        assert parser.parse_args(["direct-tools", command]).direct_tools_command == command
    with pytest.raises(SystemExit):
        parser.parse_args(["direct-tools"])
    with pytest.raises(SystemExit):
        parser.parse_args(["direct-tools", "auto"])


def test_status_of_the_default(home: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert run("status") == 0
    out, err = capsys.readouterr()
    assert out == "direct tool calls: off (default)\n" and err == ""


def test_on_prints_the_change_both_trade_offs_and_the_restart_note(
    home: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert run("on") == 0
    out, err = capsys.readouterr()
    lines = out.splitlines()
    assert lines[0] == 'direct tool calls: off -> on (tools.tool_search.enabled: "off" written to config.yaml).'
    assert "8,000 more prompt tokens" in lines[1]
    assert "remote connectors" in lines[2] and "unavailable" in lines[2]
    assert lines[3] == RESTART and len(lines) == 4 and err == ""
    assert run("status") == 0
    assert capsys.readouterr().out == "direct tool calls: on (config)\n"


def test_off_prints_the_change_both_trade_offs_and_the_restart_note(
    home: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert run("on") == 0
    capsys.readouterr()
    assert run("off") == 0
    out, _ = capsys.readouterr()
    lines = out.splitlines()
    assert lines[0].startswith("direct tool calls: on -> off (")
    assert "prompts are smaller" in lines[1] and "tool_search and tool_call" in lines[1]
    assert "remote connectors" in lines[2]
    assert lines[3] == RESTART and len(lines) == 4
    assert (home / "config.yaml").read_text(encoding="utf-8") == CONFIG


@pytest.mark.parametrize("command,state", [("off", "off (default)"), ("on", "on (config)")])
def test_an_unchanged_setting_says_so_and_writes_nothing(
    home: Path, capsys: pytest.CaptureFixture[str], command: str, state: str
) -> None:
    if command == "on":
        run("on")
        capsys.readouterr()
    before = (home / "config.yaml").stat().st_mtime_ns
    assert run(command) == 0
    out, _ = capsys.readouterr()
    assert out == f"direct tool calls: already {state}; nothing changed.\n"
    assert (home / "config.yaml").stat().st_mtime_ns == before


@pytest.mark.parametrize("command", ["on", "off", "status"])
def test_an_unreadable_config_is_refused_with_exit_1(
    home: Path, capsys: pytest.CaptureFixture[str], command: str
) -> None:
    (home / "config.yaml").write_text(f"model: [{CANARIES[0]}\n", encoding="utf-8")
    assert run(command) == 1
    out, err = capsys.readouterr()
    assert out == ""
    assert "direct-tools refused (config_unreadable)" in err and "nothing was changed" in err
    assert no_canary(out, err)


@pytest.mark.parametrize(
    "code", ["config_vault_managed", "config_write_failed", "config_unsupported_shape", "config_has_setting"]
)
def test_a_refused_write_exits_1_with_its_code_and_remedy(
    home: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch, code: str
) -> None:
    def refuse(home: Path, enabled: bool) -> None:
        raise DirectToolsError(code)

    monkeypatch.setattr("mordred_hermes.wizard.direct_tools.set_direct", refuse)
    assert run("on") == 1
    out, err = capsys.readouterr()
    assert out == "" and f"direct-tools refused ({code})" in err
    assert direct_tools_cli.REMEDIES[code] in err


def test_a_sealed_away_config_is_refused_as_vault_managed(home: Path, capsys: pytest.CaptureFixture[str]) -> None:
    from mordred_hermes.keyvault._config_bootstrap import _marker_path

    (home / "config.yaml").unlink()
    _marker_path(home).write_text("vault-managed\n", encoding="utf-8")
    assert run("status") == 1
    assert "direct-tools refused (config_vault_managed)" in capsys.readouterr().err
    assert run("on") == 1
    assert "encryption disable config" in capsys.readouterr().err
    assert not (home / "config.yaml").exists()


def test_no_other_config_value_is_ever_printed(home: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """Canary: the model, its key variable and its endpoint never appear in any output."""
    for command in ("status", "on", "status", "on", "off", "status", "off"):
        run(command)
    out, err = capsys.readouterr()
    assert out and no_canary(out, err)


def test_every_closed_code_has_a_remedy() -> None:
    from mordred_hermes.wizard.direct_tools import ERROR_CODES

    assert set(direct_tools_cli.REMEDIES) == set(ERROR_CODES)
    assert "Edit config.yaml by hand." in direct_tools_cli.REMEDIES["config_unsupported_shape"]
    assert "Edit config.yaml by hand." in direct_tools_cli.REMEDIES["config_has_setting"]


def test_a_yaml_warning_prints_nothing_but_the_refusal(home: Path, capfd: pytest.CaptureFixture[str]) -> None:
    (home / "config.yaml").write_text(f"model: &m {CANARIES[0]}\nother: &m {CANARIES[1]}\n", encoding="utf-8")
    for command in ("status", "on", "off"):
        assert run(command) == 1
    out, err = capfd.readouterr()
    assert "direct-tools refused (config_unreadable)" in err and no_canary(out, err)
