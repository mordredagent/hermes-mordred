"""Unit tests for the shared fail-closed runtime gate (``wizard._runtime_gate``).

The env / config seals' end-to-end gate behavior stays covered by
``test_wizard_env_decrypt_cli.py`` / ``test_wizard_config_decrypt_cli.py``;
these tests pin the shared core's own contract: the platform / force
short-circuits, injected-over-default probe dispatch, and the guidance
message assembly the two seals slot their target-specific text into.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from mordred_hermes.wizard._runtime_gate import RuntimeProbe, runtime_gate

_MECHANISM = "  mechanism line one\n  mechanism line two\n"
_TAIL = "  tail line one\n  tail line two."


def _boom_probe(*, home: Path) -> tuple[bool, str]:
    raise AssertionError("probe must not be consulted")


def _gate(
    home: Path,
    *,
    platform: str = "darwin",
    runtime_probe: RuntimeProbe | None = None,
    force_runtime_unverified: bool = False,
    default_probe: RuntimeProbe | None = None,
) -> int:
    if default_probe is None:
        default_probe = lambda *, home: (True, "ok")  # noqa: E731
    return runtime_gate(
        home=home,
        platform=platform,
        runtime_probe=runtime_probe,
        force_runtime_unverified=force_runtime_unverified,
        default_probe=default_probe,
        target="thing.yaml",
        mechanism=_MECHANISM,
        rerun_tail=_TAIL,
    )


class TestShortCircuits:
    def test_off_macos_never_consults_a_probe(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        rc = _gate(tmp_path, platform="linux", runtime_probe=_boom_probe, default_probe=_boom_probe)
        assert rc == 0
        out = capsys.readouterr()
        assert out.out == "" and out.err == ""

    def test_force_never_consults_a_probe(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        rc = _gate(tmp_path, force_runtime_unverified=True, runtime_probe=_boom_probe, default_probe=_boom_probe)
        assert rc == 0
        out = capsys.readouterr()
        assert out.out == "" and out.err == ""


class TestProbeDispatch:
    def test_probe_ok_passes_silently(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        rc = _gate(tmp_path, runtime_probe=lambda *, home: (True, "ok"))
        assert rc == 0
        assert capsys.readouterr().err == ""

    def test_injected_probe_wins_over_default(self, tmp_path: Path) -> None:
        assert _gate(tmp_path, runtime_probe=lambda *, home: (True, "ok"), default_probe=_boom_probe) == 0

    def test_default_probe_used_when_none_injected(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        rc = _gate(tmp_path, default_probe=lambda *, home: (False, "shim absent"))
        assert rc == 1
        assert "shim absent" in capsys.readouterr().err


class TestRefusalMessage:
    def test_message_assembles_target_detail_mechanism_and_tail(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # Pin runtime discovery to a deterministic interpreter so the uv line
        # is assertable regardless of what this host has on $PATH.
        monkeypatch.setenv("MORDRED_HERMES_RUNTIME_PYTHON", sys.executable)
        rc = _gate(tmp_path, runtime_probe=lambda *, home: (False, "no shim"))
        assert rc == 1
        err = capsys.readouterr().err
        assert "refusing to vault-seal thing.yaml — no shim.\n" in err
        assert _MECHANISM in err
        assert "  (run from the repo root):\n" in err
        assert f"    uv pip install --python {sys.executable} -e './mordred-hermes[macos]'\n" in err
        assert _TAIL in err

    def test_runtime_python_falls_back_under_home(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # With no override, no managed venv under home, and no `hermes` on
        # $PATH, the guidance still names a concrete interpreter path.
        monkeypatch.delenv("MORDRED_HERMES_RUNTIME_PYTHON", raising=False)
        monkeypatch.setenv("PATH", str(tmp_path / "empty-bin"))
        rc = _gate(tmp_path, runtime_probe=lambda *, home: (False, "no shim"))
        assert rc == 1
        expected = tmp_path / "hermes-agent" / "venv" / "bin" / "python3"
        assert str(expected) in capsys.readouterr().err
