"""``python -m mordred_hermes`` is the ``hermes-mordred`` console script.

The installer's Hermes Desktop wrapper runs the CLI through the managed
launcher's ``--run-module mordred_hermes``, which hands the module to
``runpy.run_module(..., run_name="__main__", alter_sys=True)`` and then calls
``sys.exit(0)``: the module itself must raise ``SystemExit`` with the CLI's
exit code, or every failure would be reported as success.
"""

from __future__ import annotations

import subprocess
import sys

#: What the Desktop bootstrap does with `--run-module <module> [args...]`.
_MANAGED_BOOTSTRAP = (
    "import runpy, sys\n"
    "module = sys.argv.pop(2)\n"
    "del sys.argv[1]\n"
    "runpy.run_module(module, run_name='__main__', alter_sys=True)\n"
    "sys.exit(0)\n"
)


def _python(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run([sys.executable, *args], check=False, capture_output=True, text=True, timeout=120)


def test_python_m_runs_the_hermes_mordred_cli() -> None:
    result = _python("-m", "mordred_hermes", "--help")

    assert result.returncode == 0, result.stderr
    assert result.stdout.startswith("usage: hermes-mordred")


def test_managed_launcher_run_module_keeps_the_cli_exit_code() -> None:
    ok = _python("-c", _MANAGED_BOOTSTRAP, "--run-module", "mordred_hermes", "--help")
    assert ok.returncode == 0, ok.stderr
    assert ok.stdout.startswith("usage: hermes-mordred")

    bad = _python("-c", _MANAGED_BOOTSTRAP, "--run-module", "mordred_hermes", "--no-such-option")
    assert bad.returncode == 2
    assert "hermes-mordred: error:" in bad.stderr


def test_importing_the_entry_module_does_not_run_the_cli() -> None:
    result = _python("-c", "import mordred_hermes.__main__")

    assert result.returncode == 0, result.stderr
    assert result.stdout == ""
