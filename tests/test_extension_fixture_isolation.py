"""Interleaved file arguments must retain extension isolation or refuse collection."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

import mordred_hermes

_PROBE = r"""
import json, os, sys
from pathlib import Path
import pytest

output = Path(sys.argv[1])
missing = sys.argv[2]
target = "tests/extension/test_telegram_local_llm.py::test_success_still_returns_the_local_answer"

class Probe:
    def pytest_collection_modifyitems(self, items):
        # Collect all three modules first: selection must not hide directory re-entry.
        items[:] = [item for item in items if item.nodeid == target]
        assert len(items) == 1
        item = items[0]
        if missing:
            item.fixturenames.remove(missing)
        (output / "closure.json").write_text(json.dumps(item.fixturenames))

    def pytest_runtest_call(self, item):
        from mordred_hermes._home import hermes_home
        # This hook runs only after collection and fixture setup, before the real HTTP body.
        home = hermes_home()
        (output / "called.json").write_text(json.dumps({
            "home": str(home), "tmp_path": str(item.funcargs["tmp_path"]),
        }))
        assert home == item.funcargs["tmp_path"]

    def pytest_runtest_logreport(self, report):
        if report.when == "call":
            (output / "result.json").write_text(json.dumps({"node": report.nodeid, "outcome": report.outcome}))

status = pytest.main([
    "-q",
    "tests/extension/test_telegram_llm_settings.py",
    "tests/test_config_text_io.py",
    "tests/extension/test_telegram_local_llm.py",
], plugins=[Probe()])
import mordred_hermes
(output / "origin.json").write_text(json.dumps({"package": mordred_hermes.__file__, "pytest": pytest.__version__}))
raise SystemExit(status)
"""


@pytest.mark.parametrize("missing", ["", "_isolated_home", "_memory_encryption_on"])
def test_interleaved_extension_collection_keeps_isolation_or_refuses_before_body(tmp_path: Path, missing: str) -> None:
    env = dict(os.environ, HERMES_HOME=str(tmp_path / "ambient-home"))
    result = subprocess.run(
        [sys.executable, "-c", _PROBE, str(tmp_path), missing],
        cwd=Path(__file__).resolve().parents[1],
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
    )
    output = result.stdout + result.stderr
    origin = json.loads((tmp_path / "origin.json").read_text())
    assert origin["package"] == mordred_hermes.__file__
    if missing:
        assert result.returncode == pytest.ExitCode.USAGE_ERROR, output
        assert "extension isolation fixtures missing" in output
        assert missing in output
        assert not (tmp_path / "called.json").exists()
    else:
        assert result.returncode == 0, output
        report = json.loads((tmp_path / "result.json").read_text())
        assert report["outcome"] == "passed"  # The actual Telegram service/HTTP success body ran.
        closure = json.loads((tmp_path / "closure.json").read_text())
        assert {"_isolated_home", "_memory_encryption_on"} <= set(closure)
        call = json.loads((tmp_path / "called.json").read_text())
        assert call["home"] == call["tmp_path"]
        assert call["home"] != env["HERMES_HOME"]
