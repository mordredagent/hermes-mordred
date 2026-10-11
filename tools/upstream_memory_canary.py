"""Run the selected-source canary; publish only a fixed classification token."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from typing import Any

import pytest


class Outcomes:
    def __init__(self) -> None:
        self.passed = 0
        self.drift = False
        self.unavailable = False

    def record(self, outcome: str, error: BaseException | None) -> None:
        if outcome == "passed":
            self.passed += 1
        elif outcome == "failed" and isinstance(error, (AssertionError, pytest.fail.Exception)):
            self.drift = True
        elif outcome != "passed":
            self.unavailable = True

    def status(self, code: int) -> str:
        if self.unavailable or code not in (0, 1) or (not self.passed and not self.drift):
            return "unavailable"
        if code == 1 and not self.drift:
            return "unavailable"
        return "drift" if self.drift else "ok"

    @pytest.hookimpl(hookwrapper=True)
    def pytest_runtest_makereport(self, item: Any, call: Any) -> Any:
        outcome = yield
        report = outcome.get_result()
        if report.when == "call" or report.failed or report.skipped:
            self.record(report.outcome, call.excinfo.value if call.excinfo is not None else None)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--status-file", required=True, type=Path)
    args = parser.parse_args()
    args.status_file.write_text("unavailable\n", encoding="utf-8")
    if not os.environ.get("HERMES_HOME"):
        print("HERMES_HOME must be isolated before interpreter startup", file=sys.stderr)
        return 2
    # Protect local tests._helpers from the selected checkout's tests package.
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    outcomes = Outcomes()
    code = pytest.main(["-q", "-s", "tests/test_keyvault_memory_hook_canary.py"], plugins=[outcomes])
    status = outcomes.status(int(code))
    args.status_file.write_text(status + "\n", encoding="utf-8")
    return {"ok": 0, "drift": 1, "unavailable": 2}[status]


if __name__ == "__main__":
    raise SystemExit(main())
