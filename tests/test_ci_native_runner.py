"""Selected Windows modules must retain critical coverage without duplicates."""

from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / "tools/run_ci_native_tests.py"


def tool():
    assert TOOL.is_file(), "selected native test runner is missing"
    spec = importlib.util.spec_from_file_location("run_ci_native_tests", TOOL)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_whole_modules_replace_only_their_critical_nodes() -> None:
    assert tool().select_nodes(
        ["tests/test_first.py", "tests/test_second.py"],
        ["tests/test_first.py::test_a[param]", "tests/test_other.py::test_c", "tests/test_second.py::Test::test_b"],
    ) == ["tests/test_first.py", "tests/test_second.py", "tests/test_other.py::test_c"]


def test_critical_only_retains_every_original_node() -> None:
    nodes = ["tests/test_a.py::test_one[x]", "tests/test_a.py::test_one[y]"]
    assert tool().select_nodes([], nodes) == nodes


@pytest.mark.parametrize("modules", [["../outside.py"], ["tests/test_a.py", "tests/test_a.py"], ["tests/a.py::test_x"]])
def test_refuses_unsafe_or_duplicate_modules(modules) -> None:
    with pytest.raises(ValueError):
        tool().select_nodes(modules, ["tests/test_known.py::test_safe"])


def test_empty_selection_never_runs_an_unintended_entire_suite() -> None:
    with pytest.raises(ValueError):
        tool().select_nodes([], [])


@pytest.mark.parametrize("exit_code", [0, 1, 5])
def test_runner_preserves_pytest_failure_and_the_exact_selected_cases(tmp_path, monkeypatch, exit_code) -> None:
    runner = tool()
    evidence = ModuleType("ci_evidence")
    evidence.load_policy = lambda path: {
        "mode": "ordinary",
        "windows": True,
        "windows_modules": ["tests/test_private_fs.py"],
    }
    critical = ModuleType("run_critical_tests")
    nodes = ["tests/test_private_fs.py::test_one", "tests/test_config_io.py::test_two"]
    critical.select_cases = lambda platform: [("risk", node) for node in nodes]
    observed = []

    def run_cases(selected, **kwargs):
        observed.append((selected, kwargs))
        return exit_code

    critical.run_cases = run_cases
    monkeypatch.setattr(runner, "_load_sibling", lambda name: evidence if name == "ci_evidence" else critical)
    junit = tmp_path / "native.xml"
    assert runner.main(["--policy", "policy.json", "--junitxml", str(junit), "--dry-run"]) == exit_code
    assert observed == [
        (["tests/test_private_fs.py", "tests/test_config_io.py::test_two"], {"collect_only": True, "junitxml": junit})
    ]
