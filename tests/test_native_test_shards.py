"""Module sharding must preserve every native assertion and pytest failure."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import re
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / "tools/run_native_test_shard.py"
WEIGHTS = ROOT / "tools/native_test_durations.json"


def _tool():
    assert TOOL.is_file(), "native shard runner is missing"
    spec = importlib.util.spec_from_file_location("run_native_test_shard", TOOL)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_balances_whole_modules_and_preserves_selector_order() -> None:
    # LPT: a=9 -> 1, b=8 -> 2, c=7 -> 3, d=6 -> 3, e=5 -> 2, f=4 -> 1.
    modules = ["f.py", "a.py", "b.py", "c.py", "d.py", "e.py"]
    weights = dict(zip(["a.py", "b.py", "c.py", "d.py", "e.py", "f.py"], [9, 8, 7, 6, 5, 4], strict=True))
    assert _tool().shard_modules(modules, weights, 3) == [["f.py", "a.py"], ["b.py", "e.py"], ["c.py", "d.py"]]


def test_unknown_modules_receive_nonzero_weight() -> None:
    assert _tool().shard_modules(["new.py", "known.py", "other.py"], {"known.py": 1}, 2) == [
        ["new.py", "other.py"],
        ["known.py"],
    ]


@pytest.mark.parametrize("modules,count", [([], 3), (["a.py", "a.py"], 3), (["a.py"], 0), (["a.py"], 2)])
def test_rejects_empty_duplicate_or_empty_shard_inputs(modules, count) -> None:
    with pytest.raises(ValueError):
        _tool().shard_modules(modules, {}, count)


@pytest.mark.parametrize("weight", [0, -1, True, "slow", float("nan"), float("inf")])
def test_rejects_malformed_duration_values(tmp_path: Path, weight) -> None:
    path = tmp_path / "weights.json"
    path.write_text(json.dumps({"provenance": "fixture", "seconds": {"a.py": weight}}))
    with pytest.raises(ValueError):
        _tool().load_weights(path)


@pytest.mark.parametrize("raw", ["[]", "{}", '{"seconds": []}', '{"seconds": {"a.py": 1, "a.py": 2}}'])
def test_rejects_invalid_weight_structure_or_duplicate_keys(tmp_path: Path, raw: str) -> None:
    path = tmp_path / "weights.json"
    path.write_text(raw)
    with pytest.raises(ValueError):
        _tool().load_weights(path)


def test_workflow_selector_preserves_frozen_native_harness_contract() -> None:
    workflow = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text())
    job = workflow["jobs"]["windows-private-fs"]
    step = next(s for s in job["steps"] if s.get("name") == "Native ACL, path, publication and process tests")
    # The external harness extracts filenames directly from this named run step.
    modules = re.findall(r"tests/[\w/]+\.py", step["run"])
    weights = _tool().load_weights(WEIGHTS)
    assert len(modules) == len(set(modules)) == 82
    # SHA256 of newline-joined, sorted distinct modules at frozen BASE f3506b7dc.
    # Independent of the weights fixture, so replacing a module cannot hide loss.
    assert hashlib.sha256("\n".join(sorted(modules)).encode()).hexdigest() == (
        "7d7b2b9da0549e631373054f3741a8c1e8cd8c96c51e3261538af783c6667b0d"
    )
    assert set(modules) == set(weights)  # Frozen BASE selector, independently measured in native JUnit.
    shards = _tool().shard_modules(modules, weights, 3)
    assert sorted(m for shard in shards for m in shard) == sorted(modules)
    totals = [sum(weights[m] for m in shard) for shard in shards]
    assert max(totals) - min(totals) < 1
    assert max(totals) < 950
    assert job["strategy"]["matrix"] == {"python-version": ["3.11", "3.12", "3.13"], "shard": [1, 2, 3]}
    assert job["strategy"]["fail-fast"] is False
    smoke = next(s for s in job["steps"] if s.get("name", "").startswith("Build a wheel"))
    assert smoke["if"] == "matrix.shard == 1"
    upload = next(s for s in job["steps"] if s.get("uses", "").startswith("actions/upload-artifact@"))
    assert upload["if"] == "always()"
    assert "matrix.shard" in upload["with"]["name"]
    assert "matrix.python-version" in upload["with"]["name"]


@pytest.mark.parametrize("index", ["0", "4", "", "garbage"])
def test_cli_rejects_invalid_shard_index(tmp_path: Path, index: str) -> None:
    assert TOOL.is_file(), "native shard runner is missing"
    result = subprocess.run(
        [
            sys.executable,
            str(TOOL),
            "--shard-index",
            index,
            "--shard-count",
            "3",
            "--junitxml",
            str(tmp_path / "j.xml"),
            "a.py",
            "b.py",
            "c.py",
        ],
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 2
    assert not (tmp_path / "j.xml").exists()


@pytest.mark.parametrize("body,exit_code", [("def test_ok(): assert True", 0), ("def test_bad(): assert False", 1)])
def test_cli_runs_pytest_and_propagates_failure(tmp_path: Path, body: str, exit_code: int) -> None:
    assert TOOL.is_file(), "native shard runner is missing"
    module = tmp_path / "test_example.py"
    module.write_text(body)
    junit = tmp_path / "result.xml"
    result = subprocess.run(
        [sys.executable, str(TOOL), "--shard-index", "1", "--shard-count", "1", "--junitxml", str(junit), str(module)],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == exit_code, result.stdout + result.stderr
    assert junit.is_file()
    assert "slowest" in result.stdout
