"""Exercise actual pytest collection, exact exclusions and result recording."""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
RECORDER = ROOT / "tools/run_native_pytest.py"


def run_suite(tmp_path, body, exclusions=()):
    module = tmp_path / "test_sample.py"
    module.write_text(body)
    output = tmp_path / "selection.json"
    code = f"""
import importlib.util
from pathlib import Path
import pytest
spec = importlib.util.spec_from_file_location('native_selection_recorder', {str(RECORDER)!r})
tool = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tool)
selection = tool.NativeSelection(tier='routine', shard=1, shard_count=2,
    modules=['test_sample.py'], exclusions={list(exclusions)!r}, output=Path({str(output)!r}))
raise SystemExit(pytest.main(['-q', '-o', 'addopts=', 'test_sample.py'], plugins=[selection]))
"""
    result = subprocess.run([sys.executable, "-c", code], cwd=tmp_path, capture_output=True, text=True, timeout=30)
    assert output.is_file(), result.stdout + result.stderr
    return result.returncode, json.loads(output.read_text())


def test_exact_exclusion_keeps_new_parameters_and_records_collection(tmp_path):
    omitted = "test_sample.py::test_case[old]"
    result, manifest = run_suite(
        tmp_path,
        "import pytest\n@pytest.mark.parametrize('value', ['old', 'new'])\n"
        "def test_case(value): assert value == 'new'\n",
        [omitted],
    )
    assert result == manifest["exit_code"] == 0
    assert manifest["excluded_nodeids"] == [omitted]
    assert manifest["tests"] == [{"nodeid": "test_sample.py::test_case[new]", "outcome": "passed"}]
    assert manifest["collected_count"] == 2
    assert (
        manifest["collection_sha256"]
        == hashlib.sha256(b"test_sample.py::test_case[new]\ntest_sample.py::test_case[old]").hexdigest()
    )
    assert manifest["modules"] == ["test_sample.py"]
    assert (manifest["schema_version"], manifest["tier"], manifest["shard"], manifest["shard_count"]) == (
        1,
        "routine",
        1,
        2,
    )


def test_missing_reviewed_exclusion_fails_instead_of_dropping_other_tests(tmp_path):
    result, manifest = run_suite(tmp_path, "def test_new(): pass\n", ["test_sample.py::test_removed"])
    assert result != 0
    assert manifest["exit_code"] != 0


@pytest.mark.parametrize(
    "body,outcome,exit_code",
    [
        ("def test_bad(): assert False\n", "failed", 1),
        ("import pytest\ndef test_skip(): pytest.skip('native only')\n", "skipped", 0),
        (
            "import pytest\n@pytest.fixture\ndef broken():\n yield\n assert False\ndef test_teardown(broken): pass\n",
            "failed",
            1,
        ),
    ],
)
def test_preserves_failure_skip_and_teardown_results(tmp_path, body, outcome, exit_code):
    result, manifest = run_suite(tmp_path, body)
    assert result == manifest["exit_code"] == exit_code
    assert len(manifest["tests"]) == 1
    assert manifest["tests"][0]["outcome"] == outcome


def test_collection_failure_cannot_emit_success(tmp_path):
    result, manifest = run_suite(tmp_path, "raise RuntimeError('broken collection')\n")
    assert result != 0
    assert manifest["exit_code"] != 0
