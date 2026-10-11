"""Fail closed when a canary cannot execute the selected source."""

from __future__ import annotations

import importlib
import importlib.util
from pathlib import Path

import pytest

from tests._upstream_canary import CanaryUnavailable, SeamDrift, import_target, verify_provenance

spec = importlib.util.spec_from_file_location(
    "upstream_memory_canary", Path(__file__).resolve().parents[1] / "tools/upstream_memory_canary.py"
)
assert spec is not None and spec.loader is not None
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)
Outcomes = runner.Outcomes


def test_optional_absence_does_not_hide_missing_internal_dependencies(monkeypatch):
    def missing(name):
        raise ModuleNotFoundError("missing internal", name="internal_dependency")

    monkeypatch.setattr(importlib, "import_module", missing)
    with pytest.raises(CanaryUnavailable, match="internal_dependency"):
        import_target("agent.learning_mutations", optional=True)


def test_only_optional_journey_absence_skips(monkeypatch):
    def missing(name):
        raise ModuleNotFoundError("missing target", name=name)

    monkeypatch.setattr(importlib, "import_module", missing)
    with pytest.raises(pytest.skip.Exception):
        import_target("agent.learning_mutations", optional=True)
    with pytest.raises(SeamDrift):
        import_target("tools.memory_tool")


def test_strict_requires_root_and_cannot_skip(monkeypatch, tmp_path):
    monkeypatch.setenv("MORDRED_REQUIRE_UPSTREAM_MEMORY_SEAMS", "1")
    monkeypatch.delenv("MORDRED_EXPECTED_UPSTREAM_ROOT", raising=False)
    with pytest.raises(CanaryUnavailable, match="root"):
        import_target("tools.memory_tool")
    monkeypatch.setenv("MORDRED_EXPECTED_UPSTREAM_ROOT", str(tmp_path))
    with pytest.raises(SeamDrift):
        import_target("agent.learning_mutations", optional=True)


def test_strict_rejects_installed_release_fallback(monkeypatch, tmp_path):
    monkeypatch.setenv("MORDRED_REQUIRE_UPSTREAM_MEMORY_SEAMS", "1")
    monkeypatch.setenv("MORDRED_EXPECTED_UPSTREAM_ROOT", str(tmp_path))
    # A file exists in the checkout, but importing a cached wheel must fail.
    target = tmp_path / "tools" / "memory_tool.py"
    target.parent.mkdir()
    target.write_text("")
    from types import SimpleNamespace

    module = SimpleNamespace(__file__="/installed/tools/memory_tool.py")
    with pytest.raises(CanaryUnavailable, match="provenance"):
        verify_provenance(module, "tools.memory_tool", tmp_path)


@pytest.mark.parametrize(
    "events,code,want",
    [
        ([("passed", None)], 0, "ok"),
        ([("failed", AssertionError("changed seam"))], 1, "drift"),
        ([("failed", SeamDrift("missing seam"))], 1, "drift"),
        ([("failed", ImportError("dependency"))], 1, "unavailable"),
        ([("failed", CanaryUnavailable("provenance"))], 1, "unavailable"),
        ([("failed", AssertionError()), ("failed", ImportError())], 1, "unavailable"),
        ([("skipped", None)], 0, "unavailable"),
        ([], 2, "unavailable"),
        ([("passed", None)], 3, "unavailable"),
        ([("passed", None)], 1, "unavailable"),
    ],
)
def test_runner_distinguishes_behavior_drift_from_incomplete_execution(events, code, want):
    outcomes = Outcomes()
    for outcome, error in events:
        outcomes.record(outcome, error)
    assert outcomes.status(code) == want


@pytest.mark.parametrize(
    "body,want",
    [
        ("assert 1 == 1", "ok"),
        ("assert 1 == 2", "drift"),
        ("raise ImportError('dependency unavailable')", "unavailable"),
        ("pytest.skip('cannot execute')", "unavailable"),
    ],
)
def test_real_pytest_results_are_classified(tmp_path, body, want):
    import os
    import subprocess
    import sys

    case = tmp_path / "test_case.py"
    case.write_text("import pytest\ndef test_case():\n    " + body + "\n")
    code = f"""
import importlib.util, pytest
spec = importlib.util.spec_from_file_location('runner', {str(Path(runner.__file__))!r})
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
outcomes = module.Outcomes()
code = pytest.main(['-q', '-o', 'addopts=', {str(case)!r}], plugins=[outcomes])
print('CLASSIFICATION=' + outcomes.status(int(code)))
"""
    proc = subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
        check=False,
        env={**os.environ, "HERMES_HOME": str(tmp_path / "home")},
    )
    assert proc.returncode == 0, proc.stderr
    assert f"CLASSIFICATION={want}" in proc.stdout


@pytest.mark.parametrize("residue,want", [("", 0), ("import hermes_cli", 12), ("external_class", 12)])
def test_child_checks_shared_imports_and_reexported_class_provenance(tmp_path, residue, want):
    import os
    import subprocess
    import sys

    root = tmp_path / "upstream"
    for package in ("tools", "agent"):
        (root / package).mkdir(parents=True)
        (root / package / "__init__.py").write_text("")
    (root / "tools" / "memory_tool.py").write_text(
        "from pathlib import Path as MemoryStore\n"
        if residue == "external_class"
        else "from memory_store import MemoryStore\n"
    )
    (root / "memory_store.py").write_text("class MemoryStore: pass\n")
    (root / "agent" / "learning_mutations.py").write_text("")
    (root / "utils.py").write_text("")
    (root / "hermes_constants.py").write_text("")
    code = f"""
import sys
sys.path.insert(0, {str(root)!r})
{residue if residue != "external_class" else ""}
from tests._upstream_canary import child_main
raise SystemExit(child_main())
"""
    env = {
        **os.environ,
        "HERMES_HOME": str(tmp_path / "home"),
        "MORDRED_REQUIRE_UPSTREAM_MEMORY_SEAMS": "1",
        "MORDRED_EXPECTED_UPSTREAM_ROOT": str(root),
    }
    proc = subprocess.run([sys.executable, "-c", code], env=env, capture_output=True, text=True, check=False)
    assert proc.returncode == want, proc.stdout + proc.stderr
