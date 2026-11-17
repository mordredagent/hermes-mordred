"""Critical feedback selection must stay native and preserve collection failures."""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / "tools/run_critical_tests.py"


def tool():
    assert TOOL.is_file(), "critical-test runner is missing"
    spec = importlib.util.spec_from_file_location("run_critical_tests", TOOL)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize("platform", ["linux", "darwin", "win32"])
def test_critical_selection_uses_real_current_platform_filesystem_cases(platform: str) -> None:
    cases = tool().select_cases(platform)
    nodes = [node for _risk, node in cases]
    assert len(nodes) == len(set(nodes))
    assert all("::test_" in node and "integration" not in node and "_live" not in node for node in nodes)
    assert "tests/test_windows_memory_lifecycle.py::test_enable_fresh_read_rerun_and_disable" in nodes
    if platform == "win32":
        assert "tests/test_private_fs_windows.py::test_junction_at_final_or_parent_is_refused" in nodes
        assert "tests/test_private_fs_windows.py::test_hardlink_read_refused" in nodes
        assert not any("test_private_fs_posix.py" in node for node in nodes)
    else:
        assert "tests/test_private_fs_posix.py::test_symlink_and_hardlink_refused" in nodes
        assert not any("test_private_fs_windows.py" in node for node in nodes)
        assert any("test_macos_ancestor_acl" in node for node in nodes) == (platform == "darwin")


def test_unsupported_platform_is_not_foreign_platform_skip_coverage() -> None:
    with pytest.raises(ValueError):
        tool().select_cases("unknown")


@pytest.fixture
def temporary_suite(tmp_path: Path) -> Path:
    (tmp_path / "pytest.ini").write_text("[pytest]\nmarkers =\n    integration: live integration tests\n")
    return tmp_path / "test_small.py"


def test_missing_node_id_is_a_real_collection_failure(temporary_suite: Path) -> None:
    path = temporary_suite
    path.write_text("def test_present(): assert True\n")
    assert tool().run_cases([f"{path}::test_absent"], collect_only=True) == 4


def test_test_failure_is_propagated(temporary_suite: Path) -> None:
    path = temporary_suite
    path.write_text("def test_security_regression(): assert False\n")
    assert tool().run_cases([f"{path}::test_security_regression"]) == 1


def test_integration_failure_is_excluded(temporary_suite: Path) -> None:
    temporary_suite.write_text(
        "import pytest\n"
        "@pytest.mark.integration\n"
        "def test_integration_failure(): assert False\n"
        "def test_unit(): assert True\n"
    )
    assert tool().run_cases([str(temporary_suite)]) == 0


def test_empty_selection_cannot_accidentally_run_the_full_suite(monkeypatch) -> None:
    runner = tool()

    def refuse_full_sweep(*args, **kwargs):
        pytest.fail("empty selection attempted to launch pytest")

    monkeypatch.setattr(runner.subprocess, "run", refuse_full_sweep)
    with pytest.raises(ValueError, match="empty"):
        runner.run_cases([])


def test_critical_feedback_covers_passive_database_status_and_native_source_refusal():
    for platform in ("linux", "darwin", "win32"):
        nodes = [node for _, node in tool().select_cases(platform)]
        assert "tests/test_dbcrypt_capability.py::test_driver_import_is_not_readiness" in nodes
        assert "tests/test_keyvault_mail_key.py::test_read_backend_never_upgrades_or_enrolls" in nodes
        assert ("tests/test_dbcrypt_authority.py::test_hundred_operations_one_unwrap" in nodes) is (platform != "win32")
