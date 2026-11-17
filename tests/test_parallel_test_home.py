"""Exercise collection-time homes in independent, real pytest processes."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
PARALLEL = ["-n", "2", "--dist=loadfile", "--max-worker-restart=0"]


def tree(tmp_path: Path) -> Path:
    suite = tmp_path / "suite"
    suite.mkdir()
    shutil.copyfile(ROOT / "tests/conftest.py", suite / "conftest.py")
    for name in ("one", "two"):
        (suite / f"test_{name}.py").write_text(
            "import json, os\n"
            "from pathlib import Path\n"
            "from mordred_hermes._core._home import HERMES_BASE\n"
            "from mordred_hermes.llm_guard.local_adapter import DEFAULT_POLICY_JSON_PATH\n"
            "worker = os.environ.get('PYTEST_XDIST_WORKER', 'serial')\n"
            f"Path({str(tmp_path)!r}, worker + '-{name}.json').write_text(json.dumps(dict(\n"
            "    home=str(HERMES_BASE), policy=str(DEFAULT_POLICY_JSON_PATH))))\n"
            "def test_frozen_home():\n"
            "    assert HERMES_BASE == Path(os.environ['HERMES_HOME'])\n"
            "    assert DEFAULT_POLICY_JSON_PATH == HERMES_BASE / 'mordred' / 'policy.json'\n"
            f"    Path({str(tmp_path)!r}, worker + '-{name}.called').touch()\n",
            encoding="utf-8",
        )
    return suite


def run(suite: Path, args: list[str], home: Path | None, **environment: str) -> subprocess.CompletedProcess[str]:
    env = dict(os.environ)
    # The parent itself can be an xdist worker. Only the child's real config counts.
    env.pop("HERMES_HOME", None)
    env.pop("PYTEST_ADDOPTS", None)
    env.update(environment)
    env["PYTHONPATH"] = os.pathsep.join((str(ROOT), str(suite)))
    if home is not None:
        env["HERMES_HOME"] = str(home)
    return subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "-o", "addopts=", *args],
        cwd=suite,
        env=env,
        capture_output=True,
        text=True,
        timeout=45,
    )


def records(tmp_path: Path) -> list[dict[str, str]]:
    return [json.loads(path.read_text()) for path in sorted(tmp_path.glob("*.json"))]


def test_real_workers_freeze_distinct_owned_homes_and_clean_only_their_homes(tmp_path: Path) -> None:
    suite = tree(tmp_path)
    caller = tmp_path / "caller"
    caller.mkdir()
    (caller / "keep").touch()
    result = run(suite, PARALLEL, caller)
    assert result.returncode == 0, result.stdout + result.stderr
    found = records(tmp_path)
    assert len(found) == 4  # Both files were collected independently by each real worker.
    homes = {entry["home"] for entry in found}
    assert len(homes) == 2, found
    assert str(caller) not in homes
    assert str(Path.home() / ".hermes") not in homes
    assert all(not Path(home).exists() for home in homes)
    assert (caller / "keep").is_file()
    assert {path.name for path in tmp_path.glob("*.called")} in (
        {"gw0-one.called", "gw1-two.called"},
        {"gw1-one.called", "gw0-two.called"},
    )


@pytest.mark.parametrize("explicit", [False, True])
@pytest.mark.parametrize("args", [[], ["-n", "0"]])
def test_serial_home_preserves_caller_or_owns_fallback(tmp_path: Path, explicit: bool, args: list[str]) -> None:
    suite = tree(tmp_path)
    caller = tmp_path / "caller"
    caller.mkdir()
    result = run(suite, args, caller if explicit else None)
    assert result.returncode == 0, result.stdout + result.stderr
    homes = {entry["home"] for entry in records(tmp_path)}
    assert len(homes) == 1
    home = Path(homes.pop())
    if explicit:
        assert home == caller and home.is_dir()
    else:
        assert home != caller and home != Path.home() / ".hermes"
        assert not home.exists()
    assert caller.is_dir()


def test_nested_serial_ignores_inherited_worker_environment(tmp_path: Path) -> None:
    suite = tree(tmp_path)
    caller = tmp_path / "nested-home"
    caller.mkdir()
    result = run(suite, ["-n", "0"], caller, PYTEST_XDIST_WORKER="gw9", PYTEST_XDIST_WORKER_COUNT="2")
    assert result.returncode == 0, result.stdout + result.stderr
    assert {entry["home"] for entry in records(tmp_path)} == {str(caller)}
    assert caller.is_dir()


def test_real_worker_can_launch_nested_serial_with_explicit_home(tmp_path: Path) -> None:
    suite = tree(tmp_path)
    nested = suite / "nested"
    nested.mkdir()
    shutil.copyfile(ROOT / "tests/conftest.py", nested / "conftest.py")
    caller = tmp_path / "nested-home"
    caller.mkdir()
    (nested / "test_nested.py").write_text(
        "import os\nfrom pathlib import Path\n"
        "from mordred_hermes._core._home import HERMES_BASE\n"
        f"assert HERMES_BASE == Path({str(caller)!r})\n"
        "def test_nested():\n"
        "    assert os.environ['PYTEST_XDIST_WORKER'].startswith('gw')\n",
        encoding="utf-8",
    )
    # Collection of the nested tree belongs solely to the child serial process.
    with (suite / "conftest.py").open("a", encoding="utf-8") as conftest:
        conftest.write("\ncollect_ignore = ['nested']\n")
    (suite / "test_one.py").write_text(
        "import os, subprocess, sys\n"
        "def test_nested_launch():\n"
        "    assert os.environ['PYTEST_XDIST_WORKER'].startswith('gw')\n"
        f"    result = subprocess.run([sys.executable, '-m', 'pytest', '-q', '-n', '0', '-o', 'addopts='],\n"
        f"        cwd={str(nested)!r}, env=dict(os.environ, HERMES_HOME={str(caller)!r}),\n"
        "        capture_output=True, text=True, timeout=30)\n"
        "    assert result.returncode == 0, result.stdout + result.stderr\n",
        encoding="utf-8",
    )
    result = run(suite, PARALLEL, tmp_path / "controller")
    assert result.returncode == 0, result.stdout + result.stderr
    assert caller.is_dir()


def test_worker_refuses_product_import_before_configure(tmp_path: Path) -> None:
    suite = tree(tmp_path)
    (suite / "frozen.py").write_text("from mordred_hermes._core._home import HERMES_BASE\n", encoding="utf-8")
    caller = tmp_path / "caller"
    caller.mkdir()
    result = run(suite, ["-p", "frozen", *PARALLEL], caller)
    assert result.returncode != 0
    assert "product modules imported before worker home isolation" in result.stdout + result.stderr
    assert not records(tmp_path)
    assert caller.is_dir()


@pytest.mark.parametrize("missing", [False, True])
def test_extension_fixture_closure_guard_runs_in_real_workers(tmp_path: Path, missing: bool) -> None:
    suite = tree(tmp_path)
    # Capture the actual UsageError inside the worker: xdist can summarize an
    # early collection abort as worker-not-down without forwarding its text.
    with (suite / "guard_probe.py").open("w", encoding="utf-8") as probe:
        probe.write(
            "import os, pytest\nfrom pathlib import Path\n"
            "@pytest.hookimpl(hookwrapper=True)\n"
            "def pytest_collection_finish(session):\n"
            "    outcome = yield\n"
            "    if outcome.excinfo:\n"
            f"        Path({str(tmp_path)!r}, 'guard-' + os.environ['PYTEST_XDIST_WORKER'] + '.txt')"
            ".write_text(str(outcome.excinfo[1]))\n"
        )
    extension = suite / "extension"
    extension.mkdir()
    if not missing:
        (extension / "conftest.py").write_text(
            "import pytest\n"
            "@pytest.fixture(autouse=True)\n"
            "def _isolated_home(): pass\n"
            "@pytest.fixture(autouse=True)\n"
            "def _memory_encryption_on(): pass\n",
            encoding="utf-8",
        )
    (extension / "test_guard.py").write_text("def test_guard(): pass\n", encoding="utf-8")
    result = run(suite, ["-p", "guard_probe", *PARALLEL], tmp_path / "caller")
    if missing:
        assert result.returncode != 0
        errors = list(tmp_path.glob("guard-*.txt"))
        assert errors and all("extension isolation fixtures missing" in path.read_text() for path in errors)
    else:
        assert result.returncode == 0, result.stdout + result.stderr
