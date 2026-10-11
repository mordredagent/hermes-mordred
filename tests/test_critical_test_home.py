"""CI ambient home must be checked before plugin paths freeze at collection."""

from __future__ import annotations

import os
import stat
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]


def home_script() -> str:
    workflow = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text())
    steps = workflow["jobs"]["critical-feedback"]["steps"]
    preparation = next((s for s in steps if s.get("name") == "Prepare checked Windows feedback home"), None)
    assert preparation is not None, "checked Windows ambient home preparation is missing"
    assert preparation["if"] == "runner.os == 'Windows'"
    collection = next(s for s in steps if s.get("name") == "Critical regression feedback")
    assert steps.index(preparation) < steps.index(collection)
    return preparation["run"].split("<<'PY'\n", 1)[1].rsplit("\nPY", 1)[0]


def test_prepared_home_is_checked_and_frozen_before_collection(tmp_path: Path) -> None:
    output = tmp_path / "github-env"
    # Preserve previous environment writes; the new admitted value overrides the old one.
    output.write_text("HERMES_HOME=unadmitted-runner-temp\n", encoding="utf-8")
    result = subprocess.run(
        [sys.executable, "-c", home_script()],
        cwd=ROOT,
        env=os.environ | {"USERPROFILE": str(tmp_path), "GITHUB_ENV": str(output)},
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
    home = Path(output.read_text(encoding="utf-8").splitlines()[-1].removeprefix("HERMES_HOME="))
    assert home.parent == tmp_path and home.name.startswith("mordred-critical-")
    from mordred_hermes._private_fs import open_private_directory

    for path in (home, home / "mordred"):
        with open_private_directory(path) as directory:
            assert directory.directory_identity() is not None
    child = subprocess.run(
        [
            sys.executable,
            "-c",
            "import os; from pathlib import Path; from mordred_hermes._home import HERMES_BASE; "
            "from mordred_hermes.llm_guard import local_adapter; "
            "assert HERMES_BASE == Path(os.environ['HERMES_HOME']); "
            "assert local_adapter.DEFAULT_POLICY_JSON_PATH == HERMES_BASE / 'mordred' / 'policy.json'",
        ],
        cwd=ROOT,
        env=os.environ | {"HERMES_HOME": str(home)},
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert child.returncode == 0, child.stderr


@pytest.mark.skipif(os.name != "posix", reason="real POSIX permission refusal; Windows admission is checked in CI")
@pytest.mark.parametrize("unsafe_child", [False, True])
def test_preparation_refuses_unsafe_existing_namespace_without_repair(tmp_path: Path, unsafe_child: bool) -> None:
    from mordred_hermes._private_fs import open_private_directory

    home = tmp_path / ("mordred-critical-" + "0" * 32)
    with open_private_directory(home, create=True):
        pass
    with open_private_directory(home / "mordred", create=True):
        pass
    unsafe = home / "mordred" if unsafe_child else home
    unsafe.chmod(0o755)
    before = stat.S_IMODE(unsafe.stat().st_mode)
    output = tmp_path / "github-env"
    output.write_text("HERMES_HOME=old-unadmitted-home\n", encoding="utf-8")
    # Force a collision only at the UUID boundary; checked security APIs remain real.
    code = "import uuid; uuid.uuid4 = lambda: uuid.UUID(int=0)\n" + home_script()
    result = subprocess.run(
        [sys.executable, "-c", code],
        cwd=ROOT,
        env=os.environ | {"USERPROFILE": str(tmp_path), "GITHUB_ENV": str(output)},
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode != 0
    assert "PrivateFSError" in result.stderr and "unsafe" in result.stderr
    assert stat.S_IMODE(unsafe.stat().st_mode) == before
    assert output.read_text(encoding="utf-8") == "HERMES_HOME=old-unadmitted-home\n"
