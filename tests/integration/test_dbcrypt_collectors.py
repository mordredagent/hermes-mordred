"""Explicit source/wheel collector gate; never portable custody as native proof."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        os.environ.get("MORDRED_DBCRYPT_COLLECTORS_TEST") != "1", reason="explicit real native collectors acceptance"
    ),
]


def _run(operation: str, root: Path, name: str) -> dict:
    from tests import _dbcrypt_acceptance_native

    helper = Path(_dbcrypt_acceptance_native.__file__)
    environment = {**os.environ, "HERMES_HOME": str(root), "MORDRED_DBCRYPT_TEST_ROOT": str(root)}
    if os.environ["MORDRED_DBCRYPT_ACCEPTANCE_KIND"] == "candidate":
        source = f"import runpy; raise SystemExit(runpy.run_path({str(helper)!r})['main']({operation!r}))"
        argv = [sys.executable, "-c", source]
    else:
        driver = Path(os.environ["MORDRED_DBCRYPT_PRODUCTION_DRIVER"])
        assert driver.name == "hermes" and driver.is_file()
        argv = [sys.executable, str(driver), operation]
    result = subprocess.run(
        argv,
        cwd=Path(__file__).resolve().parents[2],
        env=environment,
        capture_output=True,
        text=True,
        timeout=900,
        stdin=subprocess.DEVNULL,
    )
    assert result.returncode == 0, "native child refused/failed; no raw traceback is exported"
    actual = json.loads(result.stdout)
    assert actual["status"] == "executed" and actual["operation"] == operation
    directory = Path(os.environ["MORDRED_DBCRYPT_ROW_DIRECTORY"])
    fd = os.open(directory / (name + ".json"), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as handle:
        json.dump(actual, handle, sort_keys=True)
    return actual


def test_real_native_collectors_reopen_logical_records_and_sealed_credentials() -> None:
    from tests import _dbcrypt_acceptance_native

    root = Path(os.environ["MORDRED_DBCRYPT_PERSISTENCE_ROOT"])
    assert root.name.endswith("-persistence"), "Task7 crash root is never a persistence root"
    baseline = json.loads(Path(os.environ["MORDRED_DBCRYPT_BASELINE"]).read_text())
    actual = _run("read", root, "public-collectors")
    assert actual["logical"] == baseline["logical"]
    assert actual["fixture"] == baseline["fixture"]
    assert set(actual["rows"]) == set(_dbcrypt_acceptance_native.COLLECTOR_ROWS)


def test_real_native_backup_restore_closes_sh_before_ex_and_fresh_reopen() -> None:
    root = Path(os.environ["MORDRED_DBCRYPT_NEGATIVE_ROOT"])
    assert root.name.endswith("-negative")
    before = _run("read", root, "before-restore")
    restored = _run("backup_restore", root, "backup-restore")
    assert restored["component_generation_before"] != restored["component_generation_after"]
    after = _run("read", root, "after-restore")
    assert before["logical"] == after["logical"] and before["fixture"] == after["fixture"]


def test_real_native_restore_finalization_failure_retains_registered_backup_and_key() -> None:
    root = Path(os.environ["MORDRED_DBCRYPT_NEGATIVE_ROOT"])
    actual = _run("backup_restore_failure", root, "restore-finalization-failure")
    assert actual["result"] == "restore_incomplete" and actual["backup_and_native_key_retained"] is True


def test_real_native_negative_lifetimes_roles_and_keyless_reads_use_sacrificial_root() -> None:
    root = Path(os.environ["MORDRED_DBCRYPT_NEGATIVE_ROOT"])
    assert root.name.endswith("-negative")
    actual = _run("negative", root, "negative")
    assert actual["initial_unwraps"] == 1 and actual["operation_unwraps"] == 0
    assert {
        "held_terminality",
        "role_forget",
        "wrong_key",
        "multiprocess_reader_writers",
        "fresh_unpatched_native_provider_unavailable",
    } <= set(actual["rows"])
    copied = actual["owned_helper_withdrawal"]
    assert copied["restored"]["identity"] == copied["copy"]["identity"]
    assert copied["missing_helper_acquisition"]["payload"]["helper_found"] is None
