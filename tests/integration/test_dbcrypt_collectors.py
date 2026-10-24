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
    pytest.mark.skipif(os.environ.get("MORDRED_DBCRYPT_COLLECTORS_TEST") != "1",
                       reason="explicit real native collectors acceptance"),
]


def test_real_native_collectors_reopen_logical_records_and_sealed_credentials() -> None:
    from tests import _dbcrypt_acceptance_native

    root = Path(os.environ["MORDRED_DBCRYPT_TEST_ROOT"])
    assert root.name.endswith("-persistence"), "Task7 crash root is never a persistence root"
    baseline_path = Path(os.environ["MORDRED_DBCRYPT_BASELINE"])
    baseline = json.loads(baseline_path.read_text())
    source = f"import runpy; raise SystemExit(runpy.run_path({str(Path(_dbcrypt_acceptance_native.__file__))!r})['main']('read'))"
    assert os.environ["MORDRED_DBCRYPT_ACCEPTANCE_KIND"] == "candidate", "production uses the hermes-named startup driver"
    result = subprocess.run([sys.executable, "-c", source], cwd=Path(__file__).resolve().parents[2],
                            env={**os.environ, "HERMES_HOME": str(root)}, capture_output=True, text=True, timeout=600)
    assert result.returncode == 0, "native collector child refused or failed; inspect safe phase evidence"
    actual = json.loads(result.stdout)
    assert actual["logical"] == baseline["logical"]
    assert actual["fixture"] == baseline["fixture"]
    assert set(actual["rows"]) == set(_dbcrypt_acceptance_native.COLLECTOR_ROWS)
