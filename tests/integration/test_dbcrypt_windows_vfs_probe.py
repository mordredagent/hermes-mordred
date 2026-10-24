"""Explicit ordinary-user Windows SQLCipher VFS feasibility, synthetic only."""

from __future__ import annotations

import ctypes
import json
import os
import sys
from pathlib import Path

import pytest

from tests._dbcrypt_support import acceptance_tool

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        sys.platform != "win32" or os.environ.get("MORDRED_DBCRYPT_VFS_PROBE") != "1",
        reason="explicit Windows VFS feasibility requires an ordinary native token",
    ),
]


def test_current_wheel_vfs_callbacks() -> None:
    assert not ctypes.windll.shell32.IsUserAnAdmin(), "an elevated pass is not ordinary-user evidence"
    root_text = os.environ.get("MORDRED_DBCRYPT_TEST_ROOT")
    assert root_text, "an isolated synthetic evidence root is required"
    root = Path(root_text)
    assert root.is_absolute() and root.is_dir() and root.name.startswith("mordred-dbcrypt-")
    tool = acceptance_tool("dbcrypt_vfs_probe")
    output = root / "vfs-probe.json"
    result = tool.probe(output=output)
    assert result.passed, "same-library, persistent VFS and SHM interception must all be proven"
    evidence = json.loads(output.read_text())
    assert evidence["encryption_verified"] and evidence["fts_japanese_verified"]
    assert evidence["bootstrap_closed"] and evidence["shm_denial_verified"]
    assert evidence["production_filesystem_acceptance"] is False
    import mordred_hermes

    expected = os.environ.get("MORDRED_DBCRYPT_PRODUCT_PREFIX")
    assert expected, "source and installed-wheel import provenance must be set explicitly"
    assert Path(mordred_hermes.__file__).resolve().is_relative_to(Path(expected).resolve())
    print(json.dumps({"passed": True, "report": str(output), "product": mordred_hermes.__file__}))
