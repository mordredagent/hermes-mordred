"""Explicit ordinary-user Windows SQLCipher VFS feasibility, synthetic only."""

from __future__ import annotations

import ctypes
import json
import os
import subprocess
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


@pytest.mark.parametrize("name", ["mordred_probe_stats", "mordred_probe_deny_shm", "mordred_probe_vfs"])
def test_failed_extension_initialization_leaves_no_callbacks(name: str) -> None:
    library = os.environ.get("MORDRED_DBCRYPT_PROBE_LIBRARY")
    assert library, "an explicit native diagnostic library is required"
    child = r"""
import os
import sys
if os.name != "nt":
    import resource
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
import sqlcipher3.dbapi2 as driver
c = driver.connect(":memory:")
name = sys.argv[2]
args = "1" if name == "mordred_probe_deny_shm" else ""
c.create_function(name, 1 if args else 0, lambda *args: "existing")
cursor = c.execute(f"SELECT {name}({args}) FROM (SELECT 1 UNION ALL SELECT 2)")
assert cursor.fetchone() == ("existing",)
c.enable_load_extension(True)
try:
    c.execute("SELECT load_extension(?, ?)", (sys.argv[1], "sqlite3_mordredprobe_init"))
except driver.Error:
    pass
else:
    raise AssertionError("active function must refuse replacement")
finally:
    c.enable_load_extension(False)
    cursor.close()
# Partial registrations must not leave an executable pointer on bootstrap either.
for candidate, args in (("mordred_probe_stats", ""), ("mordred_probe_deny_shm", "1"), ("mordred_probe_vfs", "")):
    if candidate == name:
        assert c.execute(f"SELECT {candidate}({args})").fetchone() == ("existing",)
    else:
        try:
            c.execute(f"SELECT {candidate}({args})")
        except driver.Error:
            pass
        else:
            raise AssertionError("failed init leaked a bootstrap callback")
c.close()
# This crashed when failed initialization left unloaded auto-extension callbacks.
with driver.connect(":memory:") as later:
    assert later.execute("SELECT 1").fetchone() == (1,)
    try:
        later.execute("SELECT mordred_probe_stats()")
    except driver.Error:
        pass
    else:
        raise AssertionError("failed init leaked an automatic function")
try:
    driver.connect("file:atomic-init?mode=memory&vfs=mordred_probe_v1", uri=True)
except driver.Error:
    pass
else:
    raise AssertionError("failed init leaked a VFS")
"""
    result = subprocess.run([sys.executable, "-c", child, library, name], capture_output=True, text=True, timeout=20)
    assert result.returncode == 0, (result.returncode, result.stdout, result.stderr)
