"""Real upstream MemoryStore lifecycle with the real hook and software custody.

Explicit import-hook registration composes these local boundaries; it does not
qualify automatic Hermes startup or a native TPM. No memories directory is seeded
by the fixture, and MemoryStore, collector probes and crypto are never replaced.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(os.name != "posix", reason="Linux custody composition requires POSIX locks")

_PROBE = """
import json
import os
import runpy
import sys
from pathlib import Path
from types import SimpleNamespace

from mordred_hermes.keyvault import _memory_hook, _memory_key
from mordred_hermes.keyvault.memory_crypto import is_sealed
from tests._keyvault_fakes import FakeBackend

home = Path(os.environ['HERMES_HOME'])
home.mkdir(parents=True, mode=0o700)
case = sys.argv[1]
backend = FakeBackend()
_memory_key.linux_memory_backend = lambda home: backend
# Select the Linux hook route without changing the interpreter's platform or
# upstream MemoryStore. Actual filesystem, locking, wrapping and AEAD remain.
_memory_hook.sys = SimpleNamespace(**{**vars(sys), 'platform': 'linux'})
_memory_key.ensure_linux_memory_key(home=home, backend=backend)
_memory_hook.memory_marker_path(home).touch(mode=0o600)
assert not (home / 'memories').exists()
assert 'tools.memory_tool' not in sys.modules
if case != 'missing_hook':
    assert _memory_hook.install_memory_import_hook()
from tools import memory_tool
assert Path(memory_tool.__file__).resolve().is_relative_to(Path(sys.prefix).resolve())
assert memory_tool.get_memory_dir() == home / 'memories'
# Prove the constructor itself supplies no on-disk lifecycle initialization.
store = memory_tool.MemoryStore(memory_char_limit=2048)
assert not (home / 'memories').exists()
helper = runpy.run_path(str(Path(os.environ['DBCRYPT_CHECKOUT']) / 'tests/_dbcrypt_acceptance_native.py'))
probe = helper['_memory_probe']
if case == 'missing_hook':
    assert not _memory_hook.memory_hook_installed(memory_tool)
    try:
        probe(True)
    except AssertionError:
        pass
    else:
        raise AssertionError('production collector admitted an absent memory hook')
    assert not (home / 'memories').exists()
else:
    assert _memory_hook.memory_hook_installed(memory_tool)
    seeded = probe(True)
    path = home / 'memories/MEMORY.md'
    sealed = path.read_bytes()
    assert is_sealed(sealed)
    assert helper['TEXT'].encode() not in sealed
    assert seeded['count'] == 1
    assert seeded['memory_module'] == str(Path(memory_tool.__file__).resolve())
    # This real upstream public lifecycle also reconstructs the loaded state.
    store.load_from_disk()
    assert store.memory_entries == [helper['TEXT']]
    assert probe(False) == seeded
    assert path.read_bytes() == sealed
    if case == 'lost_key':
        backend._keys.clear()
        try:
            probe(False)
        except _memory_hook.MemoryEncryptionUnavailable:
            pass
        else:
            raise AssertionError('collector hid unreadable sealed memory')
        assert path.read_bytes() == sealed
print(json.dumps({'case': case, 'software_composition_only': True}))
"""


@pytest.mark.parametrize("profile", [False, True], ids=["root", "profile"])
@pytest.mark.parametrize("case", ["roundtrip", "lost_key", "missing_hook"])
def test_collector_uses_real_memory_store_lifecycle(tmp_path: Path, profile: bool, case: str) -> None:
    root = tmp_path / "home"
    home = root / "profiles/work" if profile else root
    environment = {
        key: value
        for key, value in os.environ.items()
        if key not in {"HERMES_MEMORY_KEY", "HERMES_SAFE_MODE", "PYTHONPATH"}
    }
    environment.update(
        HOME=str(tmp_path),
        HERMES_HOME=str(home),
        DBCRYPT_CHECKOUT=str(Path(__file__).resolve().parents[1]),
        DBCRYPT_BUNDLE=str(tmp_path / "bundle"),
        MORDRED_DBCRYPT_ACCEPTANCE_MODE="source",
        MORDRED_DBCRYPT_ACCEPTANCE_KIND="production",
    )
    result = subprocess.run(
        [sys.executable, "-B", "-c", _PROBE, case],
        env=environment,
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert json.loads(result.stdout) == {"case": case, "software_composition_only": True}
