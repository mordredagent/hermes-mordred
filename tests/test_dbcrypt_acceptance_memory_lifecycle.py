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


_PROVISION = r"""
import json
import os
import runpy
import sys
from pathlib import Path
from types import SimpleNamespace

from mordred_hermes.keyvault import _database_authority, _memory_hook, _memory_key
from mordred_hermes.keyvault.memory_crypto import is_sealed
from tests._keyvault_fakes import FakeBackend

root = Path(os.environ['HERMES_HOME'])
case = sys.argv[1]
backend = FakeBackend()
_memory_key.linux_memory_backend = lambda home: backend
_memory_hook.sys = SimpleNamespace(**{**vars(sys), 'platform': 'linux'})
assert _memory_hook.install_memory_import_hook()
helper = runpy.run_path(str(Path(os.environ['DBCRYPT_CHECKOUT']) / 'tests/_dbcrypt_acceptance_native.py'))
provision = helper['provision']
assert helper['_interfaces']() is _database_authority.require_database_memory_enabled
progress = []

class DatabaseBoundaryReached(Exception):
    pass

def maintenance(home, args):
    # Explicit software ceremony fixture: real custody/marker, no native CLI
    # qualification. The database conversion is never simulated as successful.
    if args == ['databases', 'encrypt']:
        assert home == root
        raise DatabaseBoundaryReached
    assert args == ['encryption', 'enable', 'memory']
    assert not (home / 'memories').exists()
    _memory_key.ensure_linux_memory_key(home=home, backend=backend)
    marker = _memory_hook.memory_marker_path(home)
    marker.write_bytes(b'memory-encryption enabled\n')
    marker.chmod(0o600)
    progress.append([str(home.relative_to(root)), 'enabled'])
    if home == root / 'profiles/work':
        if case == 'root_disabled':
            _memory_hook.memory_marker_path(root).unlink()
        elif case == 'root_optout':
            _memory_hook.memory_optout_marker_path(root).touch(mode=0o600)
    return {'fixture': 'software_custody_only'}

def fresh_memory(home, *, seed):
    # Same interpreter preserves software hardware. The actual collector probe,
    # upstream store, public load lifecycle, import hook and AEAD are unchanged.
    os.environ['HERMES_HOME'] = str(home)
    if seed:
        assert not (home / 'memories').exists()
    result = helper['_memory_probe'](seed)
    sealed = (home / 'memories/MEMORY.md').read_bytes()
    assert is_sealed(sealed) and helper['TEXT'].encode() not in sealed
    progress.append([str(home.relative_to(root)), 'seed' if seed else 'read'])
    return result

provision.__globals__['_maintenance'] = maintenance
provision.__globals__['_fresh_memory'] = fresh_memory
try:
    provision(root)
except DatabaseBoundaryReached:
    assert case == 'all_profiles'
except _database_authority.DatabaseRefused as exc:
    assert case in {'root_disabled', 'root_optout'}, str(exc)
    assert str(exc) == 'root native memory must be explicitly enabled first'
else:
    raise AssertionError('provision crossed the declared database boundary')
expected = [['.', 'enabled'], ['.', 'seed'], ['.', 'read'], ['profiles/work', 'enabled']]
if case == 'all_profiles':
    expected += [['profiles/work', 'seed'], ['profiles/work', 'read'],
                 ['profiles/other', 'enabled'], ['profiles/other', 'seed'], ['profiles/other', 'read']]
else:
    assert not (root / 'profiles/work/memories').exists()
    assert not (root / 'profiles/other').exists()
assert progress == expected
# The product's deliberate root-only contract remains enforced independently.
try:
    _database_authority.require_database_memory_enabled(root=root / 'profiles/work')
except _database_authority.DatabaseRefused as exc:
    assert str(exc) == 'database source requires the resolved root home'
else:
    raise AssertionError('database authority accepted profile custody as root')
assert not (root / 'mordred/db-key-source.json').exists()
print(json.dumps({'case': case, 'software_composition_only': True, 'progress': progress}))
"""


@pytest.mark.parametrize("case", ["all_profiles", "root_disabled", "root_optout"])
def test_provision_checks_root_prerequisite_across_profile_memory(tmp_path: Path, case: str) -> None:
    environment = {
        key: value
        for key, value in os.environ.items()
        if key not in {"HERMES_MEMORY_KEY", "HERMES_SAFE_MODE", "PYTHONPATH"}
    }
    environment.update(
        HOME=str(tmp_path),
        HERMES_HOME=str(tmp_path / "home"),
        DBCRYPT_CHECKOUT=str(Path(__file__).resolve().parents[1]),
        DBCRYPT_BUNDLE=str(tmp_path / "bundle"),
        MORDRED_DBCRYPT_ACCEPTANCE_MODE="source",
        MORDRED_DBCRYPT_ACCEPTANCE_KIND="production",
    )
    result = subprocess.run(
        [sys.executable, "-B", "-c", _PROVISION, case],
        env=environment,
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    observed = json.loads(result.stdout)
    assert observed["case"] == case
    assert observed["software_composition_only"] is True
