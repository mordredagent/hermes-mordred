"""Explicit real CNG/installed-Hermes smoke; creates only a fresh retained UUID profile."""

import json
import os
import subprocess
import sys
import uuid
from pathlib import Path

import pytest

pytestmark = pytest.mark.integration


@pytest.mark.skipif(
    os.name != "nt" or os.environ.get("MORDRED_TEST_WINDOWS_MEMORY_LIVE") != "1",
    reason="explicit ordinary-user Windows CNG memory acceptance",
)
def test_installed_memory_hook_real_cng():
    import ctypes

    import mordred_hermes
    from mordred_hermes._private_fs import open_confidential_directory
    from mordred_hermes._windows_runtime import scrubbed_environment
    from mordred_hermes.keyvault._memory_storage import inventory_memory_files, windows_memory_runtime_admitted
    from mordred_hermes.keyvault._runtime_probe import require_stopped_windows_gateways
    from mordred_hermes.keyvault._windows_custody import windows_custody_session
    from mordred_hermes.keyvault.memory_crypto import is_sealed, seal, unseal

    assert not ctypes.windll.shell32.IsUserAnAdmin(), "ordinary-user acceptance required"
    assert windows_memory_runtime_admitted(), "run in the admitted installed Hermes Python environment"
    root_value = os.environ.get("MORDRED_WINDOWS_CUSTODY_TEST_ROOT")
    assert root_value, "explicit retained isolated root required"
    root = Path(root_value)
    with open_confidential_directory(root):
        pass
    home = root / ("memory-hook-" + uuid.uuid4().hex)
    # Do not work around the C5c process gate. Failure precedes any native key.
    require_stopped_windows_gateways(home)
    try:
        with windows_custody_session(home, create=True) as owner:
            key = owner.enroll_memory()
            lease = owner.lease("memory")
        with open_confidential_directory(home / "memories", create=True) as directory, directory.transaction() as tx:
            tx.create_bytes("MEMORY.md", seal(b"synthetic smoke", key=key, name="MEMORY.md"))
        script = r"""
import json, sys
from pathlib import Path
import mordred_hermes
from mordred_hermes.keyvault import _memory_hook as hook
from mordred_hermes.keyvault._seckey_helper import find_winkey_helper
import tools.memory_tool as memory
home = Path(sys.argv[1])
installed = hook.install_memory_hook(home=home, memory_tool_module=memory, environ={})
path = home / 'memories' / 'MEMORY.md'
store = memory.MemoryStore(memory_char_limit=1)
store._write_file(path, ['installed smoke'])
opened = store._read_file(path) == ['installed smoke']
shape = hook.memory_seam_shape(memory)
if shape == 'A':
    backup = store._detect_external_drift('memory', store._read_raw_checked(path)[0])
elif shape == 'B':
    backup = store._detect_external_drift('memory')
else:
    raise RuntimeError('installed drift seam required for smoke')
print(json.dumps(dict(installed=installed, opened=opened, backup=bool(backup),
                     module=mordred_hermes.__file__, helper=str(find_winkey_helper()), shape=shape)))
"""
        env = scrubbed_environment(os.environ)
        env.pop("HERMES_MEMORY_KEY", None)
        env.update(HERMES_HOME=str(home), HERMES_SAFE_MODE="1", PYTHONUTF8="1")
        result = subprocess.run(
            [sys.executable, "-c", script, str(home)],
            env=env,
            capture_output=True,
            text=True,
            timeout=60,
            check=True,
        )
        data = json.loads(result.stdout)
        assert data["installed"] and data["opened"] and data["backup"], "installed memory smoke failed"
        assert data["module"] == mordred_hermes.__file__, "installed child resolved a different package"
        assert data["helper"] and data["helper"] != "None", "package-bound native helper required"
        print(json.dumps({name: data[name] for name in ("module", "helper", "shape")}))
        # A new owner/native load authenticates every saved file and backup.
        with windows_custody_session(home) as owner:
            owner.validate_lease(lease)
            reopened = owner.load_memory_key()
            rows = inventory_memory_files(home)
            assert len(rows) == 2
            for row in rows:
                assert is_sealed(row.data), "smoke published plaintext"
                matches = unseal(row.data, key=reopened, name=row.name) == b"installed smoke"
                assert matches, "saved memory authentication failed"
        # Fixture-only removal after full authentication; no product migration
        # or marker API is being exercised or advertised as implemented.
        with windows_custody_session(home) as owner:
            owner.validate_lease(lease)
            with (
                owner.canonical.publication_receipt() as receipt,
                open_confidential_directory(home / "memories") as directory,
                directory.transaction() as tx,
            ):
                for row in rows:
                    tx.delete_file(row.name, expected_identity=row.metadata.identity)
                    receipt.mark_published()
            with owner.canonical.borrow_mordred_transaction() as tx:
                tx.create_bytes("memory-vault.optout", b"1\n")
            owner.delete_role(lease)
    except BaseException as exc:
        exc.add_note(f"retained isolated memory smoke profile: {home}")
        raise
