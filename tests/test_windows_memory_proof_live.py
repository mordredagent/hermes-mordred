"""Explicit real-CNG installed-runtime proof and lifecycle on a fresh UUID profile.

Gated: Windows, an ordinary token, ``MORDRED_TEST_WINDOWS_PROOF_LIVE=1``, an
existing retained ``MORDRED_WINDOWS_CUSTODY_TEST_ROOT``, the installed Hermes
interpreter in ``MORDRED_HERMES_PYTHON`` (which must also run this test) and an
owned helper in ``MORDRED_WINKEY_HELPER``. Only a new UUID profile and its own
fresh CNG key are created. Failures preserve the profile and its journals; the
root is never recursively removed. Only paths and shapes are printed.
"""

import hashlib
import json
import os
import subprocess
import uuid
from pathlib import Path

import pytest

pytestmark = pytest.mark.integration

READER = r"""
import hashlib, json, os
from pathlib import Path
from mordred_hermes.keyvault._memory_storage import windows_memory_session
with windows_memory_session(Path(os.environ["HERMES_HOME"])) as session:
    rows = {
        row.name: hashlib.sha256(session.read_plaintext(row.name).encode()).hexdigest()
        for row in session.inventory()
    }
print(json.dumps(rows, sort_keys=True))
"""
CONTENT = "synthetic proof smoke\n§\nsecond entry"


def _fresh_read(python: str, home: Path) -> dict[str, str]:
    from mordred_hermes._windows_runtime import scrubbed_environment

    env = {k: v for k, v in scrubbed_environment(os.environ).items() if k.upper() != "HERMES_MEMORY_KEY"}
    env.update(HERMES_HOME=str(home), PYTHONUTF8="1", MORDRED_CONFIG_DECRYPT="0")
    child = subprocess.run([python, "-c", READER], env=env, capture_output=True, text=True, timeout=120, check=False)
    assert child.returncode == 0, child.stderr[-2048:]
    result: dict[str, str] = json.loads(child.stdout)
    return result


@pytest.mark.skipif(
    os.name != "nt" or os.environ.get("MORDRED_TEST_WINDOWS_PROOF_LIVE") != "1",
    reason="explicit ordinary-user Windows CNG installed-runtime proof acceptance",
)
def test_installed_runtime_proof_and_lifecycle_real_cng():
    import ctypes

    from mordred_hermes._private_fs import open_confidential_directory
    from mordred_hermes.keyvault._memory_storage import (
        disable_memory_encryption,
        enable_memory_encryption,
        verify_memory_purge_candidates,
        windows_memory_runtime_admitted,
    )
    from mordred_hermes.keyvault._runtime_probe import require_stopped_windows_gateways
    from mordred_hermes.keyvault._windows_custody import windows_custody_session
    from mordred_hermes.keyvault._windows_proof import prove_windows_memory_runtime
    from mordred_hermes.keyvault.memory_crypto import is_sealed

    assert not ctypes.windll.shell32.IsUserAnAdmin(), "ordinary-user acceptance required"
    assert windows_memory_runtime_admitted(), "run pytest with the admitted installed Hermes interpreter"
    python = os.environ.get("MORDRED_HERMES_PYTHON")
    assert python, "explicit installed Hermes interpreter required"
    assert os.environ.get("MORDRED_WINKEY_HELPER"), "explicit owned helper required"
    root_value = os.environ.get("MORDRED_WINDOWS_CUSTODY_TEST_ROOT")
    assert root_value, "explicit retained isolated root required"
    root = Path(root_value)
    with open_confidential_directory(root):
        pass
    home = root / ("memory-proof-" + uuid.uuid4().hex)
    # The real gate runs before any native key exists; no workaround is applied.
    require_stopped_windows_gateways(home)
    try:
        with windows_custody_session(home, create=True) as owner:
            owner.enroll_memory()
            lease = owner.lease("memory")
        with open_confidential_directory(home / "memories", create=True) as directory, directory.transaction() as tx:
            tx.create_bytes("MEMORY.md", CONTENT.encode("utf-8"))
        proof = prove_windows_memory_runtime(home)
        print(json.dumps({"python": str(proof.python), "module": proof.module_path, "helper": proof.helper_path}))
        print(json.dumps({"seam": proof.seam, "generation_matches": proof.memory_generation == lease.generation}))
        assert proof.memory_generation == lease.generation

        assert enable_memory_encryption(home, proof).armed
        sealed = (home / "memories" / "MEMORY.md").read_bytes()
        assert is_sealed(sealed), "enable left plaintext"
        expected = {"MEMORY.md": hashlib.sha256(CONTENT.encode("utf-8")).hexdigest()}
        assert _fresh_read(python, home) == expected, "fresh installed-runtime read failed"

        assert disable_memory_encryption(home, proof).opted_out
        assert (home / "memories" / "MEMORY.md").read_bytes() == CONTENT.encode("utf-8")
        assert _fresh_read(python, home) == expected
        report = verify_memory_purge_candidates(home)
        assert report.may_purge, report.reasons
        # Fixture-only cleanup through the C5a deletion journal: no seals remain.
        with windows_custody_session(home) as owner:
            owner.delete_role(lease)
    except BaseException as exc:
        exc.add_note(f"retained isolated proof profile and journals: {home}")
        raise
