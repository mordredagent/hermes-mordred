"""Compose Linux enrollment with the real installed Hermes proof subprocess."""

from __future__ import annotations

import os
import select
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from mordred_hermes._database_contracts import DatabaseBusy
from mordred_hermes._database_lifecycle import acquire_exclusive, acquire_runtime
from mordred_hermes.keyvault import _memory_key as mk
from mordred_hermes.keyvault import _runtime_probe
from mordred_hermes.keyvault._memory_hook import memory_marker_path
from mordred_hermes.keyvault.memory_crypto import is_sealed
from mordred_hermes.wizard import memory_cli
from tests._keyvault_fakes import FakeBackend

pytestmark = pytest.mark.skipif(os.name != "posix", reason="real POSIX lifecycle; Linux-only enable route")


@pytest.fixture
def runtime_proof(tmp_path, monkeypatch, request):
    root = tmp_path / "home"
    root.mkdir(mode=0o700)
    home = root
    if getattr(request, "param", "root") == "profile":
        (root / "profiles").mkdir(mode=0o700)
        home = root / "profiles/work"
        home.mkdir(mode=0o700)
    (home / "memories").mkdir(mode=0o700)
    (home / "memories/MEMORY.md").write_text("synthetic memory")
    backend = FakeBackend()
    # An explicit synthetic native-key fixture, shared by both processes. Real
    # ECDH/wrapping and the installed startup/SH/probe body remain unchanged.
    backend._keys[mk.memory_key_id(home)] = ec.derive_private_key(7, ec.SECP256R1())
    monkeypatch.setattr(mk, "linux_memory_backend", lambda _home: backend)
    monkeypatch.setenv("HERMES_HOME", str(home))
    monkeypatch.setenv(_runtime_probe.RUNTIME_PYTHON_ENV, sys.executable)
    prefix = f"""
import sys
sys.path.insert(0, {str(Path(__file__).resolve().parents[1])!r})
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import ec
from mordred_hermes.keyvault import _memory_key as mk
from tests._keyvault_fakes import FakeBackend
backend = FakeBackend()
backend._keys[mk.memory_key_id(Path({str(home)!r}))] = ec.derive_private_key(7, ec.SECP256R1())
mk.linux_memory_backend = lambda home: backend
with mk.memory_key_lock(Path({str(home)!r})):
    pass
"""
    monkeypatch.setattr(_runtime_probe, "_MEMORY_KEY_PROBE_SRC", prefix + _runtime_probe._MEMORY_KEY_PROBE_SRC)
    return home, backend


@pytest.mark.parametrize("runtime_proof", ["root", "profile"], indirect=True)
def test_fresh_linux_enable_completes_real_installed_runtime_proof(runtime_proof):
    home, _backend = runtime_proof
    assert memory_cli.enable(home=home, root=home / "vault", platform="linux") == 0
    assert memory_marker_path(home).exists()
    assert is_sealed((home / "memories/MEMORY.md").read_bytes())


@pytest.mark.parametrize("damage", ["missing", "replaced", "corrupt", "native", "root", "home"])
@pytest.mark.parametrize("runtime_proof", ["root", "profile"], indirect=True)
@pytest.mark.parametrize("existing", [False, True])
def test_changed_source_after_real_proof_never_arms_or_recreates(runtime_proof, monkeypatch, damage, existing):
    home, backend = runtime_proof
    if existing:
        mk.ensure_linux_memory_key(home=home, backend=backend)
    path = mk.memory_key_path(home)
    proof = _runtime_probe.runtime_memory_key_available
    originals = []

    def change_after_proof(**kwargs):
        result = proof(**kwargs)
        assert result[0], result[1]
        original = path.read_bytes()
        originals.append(original)
        if damage == "missing":
            path.unlink()
        elif damage == "replaced":
            path.rename(path.with_suffix(".old"))
            path.write_bytes(original)
            path.chmod(0o600)
        elif damage == "corrupt":
            path.write_bytes(b"invalid synthetic wrapper")
        elif damage == "native":
            backend._keys[mk.memory_key_id(home)] = ec.derive_private_key(9, ec.SECP256R1())
        else:
            changed = home.parents[1] if damage == "root" and home.parent.name == "profiles" else home
            retained = changed.with_name("retained")
            changed.rename(retained)
            changed.mkdir(mode=0o700)
            # Keep custody/wrapper inodes and bytes identical: only the physical
            # root or profile identity changes, so ciphertext equality is not enough.
            for item in retained.iterdir():
                shutil.move(item, changed / item.name)
        return result

    monkeypatch.setattr(_runtime_probe, "runtime_memory_key_available", change_after_proof)
    assert memory_cli.enable(home=home, root=home / "vault", platform="linux") == 1
    assert not memory_marker_path(home).exists()
    assert (home / "memories/MEMORY.md").read_text() == "synthetic memory"
    assert not any(operation == "generate" for operation, _ in backend.calls)
    if damage == "missing":
        assert not path.exists()
    elif damage == "corrupt":
        assert path.read_bytes() == b"invalid synthetic wrapper"
    else:
        assert path.read_bytes() == originals[0]


def test_real_key_proof_failure_preserves_paused_marker_and_plaintext(runtime_proof, monkeypatch):
    home, backend = runtime_proof
    mk.ensure_linux_memory_key(home=home, backend=backend)
    original = mk.memory_key_path(home).read_bytes()
    paused = home / "mordred/memory-vault.optout"
    paused.write_bytes(b"paused")
    paused.chmod(0o600)
    # Only the child hardware key differs; real unwrap and probe failure remain.
    monkeypatch.setattr(
        _runtime_probe,
        "_MEMORY_KEY_PROBE_SRC",
        _runtime_probe._MEMORY_KEY_PROBE_SRC.replace("derive_private_key(7,", "derive_private_key(9,"),
    )
    assert memory_cli.enable(home=home, root=home / "vault", platform="linux") == 1
    assert paused.read_bytes() == b"paused"
    assert not memory_marker_path(home).exists()
    assert mk.memory_key_path(home).read_bytes() == original
    assert (home / "memories/MEMORY.md").read_text() == "synthetic memory"


def test_existing_key_enable_keeps_runtime_shared_admission(runtime_proof):
    home, backend = runtime_proof
    mk.ensure_linux_memory_key(home=home, backend=backend)
    original = mk.memory_key_path(home).read_bytes()
    with acquire_runtime(home):
        assert memory_cli.enable(home=home, root=home / "vault", platform="linux") == 0
    assert mk.memory_key_path(home).read_bytes() == original
    assert is_sealed((home / "memories/MEMORY.md").read_bytes())


def test_ordinary_installed_runtime_still_excludes_database_exclusive(runtime_proof, tmp_path):
    home, _backend = runtime_proof
    driver = tmp_path / "hermes"
    driver.write_text("print('ready', flush=True)\ninput()\n")
    process = subprocess.Popen(
        [sys.executable, str(driver)],
        env={**os.environ, "HERMES_HOME": str(home)},
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        assert process.stdout is not None
        assert select.select([process.stdout], [], [], 10)[0], "ordinary runtime did not reach its driver"
        assert process.stdout.readline().strip() == "ready"
        with pytest.raises(DatabaseBusy), acquire_exclusive(home):
            pass
    finally:
        try:
            process.communicate("\n", timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.communicate(timeout=10)
            raise
    assert process.returncode == 0
    with acquire_exclusive(home):
        pass


@pytest.mark.parametrize(
    "ordinary,noninteractive,expected",
    [
        (False, False, "ran:"),
        (True, False, "failed:"),
        (False, True, "manual:"),
    ],
)
def test_installed_setup_startup_memory_composition(
    runtime_proof, tmp_path, monkeypatch, ordinary, noninteractive, expected
):
    """Real .pth/startup/leases/setup/proofs, with only native custody replaced."""
    import json

    from tests.integration import test_linux_memory_orchestration_tpm as orchestration

    home, _backend = runtime_proof
    original_run = orchestration._run
    prefix = f"""
import sys, json
sys.path.insert(0, {str(Path(__file__).resolve().parents[1])!r})
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import ec
from mordred_hermes.keyvault import _memory_key as mk, _runtime_probe, _seckey_helper
from tests._keyvault_fakes import FakeBackend
backend = FakeBackend()
backend._keys[mk.memory_key_id(Path({str(home)!r}))] = ec.derive_private_key(7, ec.SECP256R1())
mk.linux_memory_backend = lambda home: backend
_runtime_probe._MEMORY_KEY_PROBE_SRC = {_runtime_probe._MEMORY_KEY_PROBE_SRC!r}
helper_calls = []
def refuse_helper(*args, **kwargs):
    helper_calls.append(True)
    raise AssertionError('native helper forbidden')
_seckey_helper._run_helper = refuse_helper
"""
    results = []

    def software_run(home, script, source, env, **kwargs):
        if ordinary:
            script = script.with_name("hermes")
            if "args" in kwargs:
                kwargs["args"] = ()
        result = original_run(
            home,
            script,
            prefix + source + "\nprint('CUSTODY:' + json.dumps([len(backend.calls), len(helper_calls)]))\n",
            env,
            **kwargs,
        )
        results.append(result)
        return result

    monkeypatch.setattr(orchestration, "_run", software_run)
    result = orchestration._setup(home, tmp_path / "hermes", dict(os.environ), noninteractive=noninteractive)
    assert result.startswith(expected), result
    calls, helper_calls = json.loads(
        next(line.removeprefix("CUSTODY:") for line in results[0].stdout.splitlines() if line.startswith("CUSTODY:"))
    )
    assert helper_calls == 0
    if expected == "ran:":
        assert calls > 0
        assert memory_marker_path(home).is_file()
        assert is_sealed((home / "memories/MEMORY.md").read_bytes())
    else:
        assert calls == 0
        assert not mk.memory_key_path(home).exists()
        assert not memory_marker_path(home).exists()
        assert (home / "memories/MEMORY.md").read_text() == "synthetic memory"
