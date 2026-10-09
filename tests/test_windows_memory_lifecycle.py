"""Proof-bound Windows memory enable/disable, markers and purge verification.

Every proof comes from the real installed-runtime child (see
``tests/test_windows_memory_proof.py``). Files go through real checked
transactions with real MRKW and AES-GCM; faults are injected at the checked
transaction primitives. Key bytes never appear in assertion operands.
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from mordred_hermes import _config_io as cio
from mordred_hermes import _windows_runtime
from mordred_hermes._private_fs import PrivateFSError, open_private_directory
from mordred_hermes.keyvault import _windows_processes, wrap
from mordred_hermes.keyvault._runtime_probe import GatewayDiscoveryUnavailable, GatewayRuntime
from mordred_hermes.keyvault.memory_crypto import is_sealed, seal, unseal
from tests import _windows_proof_runtime as injected
from tests.test_windows_custody import fs as fs
from tests.test_windows_memory_proof import INJECTION, enroll, proof_module, prove
from tests.test_windows_memory_proof import installed_runtime as installed_runtime
from tests.test_windows_memory_proof import proof_env as proof_env

ORIGINALS = {
    "MEMORY.md": b"alpha\n\xc2\xa7\nbeta",
    "USER.md": b"name: operator\r\n\xc2\xa7\r\nrole: tester\r\n",
    "MEMORY.md.bak.1700000000": b"older alpha",
}
MARKER = "memory-vault.marker"
OPTOUT = "memory-vault.optout"


def normalized(data: bytes) -> str:
    return data.decode("utf-8").replace("\r\n", "\n").replace("\r", "\n")


def storage():
    from mordred_hermes.keyvault import _memory_storage

    return _memory_storage


def put(home, directory, name, data):
    with open_private_directory(home / directory, create=True) as d, d.transaction() as tx:
        tx.create_bytes(name, data)


def files(home):
    root = home / "memories"
    if not root.exists():
        return {}
    # The C1 sidecar lock is foundation-owned, not memory content.
    return {path.name: path.read_bytes() for path in sorted(root.iterdir()) if not path.name.startswith(".mordred-fs")}


def markers(home):
    return {name for name in (MARKER, OPTOUT) if (home / "mordred" / name).exists()}


@pytest.fixture
def proven(proof_env):
    env = proof_env
    env.lease = enroll(env)
    for name, data in ORIGINALS.items():
        put(env.home, "memories", name, data)
    env.proof = prove(env)
    return env


def with_key(env, check):
    """Run ``check(key)`` on a freshly loaded key; return only its boolean."""
    with env.custody.windows_custody_session(env.home, backend=env.backend) as owner:
        return bool(check(owner.load_memory_key()))


def seal_with_profile_key(env, plaintext, name):
    """Ciphertext under the profile key; the key itself never leaves this scope."""
    with env.custody.windows_custody_session(env.home, backend=env.backend) as owner:
        return seal(plaintext, key=owner.load_memory_key(), name=name)


def sealed_as_original(env, name, data):
    return with_key(env, lambda key: unseal(data, key=key, name=name).decode("utf-8") == normalized(ORIGINALS[name]))


def assert_coherent(env):
    """Each memory is its original plaintext or an authenticated seal of it."""
    current = files(env.home)
    assert set(ORIGINALS) <= set(current)
    for name, original in ORIGINALS.items():
        data = current[name]
        ok = data in (original, normalized(original).encode()) or (
            is_sealed(data) and sealed_as_original(env, name, data)
        )
        assert ok, f"{name} lost its content"
    assert markers(env.home) != {MARKER, OPTOUT}, "armed and opt-out markers coexist"


def assert_all_sealed(env):
    for name, data in files(env.home).items():
        ok = is_sealed(data) and sealed_as_original(env, name, data)
        assert ok, f"{name} is not an authenticated seal of its original"


READER = r"""
import hashlib, importlib.util, json, os, sys
from pathlib import Path
spec = importlib.util.spec_from_file_location("_inject", os.environ["MORDRED_TEST_INJECT_BACKEND"])
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
module.install()
from mordred_hermes.keyvault._memory_storage import windows_memory_session
with windows_memory_session(Path(os.environ["HERMES_HOME"])) as session:
    report = {
        row.name: hashlib.sha256(session.read_plaintext(row.name).encode("utf-8")).hexdigest()
        for row in session.inventory()
    }
print(json.dumps(report, sort_keys=True))
"""


def fresh_process_read(env):
    environ = _windows_runtime.scrubbed_environment(os.environ)
    environ = {key: value for key, value in environ.items() if not key.upper().startswith(("MORDRED_", "HERMES_"))}
    environ |= {"HERMES_HOME": str(env.home), "MORDRED_TEST_INJECT_BACKEND": str(INJECTION), "PYTHONUTF8": "1"}
    child = subprocess.run(
        [str(env.python), "-c", READER], env=environ, capture_output=True, text=True, timeout=120, check=False
    )
    assert child.returncode == 0, child.stderr
    return json.loads(child.stdout)


def expected_hashes():
    return {name: hashlib.sha256(normalized(data).encode("utf-8")).hexdigest() for name, data in ORIGINALS.items()}


def test_enable_fresh_read_rerun_and_disable(proven):
    env = proven
    module = storage()
    report = module.enable_memory_encryption(env.home, env.proof)
    assert report == module.EnableReport(sealed=3, already_sealed=0, reconciled=0, armed=True)
    assert_all_sealed(env)
    assert markers(env.home) == {MARKER}
    assert fresh_process_read(env) == expected_hashes()
    again = module.enable_memory_encryption(env.home, env.proof)
    assert again == module.EnableReport(sealed=0, already_sealed=3, reconciled=0, armed=True)

    disabled = module.disable_memory_encryption(env.home, env.proof)
    assert disabled == module.DisableReport(decrypted=3, already_plaintext=0, reconciled=0, opted_out=True)
    assert files(env.home) == {name: normalized(data).encode() for name, data in ORIGINALS.items()}
    assert markers(env.home) == {OPTOUT}
    assert fresh_process_read(env) == expected_hashes()
    with env.custody.windows_custody_session(env.home, backend=env.backend) as owner:
        state = owner.memory_state()
        assert state.lease == env.lease and not state.armed
        retained = len(owner.load_memory_key()) == 32
    assert retained, "disable must retain the memory key"
    rerun = module.disable_memory_encryption(env.home, env.proof)
    assert rerun == module.DisableReport(decrypted=0, already_plaintext=3, reconciled=0, opted_out=True)


def test_enable_without_memories_directory_only_arms(proof_env):
    env = proof_env
    enroll(env)
    proof = prove(env)
    report = storage().enable_memory_encryption(env.home, proof)
    assert report.sealed == 0 and report.armed
    assert not (env.home / "memories").exists()
    assert markers(env.home) == {MARKER}


@pytest.mark.skipif(os.name == "nt", reason="host emulation of a global POSIX pytest parent")
def test_host_lifecycle_does_not_require_the_pytest_parent_to_be_a_venv(proof_env, monkeypatch, tmp_path):
    env = proof_env
    module = storage()
    parent = tmp_path / "global" / "bin" / "python"
    parent.parent.mkdir(parents=True)
    parent.touch()
    assert _windows_runtime.environment_root(parent) is None
    # Replace only storage's sys binding; the real proof child and pytest's
    # own sys.executable stay untouched.
    monkeypatch.setattr(module, "sys", SimpleNamespace(executable=str(parent)))
    enroll(env)
    proof = prove(env)
    report = module.enable_memory_encryption(env.home, proof)
    assert report.sealed == 0 and report.armed
    assert markers(env.home) == {MARKER}
    disabled = module.disable_memory_encryption(env.home, proof)
    assert disabled.decrypted == 0 and disabled.opted_out
    assert markers(env.home) == {OPTOUT}


def test_keep_key_false_refuses_before_any_lock_or_mutation(proven):
    env = proven
    before = files(env.home)
    with pytest.raises(storage().MemoryStorageError, match="purge"):
        storage().disable_memory_encryption(env.home, env.proof, keep_key=False)
    assert files(env.home) == before and markers(env.home) == set()


def _bump_epoch(env):
    with env.custody.windows_custody_session(env.home, backend=env.backend) as owner:
        owner.enroll_role("audit")


def _rewrap(env):
    with env.custody.windows_custody_session(env.home, backend=env.backend) as owner:
        key = owner.load_memory_key()
        blob = wrap.wrap_dek(key, env.lease.native_key_id, backend=env.backend)
        del key
    with open_private_directory(env.home / "mordred") as d, d.transaction() as tx:
        tx.replace_bytes("memory-key.wrapped", blob)


def _new_generation(env):
    put(env.home, "mordred", OPTOUT, b"opt-out\n")
    with env.custody.windows_custody_session(env.home, backend=env.backend) as owner:
        owner.delete_role(env.lease)
    with env.custody.windows_custody_session(env.home, backend=env.backend) as owner:
        owner.enroll_memory()
        assert owner.lease("memory").generation != env.lease.generation


STALE = {"epoch": _bump_epoch, "wrapped": _rewrap, "generation": _new_generation}


@pytest.mark.parametrize("change", list(STALE))
@pytest.mark.parametrize("operation", ["enable", "disable"])
def test_stale_proof_refuses_without_mutation(proven, change, operation):
    env = proven
    STALE[change](env)
    before, flags = files(env.home), markers(env.home)
    method = getattr(storage(), f"{operation}_memory_encryption")
    with pytest.raises(proof_module().WindowsRuntimeProofError, match=r"\(proof-stale\)"):
        method(env.home, env.proof)
    assert files(env.home) == before and markers(env.home) == flags


def test_proof_for_another_profile_refuses(proven, tmp_path):
    env = proven
    other = tmp_path / "other"
    with open_private_directory(other, create=True):
        pass
    with env.custody.windows_custody_session(other, create=True, backend=env.backend) as owner:
        owner.enroll_memory()
    put(other, "memories", "MEMORY.md", b"other profile")
    with pytest.raises(proof_module().WindowsRuntimeProofError, match=r"\(proof-stale\)"):
        storage().enable_memory_encryption(other, env.proof)
    assert (other / "memories" / "MEMORY.md").read_bytes() == b"other profile"
    assert not (other / "mordred" / MARKER).exists()


def test_expired_or_copied_proof_refuses_before_locks(proven, monkeypatch):
    env = proven
    module = proof_module()
    with pytest.raises(module.WindowsRuntimeProofError, match=r"\(proof-not-issued\)"):
        storage().enable_memory_encryption(env.home, copy.copy(env.proof))
    monkeypatch.setattr(module, "_clock", lambda: env.proof.proved_at + module.PROOF_TTL_SECONDS + 1)
    with pytest.raises(module.WindowsRuntimeProofError, match=r"\(proof-expired\)"):
        storage().enable_memory_encryption(env.home, env.proof)
    assert files(env.home) == ORIGINALS and markers(env.home) == set()


@pytest.mark.parametrize("state", ["running", "unknown"])
def test_gateway_gate_reruns_at_consumption(proven, monkeypatch, state):
    env = proven

    def inventory(home, **kwargs):
        if state == "running":
            return _windows_processes.GatewayInventory("known", (GatewayRuntime(4242, env.python),), ())
        return _windows_processes.GatewayInventory("unknown", (), ("scan:inventory-unavailable",))

    monkeypatch.setattr(_windows_processes, "inspect_windows_gateway_runtimes", inventory)
    with pytest.raises(GatewayDiscoveryUnavailable):
        storage().enable_memory_encryption(env.home, env.proof)
    assert files(env.home) == ORIGINALS and markers(env.home) == set()


def transaction_class():
    if os.name == "nt":
        from mordred_hermes._private_fs import _windows_io as implementation
    else:
        from mordred_hermes._private_fs import _posix as implementation
    return implementation._Transaction


class Fault:
    """Fail the first checked primitive matching ``method``/``target`` once."""

    def __init__(self, monkeypatch, method, target, *, after=False):
        self.fired = False
        cls = transaction_class()
        real = getattr(cls, method)
        fault = self

        def matches(name):
            return name.startswith(target) if target.endswith("-") else name == target

        def injected_method(tx, name, *args, **kwargs):
            if fault.fired or not matches(name):
                return real(tx, name, *args, **kwargs)
            fault.fired = True
            if after:
                real(tx, name, *args, **kwargs)
                raise PrivateFSError("io", "injected", commit_state="uncertain")
            raise PrivateFSError("io", "injected")

        monkeypatch.setattr(cls, method, injected_method)


SIBLING = ".mordred-memory-"
ENABLE_FAULTS = {
    "sibling-create": ("create_bytes", SIBLING, {}),
    "publish": ("replace_bytes", "MEMORY.md", {"after": True}),
    "verify": None,
    "sibling-cleanup": ("delete_file", SIBLING, {}),
    "optout-removal": ("delete_file", OPTOUT, {}),
    "marker-create": ("create_bytes", MARKER, {"after": True}),
}


def _arm_read_fault_after_publish(monkeypatch, name):
    """Corrupt only the post-publication read-back of ``name``."""
    cls = transaction_class()
    real_replace, real_read = cls.replace_bytes, cls.read_bytes
    state = {"published": False, "fired": False}

    def replace(tx, target, data):
        real_replace(tx, target, data)
        state["published"] = state["published"] or target == name

    def read(tx, target, **kwargs):
        data = real_read(tx, target, **kwargs)
        if state["published"] and not state["fired"] and target == name:
            state["fired"] = True
            return b"corrupted"
        return data

    monkeypatch.setattr(cls, "replace_bytes", replace)
    monkeypatch.setattr(cls, "read_bytes", read)
    return state


@pytest.mark.parametrize("step", list(ENABLE_FAULTS))
def test_enable_fault_at_each_publication_step_stays_coherent(proven, monkeypatch, step):
    env = proven
    module = storage()
    if step == "optout-removal":
        put(env.home, "mordred", OPTOUT, b"opt-out\n")
    with monkeypatch.context() as patch:
        if step == "verify":
            fired = _arm_read_fault_after_publish(patch, "MEMORY.md")
        else:
            method, target, options = ENABLE_FAULTS[step]
            fired = Fault(patch, method, target, **options).__dict__
        with pytest.raises((module.MemoryLifecycleError, PrivateFSError)):
            module.enable_memory_encryption(env.home, env.proof)
        assert fired["fired"]
    assert_coherent(env)
    assert MARKER not in markers(env.home) or step == "marker-create"
    report = module.enable_memory_encryption(env.home, env.proof)
    assert report.armed
    assert_all_sealed(env)
    assert markers(env.home) == {MARKER}
    assert not [name for name in os.listdir(env.home / "memories") if name.startswith(SIBLING)]


DISABLE_FAULTS = {
    "sibling-create": ("create_bytes", SIBLING, {}),
    "publish": ("replace_bytes", "MEMORY.md", {"after": True}),
    "verify": None,
    "sibling-cleanup": ("delete_file", SIBLING, {}),
    "marker-removal": ("delete_file", MARKER, {}),
    "optout-create": ("create_bytes", OPTOUT, {"after": True}),
}


@pytest.mark.parametrize("step", list(DISABLE_FAULTS))
def test_disable_fault_at_each_publication_step_stays_coherent(proven, monkeypatch, step):
    env = proven
    module = storage()
    module.enable_memory_encryption(env.home, env.proof)
    with monkeypatch.context() as patch:
        if step == "verify":
            fired = _arm_read_fault_after_publish(patch, "MEMORY.md")
        else:
            method, target, options = DISABLE_FAULTS[step]
            fired = Fault(patch, method, target, **options).__dict__
        with pytest.raises((module.MemoryLifecycleError, PrivateFSError)):
            module.disable_memory_encryption(env.home, env.proof)
        assert fired["fired"]
    assert_coherent(env)
    if step not in ("marker-removal", "optout-create"):
        assert markers(env.home) == {MARKER}, "a file failure must keep the armed state"
    with env.custody.windows_custody_session(env.home, backend=env.backend) as owner:
        assert owner.memory_state().lease == env.lease
    report = module.disable_memory_encryption(env.home, env.proof)
    assert report.opted_out
    assert files(env.home) == {name: normalized(data).encode() for name, data in ORIGINALS.items()}
    assert markers(env.home) == {OPTOUT}


def test_lifecycle_failure_reports_progress(proven, monkeypatch):
    env = proven
    module = storage()
    Fault(monkeypatch, "replace_bytes", "MEMORY.md.bak.1700000000", after=True)
    with pytest.raises(module.MemoryLifecycleError) as failure:
        module.enable_memory_encryption(env.home, env.proof)
    assert failure.value.operation == "enable"
    assert failure.value.completed == 1 and failure.value.remaining == 2
    assert failure.value.uncertain


def test_rerun_validates_every_existing_seal(proven):
    env = proven
    module = storage()
    module.enable_memory_encryption(env.home, env.proof)
    forged = seal(b"forged", key=b"\x07" * 32, name="USER.md")
    with open_private_directory(env.home / "memories") as d, d.transaction() as tx:
        tx.replace_bytes("USER.md", forged)
    before = files(env.home)
    for method in (module.enable_memory_encryption, module.disable_memory_encryption):
        with pytest.raises(module.MemoryStorageError):
            method(env.home, env.proof)
        assert files(env.home) == before and markers(env.home) == {MARKER}


def test_broken_seal_refuses_enable_before_mutation(proven):
    env = proven
    put(env.home, "memories", "BROKEN.md", b"HERMES-MEMORY-ENC-v1\nnot-a-seal")
    before = files(env.home)
    with pytest.raises(storage().MemoryStorageError):
        storage().enable_memory_encryption(env.home, env.proof)
    assert files(env.home) == before and markers(env.home) == set()


def test_disable_refuses_plaintext_that_would_impersonate_a_seal(proven):
    env = proven
    module = storage()
    module.enable_memory_encryption(env.home, env.proof)
    put(env.home, "memories", "FAKE.md", seal_with_profile_key(env, b"HERMES-MEMORY-ENC-v1\nx", "FAKE.md"))
    before = files(env.home)
    with pytest.raises(module.MemoryStorageError):
        module.disable_memory_encryption(env.home, env.proof)
    assert files(env.home) == before and markers(env.home) == {MARKER}


def test_orphan_lifecycle_sibling_refuses(proven):
    env = proven
    sibling = SIBLING + "seal-" + b"GONE.md".hex()
    put(env.home, "memories", sibling, b"leftover")
    before = files(env.home)
    with pytest.raises(storage().MemoryStorageError, match="sibling"):
        storage().enable_memory_encryption(env.home, env.proof)
    assert files(env.home) == before and markers(env.home) == set()


def test_leftover_sibling_with_target_is_reconciled(proven):
    env = proven
    put(env.home, "memories", SIBLING + "open-" + b"MEMORY.md".hex(), b"stale plaintext copy")
    report = storage().enable_memory_encryption(env.home, env.proof)
    assert report.reconciled == 1 and report.sealed == 3
    assert not [name for name in os.listdir(env.home / "memories") if name.startswith(SIBLING)]


def test_markers_never_coexist_after_transitions(proven):
    env = proven
    module = storage()
    put(env.home, "mordred", MARKER, b"memory-encryption enabled\n")
    put(env.home, "mordred", OPTOUT, b"opt-out\n")
    module.enable_memory_encryption(env.home, env.proof)
    assert markers(env.home) == {MARKER}
    module.disable_memory_encryption(env.home, env.proof)
    assert markers(env.home) == {OPTOUT}
    module.enable_memory_encryption(env.home, env.proof)
    assert markers(env.home) == {MARKER}
    assert (env.home / "mordred" / MARKER).read_bytes() == b"memory-encryption enabled\n"


def test_purge_report_tracks_lifecycle_without_native_calls(proven):
    env = proven
    module = storage()

    def verify():
        before = list(env.backend.calls)
        report = module.verify_memory_purge_candidates(env.home)
        assert env.backend.calls == before, "purge verification must not touch the native key"
        return report

    initial = verify()
    assert initial.managed and not initial.may_purge
    assert initial.plaintext == ("MEMORY.md", "MEMORY.md.bak.1700000000", "USER.md")
    assert initial.backups == ("MEMORY.md.bak.1700000000",)
    module.enable_memory_encryption(env.home, env.proof)
    armed = verify()
    assert armed.armed and armed.sealed == initial.plaintext and not armed.may_purge
    module.disable_memory_encryption(env.home, env.proof)
    ready = verify()
    assert ready.may_purge and ready.opted_out and ready.reasons == ()
    put(env.home, "memories", SIBLING + "open-" + b"USER.md".hex(), b"leftover")
    put(env.home, "memories", "BROKEN.md", b"HERMES-MEMORY-ENC-v1\nnot-a-seal")
    blocked = verify()
    assert blocked.pending == (SIBLING + "open-" + b"USER.md".hex(),)
    assert blocked.broken == ("BROKEN.md",) and not blocked.may_purge


def test_purge_report_for_unmanaged_profile(proof_env):
    env = proof_env
    put(env.home, "memories", "MEMORY.md", b"plain")
    report = storage().verify_memory_purge_candidates(env.home)
    assert not report.managed and not report.may_purge
    assert report.plaintext == ("MEMORY.md",)


def test_lifecycle_launches_no_subprocess(proven):
    env = proven
    launches = len(env.launches.argv)
    storage().enable_memory_encryption(env.home, env.proof)
    storage().disable_memory_encryption(env.home, env.proof)
    storage().verify_memory_purge_candidates(env.home)
    assert len(env.launches.argv) == launches


REAL_INVENTORY = _windows_processes.inspect_windows_gateway_runtimes


def test_real_gate_runs_under_lifecycle_locks(proof_env, monkeypatch):
    """Only psutil and the state-file PID reader are stubbed; the real gate decides."""
    import psutil

    env = proof_env
    observed = []

    class Owner:
        def __init__(self, pid):
            self.pid = pid

        def username(self):
            return "operator"

    def pids():
        observed.append(getattr(cio._local, "state", None) is not None)
        return []

    fake = SimpleNamespace(
        Process=Owner,
        pids=pids,
        Error=psutil.Error,
        NoSuchProcess=psutil.NoSuchProcess,
        AccessDenied=psutil.AccessDenied,
    )
    monkeypatch.setattr(_windows_processes, "inspect_windows_gateway_runtimes", REAL_INVENTORY)
    monkeypatch.setattr(_windows_processes, "psutil", fake)
    monkeypatch.setattr(_windows_processes, "_read_state_pid", lambda home: None)
    enroll(env)
    put(env.home, "memories", "MEMORY.md", b"gated")
    proof = prove(env)
    report = storage().enable_memory_encryption(env.home, proof)
    assert report.sealed == 1 and report.armed
    assert observed[0] is False, "the proof gate must run outside locks"
    assert observed[1:] == [True, True], "the lifecycle gate must run twice under held locks"


def test_pending_lifecycle_siblings_reports_interrupted_disable(proven, monkeypatch):
    env = proven
    module = storage()
    module.enable_memory_encryption(env.home, env.proof)
    assert module.pending_lifecycle_siblings(env.home) == ()
    with monkeypatch.context() as patch:
        Fault(patch, "replace_bytes", "MEMORY.md")
        with pytest.raises((module.MemoryLifecycleError, PrivateFSError)):
            module.disable_memory_encryption(env.home, env.proof)
    sibling = SIBLING + "open-" + b"MEMORY.md".hex()
    assert module.pending_lifecycle_siblings(env.home) == (sibling,)
    assert is_sealed(files(env.home)["MEMORY.md"]), "the target stays sealed beside the plaintext sibling"
    module.disable_memory_encryption(env.home, env.proof)
    assert module.pending_lifecycle_siblings(env.home) == ()


def test_pending_lifecycle_siblings_without_memories(proof_env):
    assert storage().pending_lifecycle_siblings(proof_env.home) == ()


def test_injected_backend_is_test_only_file():
    assert Path(injected.HELPER) == Path(os.path.realpath(INJECTION))
