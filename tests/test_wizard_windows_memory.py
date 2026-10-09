"""Wizard Windows memory lifecycle and the native custody ceremony (C6).

Portable: real checked files, real MRKW/AES-GCM and real installed-runtime
proofs from the proof slice's child harness (``tests/_windows_proof_runtime.py``),
with the native CNG boundary, principal and platform admission injected. Each
refusal asserts the step it names and that memory files, markers and custody
are exactly as before. Key bytes never appear in an assertion operand.
"""

from __future__ import annotations

import builtins
import io
import os
import sys
from pathlib import Path

import pytest

from mordred_hermes._private_fs import PrivateFSError, open_private_directory
from mordred_hermes.keyvault import _seckey_helper, _windows_capability, _windows_processes
from mordred_hermes.keyvault._runtime_probe import GatewayRuntime
from mordred_hermes.wizard import _windows_gates, cli, keyvault_windows_cli, memory_cli
from tests.test_windows_custody import fs as fs
from tests.test_windows_memory_lifecycle import (
    MARKER,
    OPTOUT,
    ORIGINALS,
    Fault,
    assert_all_sealed,
    assert_coherent,
    expected_hashes,
    files,
    fresh_process_read,
    markers,
    normalized,
    put,
)
from tests.test_windows_memory_proof import installed_runtime as installed_runtime
from tests.test_windows_memory_proof import proof_env as proof_env


@pytest.fixture
def win(proof_env, monkeypatch):
    """Windows routing on any host: C5e predicates and the wizard seam say win32."""
    env = proof_env
    monkeypatch.setattr(_windows_capability, "_platform", lambda: "win32")
    monkeypatch.setattr(_windows_gates, "host_platform", lambda: "win32")
    monkeypatch.setenv("MORDRED_HERMES_PYTHON", str(env.python))
    monkeypatch.setenv("HERMES_HOME", str(env.home))
    return env


@pytest.fixture
def seeded(win):
    for name, data in ORIGINALS.items():
        put(win.home, "memories", name, data)
    return win


def generated(env) -> int:
    return sum(1 for op, _ in env.backend.calls if op == "generate")


def memory_lease(env):
    with env.custody.windows_custody_session(env.home, backend=env.backend) as owner:
        return owner.memory_state().lease


def role_current(env, role):
    with env.custody.windows_custody_session(env.home, backend=env.backend) as owner:
        return owner.role_status(role).current


def key_absent_from(env, text: str) -> bool:
    with env.custody.windows_custody_session(env.home, backend=env.backend) as owner:
        key = owner.load_memory_key()
        return key.hex() not in text and key.hex().upper() not in text


class Inventory:
    """Gateway inventory spy: ``known`` empty unless told otherwise."""

    def __init__(self, monkeypatch, state="known", running=()):
        self.calls = 0
        self.state, self.running = state, running

        def inspect(home, **kwargs):
            self.calls += 1
            reasons = () if self.state == "known" else ("scan:inventory-unavailable",)
            return _windows_processes.GatewayInventory(self.state, self.running, reasons)

        monkeypatch.setattr(_windows_processes, "inspect_windows_gateway_runtimes", inspect)


#: The SPEC-frozen substance of the notice printed whenever a CNG custody key is created.
NO_PRESENCE_NO_RECOVERY = "There is no per-use presence and no portable recovery: losing the TPM"


def snapshot(env):
    mordred = env.home / "mordred"
    entries = sorted(path.name for path in mordred.iterdir()) if mordred.exists() else []
    return files(env.home), markers(env.home), entries


# -----------------------------------------------------------------------------
# keyvault native init — the explicit ceremony
# -----------------------------------------------------------------------------
def test_ceremony_enrolls_inert_memory_once_and_prints_metadata_only(seeded, capsys):
    env = seeded
    assert keyvault_windows_cli.native_init(home=env.home) == 0
    out = capsys.readouterr().out
    lease = memory_lease(env)
    assert lease is not None
    assert f"memory : enrolled now — generation {lease.generation}" in out
    assert lease.public_sha256 in out
    assert key_absent_from(env, out)
    assert "excluded on Windows (excluded-on-windows)" in out
    assert "not ported to Windows (not-ported-on-windows)" in out
    assert NO_PRESENCE_NO_RECOVERY in out and keyvault_windows_cli.CUSTODY_NOTICE in out
    assert files(env.home) == ORIGINALS and markers(env.home) == set(), "enrollment must stay inert"
    assert role_current(env, "audit") is None, "audit is never enrolled implicitly"
    assert generated(env) == 1

    assert keyvault_windows_cli.native_init(home=env.home) == 0
    assert "already enrolled (unchanged)" in capsys.readouterr().out
    assert generated(env) == 1 and memory_lease(env) == lease


def test_ceremony_enrolls_only_the_requested_roles(win, capsys):
    env = win
    assert keyvault_windows_cli.native_init(home=env.home, roles=["audit"]) == 0
    assert role_current(env, "audit") is not None and memory_lease(env) is None
    assert keyvault_windows_cli.native_init(home=env.home, roles=["memory", "audit", "audit"]) == 0
    out = capsys.readouterr().out
    assert "audit  : already enrolled" in out and "memory : enrolled now" in out
    assert generated(env) == 2


def test_ceremony_cli_parses_role_flags(win, capsys):
    assert cli.main(["keyvault", "native", "init", "--role", "audit"]) == 0
    assert role_current(win, "audit") is not None and memory_lease(win) is None


def test_ceremony_refuses_a_copied_profile_without_generating(win, capsys):
    env = win
    assert keyvault_windows_cli.native_init(home=env.home, roles=["memory"]) == 0
    copied = env.home.parent / "copied"
    with open_private_directory(copied, create=True):
        pass
    with open_private_directory(copied / "mordred", create=True) as directory, directory.transaction() as tx:
        for name in ("windows-custody.json", "memory-key.wrapped"):
            tx.create_bytes(name, (env.home / "mordred" / name).read_bytes())
    before = generated(env)
    assert keyvault_windows_cli.native_init(home=copied, roles=["memory", "audit"]) == 1
    err = capsys.readouterr().err
    assert "custody refused (custody-broken)" in err and "never adopted" in err
    assert generated(env) == before
    assert sorted(path.name for path in (copied / "mordred").iterdir() if not path.name.startswith(".")) == [
        "memory-key.wrapped",
        "windows-custody.json",
    ]


def test_ceremony_refuses_retained_marker_without_ownership(win, capsys):
    env = win
    put(env.home, "mordred", MARKER, b"memory-encryption enabled\n")
    assert keyvault_windows_cli.native_init(home=env.home) == 1
    assert "(custody-broken)" in capsys.readouterr().err
    assert generated(env) == 0 and not (env.home / "mordred" / "windows-custody.json").exists()


def test_ceremony_refuses_without_helper_before_any_custody_write(win, monkeypatch, capsys):
    env = win
    monkeypatch.setattr(_seckey_helper, "find_winkey_helper", lambda: None)
    assert keyvault_windows_cli.native_init(home=env.home) == 1
    err = capsys.readouterr().err
    assert "(helper-missing)" in err and "keyvault enable-winkey" in err
    assert generated(env) == 0 and not (env.home / "mordred").exists()


@pytest.mark.skipif(sys.platform == "win32", reason="this host is Windows")
def test_ceremony_refuses_off_windows(proof_env, capsys):
    assert keyvault_windows_cli.native_init(home=proof_env.home) == 1
    assert "only on native Windows" in capsys.readouterr().err
    assert not (proof_env.home / "mordred").exists()


def test_ceremony_native_failure_keeps_intent_and_creates_no_wrapper(win, monkeypatch, capsys):
    env = win

    def denied(*args, **kwargs):
        raise env.custody.CustodyError("native creation failed")

    monkeypatch.setattr(env.backend, "generate_enclave_key", denied)
    assert keyvault_windows_cli.native_init(home=env.home) == 1
    assert "memory custody refused" in capsys.readouterr().err
    assert (env.home / "mordred" / "windows-memory.pending.json").exists()
    assert not (env.home / "mordred" / "memory-key.wrapped").exists()


# -----------------------------------------------------------------------------
# encryption enable memory
# -----------------------------------------------------------------------------
def test_enable_end_to_end_through_the_cli(seeded, capsys):
    env = seeded
    assert cli.main(["encryption", "enable", "memory"]) == 0
    out = capsys.readouterr().out
    assert "Enrolled inert Windows memory custody" in out
    assert NO_PRESENCE_NO_RECOVERY in out and keyvault_windows_cli.CUSTODY_NOTICE in out
    assert out.index(NO_PRESENCE_NO_RECOVERY) < out.index("Agent-memory encryption enabled on Windows")
    assert "Agent-memory encryption enabled on Windows: 3 file(s) sealed" in out
    assert_all_sealed(env)
    assert markers(env.home) == {MARKER}
    assert fresh_process_read(env) == expected_hashes()
    assert role_current(env, "audit") is None, "memory enable never enrolls audit"
    assert key_absent_from(env, out)

    assert memory_cli.enable(home=env.home, root=env.home / "vault", platform="win32") == 0
    rerun = capsys.readouterr().out
    assert "0 file(s) sealed, 3 already sealed and verified" in rerun
    assert NO_PRESENCE_NO_RECOVERY not in rerun, "the notice accompanies key creation only"
    assert generated(env) == 1, "an enrolled key is reused, never re-created"


def test_force_runtime_unverified_is_refused_before_inventory(seeded, monkeypatch, capsys):
    env = seeded
    inventory = Inventory(monkeypatch)
    before = snapshot(env)
    assert cli.main(["encryption", "enable", "memory", "--force-runtime-unverified"]) == 1
    err = capsys.readouterr().err
    assert "refusing --force-runtime-unverified for agent memory on Windows" in err
    assert inventory.calls == 0 and generated(env) == 0
    assert snapshot(env) == before


@pytest.mark.parametrize("fault", ["helper-missing", "custody-broken"])
def test_enable_refuses_at_capabilities_without_changes(seeded, monkeypatch, capsys, fault):
    env = seeded
    if fault == "helper-missing":
        monkeypatch.setattr(_seckey_helper, "find_winkey_helper", lambda: None)
    else:
        put(env.home, "mordred", OPTOUT, b"opt-out\n")
    inventory = Inventory(monkeypatch)
    before = snapshot(env)
    assert memory_cli.enable(home=env.home, root=env.home / "vault", platform="win32") == 1
    assert f"refused at the capabilities step ({fault})" in capsys.readouterr().err
    assert inventory.calls == 0 and generated(env) == 0
    assert snapshot(env) == before


@pytest.mark.parametrize("state", ["running", "unknown"])
def test_enable_refuses_at_the_gate_before_enrollment(seeded, monkeypatch, capsys, state):
    env = seeded
    running = (GatewayRuntime(4242, env.python),) if state == "running" else ()
    Inventory(monkeypatch, state="known" if running else "unknown", running=running)
    before = snapshot(env)
    assert memory_cli.enable(home=env.home, root=env.home / "vault", platform="win32") == 1
    err = capsys.readouterr().err
    assert "refusing to change agent memory on Windows" in err and "no force option" in err
    assert generated(env) == 0 and snapshot(env) == before


def test_enable_refuses_at_the_ceremony_step(seeded, monkeypatch, capsys):
    env = seeded

    def denied(*args, **kwargs):
        raise env.custody.CustodyError("native creation failed")

    monkeypatch.setattr(env.backend, "generate_enclave_key", denied)
    assert memory_cli.enable(home=env.home, root=env.home / "vault", platform="win32") == 1
    assert "encryption enable memory (ceremony step)" in capsys.readouterr().err
    assert files(env.home) == ORIGINALS and markers(env.home) == set()


def test_enable_refuses_at_the_proof_step_and_keeps_the_inert_key(seeded, monkeypatch, capsys):
    env = seeded
    monkeypatch.setenv("MORDRED_HERMES_PYTHON", str(env.home.parent / "missing" / "python.exe"))
    assert memory_cli.enable(home=env.home, root=env.home / "vault", platform="win32") == 1
    captured = capsys.readouterr()
    err = captured.err
    assert "refused at the proof step (interpreter-invalid)" in err
    assert "inert memory custody key is kept" in err
    assert NO_PRESENCE_NO_RECOVERY in captured.out, "the created key is announced even when the proof refuses"
    assert memory_lease(env) is not None
    assert files(env.home) == ORIGINALS and markers(env.home) == set()


def test_enable_ceremony_refuses_sealed_memory_without_ownership(seeded, capsys):
    env = seeded
    put(env.home, "memories", "BROKEN.md", b"HERMES-MEMORY-ENC-v1\nnot-a-seal")
    before = files(env.home)
    assert memory_cli.enable(home=env.home, root=env.home / "vault", platform="win32") == 1
    assert "(ceremony step): memory custody refused (custody-broken)" in capsys.readouterr().err
    assert generated(env) == 0 and files(env.home) == before and markers(env.home) == set()


def test_enable_refuses_at_the_lifecycle_step_before_mutation(seeded, capsys):
    env = seeded
    assert keyvault_windows_cli.native_init(home=env.home) == 0
    put(env.home, "memories", "BROKEN.md", b"HERMES-MEMORY-ENC-v1\nnot-a-seal")
    before = files(env.home)
    assert memory_cli.enable(home=env.home, root=env.home / "vault", platform="win32") == 1
    assert "refused at the lifecycle step" in capsys.readouterr().err
    assert files(env.home) == before and markers(env.home) == set()


def test_enable_partial_lifecycle_failure_stays_coherent_and_reruns(seeded, monkeypatch, capsys):
    env = seeded
    with monkeypatch.context() as patch:
        fault = Fault(patch, "replace_bytes", "MEMORY.md.bak.1700000000", after=True)
        assert memory_cli.enable(home=env.home, root=env.home / "vault", platform="win32") == 1
        assert fault.fired
    err = capsys.readouterr().err
    assert "stopped during the lifecycle step after 1 file(s), 2 remaining" in err
    assert "the profile is NOT armed" in err
    assert_coherent(env)
    assert MARKER not in markers(env.home)
    assert memory_cli.enable(home=env.home, root=env.home / "vault", platform="win32") == 0
    assert_all_sealed(env)
    assert markers(env.home) == {MARKER}


# -----------------------------------------------------------------------------
# disable / purge
# -----------------------------------------------------------------------------
def test_disable_decrypts_and_keeps_the_key(seeded, capsys):
    env = seeded
    assert memory_cli.enable(home=env.home, root=env.home / "vault", platform="win32") == 0
    lease = memory_lease(env)
    assert cli.main(["encryption", "disable", "memory"]) == 0
    assert "3 file(s) decrypted back to plaintext" in capsys.readouterr().out
    assert files(env.home) == {name: normalized(data).encode() for name, data in ORIGINALS.items()}
    assert markers(env.home) == {OPTOUT}
    assert memory_lease(env) == lease
    assert fresh_process_read(env) == expected_hashes()
    assert memory_cli.disable(home=env.home, root=env.home / "vault", platform="win32") == 0
    assert "already disabled" in capsys.readouterr().out


def test_disable_on_unmanaged_profile_is_a_noop(seeded, monkeypatch, capsys):
    env = seeded
    inventory = Inventory(monkeypatch)
    assert memory_cli.disable(home=env.home, root=env.home / "vault", platform="win32") == 0
    assert "not enabled on this profile" in capsys.readouterr().out
    assert inventory.calls == 0 and files(env.home) == ORIGINALS


def test_disable_refuses_at_the_gate_and_keeps_the_seals(seeded, monkeypatch, capsys):
    env = seeded
    assert memory_cli.enable(home=env.home, root=env.home / "vault", platform="win32") == 0
    before = snapshot(env)
    Inventory(monkeypatch, state="known", running=(GatewayRuntime(7, env.python),))
    assert memory_cli.disable(home=env.home, root=env.home / "vault", platform="win32") == 1
    assert "refusing to change agent memory on Windows" in capsys.readouterr().err
    assert snapshot(env) == before


def test_purge_refuses_with_seals_and_succeeds_after_disable(seeded, capsys):
    env = seeded
    assert memory_cli.enable(home=env.home, root=env.home / "vault", platform="win32") == 0
    assert keyvault_windows_cli.native_init(home=env.home, roles=["audit"]) == 0
    audit = role_current(env, "audit")
    sealed = snapshot(env)
    assert cli.main(["encryption", "purge", "memory", "--yes"]) == 1
    err = capsys.readouterr().err
    assert "refused at the verification step (not-purgeable)" in err
    assert "sealed memory remains" in err and "encryption disable memory" in err
    assert snapshot(env) == sealed and memory_lease(env) is not None

    assert memory_cli.disable(home=env.home, root=env.home / "vault", platform="win32") == 0
    plaintext = files(env.home)
    native = memory_lease(env).native_key_id
    assert cli.main(["encryption", "purge", "memory", "--yes"]) == 0
    assert "1 generation(s) deleted" in capsys.readouterr().out
    assert memory_lease(env) is None and markers(env.home) == set()
    assert ("delete", native) in env.backend.calls
    assert files(env.home) == plaintext, "purge never touches memory files"
    assert role_current(env, "audit") == audit, "memory purge preserves audit custody"
    assert (env.home / "mordred" / "windows-custody.json").exists()

    assert memory_cli.purge(home=env.home, root=env.home / "vault", platform="win32") == 0
    assert "nothing to purge" in capsys.readouterr().out


def test_purge_refuses_interrupted_staging(seeded, capsys):
    env = seeded
    assert memory_cli.enable(home=env.home, root=env.home / "vault", platform="win32") == 0
    assert memory_cli.disable(home=env.home, root=env.home / "vault", platform="win32") == 0
    put(env.home, "memories", ".mordred-memory-open-" + b"MEMORY.md".hex(), b"left behind")
    assert memory_cli.purge(home=env.home, root=env.home / "vault", platform="win32") == 1
    assert "interrupted lifecycle staging remains" in capsys.readouterr().err
    assert memory_lease(env) is not None


def test_purge_refuses_at_the_gate_without_journal(seeded, monkeypatch, capsys):
    env = seeded
    assert memory_cli.enable(home=env.home, root=env.home / "vault", platform="win32") == 0
    assert memory_cli.disable(home=env.home, root=env.home / "vault", platform="win32") == 0
    Inventory(monkeypatch, state="unknown")
    assert memory_cli.purge(home=env.home, root=env.home / "vault", platform="win32") == 1
    assert "refusing to change agent memory on Windows" in capsys.readouterr().err
    assert memory_lease(env) is not None
    assert not (env.home / "mordred" / "windows-memory.pending.json").exists()


def test_proof_python_routes_through_the_launcher(win, monkeypatch):
    from mordred_hermes import _windows_runtime
    from mordred_hermes.keyvault._windows_proof import WindowsRuntimeProofError
    from mordred_hermes.wizard import _uninstall_hermes_env, _windows_memory

    launcher = win.home / "bin" / "hermes.exe"
    monkeypatch.setattr(_uninstall_hermes_env, "find_hermes_launcher", lambda home: launcher)
    assert _windows_memory.proof_python(win.home) is None, "MORDRED_HERMES_PYTHON stays authoritative"
    monkeypatch.delenv("MORDRED_HERMES_PYTHON")
    selected = Path("C:/hermes/python.exe")
    monkeypatch.setattr(_windows_runtime, "resolve_windows_python", lambda home, found: selected)
    assert _windows_memory.proof_python(win.home) == selected
    monkeypatch.setattr(_windows_runtime, "resolve_windows_python", lambda home, found: None)
    with pytest.raises(WindowsRuntimeProofError, match=r"\(interpreter-invalid\)"):
        _windows_memory.proof_python(win.home)
    monkeypatch.setattr(_uninstall_hermes_env, "find_hermes_launcher", lambda home: None)
    assert _windows_memory.proof_python(win.home) is None


_WRITE_SPIES: tuple[tuple[object, str], ...] = (
    (os, "open"),
    (os, "replace"),
    (os, "rename"),
    (os, "remove"),
    (os, "unlink"),
    (builtins, "open"),
    (io, "open"),
    (Path, "open"),
    (Path, "write_bytes"),
    (Path, "write_text"),
    (Path, "touch"),
    (Path, "unlink"),
    (Path, "replace"),
    (Path, "rename"),
)


def spy_wizard_file_operations(monkeypatch, home: Path) -> list[str]:
    """Record every file open/write/rename/unlink a ``mordred_hermes.wizard`` frame issues under ``home``.

    Keyvault and private-fs frames (the checked lifecycle) are not recorded: only
    a direct call from wizard code counts.
    """
    root = os.fspath(home)
    touched: list[str] = []

    def wrap(name: str, real):
        def spy(*args, **kwargs):
            caller = sys._getframe(1).f_globals.get("__name__", "")
            if caller.startswith("mordred_hermes.wizard"):
                paths = [os.fspath(arg) for arg in args[:2] if isinstance(arg, (str, os.PathLike))]
                if any(path.startswith(root) for path in paths):
                    touched.append(f"{caller}:{name}:{' -> '.join(paths)}")
            return real(*args, **kwargs)

        return spy

    for owner, name in _WRITE_SPIES:
        monkeypatch.setattr(owner, name, wrap(name, getattr(owner, name)))
    return touched


def test_lifecycle_never_writes_memory_or_markers_itself(seeded, monkeypatch):
    """The wizard only calls keyvault APIs: no raw file operation of its own reaches the home."""
    env = seeded
    touched = spy_wizard_file_operations(monkeypatch, env.home)
    probe = env.home / "spy-probe"
    exec(  # the spy is not vacuous: a wizard-module frame writing under the home is recorded
        compile("probe.write_bytes(b'x'); os.replace(probe, probe); probe.unlink()", "<wizard-probe>", "exec"),
        {"__name__": "mordred_hermes.wizard._spy_probe", "probe": probe, "os": os},
    )
    assert [entry.split(":")[1] for entry in touched] == ["write_bytes", "replace", "unlink"]
    touched.clear()

    assert memory_cli.enable(home=env.home, root=env.home / "vault", platform="win32") == 0
    assert memory_cli.disable(home=env.home, root=env.home / "vault", platform="win32") == 0
    assert memory_cli.purge(home=env.home, root=env.home / "vault", platform="win32") == 0
    assert touched == []


def test_unknown_inventory_error_is_classified_not_raised(seeded, monkeypatch, capsys):
    env = seeded

    def broken(home, **kwargs):
        raise PrivateFSError("io", "inventory", commit_state="uncertain")

    monkeypatch.setattr(_windows_processes, "inspect_windows_gateway_runtimes", broken)
    assert memory_cli.enable(home=env.home, root=env.home / "vault", platform="win32") == 1
    assert generated(env) == 0 and files(env.home) == ORIGINALS
