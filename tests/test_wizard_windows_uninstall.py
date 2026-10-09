"""``hermes-mordred uninstall`` on Windows (C6).

The memory restore is the proof-bound disable (gate -> proof -> checked
disable); ``--purge-data`` purges only the memory custody key right after the
verified restore -- before Hermes's files, launchers or the package are touched
-- and keeps/reports everything else (no recursive removal). Inert custody
(``keyvault native init``, or an enable that refused at the proof) gets the
disable restore under ``--purge-data`` because the purge requires it.
``--erase-encrypted`` refuses. A refusing gate, proof or purge stops the
uninstall before anything is removed.
"""

from __future__ import annotations

import subprocess
from collections.abc import Sequence
from dataclasses import dataclass, field

import pytest

from mordred_hermes.desktop import install as desktop_install
from mordred_hermes.keyvault import _windows_processes
from mordred_hermes.keyvault._runtime_probe import GatewayRuntime
from mordred_hermes.wizard import keyvault_windows_cli, memory_cli, uninstall_cli
from mordred_hermes.wizard._uninstall_config import ConfigCleanup, EnvCleanup
from mordred_hermes.wizard._uninstall_hermes_env import LauncherFinding
from mordred_hermes.wizard.uninstall_cli import PURGE_PHRASE, UninstallContext, UninstallOptions, run_uninstall
from tests.test_windows_custody import fs as fs
from tests.test_windows_memory_lifecycle import (
    MARKER,
    OPTOUT,
    ORIGINALS,
    assert_all_sealed,
    files,
    markers,
    normalized,
    put,
)
from tests.test_windows_memory_proof import installed_runtime as installed_runtime
from tests.test_windows_memory_proof import proof_env as proof_env
from tests.test_wizard_windows_memory import memory_lease, role_current
from tests.test_wizard_windows_memory import seeded as seeded
from tests.test_wizard_windows_memory import win as win


@dataclass
class Runner:
    calls: list[list[str]] = field(default_factory=list)

    def __call__(self, argv: Sequence[str]) -> subprocess.CompletedProcess[str]:
        self.calls.append(list(argv))
        return subprocess.CompletedProcess(list(argv), 1, "", "")


class Prompt:
    def ask_bool(self, question: str, default: bool = False, **kwargs: object) -> bool:
        return True

    def ask_text(self, question: str, **kwargs: object) -> str:
        return PURGE_PHRASE


@pytest.fixture(autouse=True)
def hermes_files(monkeypatch):
    """The C3 config/.env cleanup and Desktop page are recorded, not exercised (not C6)."""
    calls: list[str] = []
    monkeypatch.setattr(uninstall_cli, "plan_config_cleanup", lambda path: ConfigCleanup(path))
    monkeypatch.setattr(uninstall_cli, "plan_env_cleanup", lambda path: EnvCleanup(path))
    monkeypatch.setattr(
        uninstall_cli, "apply_config_cleanup", lambda path, **kw: calls.append("config") or ConfigCleanup(path)
    )
    monkeypatch.setattr(uninstall_cli, "apply_env_cleanup", lambda path, **kw: calls.append("env") or EnvCleanup(path))
    monkeypatch.setattr(desktop_install, "remove_page", lambda home: calls.append("page") or False)
    return calls


@pytest.fixture
def enabled(seeded):
    env = seeded
    assert memory_cli.enable(home=env.home, root=env.home / "mordred" / "vault", platform="win32") == 0
    assert keyvault_windows_cli.native_init(home=env.home, roles=["audit"]) == 0
    env.runner = Runner()
    return env


def context(env, **overrides: object) -> UninstallContext:
    values: dict[str, object] = {
        "home": env.home,
        "vault_root": env.home / "mordred" / "vault",
        "user_home": env.home.parent / "user",
        "platform": "win32",
        "which": lambda _name: None,
        "runner": env.runner,
        "stamp": "20261009-000000",
        "interactive": False,
        "gateways": lambda _home: [],
        "telegram_forget": lambda: pytest.fail("Telegram logout is a separate Windows ceremony"),
        "keyvault_reset": lambda _home: pytest.fail("the secret store is not ported to Windows"),
        "prompt_io": Prompt(),
    }
    values.update(overrides)
    return UninstallContext(**values)  # type: ignore[arg-type]


def mordred_entries(env):
    return sorted(path.name for path in (env.home / "mordred").iterdir())


def test_dry_run_plan_says_exactly_what_happens(enabled, capsys):
    env = enabled
    before = (files(env.home), markers(env.home), mordred_entries(env))
    assert run_uninstall(context(env), UninstallOptions(dry_run=True, purge_data=True)) == 0
    out = capsys.readouterr().out
    assert "memory: Windows: refuse unless every Hermes gateway is stopped, prove the installed Hermes runtime" in out
    assert "decrypt 3 sealed memory file(s) back" in out and "the CNG memory key is kept" in out
    assert "5. Data -- --purge-data on Windows" in out
    assert "delete the Windows CNG memory custody key right after the verified restore, before anything else" in out
    assert "keep audit custody and audit history" in out
    assert f"keep {env.home / 'mordred'}: reported, not removed" in out
    assert "keep Windows CNG audit custody key" in out
    assert "keep Windows CNG memory custody key" not in out and "memory-key.wrapped  --" not in out
    assert "Note: Windows: the memory restore refuses while any Hermes gateway" in out
    assert (files(env.home), markers(env.home), mordred_entries(env)) == before


def test_uninstall_restores_memory_and_keeps_custody_and_data(enabled, capsys, hermes_files):
    env = enabled
    lease = memory_lease(env)
    assert run_uninstall(context(env), UninstallOptions(yes=True)) == 0
    assert hermes_files == ["page", "config", "env"]
    out = capsys.readouterr().out
    assert "Agent-memory encryption disabled on Windows: 3 file(s) decrypted back" in out
    assert files(env.home) == {name: normalized(data).encode() for name, data in ORIGINALS.items()}
    assert markers(env.home) == {OPTOUT}
    assert memory_lease(env) == lease, "the restore keeps the memory key"
    assert (env.home / "mordred" / "windows-custody.json").exists()
    assert "Kept on Windows" in out


def test_purge_data_deletes_only_memory_custody_and_reports_the_rest(enabled, capsys):
    env = enabled
    audit = role_current(env, "audit")
    native = memory_lease(env).native_key_id
    assert run_uninstall(context(env), UninstallOptions(purge_data=True)) == 0
    captured = capsys.readouterr()
    out = captured.out
    assert "--purge-data on Windows permanently deletes the Windows CNG memory custody key" in captured.err
    assert "Windows memory custody purged: 1 generation(s) deleted" in out
    assert memory_lease(env) is None and ("delete", native) in env.backend.calls
    assert role_current(env, "audit") == audit
    assert files(env.home) == {name: normalized(data).encode() for name, data in ORIGINALS.items()}
    assert (env.home / "mordred").is_dir(), "no recursive removal on Windows"
    assert (env.home / "mordred" / "windows-custody.json").exists()
    assert f"Keep {env.home / 'mordred'}: reported, not removed" in out
    assert "Windows CNG audit custody key" in out


@pytest.mark.parametrize("fault", ["running-gateway", "proof"])
def test_refusing_gate_or_proof_stops_before_anything_is_removed(enabled, monkeypatch, capsys, fault, hermes_files):
    env = enabled
    if fault == "running-gateway":
        monkeypatch.setattr(
            _windows_processes,
            "inspect_windows_gateway_runtimes",
            lambda home, **kw: _windows_processes.GatewayInventory("known", (GatewayRuntime(5, env.python),), ()),
        )
    else:
        monkeypatch.setenv("MORDRED_HERMES_PYTHON", str(env.home.parent / "missing" / "python.exe"))
    before = (files(env.home), markers(env.home), mordred_entries(env))
    assert run_uninstall(context(env), UninstallOptions(yes=True, purge_data=True)) == 1
    err = capsys.readouterr().err
    assert "uninstall stopped: memory could not be restored to plaintext" in err
    assert (files(env.home), markers(env.home), mordred_entries(env)) == before
    assert markers(env.home) == {MARKER}
    assert_all_sealed(env)
    assert hermes_files == [], "nothing past the restore step ran"
    assert not [call for call in env.runner.calls if call[1:3] == ["pip", "uninstall"]]


@pytest.mark.parametrize("dry_run", [True, False])
def test_erase_encrypted_is_refused_on_windows(enabled, capsys, dry_run):
    env = enabled
    before = (files(env.home), markers(env.home), mordred_entries(env))
    assert run_uninstall(context(env), UninstallOptions(erase_encrypted=True, dry_run=dry_run)) == 1
    assert "--erase-encrypted is not supported on Windows" in capsys.readouterr().err
    assert (files(env.home), markers(env.home), mordred_entries(env)) == before


def test_unverifiable_custody_plans_a_refusing_restore(win, capsys):
    env = win
    env.runner = Runner()
    put(env.home, "mordred", MARKER, b"memory-encryption enabled\n")
    assert run_uninstall(context(env), UninstallOptions(yes=True)) == 1
    captured = capsys.readouterr()
    assert "memory custody cannot be verified (custody-broken" in captured.out
    assert "refused at the capabilities step (custody-broken)" in captured.err
    assert (env.home / "mordred" / MARKER).exists()


# -----------------------------------------------------------------------------
# Inert custody: enrolled by `keyvault native init` (or an enable refused at the
# proof), never explicitly disabled. Purge requires that disable, so
# --purge-data plans and runs it, and every refusal precedes step b.
# -----------------------------------------------------------------------------
@pytest.fixture
def inert(seeded):
    env = seeded
    assert keyvault_windows_cli.native_init(home=env.home) == 0
    env.runner = Runner()
    return env


@pytest.fixture
def launcher(inert, monkeypatch):
    """An installer-written launcher step c would remove."""
    path = inert.home.parent / "user-bin" / "hermes-mordred"
    path.parent.mkdir()
    path.write_text("#!/bin/sh\n# hermes-mordred installer\n", encoding="utf-8")
    finding = LauncherFinding(path, True, "written by the Mordred installer")
    monkeypatch.setattr(uninstall_cli, "classify_launchers", lambda env, **kwargs: [finding])
    return path


def test_inert_custody_purge_plan_records_the_disable_first(inert, launcher, capsys):
    env = inert
    lease = memory_lease(env)
    before = (files(env.home), markers(env.home), mordred_entries(env))
    assert run_uninstall(context(env), UninstallOptions(dry_run=True, purge_data=True)) == 0
    out = capsys.readouterr().out
    assert "1. Restore plaintext: nothing is encrypted." not in out
    assert "memory: Windows: nothing is sealed, but the enrolled memory custody was never explicitly disabled" in out
    assert "prove the installed Hermes runtime, then record the disable (opt-out marker)" in out
    assert "delete the Windows CNG memory custody key right after the verified restore, before anything else" in out
    assert f"remove {launcher}" in out
    assert "Dry run: nothing was changed." in out
    assert (files(env.home), markers(env.home), mordred_entries(env)) == before
    assert memory_lease(env) == lease and launcher.exists()
    assert env.launches.argv == [], "a dry run never launches the proof"


def test_inert_custody_without_purge_data_needs_no_restore_or_proof(inert, launcher, capsys, hermes_files):
    env = inert
    lease = memory_lease(env)
    assert run_uninstall(context(env), UninstallOptions(yes=True)) == 0
    out = capsys.readouterr().out
    assert "1. Restore plaintext: nothing is encrypted." in out
    assert env.launches.argv == [], "nothing is sealed, so no installed-runtime proof is needed"
    assert markers(env.home) == set() and memory_lease(env) == lease
    assert hermes_files == ["page", "config", "env"] and not launcher.exists()
    assert "Windows CNG memory custody key (TPM-bound" in out, "the kept key is reported"


def test_inert_custody_purge_data_disables_then_purges_end_to_end(inert, launcher, capsys, hermes_files):
    env = inert
    native = memory_lease(env).native_key_id
    assert run_uninstall(context(env), UninstallOptions(purge_data=True)) == 0
    captured = capsys.readouterr()
    assert "permanently deletes the Windows CNG memory custody key right after" in captured.err
    out = captured.out
    assert "Agent-memory encryption disabled on Windows: 0 file(s) decrypted back" in out
    assert "Windows memory custody purged: 1 generation(s) deleted" in out
    assert out.index("Windows memory custody purged") < out.index(f"Removed {launcher}."), "purge precedes step c"
    assert memory_lease(env) is None and ("delete", native) in env.backend.calls
    assert markers(env.home) == set()
    assert files(env.home) == ORIGINALS, "memory files are never changed"
    assert hermes_files == ["page", "config", "env"] and not launcher.exists()
    assert (env.home / "mordred" / "windows-custody.json").exists(), "no recursive removal on Windows"


@pytest.mark.parametrize("fault", ["proof-child", "broken-seal", "reset"])
def test_inert_custody_purge_refusal_leaves_the_profile_installed(
    inert, launcher, monkeypatch, capsys, hermes_files, fault
):
    env = inert
    lease = memory_lease(env)
    if fault == "proof-child":
        env.launches.fail_child = OSError("the proof child cannot start")
    elif fault == "broken-seal":
        put(env.home, "memories", "BROKEN.md", b"HERMES-MEMORY-ENC-v1\nnot-a-seal")
    else:

        def refused(self, role, **kwargs):
            raise env.custody.CustodyError("injected reset refusal")

        monkeypatch.setattr(env.custody.WindowsCustodySession, "reset_role", refused)
    before = files(env.home)
    assert run_uninstall(context(env), UninstallOptions(yes=True, purge_data=True)) == 1
    captured = capsys.readouterr()
    if fault == "broken-seal":
        assert "1 broken seal(s) cannot be decrypted, so the restore refuses" in captured.out
    stopped = "Windows memory custody could not be purged" if fault == "reset" else "memory could not be restored"
    assert f"uninstall stopped: {stopped}" in captured.err
    assert "Nothing was removed and Mordred stays installed" in captured.err
    assert hermes_files == [] and launcher.exists(), "step b and step c never ran"
    assert not [call for call in env.runner.calls if call[1:3] == ["pip", "uninstall"]]
    assert memory_lease(env) == lease and files(env.home) == before
    assert markers(env.home) == ({OPTOUT} if fault == "reset" else set())


def test_purge_warning_names_no_key_without_memory_custody(win, capsys, hermes_files):
    env = win
    assert keyvault_windows_cli.native_init(home=env.home, roles=["audit"]) == 0
    audit = role_current(env, "audit")
    env.runner = Runner()
    assert run_uninstall(context(env), UninstallOptions(purge_data=True)) == 0
    captured = capsys.readouterr()
    assert "no Windows CNG memory custody key is enrolled on this profile" in captured.err
    assert "permanently deletes" not in captured.err
    assert "delete the Windows CNG memory custody key" not in captured.out
    assert role_current(env, "audit") == audit and env.launches.argv == []
