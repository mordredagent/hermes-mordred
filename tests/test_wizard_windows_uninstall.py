"""``hermes-mordred uninstall`` on Windows (C6).

The memory restore is the proof-bound disable (gate -> proof -> checked
disable); ``--purge-data`` purges only the memory custody key after the
verified restore and keeps/report everything else (no recursive removal);
``--erase-encrypted`` refuses. A refusing gate or proof stops the uninstall
before anything is removed.
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
from mordred_hermes.wizard.uninstall_cli import PURGE_PHRASE, UninstallContext, UninstallOptions, run_uninstall
from tests.test_windows_custody import fs as fs
from tests.test_windows_memory_lifecycle import MARKER, OPTOUT, ORIGINALS, assert_all_sealed, files, markers, normalized
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
    assert "delete the Windows CNG memory custody key after the verified restore" in out
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
    from tests.test_windows_memory_lifecycle import put

    put(env.home, "mordred", MARKER, b"memory-encryption enabled\n")
    assert run_uninstall(context(env), UninstallOptions(yes=True)) == 1
    captured = capsys.readouterr()
    assert "memory custody cannot be verified (custody-broken" in captured.out
    assert "refused at the capabilities step (custody-broken)" in captured.err
    assert (env.home / "mordred" / MARKER).exists()
