"""Excluded/unported Windows verbs refuse before any native key work (C6).

``vault init`` and the env/config seal verbs consult the C5e capability guard
before resolving a device backend or anchor store, prompting, or generating a
key: call accounting proves nothing past the refusal is reached. The runtime
gate never accepts ``--force-runtime-unverified`` on Windows, and only the
memory caller gets the stopped-gateway gate there.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import pytest

from mordred_hermes.keyvault import _windows_capability, _windows_processes
from mordred_hermes.keyvault._runtime_probe import GatewayRuntime
from mordred_hermes.wizard import (
    _keyvault_init,
    _runtime_gate,
    _vault_lifecycle,
    _vault_open,
    _windows_gates,
    cli,
    config_decrypt_cli,
    encryption_cli,
    env_decrypt_cli,
    memory_cli,
)


class Tripwire:
    """Any attribute access or call is recorded and fails the test."""

    def __init__(self) -> None:
        self.calls: list[str] = []

    def __getattr__(self, name: str):
        self.calls.append(name)

        def reached(*args: object, **kwargs: object) -> None:
            raise AssertionError(f"{name} was reached after an excluded refusal")

        return reached

    def __call__(self, *args: object, **kwargs: object) -> None:
        self.calls.append("__call__")
        raise AssertionError("a backend/store resolver was reached after an excluded refusal")


@pytest.fixture
def windows(monkeypatch, tmp_path):
    monkeypatch.setattr(_windows_capability, "_platform", lambda: "win32")
    monkeypatch.setattr(_windows_gates, "host_platform", lambda: "win32")
    home = tmp_path / "home"
    (home / "mordred").mkdir(parents=True)
    monkeypatch.setenv("HERMES_HOME", str(home))
    trip = Tripwire()
    for module in (_vault_lifecycle, _vault_open):
        monkeypatch.setattr(module, "resolve_backend", trip)
        monkeypatch.setattr(module, "resolve_store", trip)
        monkeypatch.setattr(module, "resolve_prompt_io", trip)
    return home, trip


def tree(home: Path) -> dict[str, bytes | None]:
    return {
        str(path.relative_to(home)): (path.read_bytes() if path.is_file() else None) for path in sorted(home.rglob("*"))
    }


@pytest.mark.parametrize(
    ("call", "capability"),
    [
        (lambda root, t: _vault_lifecycle.init(root=root, backend=t, store=t, prompt_io=t), "file_vault"),
        (lambda root, t: _vault_lifecycle.ensure_initialised(root=root, backend=t, store=t, prompt_io=t), "file_vault"),
        (lambda root, t: _vault_lifecycle.change_passphrase(root=root, backend=t, store=t, prompt_io=t), "recovery"),
        (lambda root, t: _vault_lifecycle.recover(root=root, backend=t, store=t, prompt_io=t), "recovery"),
    ],
)
def test_vault_lifecycle_refuses_before_any_backend_store_or_prompt(windows, capsys, call, capability):
    home, trip = windows
    root = home / "mordred" / "vault"
    before = tree(home)
    assert call(root, trip) == 1
    err = capsys.readouterr().err
    assert f"{capability} is excluded on Windows" in err and "(excluded-on-windows)" in err
    assert "Nothing was generated, opened or written" in err
    assert trip.calls == []
    assert tree(home) == before and not root.exists()


def test_vault_init_cli_refuses_before_generation(windows, capsys):
    _, trip = windows
    assert cli.main(["vault", "init"]) == 1
    assert "vault init: file_vault is excluded on Windows" in capsys.readouterr().err
    assert trip.calls == []


def test_vault_opens_refuse_before_backend_resolution(windows, capsys):
    home, trip = windows
    root = home / "mordred" / "vault"
    assert _vault_open._open_hot_path_or_report(root, backend=trip, store=trip) is None
    assert _vault_open._open_cold_path(root, prompt_io=trip) is None
    err = capsys.readouterr().err
    assert "vault open: file_vault is excluded" in err and "recovery is excluded" in err
    assert trip.calls == []


ENV = {
    "enable": lambda home, t: env_decrypt_cli.enable(home=home, root=home / "v", platform="win32", backend=t, store=t),
    "disable": lambda home, t: env_decrypt_cli.disable(home=home, root=home / "v", backend=t, store=t),
    "purge": lambda home, t: env_decrypt_cli.purge(home=home, root=home / "v", backend=t, store=t),
    "reseal": lambda home, t: env_decrypt_cli.reseal(home=home, root=home / "v", backend=t, store=t),
}
CONFIG = {
    "enable": lambda home, t: config_decrypt_cli.enable(
        home=home, root=home / "v", platform="win32", backend=t, store=t
    ),
    "disable": lambda home, t: config_decrypt_cli.disable(home=home, root=home / "v", backend=t, store=t),
    "purge": lambda home, t: config_decrypt_cli.purge(home=home, root=home / "v", backend=t, store=t),
}


@pytest.mark.parametrize("verb", sorted(ENV))
def test_env_seal_verbs_refuse_and_preserve_retained_state(windows, capsys, verb):
    home, trip = windows
    (home / ".env").write_text("OPENROUTER_API_KEY=sk-test\n", encoding="utf-8")
    (home / "mordred" / "env-vault.optout").write_text("opt-out\n", encoding="utf-8")
    before = tree(home)
    assert ENV[verb](home, trip) == 1
    assert "env_config_workspace_seals is excluded on Windows" in capsys.readouterr().err
    assert trip.calls == [] and tree(home) == before


@pytest.mark.parametrize("verb", sorted(CONFIG))
def test_config_seal_verbs_refuse_and_preserve_the_retained_marker(windows, capsys, verb):
    home, trip = windows
    (home / "config.yaml").write_text("model: x\n", encoding="utf-8")
    (home / "mordred" / "config-vault.marker").write_text("vault-managed\n", encoding="utf-8")
    before = tree(home)
    assert CONFIG[verb](home, trip) == 1
    assert "env_config_workspace_seals is excluded on Windows" in capsys.readouterr().err
    assert trip.calls == [] and tree(home) == before


def test_keyvault_init_refuses_before_prompt_or_storage(windows, monkeypatch, capsys):
    home, trip = windows
    monkeypatch.setattr(_keyvault_init, "_refuse_if_initialised", trip)
    monkeypatch.setattr(_keyvault_init, "resolve_prompt_io", trip)
    rc = _keyvault_init.init_keyvault(home=home, backend=trip, prompt_io=trip, surface=trip, blackout_assert=trip)  # type: ignore[arg-type]
    assert rc == 1
    err = capsys.readouterr().err
    assert "keyvault init: secret_store is not yet ported to Windows" in err and "(not-ported-on-windows)" in err
    assert "keyvault native init" in err
    assert trip.calls == [] and not (home / "mordred" / "keyvault").exists()


def test_excluded_guards_are_noops_off_windows(monkeypatch):
    monkeypatch.setattr(_windows_capability, "_platform", lambda: "darwin")
    assert _windows_gates.excluded_refusal("file_vault", "vault init") is None
    assert _windows_gates.unported_refusal("secret_store", "keyvault init") is None


# -----------------------------------------------------------------------------
# runtime gate on win32
# -----------------------------------------------------------------------------
class Inventory:
    def __init__(self, monkeypatch, state="known", running=()):
        self.calls = 0

        def inspect(home, **kwargs):
            self.calls += 1
            return _windows_processes.GatewayInventory(state, running, () if state == "known" else ("x",))

        monkeypatch.setattr(_windows_processes, "inspect_windows_gateway_runtimes", inspect)


def gate(home: Path, *, platforms, force=False):
    def probe(**kwargs):
        raise AssertionError("POSIX runtime probes never run on Windows")

    return _runtime_gate.runtime_gate(
        home=home,
        platform="win32",
        runtime_probe=None,
        force_runtime_unverified=force,
        default_probe=probe,
        target="agent memory",
        mechanism="",
        rerun_tail="",
        supported_platforms=platforms,
    )


MEMORY = ("darwin", "linux", "win32")


@pytest.mark.parametrize("platforms", [MEMORY, ("darwin",)])
def test_force_is_refused_on_windows_for_every_caller(tmp_path, monkeypatch, capsys, platforms):
    inventory = Inventory(monkeypatch)
    assert gate(tmp_path, platforms=platforms, force=True) == 1
    assert "Windows has no runtime-unverified bypass" in capsys.readouterr().err
    assert inventory.calls == 0


def test_memory_gate_requires_a_known_empty_inventory(tmp_path, monkeypatch, capsys):
    inventory = Inventory(monkeypatch)
    assert gate(tmp_path, platforms=MEMORY) == 0 and inventory.calls == 1
    Inventory(monkeypatch, running=(GatewayRuntime(9, tmp_path / "python.exe"),))
    assert gate(tmp_path, platforms=MEMORY) == 1
    Inventory(monkeypatch, state="unknown")
    assert gate(tmp_path, platforms=MEMORY) == 1
    assert capsys.readouterr().err.count("no force option") == 2


def test_only_the_memory_caller_lists_windows(tmp_path, monkeypatch):
    inventory = Inventory(monkeypatch)
    assert gate(tmp_path, platforms=("darwin",)) == 0
    assert inventory.calls == 0
    assert memory_cli._GATE_PLATFORMS == MEMORY


# -----------------------------------------------------------------------------
# `encryption ... all` on Windows
# -----------------------------------------------------------------------------
def test_enable_all_skips_excluded_targets_and_runs_memory(windows, monkeypatch, capsys):
    calls: list[dict[str, object]] = []
    monkeypatch.setattr(memory_cli, "enable", lambda **kw: calls.append(kw) or 0)
    for module in (env_decrypt_cli, config_decrypt_cli):
        monkeypatch.setattr(module, "enable", lambda **kw: pytest.fail("an excluded target was dispatched"))
    assert encryption_cli.cli_enable(argparse.Namespace(target="all", force_runtime_unverified=False)) == 0
    out = capsys.readouterr().out
    assert out.count("skipped (excluded on Windows") == 2
    assert [call["platform"] for call in calls] == ["win32"]


def test_disable_and_purge_memory_dispatch_with_the_windows_platform(windows, monkeypatch):
    calls: list[tuple[str, object]] = []
    monkeypatch.setattr(memory_cli, "disable", lambda **kw: calls.append(("disable", kw["platform"])) or 0)
    monkeypatch.setattr(memory_cli, "purge", lambda **kw: calls.append(("purge", kw["platform"])) or 0)
    assert encryption_cli.cli_disable(argparse.Namespace(target="memory")) == 0
    assert encryption_cli.cli_purge(argparse.Namespace(target="memory", yes=True)) == 0
    assert calls == [("disable", "win32"), ("purge", "win32")]


@pytest.mark.skipif(sys.platform == "win32", reason="the host is Windows")
def test_posix_hosts_keep_the_vault_path(monkeypatch, tmp_path):
    """Off Windows the guard is a no-op: init proceeds to its backend as before."""
    trip = Tripwire()
    monkeypatch.setattr(_vault_lifecycle, "resolve_backend", trip)
    with pytest.raises(AssertionError, match="resolver was reached"):
        _vault_lifecycle.init(root=tmp_path / "v")
    assert trip.calls == ["__call__"]
