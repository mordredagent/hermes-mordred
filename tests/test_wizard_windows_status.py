"""Windows ``status`` / ``encryption status`` / ``setup`` routing (C6).

Every Windows keyvault and memory line must come from ``windows_capabilities``
and load-only custody reads: no native backend, unwrap, subprocess or lock wait,
one line per capability and no aggregate readiness. Retained secret stores,
excluded artifacts, copied profiles and held locks print a classified reason.
"""

from __future__ import annotations

import json
import subprocess
import threading

import pytest

from mordred_hermes import _config_io as cio
from mordred_hermes.keyvault import _seckey_helper, wrap
from mordred_hermes.wizard import encryption_cli, memory_cli, setup_cli, status_cli
from mordred_hermes.wizard._encryption_status import status_mark
from mordred_hermes.wizard._workspace_paths import WorkspacePaths
from tests.test_windows_custody import fs as fs
from tests.test_windows_memory_lifecycle import ORIGINALS, put
from tests.test_windows_memory_proof import installed_runtime as installed_runtime
from tests.test_windows_memory_proof import proof_env as proof_env
from tests.test_wizard_windows_memory import seeded as seeded
from tests.test_wizard_windows_memory import win as win

ORDER = (
    "memory custody",
    "audit custody",
    "Telegram custody",
    "file vault",
    "env/config/workspace seals",
    "recovery",
    "per-use presence",
    "secret store",
)


def forbid_native(monkeypatch, env):
    """Status may read checked files only: no backend, unwrap or subprocess."""

    def tripwire(*args, **kwargs):
        raise AssertionError("status reached a native, unwrap or subprocess operation")

    monkeypatch.setattr(env.custody, "windows_backend", tripwire)
    monkeypatch.setattr(wrap, "unwrap_dek", tripwire)
    monkeypatch.setattr(subprocess, "Popen", tripwire)
    monkeypatch.setattr(subprocess, "run", tripwire)


def workspace(tmp_path):
    return WorkspacePaths(image=tmp_path / "ws.img", blob=tmp_path / "ws.blob", mount=tmp_path / "ws")


def memory_line(env):
    statuses = encryption_cli.collect_status(
        home=env.home, root=env.home / "vault", platform="win32", workspace=workspace(env.home.parent)
    )
    assert [s.target for s in statuses] == ["env", "config", "memory", "workspace"]
    return statuses[2], statuses


@pytest.fixture(autouse=True)
def quiet_policy_and_network(monkeypatch):
    """Policy/network lines are C8 readers, not C6: pin them for portability."""
    monkeypatch.setattr(status_cli, "_policy_mode", lambda home: "strict")
    monkeypatch.setattr(status_cli, "_network_state", lambda home: ("clearnet", False, None, None))


def report(env, capsys, *, as_json=False):
    status_cli.status(
        home=env.home,
        root=env.home / "mordred" / "vault",
        platform="win32",
        workspace=workspace(env.home.parent),
        as_json=as_json,
        helper_finder=lambda platform: "helper",
    )
    return capsys.readouterr().out


def enable(env):
    assert memory_cli.enable(home=env.home, root=env.home / "vault", platform="win32") == 0


def test_status_lists_every_capability_without_aggregate_readiness(win, monkeypatch, capsys):
    forbid_native(monkeypatch, win)
    out = report(win, capsys)
    assert "windows     : per capability (no aggregate readiness):" in out
    positions = [out.index(f"    {label}:") for label in ORDER]
    assert positions == sorted(positions)
    assert "memory custody: supported, unavailable (not-enrolled)" in out
    assert "keyvault native init --role audit" in out
    assert "file vault: excluded on Windows (excluded-on-windows)" in out
    assert "secret store: not ported to Windows (not-ported-on-windows)" in out
    assert "ready" not in out.lower().replace("already", "")
    data = json.loads(report(win, capsys, as_json=True))
    assert [row["name"] for row in data["windows_capabilities"]][:3] == [
        "memory_custody",
        "native_audit",
        "telegram_hardware",
    ]
    assert data["keyvault"]["initialized"] is False


def test_memory_states_from_fresh_to_purged(seeded, monkeypatch, capsys):
    env = seeded
    status, statuses = memory_line(env)
    assert (status.configured, status.active, status_mark(status)) == (False, False, "off")
    assert status.detail == "not enabled — run: encryption enable memory"
    for excluded in (statuses[0], statuses[1], statuses[3]):
        assert excluded.detail.startswith("excluded on Windows (excluded-on-windows)")
        assert not excluded.active

    from mordred_hermes.wizard import keyvault_windows_cli

    assert keyvault_windows_cli.native_init(home=env.home) == 0
    assert "memory custody enrolled (inert)" in memory_line(env)[0].detail

    enable(env)
    with monkeypatch.context() as patch:
        forbid_native(patch, env)
        status = memory_line(env)[0]
        out = report(env, capsys)
    assert status_mark(status) == "on" and "sealed memory (3 file(s))" in status.detail
    assert "memory custody: supported, available (enrolled)" in out

    put(env.home, "memories", "NEW.md", b"plaintext written outside the hook")
    status = memory_line(env)[0]
    assert status_mark(status) == "exposed" and "plaintext memory file(s) on disk" in status.detail

    assert memory_cli.disable(home=env.home, root=env.home / "vault", platform="win32") == 0
    status = memory_line(env)[0]
    assert status_mark(status) == "paused" and "CNG key kept" in status.detail


def test_armed_profile_without_helper_is_not_active(seeded, monkeypatch, capsys):
    env = seeded
    enable(env)
    monkeypatch.setattr(_seckey_helper, "find_winkey_helper", lambda: None)
    status = memory_line(env)[0]
    assert not status.active and "helper-missing" in status.detail
    assert "memory custody: supported, unavailable (helper-missing)" in report(env, capsys)


def test_copied_profile_prints_the_classified_reason(win, capsys):
    env = win
    from mordred_hermes._private_fs import open_private_directory
    from mordred_hermes.wizard import keyvault_windows_cli

    assert keyvault_windows_cli.native_init(home=env.home) == 0
    copied = env.home.parent / "copied"
    with open_private_directory(copied, create=True):
        pass
    with open_private_directory(copied / "mordred", create=True) as directory, directory.transaction() as tx:
        for name in ("windows-custody.json", "memory-key.wrapped"):
            tx.create_bytes(name, (env.home / "mordred" / name).read_bytes())
    env.home = copied
    status = memory_line(env)[0]
    assert status.detail.startswith("UNAVAILABLE (custody-broken)")
    out = report(env, capsys)
    assert "memory custody: supported, unavailable (custody-broken)" in out


def test_held_lock_is_reported_not_awaited(seeded, capsys):
    env = seeded
    enable(env)
    holding, release = threading.Event(), threading.Event()

    def holder():
        with cio.canonical_session(cio.CanonicalPaths(env.home), scope="policy"):
            holding.set()
            release.wait(30)

    thread = threading.Thread(target=holder)
    thread.start()
    try:
        assert holding.wait(30)
        status = memory_line(env)[0]
        out = report(env, capsys)
    finally:
        release.set()
        thread.join(30)
    assert "custody-uncertain" in status.detail
    assert "memory custody: supported, unavailable (custody-uncertain)" in out


def test_retained_secret_store_and_excluded_artifacts_are_reported(win, monkeypatch, capsys):
    env = win
    forbid_native(monkeypatch, env)
    from mordred_hermes._private_fs import open_private_directory

    put(env.home, "mordred", "env-vault.optout", b"opt-out\n")
    put(env.home, "mordred", "config-vault.marker", b"vault-managed\n")
    with open_private_directory(env.home / "mordred" / "keyvault", create=True):
        pass
    with open_private_directory(env.home / "mordred" / "vault", create=True):
        pass
    out = report(env, capsys)
    assert "a retained secret store is preserved unchanged" in out
    assert "Traceback" not in out
    _, statuses = memory_line(env)
    assert "retained file vault preserved unchanged" in statuses[0].detail
    assert "retained .env seal opt-out marker preserved unchanged" in statuses[0].detail
    assert "retained config seal marker preserved unchanged" in statuses[1].detail
    assert statuses[0].configured and not statuses[0].active
    assert (env.home / "mordred" / "config-vault.marker").read_bytes() == b"vault-managed\n"


def test_encryption_status_cli_routes_windows(seeded, capsys):
    from mordred_hermes.wizard import cli

    assert cli.main(["encryption", "status", "--json"]) == 0
    targets = {row["target"]: row for row in json.loads(capsys.readouterr().out)}
    assert targets["memory"]["detail"] == "not enabled — run: encryption enable memory"
    assert targets["env"]["detail"].startswith("excluded on Windows")


# -----------------------------------------------------------------------------
# setup on Windows
# -----------------------------------------------------------------------------
def run_steps(env, monkeypatch, *, non_interactive=False):
    options = setup_cli.SetupOptions(non_interactive=non_interactive)
    keyvault = setup_cli._resolve_step_keyvault(
        home=env.home,
        prompt_io=None,
        options=options,
        platform="win32",  # type: ignore[arg-type]
    )
    env_step = setup_cli._resolve_step_env_encryption(
        home=env.home,
        root=env.home / "vault",
        platform="win32",
        prompt_io=None,
        options=options,  # type: ignore[arg-type]
    )
    memory = setup_cli._resolve_step_memory_encryption(
        home=env.home,
        root=env.home / "vault",
        platform="win32",
        prompt_io=None,
        options=options,  # type: ignore[arg-type]
    )
    return keyvault, env_step, memory


def test_setup_skips_excluded_steps_and_runs_the_windows_memory_enable(seeded, monkeypatch):
    env = seeded
    keyvault, env_step, memory = run_steps(env, monkeypatch)
    assert keyvault.action == "skipped" and "not-ported-on-windows" in keyvault.detail
    assert env_step.action == "skipped" and "excluded-on-windows" in env_step.detail
    assert memory.action == "ran"
    assert not setup_cli._stops_run(keyvault)
    assert run_steps(env, monkeypatch)[2].action == "done"


def test_setup_memory_step_respects_state(seeded, monkeypatch):
    env = seeded
    assert run_steps(env, monkeypatch, non_interactive=True)[2].action == "manual"
    enable(env)
    assert memory_cli.disable(home=env.home, root=env.home / "vault", platform="win32") == 0
    memory = run_steps(env, monkeypatch)[2]
    assert memory.action == "done" and "paused by operator" in memory.detail


def test_setup_memory_step_reports_helper_and_broken_custody(win, monkeypatch):
    env = win
    with monkeypatch.context() as patch:
        patch.setattr(_seckey_helper, "find_winkey_helper", lambda: None)
        memory = run_steps(env, monkeypatch)[2]
        assert memory.action == "manual" and "keyvault enable-winkey" in memory.detail
    put(env.home, "mordred", "memory-vault.marker", b"memory-encryption enabled\n")
    memory = run_steps(env, monkeypatch)[2]
    assert memory.action == "blocked" and "custody-broken" in memory.detail
    assert setup_cli._stops_run(memory)


@pytest.mark.parametrize("name", sorted(ORIGINALS))
def test_status_never_changes_memory_files(seeded, monkeypatch, capsys, name):
    env = seeded
    enable(env)
    before = (env.home / "memories" / name).read_bytes()
    forbid_native(monkeypatch, env)
    report(env, capsys)
    memory_line(env)
    assert (env.home / "memories" / name).read_bytes() == before
