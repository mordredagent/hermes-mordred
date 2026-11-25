"""``hermes-mordred extension agent``: the LaunchAgent that starts ``extension serve`` at login."""

from __future__ import annotations

import plistlib
import subprocess
from collections.abc import Sequence
from pathlib import Path

import pytest

from mordred_hermes.extension import launch_agent
from mordred_hermes.extension.launch_agent import AgentError, build_spec, install, label_for, status, uninstall


class Launchctl:
    """Records launchctl calls; ``print`` answers with ``printed`` (or fails when it is None)."""

    def __init__(self, printed: str | None = None, bootstrap_rc: int = 0) -> None:
        self.calls: list[list[str]] = []
        self.printed = printed
        self.bootstrap_rc = bootstrap_rc

    def __call__(self, args: Sequence[str]) -> subprocess.CompletedProcess[str]:
        self.calls.append(list(args))
        if args[0] == "print":
            rc = 0 if self.printed is not None else 113
            return subprocess.CompletedProcess(list(args), rc, self.printed or "", "")
        rc = self.bootstrap_rc if args[0] == "bootstrap" else 0
        return subprocess.CompletedProcess(list(args), rc, "", "")


ENV = {
    "PATH": "/usr/bin:/bin",
    "HERMES_HOME": "/ignored",
    "HERMES_MEMORY_KEY": "memory-secret",
    "MORDRED_RECALL_LLM_ENDPOINT": "http://127.0.0.1:8081/v1",
    "MORDRED_GMAIL_CLIENT_SECRET": "gmail-secret",
    "MORDRED_SEKEY_SIGN_HELPER": "/opt/helper",
    "VENICE_API_KEY": "venice-secret",
}


def _venv(tmp_path: Path) -> Path:
    """A stand-in environment: its interpreter and the ``hermes-mordred`` script beside it."""
    bin_dir = tmp_path / "venv" / "bin"
    bin_dir.mkdir(parents=True, exist_ok=True)
    for name in ("python", "hermes-mordred"):
        (bin_dir / name).write_text("#!/bin/sh\n")
    return bin_dir / "python"


def _spec(tmp_path: Path, **kwargs: object) -> launch_agent.AgentSpec:
    return build_spec(
        home=tmp_path / "home", environ=ENV, host="127.0.0.1", port=7788, python=str(_venv(tmp_path)), **kwargs
    )  # type: ignore[arg-type]


def test_the_plist_starts_serve_at_login_and_restarts_it_after_an_error(tmp_path: Path) -> None:
    spec = _spec(tmp_path)
    doc = plistlib.loads(spec.plist())
    bin_dir = tmp_path / "venv" / "bin"
    # The console script, not `-m`: Hermes's runtime bootstrap (database encryption) knows a process by that name.
    assert doc["ProgramArguments"] == [
        str(bin_dir / "python"),
        str(bin_dir / "hermes-mordred"),
        "extension",
        "serve",
        "--host",
        "127.0.0.1",
        "--port",
        "7788",
    ]
    assert doc["RunAtLoad"] is True and doc["KeepAlive"] == {"SuccessfulExit": False}
    assert doc["StandardErrorPath"] == str((tmp_path / "home").resolve() / "logs" / "extension-serve.log")
    assert doc["EnvironmentVariables"]["HERMES_HOME"] == str((tmp_path / "home").resolve())


def test_the_plist_holds_no_secret(tmp_path: Path) -> None:
    raw = _spec(tmp_path).plist()
    env = plistlib.loads(raw)["EnvironmentVariables"]
    assert set(env) == {"PATH", "HERMES_HOME", "MORDRED_RECALL_LLM_ENDPOINT", "MORDRED_SEKEY_SIGN_HELPER"}
    for secret in (b"memory-secret", b"gmail-secret", b"venice-secret"):
        assert secret not in raw


def test_an_env_script_is_sourced_at_start_never_copied(tmp_path: Path) -> None:
    script = tmp_path / "env.sh"
    script.write_text("HERMES_MEMORY_KEY=from-file\n")
    spec = _spec(tmp_path, env_script=script)
    args = plistlib.loads(spec.plist())["ProgramArguments"]
    assert args[:2] == ["/bin/sh", "-c"]
    assert args[4:6] == [str(script.resolve()), str(tmp_path / "venv" / "bin" / "python")]
    assert b"from-file" not in spec.plist()
    # The shell line exports what the file assigns and runs the server with its arguments.
    out = subprocess.run(
        [*args[:5], "/bin/sh", "-c", 'printf %s "$HERMES_MEMORY_KEY"'],
        capture_output=True,
        text=True,
        check=True,
    )
    assert out.stdout == "from-file"
    with pytest.raises(AgentError):
        _spec(tmp_path, env_script=tmp_path / "missing.sh")


def test_an_environment_without_the_script_is_refused(tmp_path: Path) -> None:
    lone = tmp_path / "lone" / "bin" / "python"
    lone.parent.mkdir(parents=True)
    lone.write_text("#!/bin/sh\n")
    with pytest.raises(AgentError, match="hermes-mordred is not installed"):
        build_spec(home=tmp_path / "home", environ=ENV, host="127.0.0.1", port=7788, python=str(lone))


def test_each_home_gets_its_own_label(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    assert label_for(tmp_path / ".hermes") == "com.mordred.hermes.extension"
    dev = label_for(tmp_path / "dev" / "home")
    assert dev.startswith("com.mordred.hermes.extension.") and dev != label_for(tmp_path / "other")


def test_only_loopback_hosts_and_real_ports(tmp_path: Path) -> None:
    with pytest.raises(AgentError):
        build_spec(home=tmp_path, environ={}, host="0.0.0.0", port=7788)
    with pytest.raises(AgentError):
        build_spec(home=tmp_path, environ={}, host="127.0.0.1", port=0)


def test_install_replaces_a_loaded_agent_and_uninstall_removes_it(tmp_path: Path) -> None:
    spec = _spec(tmp_path)
    agents = tmp_path / "LaunchAgents"
    run = Launchctl()
    path = install(spec, agents_dir=agents, run=run)
    assert path == agents / f"{spec.label}.plist" and path.exists()
    assert [c[0] for c in run.calls] == ["bootout", "print", "bootstrap"]
    assert run.calls[2][2] == str(path)
    assert (spec.home / "logs").is_dir()

    assert uninstall(spec.label, agents_dir=agents, run=run) is True
    assert not path.exists()
    assert uninstall(spec.label, agents_dir=agents, run=run) is False


class StillThere(Launchctl):
    """``print`` keeps succeeding ``lingers`` times after the bootout, as a stopping job does."""

    def __init__(self, lingers: int) -> None:
        super().__init__(printed="state = running")
        self.lingers = lingers

    def __call__(self, args: Sequence[str]) -> subprocess.CompletedProcess[str]:
        if args[0] == "print":
            if self.lingers == 0:
                self.printed = None
            self.lingers -= 1
        return super().__call__(args)


def test_install_waits_for_the_replaced_agent_to_go(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    naps: list[float] = []
    monkeypatch.setattr(launch_agent.time, "sleep", naps.append)
    run = StillThere(lingers=2)
    install(_spec(tmp_path), agents_dir=tmp_path / "LaunchAgents", run=run)
    assert [c[0] for c in run.calls] == ["bootout", "print", "print", "print", "bootstrap"]
    assert len(naps) == 2


def test_install_gives_up_when_launchd_keeps_the_agent(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(launch_agent.time, "sleep", lambda _s: None)
    run = StillThere(lingers=10_000)
    with pytest.raises(AgentError, match="did not stop"):
        install(_spec(tmp_path), agents_dir=tmp_path / "LaunchAgents", run=run)
    assert "bootstrap" not in [c[0] for c in run.calls]


def test_a_failed_load_is_reported(tmp_path: Path) -> None:
    with pytest.raises(AgentError, match="could not load"):
        install(_spec(tmp_path), agents_dir=tmp_path / "LaunchAgents", run=Launchctl(bootstrap_rc=5))


def test_status_reads_what_launchd_reports(tmp_path: Path) -> None:
    agents = tmp_path / "LaunchAgents"
    printed = "gui/501/x = {\n\tstate = running\n\tpid = 4242\n\tlast exit code = (never exited)\n}\n"
    shown = status("x", agents_dir=agents, run=Launchctl(printed))
    assert (shown.loaded, shown.state, shown.pid, shown.last_exit) == (True, "running", 4242, "(never exited)")
    assert status("x", agents_dir=agents, run=Launchctl()).loaded is False


def test_files_under_protected_folders_are_refused(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # A login service cannot read ~/Documents & co. without a privacy grant: the agent would only fail.
    monkeypatch.setenv("HOME", str(tmp_path))
    (tmp_path / "Documents" / "dev").mkdir(parents=True)
    script = tmp_path / "Documents" / "dev" / "env.sh"
    script.write_text("")
    with pytest.raises(AgentError, match="Documents"):
        build_spec(home=tmp_path / "Documents" / "dev" / "home", environ={}, host="127.0.0.1", port=7788)
    with pytest.raises(AgentError, match="Documents"):
        build_spec(home=tmp_path / "home", environ={}, host="127.0.0.1", port=7788, env_script=script)
    assert launch_agent.protected_folder(tmp_path / "Library" / "Mobile Documents" / "x") == "Library/Mobile Documents"
    assert launch_agent.protected_folder(tmp_path / ".hermes") is None


def test_start_up_window_only_for_a_home_set_up_with_attended_keys(tmp_path, monkeypatch):
    import sys

    from mordred_hermes.extension import __main__ as serve_main
    from mordred_hermes.keyvault import _presence

    if sys.platform != "darwin":
        pytest.skip("macOS presence")
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    (tmp_path / "mordred").mkdir()
    opened = []
    monkeypatch.setattr(_presence, "open_window", lambda home, purpose: opened.append(purpose) or (lambda: None))
    serve_main._startup_window()()
    assert opened == []  # no marker: unattended or older homes keep their behaviour
    _presence.enable_operation_presence(tmp_path)
    serve_main._startup_window()()
    assert opened == ["startup"]


def test_start_up_opens_the_database_key_inside_its_window(monkeypatch, caplog):
    from mordred_hermes import dbcrypt
    from mordred_hermes.extension import __main__ as main

    calls = []

    class Provider:
        runtime_native = True

        def __call__(self):
            calls.append("unwrap")

    monkeypatch.setattr(dbcrypt._runtime, "_PROVIDER", Provider())
    main._open_database_key()
    assert calls == ["unwrap"]

    class Failing(Provider):
        def __call__(self):
            raise RuntimeError("no Touch ID")

    monkeypatch.setattr(dbcrypt._runtime, "_PROVIDER", Failing())
    main._open_database_key()  # logged, never raised: the first use asks instead
    assert "database key not opened at start (RuntimeError)" in caplog.text

    class Legacy(Provider):
        runtime_native = False

    monkeypatch.setattr(dbcrypt._runtime, "_PROVIDER", Legacy())
    main._open_database_key()
    assert calls == ["unwrap"]
    monkeypatch.setattr(dbcrypt._runtime, "_PROVIDER", None)
    main._open_database_key()
