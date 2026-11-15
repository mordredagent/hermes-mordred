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


def _spec(tmp_path: Path, **kwargs: object) -> launch_agent.AgentSpec:
    return build_spec(
        home=tmp_path / "home", environ=ENV, host="127.0.0.1", port=7788, python="/py/bin/python", **kwargs
    )  # type: ignore[arg-type]


def test_the_plist_starts_serve_at_login_and_restarts_it_after_an_error(tmp_path: Path) -> None:
    spec = _spec(tmp_path)
    doc = plistlib.loads(spec.plist())
    assert doc["ProgramArguments"] == [
        "/py/bin/python",
        "-m",
        "mordred_hermes.extension",
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
    assert args[4:6] == [str(script.resolve()), "/py/bin/python"]
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
    assert [c[0] for c in run.calls] == ["bootout", "bootstrap"]
    assert run.calls[1][2] == str(path)
    assert (spec.home / "logs").is_dir()

    assert uninstall(spec.label, agents_dir=agents, run=run) is True
    assert not path.exists()
    assert uninstall(spec.label, agents_dir=agents, run=run) is False


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
