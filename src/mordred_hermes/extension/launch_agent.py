"""``hermes-mordred extension agent`` — start ``extension serve`` at login (macOS LaunchAgent).

``install`` writes ``~/Library/LaunchAgents/<label>.plist`` and loads it into
the login session (``launchctl bootstrap gui/<uid>``). launchd then starts the
server at every login and starts it again when it exits with an error; a clean
stop (SIGTERM, exit 0) stays stopped. ``uninstall`` unloads and removes it;
``status`` reports what launchd knows.

At start the server opens its vault, which asks for Touch ID. With nobody at the
Mac the server keeps running with the vault locked, and the extension's Unlock
button asks again (:mod:`.vault_gate`).

One agent per Hermes home: the label is ``com.mordred.hermes.extension`` for
``~/.hermes`` and gets a short hash of the home's path for any other home, so a
development home and the real one never replace each other's agent.

The plist never holds a secret. It names the interpreter and the ``hermes-mordred``
script of the same environment (``extension serve``), and
copies a few settings from the installing shell: ``HERMES_HOME``, ``PATH``,
``PYTHONPATH``, ``LANG`` and the ``MORDRED_*`` settings, except any whose name
says it is a key, secret, token, password or hash. Secrets belong in the vault's
``.env`` (injected when the vault opens). A development home that keeps them in
a shell file can pass ``--env-script``: the agent then sources that file at each
start, so its values stay in the file, not in the plist.
"""

from __future__ import annotations

import hashlib
import os
import plistlib
import re
import subprocess
import sys
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Final

BASE_LABEL: Final = "com.mordred.hermes.extension"
#: The console script the agent runs. Hermes's runtime bootstrap (the ``.pth``
#: that installs database encryption into the process) recognises a process by
#: this name; ``python -m mordred_hermes.extension`` would run without it, and
#: the import store refuses such a process (``unprotected_process``).
CLI_NAME: Final = "hermes-mordred"
LOG_NAME: Final = "extension-serve.log"
#: Seconds launchd waits before starting the server again after it exited.
THROTTLE_SECONDS: Final = 30
#: How long ``install`` waits for launchd to let go of a replaced agent.
UNLOAD_WAIT_SECONDS: Final = 15.0
_UNLOAD_POLL_SECONDS: Final = 0.5
_COPIED: Final = ("HERMES_HOME", "PATH", "PYTHONPATH", "LANG")
#: A name part (between underscores) that marks a secret: ``*_API_KEY``, ``*_CLIENT_SECRET``, …
_SECRET_NAME: Final = re.compile(
    r"(?:^|_)(?:KEY|SECRET|TOKEN|PASSWORD|PASSPHRASE|HASH|CREDENTIALS?)(?:_|$)", re.IGNORECASE
)

Runner = Callable[[Sequence[str]], "subprocess.CompletedProcess[str]"]


class AgentError(Exception):
    """A refusal with a one-line, content-free message for the CLI."""


#: Folders macOS privacy protection (TCC) keeps from a LaunchAgent unless the user grants access.
_PROTECTED_FOLDERS: Final = ("Documents", "Desktop", "Downloads", "Library/Mobile Documents")


def protected_folder(path: Path, user_home: Path | None = None) -> str | None:
    """The protected folder ``path`` lies in, else ``None``."""
    base = (user_home or Path.home()).resolve()
    resolved = path.expanduser().resolve()
    for folder in _PROTECTED_FOLDERS:
        if resolved.is_relative_to(base / folder):
            return folder
    return None


def label_for(home: Path) -> str:
    """The launchd label of ``home``'s agent."""
    if home.resolve() == (Path.home() / ".hermes").resolve():
        return BASE_LABEL
    return f"{BASE_LABEL}.{hashlib.sha256(str(home.resolve()).encode()).hexdigest()[:8]}"


def plist_path(label: str, agents_dir: Path | None = None) -> Path:
    return (agents_dir or Path.home() / "Library" / "LaunchAgents") / f"{label}.plist"


def copied_environment(environ: Mapping[str, str], home: Path) -> dict[str, str]:
    """The settings the agent starts with: never a secret (see the module docstring)."""
    env = {name: environ[name] for name in _COPIED if environ.get(name)}
    for name, value in environ.items():
        if name.startswith("MORDRED_") and value and not _SECRET_NAME.search(name):
            env[name] = value
    env["HERMES_HOME"] = str(home.resolve())
    return env


@dataclass(frozen=True)
class AgentSpec:
    label: str
    home: Path
    python: str
    host: str
    port: int
    env: dict[str, str]
    env_script: Path | None = None

    @property
    def log_path(self) -> Path:
        return self.home / "logs" / LOG_NAME

    @property
    def cli(self) -> str:
        """``hermes-mordred`` next to the interpreter (the same environment)."""
        return str(Path(self.python).parent / CLI_NAME)

    def program_arguments(self) -> list[str]:
        serve = [self.cli, "extension", "serve", "--host", self.host, "--port", str(self.port)]
        if self.env_script is None:
            return [self.python, *serve]
        # Arguments, not interpolation: no path is ever parsed by the shell.
        # ``set -a`` exports what the file assigns, as a shell user's ``export`` would.
        return [
            "/bin/sh",
            "-c",
            'set -a && . "$1" && set +a && shift && exec "$@"',
            "mordred-extension-serve",
            str(self.env_script),
            self.python,
            *serve,
        ]

    def plist(self) -> bytes:
        return plistlib.dumps(
            {
                "Label": self.label,
                "ProgramArguments": self.program_arguments(),
                "EnvironmentVariables": self.env,
                "WorkingDirectory": str(self.home),
                "RunAtLoad": True,
                # Start again after an error exit; a clean stop (exit 0) stays stopped.
                "KeepAlive": {"SuccessfulExit": False},
                "ThrottleInterval": THROTTLE_SECONDS,
                # A login-session service that may show Touch ID prompts.
                "ProcessType": "Interactive",
                "StandardOutPath": str(self.log_path),
                "StandardErrorPath": str(self.log_path),
            }
        )


def build_spec(
    *,
    home: Path,
    environ: Mapping[str, str],
    host: str,
    port: int,
    env_script: Path | None = None,
    python: str | None = None,
) -> AgentSpec:
    from .api import _is_loopback_host

    if not _is_loopback_host(host):
        raise AgentError(f"refusing non-loopback host {host!r}; the protocol is localhost-only.")
    if not 0 < port <= 65535:
        raise AgentError(f"port must be 1-65535 (got {port}).")
    script = None
    if env_script is not None:
        script = env_script.expanduser().resolve()
        if not script.is_file():
            raise AgentError(f"--env-script {env_script} is not a file.")
    interpreter = python or sys.executable
    if not (Path(interpreter).parent / CLI_NAME).is_file():
        raise AgentError(f"{CLI_NAME} is not installed next to {interpreter}; reinstall hermes-mordred.")
    for what, path in (("the Hermes home", home), ("--env-script", script), ("the Python interpreter", interpreter)):
        if path is not None and (folder := protected_folder(Path(path))) is not None:
            raise AgentError(
                f"{what} is inside ~/{folder}, which macOS keeps from login services "
                "(privacy protection): the agent could not start. Use a home and files outside "
                "~/Documents, ~/Desktop, ~/Downloads and iCloud Drive."
            )
    return AgentSpec(
        label=label_for(home),
        home=home.resolve(),
        python=interpreter,
        host=host,
        port=port,
        env=copied_environment(environ, home),
        env_script=script,
    )


def _launchctl(args: Sequence[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["launchctl", *args], capture_output=True, text=True, check=False)  # noqa: S603, S607 - list argv, no shell; system tool resolved on PATH


def _domain() -> str:
    return f"gui/{os.getuid()}"


def install(spec: AgentSpec, *, agents_dir: Path | None = None, run: Runner = _launchctl) -> Path:
    """Write the plist and (re)load it; returns its path."""
    path = plist_path(spec.label, agents_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    spec.log_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    # An agent already loaded under this label is replaced, not doubled.
    _unload(spec.label, run)
    tmp = path.with_suffix(".plist.tmp")
    tmp.write_bytes(spec.plist())
    tmp.chmod(0o644)
    tmp.replace(path)
    loaded = run(["bootstrap", _domain(), str(path)])
    if loaded.returncode != 0:
        raise AgentError(f"launchctl could not load {path.name} (exit {loaded.returncode}).")
    return path


def _unload(label: str, run: Runner) -> None:
    """Boot the agent out and wait until launchd no longer knows it.

    ``bootout`` returns before a running job is gone; bootstrapping the same
    label meanwhile fails (launchctl exit 5).
    """
    run(["bootout", f"{_domain()}/{label}"])
    waited = 0.0
    while run(["print", f"{_domain()}/{label}"]).returncode == 0:
        if waited >= UNLOAD_WAIT_SECONDS:
            raise AgentError(f"launchd did not stop {label}; try again in a minute.")
        time.sleep(_UNLOAD_POLL_SECONDS)
        waited += _UNLOAD_POLL_SECONDS


def uninstall(label: str, *, agents_dir: Path | None = None, run: Runner = _launchctl) -> bool:
    """Unload and remove the agent; ``False`` when there was none."""
    path = plist_path(label, agents_dir)
    run(["bootout", f"{_domain()}/{label}"])
    if not path.exists():
        return False
    path.unlink()
    return True


@dataclass(frozen=True)
class AgentStatus:
    installed: bool
    loaded: bool
    state: str | None = None
    pid: int | None = None
    last_exit: str | None = None


def status(label: str, *, agents_dir: Path | None = None, run: Runner = _launchctl) -> AgentStatus:
    installed = plist_path(label, agents_dir).exists()
    shown = run(["print", f"{_domain()}/{label}"])
    if shown.returncode != 0:
        return AgentStatus(installed=installed, loaded=False)

    def field(name: str) -> str | None:
        found = re.search(rf"^\s*{re.escape(name)} = (.+)$", shown.stdout, re.MULTILINE)
        return found.group(1).strip() if found else None

    pid = field("pid")
    return AgentStatus(
        installed=installed,
        loaded=True,
        state=field("state"),
        pid=int(pid) if pid and pid.isdigit() else None,
        last_exit=field("last exit code"),
    )


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #


def cli(action: str, *, host: str, port: int, env_script: str | None) -> int:
    from .._core._home import hermes_home

    if sys.platform != "darwin":
        print("error: `extension agent` uses launchd and runs only on macOS.", file=sys.stderr)
        return 2
    home = Path(hermes_home())
    label = label_for(home)
    try:
        if action == "install":
            spec = build_spec(
                home=home,
                environ=os.environ,
                host=host,
                port=port,
                env_script=Path(env_script) if env_script else None,
            )
            path = install(spec)
            from . import native_host

            native_host.write_endpoint(home, spec.host, spec.port)  # the extension finds it here
            print(f"Installed {path}")
            print(f"Starts at login: ws://{spec.host}:{spec.port}/ext for {spec.home}")
            print(f"Settings copied: {', '.join(sorted(spec.env))}")
            if spec.env_script is not None:
                print(f"Sourced at each start: {spec.env_script}")
            print(f"Log: {spec.log_path}")
            print("It is starting now; approve Touch ID on this Mac to open the vault.")
            return 0
        if action == "uninstall":
            removed = uninstall(label)
            print(f"Removed the agent {label}." if removed else f"No agent {label} was installed.")
            return 0
        shown = status(label)
    except AgentError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    if not shown.installed and not shown.loaded:
        print(f"No agent installed for {home} ({label}).")
        return 0
    print(f"Agent {label}: {'loaded' if shown.loaded else 'installed, not loaded'}")
    if shown.loaded:
        print(f"  state: {shown.state or 'unknown'}" + (f" (pid {shown.pid})" if shown.pid else ""))
        if shown.last_exit:
            print(f"  last exit: {shown.last_exit}")
    print(f"  log: {home / 'logs' / LOG_NAME}")
    return 0
