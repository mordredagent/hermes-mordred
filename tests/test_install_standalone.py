"""Hermetic tests for ``scripts/install-standalone.sh``: what it refuses before installing anything."""

from __future__ import annotations

import os
import re
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
INSTALLER = ROOT / "scripts" / "install-standalone.sh"

pytestmark = pytest.mark.skipif(shutil.which("bash") is None, reason="needs bash")


def _run(
    tmp_path: Path, *args: str, system: str = "Darwin", machine: str = "arm64"
) -> subprocess.CompletedProcess[str]:
    """Run the installer with a stand-in ``uname`` and an empty home; nothing it could install exists."""
    shims = tmp_path / "shims"
    shims.mkdir(exist_ok=True)
    uname = shims / "uname"
    uname.write_text(f'#!/bin/sh\nif [ "$1" = -m ]; then echo {machine}; else echo {system}; fi\n')
    uname.chmod(0o755)
    home = tmp_path / "home"
    home.mkdir(exist_ok=True)
    env = {"HOME": str(home), "PATH": f"{shims}{os.pathsep}{os.environ.get('PATH', '')}", "LANG": "C"}
    return subprocess.run(
        ["bash", str(INSTALLER), *args], env=env, capture_output=True, text=True, timeout=60, check=False
    )


def test_help_lists_every_option(tmp_path: Path) -> None:
    result = _run(tmp_path, "--help")
    assert result.returncode == 0
    parsed = set(re.findall(r"^\s+(--[a-z-]+)", result.stdout, flags=re.MULTILINE))
    in_code = set(re.findall(r"^\s+(--[a-z-]+)(?: \|[^)]*)?\)", INSTALLER.read_text(), flags=re.MULTILINE))
    in_code |= {
        "--home",
        "--bin-dir",
        "--from-source",
        "--backup-file",
        "--model-dir",
        "--small-port",
        "--large-port",
        "--extension-port",
    }
    assert parsed == in_code


@pytest.mark.parametrize(
    ("args", "message"),
    [
        (["--bogus"], "unknown option: --bogus"),
        (["--home"], "--home needs a value"),
        (["--small-port", "47713"], "different ports"),
        (["--small-port", "x"], "ports must be numbers"),
        (["--extension-port", "x"], "ports must be numbers"),
        (["--extension-port", "47712"], "a port of its own"),
    ],
)
def test_bad_arguments_are_refused(tmp_path: Path, args: list[str], message: str) -> None:
    result = _run(tmp_path, *args)
    assert result.returncode == 1
    assert message in result.stderr


@pytest.mark.parametrize(("system", "machine"), [("Linux", "x86_64"), ("Darwin", "x86_64")])
def test_only_apple_silicon_macs_are_supported(tmp_path: Path, system: str, machine: str) -> None:
    result = _run(tmp_path, system=system, machine=machine)
    assert result.returncode == 1
    assert "macOS" in result.stderr or "Apple silicon" in result.stderr
    assert not (tmp_path / "home" / ".mordred-hermes").exists()


def test_the_other_hermes_home_is_refused(tmp_path: Path) -> None:
    result = _run(tmp_path, "--home", str(tmp_path / "home" / ".hermes"))
    assert result.returncode == 1
    assert "must not be ~/.hermes" in result.stderr
    assert not (tmp_path / "home" / ".hermes").exists()


def test_a_checkout_that_is_not_hermes_mordred_is_refused(tmp_path: Path) -> None:
    result = _run(tmp_path, "--from-source", str(tmp_path))
    assert result.returncode == 1
    assert "not a hermes-mordred checkout" in result.stderr


def test_the_runtime_requirements_are_exact_pins() -> None:
    lines = [
        line
        for line in (ROOT / "scripts" / "bonsai-runtime-macos.txt").read_text().splitlines()
        if line and not line.startswith("#")
    ]
    assert lines
    assert all(re.fullmatch(r"[A-Za-z0-9._-]+==[A-Za-z0-9.+-]+", line) for line in lines)
    assert any(line.startswith("mlx-vlm==") for line in lines)


@pytest.mark.skipif(sys.platform != "darwin" or shutil.which("lsof") is None, reason="macOS lsof and launchctl")
def test_a_port_another_program_listens_on_is_refused_before_installing(tmp_path: Path) -> None:
    with socket.socket() as free:
        free.bind(("127.0.0.1", 0))
        small_port = free.getsockname()[1]  # nothing listens on it
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        port = listener.getsockname()[1]
        result = _run(
            tmp_path,
            *("--small-port", str(small_port), "--extension-port", str(port)),
            *("--home", str(tmp_path / "home" / "mordred")),
        )
    assert result.returncode == 1
    assert f"port {port} (extension server) is in use" in result.stderr
    assert not (tmp_path / "home" / "mordred").exists()


def _model_copy(root: Path, name: str, revision: str) -> Path:
    """A folder shaped like `hf download --local-dir`: its files and the download record."""
    folder = root / name
    record = folder / ".cache" / "huggingface" / "download"
    record.mkdir(parents=True)
    (folder / "config.json").write_text("{}")
    (folder / "model.safetensors").write_bytes(b"\0")
    (record / "config.json.metadata").write_text(f"{revision}\nabc\n1\n")
    return folder


def _call(tmp_path: Path, model_dir: Path, *lines: str) -> subprocess.CompletedProcess[str]:
    """Run installer functions (everything but the final ``main``) against a stand-in home."""
    body = "\n".join(INSTALLER.read_text().splitlines()[:-1])
    script = tmp_path / "functions.sh"
    script.write_text(body + "\n" + "\n".join(lines) + "\n")
    home = tmp_path / "home"
    home.mkdir(exist_ok=True)
    env = {
        "HOME": str(home),
        "PATH": os.environ.get("PATH", ""),
        "LANG": "C",
        "MORDRED_HOME": str(home / "mordred"),
    }
    return subprocess.run(
        ["bash", str(script), str(model_dir)], env=env, capture_output=True, text=True, timeout=60, check=False
    )


SMALL = ("prism-ml/Ternary-Bonsai-2-2B-mlx-2bit", "Ternary-Bonsai-2-2B-mlx-2bit")


def _revision(name: str) -> str:
    match = re.search(rf'^readonly {name}="([0-9a-f]+)"', INSTALLER.read_text(), flags=re.MULTILINE)
    assert match
    return match.group(1)


def test_a_model_in_model_dir_is_used_where_it_is(tmp_path: Path) -> None:
    models = tmp_path / "models"
    src = _model_copy(models, SMALL[1], _revision("SMALL_MODEL_REVISION"))
    old_link = tmp_path / "home" / "mordred" / "models" / SMALL[1]
    old_link.parent.mkdir(parents=True)
    old_link.symlink_to(src)  # what an earlier installer left
    result = _call(
        tmp_path,
        models,
        'MODEL_DIR="$1"; MORDRED_HOME="$HOME/mordred"',
        'download_model "$SMALL_MODEL_REPO" "$SMALL_MODEL_REVISION" 1100',
        'model_path "$SMALL_MODEL_REPO"',
    )
    assert result.returncode == 0, result.stderr
    assert "no download" in result.stdout
    assert result.stdout.strip().splitlines()[-1] == str(src)
    # No link inside the home: the database inventory refuses one.
    assert not old_link.exists() and not old_link.is_symlink()


def test_another_revision_in_model_dir_is_refused(tmp_path: Path) -> None:
    models = tmp_path / "models"
    _model_copy(models, SMALL[1], "0" * 40)
    result = _call(
        tmp_path,
        models,
        'MODEL_DIR="$1"; MORDRED_HOME="$HOME/mordred"',
        'download_model "$SMALL_MODEL_REPO" "$SMALL_MODEL_REVISION" 1100',
    )
    assert result.returncode == 1
    assert "is not revision" in result.stderr
    assert not (tmp_path / "home" / "mordred" / "models" / SMALL[1]).exists()


def test_a_downloaded_copy_is_left_alone_and_reported(tmp_path: Path) -> None:
    models = tmp_path / "models"
    _model_copy(models, SMALL[1], _revision("SMALL_MODEL_REVISION"))
    downloaded = tmp_path / "home" / "mordred" / "models" / SMALL[1]
    downloaded.mkdir(parents=True)
    result = _call(
        tmp_path,
        models,
        'MODEL_DIR="$1"; MORDRED_HOME="$HOME/mordred"',
        'download_model "$SMALL_MODEL_REPO" "$SMALL_MODEL_REVISION" 1100',
    )
    assert result.returncode == 0, result.stderr
    assert "no longer used" in result.stdout
    assert downloaded.is_dir()


def test_the_large_model_in_model_dir_is_used_without_asking(tmp_path: Path) -> None:
    models = tmp_path / "models"
    _model_copy(models, "Ternary-Bonsai-2-27B-mlx-2bit", _revision("LARGE_MODEL_REVISION"))
    result = _call(
        tmp_path,
        models,
        'MODEL_DIR="$1"; MORDRED_HOME="$HOME/mordred"',
        "if want_large_model </dev/null; then echo wanted; else echo skipped; fi",
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "wanted"


def _fake_hf(tmp_path: Path, body: str) -> None:
    hf = tmp_path / "home" / "mordred" / "models" / "runtime" / "bin" / "hf"
    hf.parent.mkdir(parents=True)
    hf.write_text("#!/bin/bash\n" + body + "\n")
    hf.chmod(0o755)


def test_a_download_reports_its_progress_and_completion(tmp_path: Path) -> None:
    # The stand-in writes 2 MB in two steps, then the config: what `hf download --local-dir` leaves.
    _fake_hf(
        tmp_path,
        'dest="${@: -1}"; mkdir -p "$dest"; head -c 1048576 /dev/zero >"$dest/a"; sleep 3; '
        'head -c 1048576 /dev/zero >"$dest/b"; sleep 9; echo "{}" >"$dest/config.json"',
    )
    result = _call(
        tmp_path,
        tmp_path / "none",
        'MORDRED_HOME="$HOME/mordred"',
        'download_model "$SMALL_MODEL_REPO" "$SMALL_MODEL_REVISION" 4',
    )
    assert result.returncode == 0, result.stderr
    assert "Downloading prism-ml/Ternary-Bonsai-2-2B-mlx-2bit (about 4 MB)" in result.stdout
    assert re.search(r"downloaded [0-9]+ of about 4 MB \([0-9]+%\)", result.stdout)
    assert result.stdout.strip().endswith("downloaded prism-ml/Ternary-Bonsai-2-2B-mlx-2bit")


def test_a_failed_download_stops_the_install(tmp_path: Path) -> None:
    _fake_hf(tmp_path, "exit 3")
    result = _call(
        tmp_path,
        tmp_path / "none",
        'MORDRED_HOME="$HOME/mordred"',
        'download_model "$SMALL_MODEL_REPO" "$SMALL_MODEL_REVISION" 1100',
    )
    assert result.returncode == 1
    assert "did not download" in result.stderr
    assert "exited with status 3" in result.stdout  # for the log


def _setup_call(tmp_path: Path, *lines: str) -> subprocess.CompletedProcess[str]:
    """``run_setup`` with a stand-in ``hermes-mordred`` answering each call with the next status."""
    return _call(
        tmp_path,
        tmp_path / "none",
        'resolve_backup_file() { BACKUP_FILE="$HOME/backup.mrkv"; }',
        "require_home_unused() { :; }",
        'calls="$HOME/calls"',
        'hermes-mordred() { echo "$*" >>"$calls"; local status; '
        'status="$(sed -n "$(wc -l <"$calls")p" "$HOME/statuses")"; return "${status:-0}"; }',
        *lines,
    )


def test_a_missed_touch_id_is_offered_again(tmp_path: Path) -> None:
    (tmp_path / "home").mkdir()
    (tmp_path / "home" / "statuses").write_text("75\n0\n")
    result = _setup_call(
        tmp_path,
        'dialog() { echo "dialog: $1" >>"$HOME/dialogs"; [[ $# -gt 2 ]] && echo "${@: -1}"; return 0; }',
        "DIALOGS=1",
        "run_setup",
    )
    assert result.returncode == 0, result.stderr
    assert (tmp_path / "home" / "calls").read_text().count("setup --skip-hermes-setup --no-prompts") == 2
    dialogs = (tmp_path / "home" / "dialogs").read_text()
    assert dialogs.count("Next, confirm with Touch ID") == 2  # before each try: someone looks when it opens
    assert "Touch ID was not confirmed, so nothing was set up yet. Try again?" in dialogs


def test_unattended_keys_get_no_touch_id_notice(tmp_path: Path) -> None:
    result = _setup_call(
        tmp_path,
        'dialog() { echo "dialog: $1" >>"$HOME/dialogs"; }',
        "DIALOGS=1",
        "KEY_ARGS=(--unattended-keys)",
        "run_setup",
    )
    assert result.returncode == 0, result.stderr
    assert not (tmp_path / "home" / "dialogs").exists()


def test_a_missed_touch_id_without_dialogs_stops_the_install(tmp_path: Path) -> None:
    (tmp_path / "home").mkdir()
    (tmp_path / "home" / "statuses").write_text("75\n")
    result = _setup_call(tmp_path, "run_setup")
    assert result.returncode == 1
    assert "Touch ID was not confirmed" in result.stderr
    assert (tmp_path / "home" / "calls").read_text().count("--no-prompts") == 1


def test_another_setup_failure_is_not_retried(tmp_path: Path) -> None:
    (tmp_path / "home").mkdir()
    (tmp_path / "home" / "statuses").write_text("1\n")
    result = _setup_call(tmp_path, 'dialog() { echo "${@: -1}"; }', "DIALOGS=1", "set -e", "run_setup")
    assert result.returncode == 1
    assert (tmp_path / "home" / "calls").read_text().count("--no-prompts") == 1


@pytest.mark.skipif(sys.platform != "darwin" or shutil.which("lsof") is None, reason="macOS lsof")
def test_a_default_port_another_program_uses_moves_to_a_free_one(tmp_path: Path) -> None:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        port = listener.getsockname()[1]
        result = _call(
            tmp_path,
            tmp_path / "none",
            f"EXTENSION_PORT={port}",  # the default, not given on the command line
            "agent_pid() { :; }",
            'check_ports; echo "extension=$EXTENSION_PORT"',
        )
    assert result.returncode == 0, result.stderr
    assert f"port {port} (extension server) is in use by another program" in result.stdout
    moved = int(result.stdout.strip().rsplit("extension=", 1)[1])
    assert 47714 <= moved < 47800 and moved != port


def _keys(home: Path, *, backup: bool, vault: bool) -> None:
    keyvault = home / "mordred" / "mordred" / "keyvault"
    keyvault.mkdir(parents=True)
    (keyvault / "meta.json").write_text('{"version": 1, "keys": {"default": {}}}')
    if backup:
        (home / "backup.mrkv").write_text("backup")
    if vault:
        (home / "mordred" / "mordred" / "vault").mkdir()


@pytest.mark.parametrize(
    ("backup", "vault", "reset"),
    [(False, False, True), (True, False, False), (False, True, False)],
)
def test_keys_left_without_a_backup_are_started_over(tmp_path: Path, backup: bool, vault: bool, reset: bool) -> None:
    home = tmp_path / "home"
    _keys(home, backup=backup, vault=vault)
    result = _call(
        tmp_path,
        tmp_path / "none",
        'MORDRED_HOME="$HOME/mordred"',
        'BACKUP_FILE="$HOME/backup.mrkv"',
        'hermes-mordred() { echo "$*" >>"$HOME/calls"; }',
        "restart_unbacked_keys",
    )
    assert result.returncode == 0, result.stderr
    calls = (home / "calls").read_text() if (home / "calls").exists() else ""
    assert ("keyvault reset --yes" in calls) is reset
    assert ("starting the keys over" in result.stdout) is reset


def test_a_failure_dialog_opens_the_log(tmp_path: Path) -> None:
    (tmp_path / "home").mkdir()
    log = tmp_path / "home" / "install.log"
    log.write_text("what happened\n")
    result = _call(
        tmp_path,
        tmp_path / "none",
        f'MORDRED_INSTALL_LOG="{log}"',
        "DIALOGS=1",
        'dialog() { echo "dialog: $1 [${*:2}]" >>"$HOME/dialogs"; echo "Show Log"; }',
        'open() { echo "open $*" >>"$HOME/opened"; }',
        'fail "the network is down"',
    )
    assert result.returncode == 1
    dialogs = (tmp_path / "home" / "dialogs").read_text()
    assert "Mordred could not be installed: the network is down [Show Log OK]" in dialogs
    assert (tmp_path / "home" / "opened").read_text() == f"open -a Console {log}\n"


def test_a_leftover_mordred_process_is_stopped_when_asked(tmp_path: Path) -> None:
    home = tmp_path / "home"
    lock = home / "mordred" / "mordred" / "db-encryption.lock"
    lock.parent.mkdir(parents=True)
    lock.touch()
    holder = subprocess.Popen(  # holds the lock like a leftover setup
        [sys.executable, "-c", f"import time; f = open({str(lock)!r}); time.sleep(60)"]
    )
    try:
        time.sleep(0.5)
        result = _call(
            tmp_path,
            tmp_path / "none",
            'MORDRED_HOME="$HOME/mordred"',
            "DIALOGS=1",
            'dialog() { echo "Stop and Continue"; }',
            "require_home_unused; echo free",
        )
        assert result.returncode == 0, result.stderr
        assert result.stdout.strip().endswith("free")
        assert holder.wait(5) is not None  # stopped
    finally:
        holder.kill()


def test_a_leftover_process_without_dialogs_stops_the_install(tmp_path: Path) -> None:
    home = tmp_path / "home"
    lock = home / "mordred" / "mordred" / "db-encryption.lock"
    lock.parent.mkdir(parents=True)
    lock.touch()
    holder = subprocess.Popen([sys.executable, "-c", f"import time; f = open({str(lock)!r}); time.sleep(60)"])
    try:
        time.sleep(0.5)
        result = _call(tmp_path, tmp_path / "none", 'MORDRED_HOME="$HOME/mordred"', "require_home_unused")
        assert result.returncode == 1
        assert "Ctrl+C" in result.stderr
        assert holder.poll() is None  # left alone
    finally:
        holder.kill()
