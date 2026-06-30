"""Tests for ``hermes mordred encryption {enable,disable,purge} workspace``.

The Claude workspace is the external Touch ID / Secure Enclave-gated encrypted
APFS sparsebundle driven by ``claude-private``. This wraps it from the unified
surface WITHOUT ever auto-mounting it (mounting needs a live Touch ID and cannot
be CI-tested, and auto-unlocking a volume to delete it is too risky):

- **enable**  — drive ``claude-private-setup`` when the volume is not set up;
  guide the operator when the external tool is not installed.
- **disable** — ``hdiutil detach`` the mount (seal it). Non-destructive,
  re-mountable. No-op when already sealed / not set up.
- **purge**   — destructive: refuse while mounted, warn that the contents go too,
  then remove the sparsebundle + key material. Does NOT auto-mount / auto-export
  (the operator owns exporting first), so it needs no Touch ID and is testable.

All side effects go through injected ``run`` / ``is_mounted`` / ``tool_on_path``,
so the orchestration is verified on any platform.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from mordred_hermes.wizard import workspace_cli


def _env(tmp_path: Path) -> workspace_cli.WorkspaceEnv:
    keydir = tmp_path / "keydir"
    return workspace_cli.WorkspaceEnv(
        image=tmp_path / "claude-private.sparsebundle",
        blob=keydir / "passphrase.wrapped",
        mount=tmp_path / "mnt",
        keydir=keydir,
    )


def _set_up(env: workspace_cli.WorkspaceEnv) -> None:
    """Materialise a 'set up' workspace: sparsebundle dir + wrapped passphrase."""
    env.image.mkdir(parents=True)
    (env.image / "token.sparseimage").write_bytes(b"x")
    env.keydir.mkdir(parents=True)
    env.blob.write_bytes(b"wrapped")


class _Runner:
    def __init__(self, rc: int = 0) -> None:
        self.calls: list[list[str]] = []
        self._rc = rc

    def __call__(self, cmd: list[str]) -> int:
        self.calls.append(cmd)
        return self._rc


# -----------------------------------------------------------------------------
# enable
# -----------------------------------------------------------------------------
class TestEnable:
    def test_off_macos_errors(self, tmp_path: Path) -> None:
        run = _Runner()
        rc = workspace_cli.enable(env=_env(tmp_path), platform="linux", run=run, tool_on_path=lambda _n: True)
        assert rc == 1
        assert run.calls == []

    def test_runs_setup_when_not_configured(self, tmp_path: Path) -> None:
        run = _Runner(rc=0)
        rc = workspace_cli.enable(env=_env(tmp_path), platform="darwin", run=run, tool_on_path=lambda _n: True)
        assert rc == 0
        assert run.calls == [["claude-private-setup"]]

    def test_noop_when_already_configured(self, tmp_path: Path) -> None:
        env = _env(tmp_path)
        _set_up(env)
        run = _Runner()
        rc = workspace_cli.enable(env=env, platform="darwin", run=run, tool_on_path=lambda _n: True)
        assert rc == 0
        assert run.calls == []  # already set up — nothing to do

    def test_guides_when_tool_absent(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        run = _Runner()
        rc = workspace_cli.enable(env=_env(tmp_path), platform="darwin", run=run, tool_on_path=lambda _n: False)
        assert rc == 1
        assert run.calls == []
        assert "claude-private" in capsys.readouterr().err


# -----------------------------------------------------------------------------
# disable (seal — non-destructive)
# -----------------------------------------------------------------------------
class TestDisable:
    def test_off_macos_errors(self, tmp_path: Path) -> None:
        run = _Runner()
        rc = workspace_cli.disable(env=_env(tmp_path), platform="linux", run=run, is_mounted=lambda _p: True)
        assert rc == 1
        assert run.calls == []

    def test_detaches_when_mounted(self, tmp_path: Path) -> None:
        env = _env(tmp_path)
        _set_up(env)
        run = _Runner(rc=0)
        rc = workspace_cli.disable(env=env, platform="darwin", run=run, is_mounted=lambda _p: True)
        assert rc == 0
        assert run.calls == [["hdiutil", "detach", str(env.mount)]]

    def test_noop_when_already_sealed(self, tmp_path: Path) -> None:
        env = _env(tmp_path)
        _set_up(env)
        run = _Runner()
        rc = workspace_cli.disable(env=env, platform="darwin", run=run, is_mounted=lambda _p: False)
        assert rc == 0
        assert run.calls == []

    def test_noop_when_not_set_up(self, tmp_path: Path) -> None:
        run = _Runner()
        rc = workspace_cli.disable(env=_env(tmp_path), platform="darwin", run=run, is_mounted=lambda _p: False)
        assert rc == 0
        assert run.calls == []


# -----------------------------------------------------------------------------
# purge (destructive — no auto-mount)
# -----------------------------------------------------------------------------
class TestPurge:
    def test_off_macos_errors(self, tmp_path: Path) -> None:
        rc = workspace_cli.purge(env=_env(tmp_path), platform="linux", is_mounted=lambda _p: False)
        assert rc == 1

    def test_refuses_when_mounted(self, tmp_path: Path) -> None:
        env = _env(tmp_path)
        _set_up(env)
        rc = workspace_cli.purge(env=env, platform="darwin", is_mounted=lambda _p: True)
        assert rc == 1
        assert env.image.exists()  # not removed while mounted (mid-session)

    def test_removes_volume_when_unmounted(self, tmp_path: Path) -> None:
        env = _env(tmp_path)
        _set_up(env)
        rc = workspace_cli.purge(env=env, platform="darwin", is_mounted=lambda _p: False)
        assert rc == 0
        assert not env.image.exists()  # sparsebundle removed
        assert not env.keydir.exists()  # key material removed

    def test_removes_single_file_image(self, tmp_path: Path) -> None:
        """A single-file image (not a sparsebundle dir) must also be removed."""
        env = _env(tmp_path)
        env.image.write_bytes(b"dmg")  # file, not a directory bundle
        env.keydir.mkdir(parents=True)
        env.blob.write_bytes(b"wrapped")
        rc = workspace_cli.purge(env=env, platform="darwin", is_mounted=lambda _p: False)
        assert rc == 0
        assert not env.image.exists()

    def test_reports_failure_on_residue(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """A destructive op must NOT claim success when removal actually failed."""
        env = _env(tmp_path)
        _set_up(env)

        def _boom(*_a: object, **_k: object) -> None:
            raise OSError("permission denied")

        monkeypatch.setattr(workspace_cli.shutil, "rmtree", _boom)
        rc = workspace_cli.purge(env=env, platform="darwin", is_mounted=lambda _p: False)
        assert rc == 1
        assert env.image.exists()  # still there — not silently misreported as gone
        assert "remove" in capsys.readouterr().err.lower()

    def test_noop_when_not_set_up(self, tmp_path: Path) -> None:
        rc = workspace_cli.purge(env=_env(tmp_path), platform="darwin", is_mounted=lambda _p: False)
        assert rc == 0


# -----------------------------------------------------------------------------
# CLI dispatch — workspace is a valid target for enable/disable/purge
# -----------------------------------------------------------------------------
class TestCliDispatch:
    def test_enable_workspace_dispatches(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        from mordred_hermes.wizard import cli, encryption_cli

        monkeypatch.setattr(encryption_cli, "_hermes_home", lambda: tmp_path / "home")
        called = {"n": 0}
        monkeypatch.setattr(workspace_cli, "cli_enable", lambda: called.__setitem__("n", called["n"] + 1) or 0)
        assert cli.main(["encryption", "enable", "workspace"]) == 0
        assert called["n"] == 1

    def test_purge_workspace_requires_yes(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        from mordred_hermes.wizard import cli, encryption_cli

        monkeypatch.setattr(encryption_cli, "_hermes_home", lambda: tmp_path / "home")
        called = {"n": 0}
        monkeypatch.setattr(workspace_cli, "cli_purge", lambda: called.__setitem__("n", called["n"] + 1) or 0)
        assert cli.main(["encryption", "purge", "workspace"]) != 0  # refused without --yes
        assert called["n"] == 0
        assert cli.main(["encryption", "purge", "workspace", "--yes"]) == 0
        assert called["n"] == 1
