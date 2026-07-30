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
    (env.image / "Info.plist").write_bytes(b"plist")
    (env.image / "bands").mkdir()
    env.keydir.mkdir(parents=True)
    env.blob.write_bytes(b"wrapped")
    (env.keydir / "se.key").write_bytes(b"private")
    (env.keydir / "se.pub").write_bytes(b"public")


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
        (env.keydir / "se.key").write_bytes(b"private")
        (env.keydir / "se.pub").write_bytes(b"public")
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

    @pytest.mark.parametrize("target_name", ["image", "keydir"])
    def test_dangling_symlink_is_refused_not_treated_as_absent(
        self,
        tmp_path: Path,
        target_name: str,
    ) -> None:
        env = _env(tmp_path)
        target = getattr(env, target_name)
        target.symlink_to(tmp_path / "missing-target", target_is_directory=True)

        assert workspace_cli.purge(env=env, platform="darwin", is_mounted=lambda _p: False) == 1
        assert target.is_symlink()

    def test_remove_path_never_reports_a_dangling_symlink_as_gone(self, tmp_path: Path) -> None:
        dangling = tmp_path / "dangling"
        dangling.symlink_to(tmp_path / "missing")

        assert workspace_cli._remove_path(dangling) is False
        assert dangling.is_symlink()

    @pytest.mark.parametrize("dangerous", [Path("/"), Path.home(), Path.cwd()])
    def test_refuses_broad_key_directory(self, tmp_path: Path, dangerous: Path) -> None:
        env = _env(tmp_path)
        _set_up(env)
        unsafe = workspace_cli.WorkspaceEnv(
            image=env.image,
            blob=dangerous / "passphrase.wrapped",
            mount=env.mount,
            keydir=dangerous,
        )

        assert workspace_cli.purge(env=unsafe, platform="darwin", is_mounted=lambda _p: False) == 1
        assert env.image.exists()

    def test_refuses_overlapping_targets(self, tmp_path: Path) -> None:
        env = _env(tmp_path)
        _set_up(env)
        unsafe = workspace_cli.WorkspaceEnv(
            image=env.image,
            blob=env.image / "passphrase.wrapped",
            mount=env.mount,
            keydir=env.image,
        )

        assert workspace_cli.purge(env=unsafe, platform="darwin", is_mounted=lambda _p: False) == 1
        assert env.image.exists()

    def test_refuses_key_directory_with_unexpected_files(self, tmp_path: Path) -> None:
        env = _env(tmp_path)
        _set_up(env)
        (env.keydir / "unrelated-document.txt").write_text("keep", encoding="utf-8")

        assert workspace_cli.purge(env=env, platform="darwin", is_mounted=lambda _p: False) == 1
        assert (env.keydir / "unrelated-document.txt").exists()

    def test_refuses_parent_symlink_without_deleting_external_targets(self, tmp_path: Path) -> None:
        external_env = _env(tmp_path / "external")
        _set_up(external_env)
        linked_parent = tmp_path / "linked-parent"
        linked_parent.symlink_to(external_env.image.parent, target_is_directory=True)
        redirected = workspace_cli.WorkspaceEnv(
            image=linked_parent / external_env.image.name,
            blob=linked_parent / external_env.keydir.name / "passphrase.wrapped",
            mount=tmp_path / "mnt",
            keydir=linked_parent / external_env.keydir.name,
        )

        assert workspace_cli.purge(env=redirected, platform="darwin", is_mounted=lambda _p: False) == 1
        assert external_env.image.exists()
        assert external_env.blob.exists()
        assert linked_parent.is_symlink()

    def test_rechecks_parent_symlinks_immediately_before_deletion(self, tmp_path: Path) -> None:
        safe_root = tmp_path / "safe"
        safe_env = _env(safe_root)
        _set_up(safe_env)
        external_env = _env(tmp_path / "external")
        _set_up(external_env)

        def swap_parent_before_delete(_mount: Path) -> bool:
            workspace_cli.shutil.rmtree(safe_root)
            safe_root.symlink_to(external_env.image.parent, target_is_directory=True)
            return False

        assert workspace_cli.purge(env=safe_env, platform="darwin", is_mounted=swap_parent_before_delete) == 1
        assert external_env.image.exists()
        assert external_env.blob.exists()

    def test_purges_valid_partial_setup(self, tmp_path: Path) -> None:
        env = _env(tmp_path)
        env.keydir.mkdir(parents=True)
        env.blob.write_bytes(b"wrapped")

        assert workspace_cli.purge(env=env, platform="darwin", is_mounted=lambda _p: False) == 0
        assert not env.keydir.exists()


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
