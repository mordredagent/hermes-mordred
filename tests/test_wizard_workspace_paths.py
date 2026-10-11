"""Unit tests for ``wizard._workspace_paths`` — the shared claude-private model.

Pins the property the split modules used to guarantee only by copy-paste:
``encryption status`` (read side, :class:`WorkspacePaths`) and the
enable/disable/purge verbs (:class:`WorkspaceEnv`) resolve the *same*
artifacts, including every ``CLAUDE_PRIVATE_*`` override.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from mordred_hermes.wizard._workspace_paths import (
    WorkspacePaths,
    is_mountpoint,
    resolve_workspace_env,
)


class TestResolveWorkspaceEnv:
    def test_defaults_derive_from_home(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("HOME", str(tmp_path))
        for var in ("CLAUDE_PRIVATE_IMAGE", "CLAUDE_PRIVATE_KEYDIR", "CLAUDE_PRIVATE_MOUNT"):
            monkeypatch.delenv(var, raising=False)
        env = resolve_workspace_env()
        assert env.image == tmp_path / "Private" / "claude-private.sparsebundle"
        assert env.keydir == tmp_path / ".config" / "claude-private"
        assert env.blob == env.keydir / "passphrase.wrapped"
        assert env.mount == tmp_path / ".claude-private-mnt"

    def test_env_overrides_win(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("CLAUDE_PRIVATE_IMAGE", str(tmp_path / "img.sparsebundle"))
        monkeypatch.setenv("CLAUDE_PRIVATE_KEYDIR", str(tmp_path / "keys"))
        monkeypatch.setenv("CLAUDE_PRIVATE_MOUNT", str(tmp_path / "mnt"))
        env = resolve_workspace_env()
        assert env.image == tmp_path / "img.sparsebundle"
        assert env.keydir == tmp_path / "keys"
        assert env.blob == tmp_path / "keys" / "passphrase.wrapped"
        assert env.mount == tmp_path / "mnt"

    def test_env_is_a_workspace_paths(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        # The read side annotates against WorkspacePaths; the resolver's
        # WorkspaceEnv must satisfy it so one resolution serves both surfaces.
        monkeypatch.setenv("HOME", str(tmp_path))
        assert isinstance(resolve_workspace_env(), WorkspacePaths)


class TestIsMountpoint:
    def test_plain_directory_is_not_a_mountpoint(self, tmp_path: Path) -> None:
        assert is_mountpoint(tmp_path) is False

    def test_missing_path_is_not_a_mountpoint(self, tmp_path: Path) -> None:
        assert is_mountpoint(tmp_path / "absent") is False

    def test_root_is_a_mountpoint(self) -> None:
        assert is_mountpoint(Path("/")) is True
